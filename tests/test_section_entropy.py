"""节区滑动窗口局部高熵块细粒度探测 (get_sections 增强) 端到端测试套件

@author Ateng
@since 2026-10-14
"""

import os
from pathlib import Path
from typing import Any

import pytest

from mcp_server_reverse.core.config import ServerConfig
from mcp_server_reverse.core.inspection import scan_local_entropy_blocks
from mcp_server_reverse.core.models import ErrorCode
from mcp_server_reverse.core.parser import BinaryParser
from mcp_server_reverse.core.security import SecurityGuard
from mcp_server_reverse.core.session import SessionStore
from mcp_server_reverse.tools.patch import patch_memory_impl
from mcp_server_reverse.tools.session import open_binary_impl
from mcp_server_reverse.tools.symbols import get_sections_impl
from tests.fixtures.synthetic import build_synthetic_pe64_large_text


@pytest.fixture
def pe_session(tmp_path: Path) -> tuple[SessionStore, str, Path]:
    pe_file = tmp_path / "target_entropy.exe"
    build_synthetic_pe64_large_text(pe_file)

    config = ServerConfig()
    store = SessionStore()
    resp = open_binary_impl(
        file_path=str(pe_file),
        target_arch=None,
        config=config,
        session_store=store,
        security_guard=SecurityGuard(),
        parser=BinaryParser(),
    )
    return store, resp["session_id"], pe_file


def test_get_sections_default_local_entropy_detection(
    pe_session: tuple[SessionStore, str, Path],
) -> None:
    store, sid, _ = pe_session

    # 默认调用 get_sections_impl 并验证向后兼容字段存在
    resp = get_sections_impl(session_id=sid, session_store=store)
    assert resp["ok"] is True
    sections = resp["data"]["sections"]
    assert len(sections) > 0

    # 检查向后兼容性：每个节区均包含 local_high_entropy_blocks 字段
    for sec in sections:
        assert "local_high_entropy_blocks" in sec
        assert isinstance(sec["local_high_entropy_blocks"], list)


def test_get_sections_detect_diluted_local_high_entropy_default_params(
    pe_session: tuple[SessionStore, str, Path],
) -> None:
    store, sid, _ = pe_session

    # 1. 在 8KB .text 大节区内对齐注入 2048 字节伪随机高熵块 (香农熵 > 7.5)
    # 注入基地址 0x140001800 (相对 .text 起始 0x140001000 偏移 2048 字节)
    random_payload = os.urandom(2048)
    patch_hex = random_payload.hex()

    patch_resp = patch_memory_impl(
        session_id=sid,
        address_or_offset="0x140001800",
        patch_hex=patch_hex,
        address_type="va",
        session_store=store,
    )
    assert patch_resp["ok"] is True

    # 2. 以缺省参数 (detect_local_entropy=True, window_size=2048, step=1024) 运行
    resp = get_sections_impl(session_id=sid, session_store=store)
    assert resp["ok"] is True
    sections = resp["data"]["sections"]

    text_sec = next((s for s in sections if s["name"] == ".text"), None)
    assert text_sec is not None

    # 3. 校验整体低熵稀释大节区 (< 6.0 且非高熵节区) 下局部高熵块被精准识别
    assert text_sec["entropy"] < 6.0
    assert text_sec["is_high_entropy"] is False

    local_blocks: list[dict[str, Any]] = text_sec["local_high_entropy_blocks"]
    assert len(local_blocks) == 1

    hit = local_blocks[0]
    assert hit["max_entropy"] >= 7.2
    assert hit["size"] == 2048
    assert hit["virtual_address"] == "0x140001800"


def test_get_sections_detect_diluted_local_high_entropy_custom_params(
    pe_session: tuple[SessionStore, str, Path],
) -> None:
    store, sid, _ = pe_session

    # 1. 在 .text 节区偏移 0x200 处注入 2048 字节随机高熵块
    random_payload = os.urandom(2048)
    patch_hex = random_payload.hex()

    patch_resp = patch_memory_impl(
        session_id=sid,
        address_or_offset="0x140001200",
        patch_hex=patch_hex,
        address_type="va",
        session_store=store,
    )
    assert patch_resp["ok"] is True

    # 2. 执行带有自定义小尺寸滑动窗口 (window_size=1024, step=512) 探测
    resp = get_sections_impl(
        session_id=sid,
        session_store=store,
        detect_local_entropy=True,
        window_size=1024,
        step=512,
    )
    assert resp["ok"] is True
    sections = resp["data"]["sections"]

    text_sec = next((s for s in sections if s["name"] == ".text"), None)
    assert text_sec is not None

    local_blocks: list[dict[str, Any]] = text_sec["local_high_entropy_blocks"]
    assert len(local_blocks) >= 1

    hit = local_blocks[0]
    assert hit["max_entropy"] >= 7.2
    assert hit["size"] >= 1024
    assert hit["virtual_address"] is not None
    assert int(hit["virtual_address"], 16) >= 0x140001200


def test_get_sections_detect_local_entropy_disabled(
    pe_session: tuple[SessionStore, str, Path],
) -> None:
    store, sid, _ = pe_session

    # 当显式关闭 detect_local_entropy 时，不执行滑动窗口扫描
    resp = get_sections_impl(
        session_id=sid,
        session_store=store,
        detect_local_entropy=False,
    )
    assert resp["ok"] is True
    for sec in resp["data"]["sections"]:
        assert sec["local_high_entropy_blocks"] == []


def test_get_sections_invalid_session_defense() -> None:
    store = SessionStore()
    resp = get_sections_impl(session_id="non_exist_id", session_store=store)
    assert resp["ok"] is False
    assert resp["error"]["code"] == ErrorCode.SESSION_NOT_FOUND.value


def test_scan_local_entropy_blocks_interval_merging() -> None:
    # 构造由低熵与连续高熵组成的数据流：
    # 0..1024: 0x90 (低熵)
    # 1024..4096: 3072 字节伪随机高熵 (跨越多个连续窗口)
    # 4096..5120: 0x90 (低熵)
    data = bytearray(b"\x90" * 1024)
    data.extend(os.urandom(3072))
    data.extend(b"\x90" * 1024)

    # 以 window_size=1024, step=512 扫描
    blocks = scan_local_entropy_blocks(
        data=bytes(data),
        raw_offset=0x1000,
        base_va=0x401000,
        window_size=1024,
        step=512,
    )

    # 验证重叠与相交高熵区间被聚合成单个连续大块
    assert len(blocks) == 1
    block = blocks[0]
    assert block.offset == 0x1000 + 1024
    assert block.virtual_address == f"0x{0x401000 + 1024:X}"
    assert block.size >= 3072
    assert block.max_entropy >= 7.2


def test_scan_local_entropy_blocks_large_section_adaptive_step() -> None:
    # 构造小于窗口的数据，确保直接返回空
    small_data = b"\x90" * 500
    assert scan_local_entropy_blocks(small_data, 0, 0x400000, window_size=2048) == []

    # 验证空数据返回空列表
    assert scan_local_entropy_blocks(b"", 0, 0x400000) == []
