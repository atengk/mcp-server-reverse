"""会话级写时复制 (COW) 内存虚拟补丁 MCP 工具端到端测试套件

@author Ateng
@since 2026-10-14
"""

import hashlib
from pathlib import Path

import pytest

from mcp_server_reverse.core.config import ServerConfig
from mcp_server_reverse.core.models import ErrorCode
from mcp_server_reverse.core.parser import BinaryParser
from mcp_server_reverse.core.security import SecurityGuard
from mcp_server_reverse.core.session import SessionStore
from mcp_server_reverse.tools.disasm import disassemble_impl, read_memory_impl
from mcp_server_reverse.tools.patch import (
    list_patches_impl,
    patch_memory_impl,
    revert_patch_impl,
)
from mcp_server_reverse.tools.session import open_binary_impl
from tests.fixtures.synthetic import build_synthetic_pe64


@pytest.fixture
def active_store_and_sid(tmp_path: Path) -> tuple[SessionStore, str, Path]:
    pe_file = tmp_path / "target_patch_tools.exe"
    build_synthetic_pe64(pe_file)

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


def test_patch_memory_success_and_read_overlay(
    active_store_and_sid: tuple[SessionStore, str, Path],
) -> None:
    store, sid, pe_file = active_store_and_sid
    initial_disk_bytes = pe_file.read_bytes()
    initial_disk_sha256 = hashlib.sha256(initial_disk_bytes).hexdigest()

    # 1. 前置读取入口点原始指令与内存
    read_before = read_memory_impl(
        session_id=sid,
        address="0x140001000",
        address_type="va",
        size=4,
        session_store=store,
    )
    assert read_before["ok"] is True
    orig_hex = read_before["data"]["hex_bytes"]

    # 2. 应用 NOP + INT3 补丁 (90 90 CC)
    patch_resp = patch_memory_impl(
        session_id=sid,
        address_or_offset="0x140001000",
        patch_hex="90 90 CC",
        address_type="va",
        session_store=store,
    )
    assert patch_resp["ok"] is True
    assert patch_resp["data"]["patch_id"] == "patch_0001"
    assert patch_resp["data"]["target_address"] == "0x140001000"
    assert patch_resp["data"]["patch_bytes_hex"] == "90 90 CC"
    assert patch_resp["data"]["original_bytes_hex"] == orig_hex[:8].strip()
    assert patch_resp["data"]["size"] == 3
    assert patch_resp["data"]["status"] == "active"

    # 3. 验证 read_memory 透明感知补丁覆写
    read_after = read_memory_impl(
        session_id=sid,
        address="0x140001000",
        address_type="va",
        size=4,
        session_store=store,
    )
    assert read_after["ok"] is True
    assert read_after["data"]["hex_bytes"].startswith("90 90 CC")

    # 4. 验证 disassemble 透明感知补丁新指令
    disasm_after = disassemble_impl(
        session_id=sid,
        target="0x140001000",
        count=3,
        stop_at_ret=False,
        session_store=store,
    )
    assert disasm_after["ok"] is True
    insns = disasm_after["data"]["instructions"]
    assert len(insns) >= 2
    assert insns[0]["mnemonic"] == "nop"
    assert insns[1]["mnemonic"] == "nop"

    # 5. 核心铁律验证：物理磁盘文件 100% 字节不变
    current_disk_bytes = pe_file.read_bytes()
    assert current_disk_bytes == initial_disk_bytes
    assert hashlib.sha256(current_disk_bytes).hexdigest() == initial_disk_sha256


def test_list_and_revert_patches(
    active_store_and_sid: tuple[SessionStore, str, Path],
) -> None:
    store, sid, pe_file = active_store_and_sid
    initial_disk_bytes = pe_file.read_bytes()

    # 1. 初始补丁列表为空
    list_init = list_patches_impl(session_id=sid, session_store=store)
    assert list_init["ok"] is True
    assert list_init["data"]["patches"] == []
    assert list_init["data"]["total"] == 0

    # 2. 连续打入两个补丁
    p1 = patch_memory_impl(
        session_id=sid,
        address_or_offset="0x140001000",
        patch_hex="90 90",
        address_type="va",
        session_store=store,
    )
    assert p1["ok"] is True
    p2 = patch_memory_impl(
        session_id=sid,
        address_or_offset="0x140001002",
        patch_hex="CC",
        address_type="va",
        session_store=store,
    )
    assert p2["ok"] is True

    # 3. 校验 list_patches 呈现两个条目
    list_mid = list_patches_impl(session_id=sid, session_store=store)
    assert list_mid["ok"] is True
    assert list_mid["data"]["total"] == 2
    patch_ids = [p["patch_id"] for p in list_mid["data"]["patches"]]
    assert patch_ids == ["patch_0001", "patch_0002"]

    # 4. 单项回滚 patch_0001
    rev1 = revert_patch_impl(session_id=sid, patch_id="patch_0001", session_store=store)
    assert rev1["ok"] is True
    assert rev1["data"]["reverted_patch_ids"] == ["patch_0001"]
    assert rev1["data"]["remaining_patches_count"] == 1

    # 5. 验证 0x140001000 恢复原样，而 0x140001002 依然保持 CC
    read_mid = read_memory_impl(
        session_id=sid,
        address="0x140001000",
        address_type="va",
        size=3,
        session_store=store,
    )
    assert read_mid["ok"] is True
    bytes_list = read_mid["data"]["hex_bytes"].split()
    assert bytes_list[2] == "CC"

    # 6. 全量回滚 (patch_id=None)
    rev_all = revert_patch_impl(session_id=sid, patch_id=None, session_store=store)
    assert rev_all["ok"] is True
    assert "patch_0002" in rev_all["data"]["reverted_patch_ids"]
    assert rev_all["data"]["remaining_patches_count"] == 0

    # 7. 再次读取激活补丁列表，确认全部恢复原样 (激活数为 0)
    list_final = list_patches_impl(session_id=sid, session_store=store)
    assert list_final["data"]["total"] == 0

    # 8. 校验 include_reverted=True 留存完整撤回审计历史
    list_hist = list_patches_impl(session_id=sid, include_reverted=True, session_store=store)
    assert list_hist["data"]["total"] == 2
    assert all(p["status"] == "reverted" for p in list_hist["data"]["patches"])
    assert pe_file.read_bytes() == initial_disk_bytes


def test_patch_memory_validation_and_errors(
    active_store_and_sid: tuple[SessionStore, str, Path],
) -> None:
    store, sid, _ = active_store_and_sid

    # 1. 无效 session_id
    err_sid = patch_memory_impl(
        session_id="non_exist_sid",
        address_or_offset="0x140001000",
        patch_hex="90 90",
        session_store=store,
    )
    assert err_sid["ok"] is False
    assert err_sid["error"]["code"] == ErrorCode.SESSION_NOT_FOUND.value

    # 2. 非法十六进制字符串 (包含非法字符或奇数长度)
    err_hex1 = patch_memory_impl(
        session_id=sid,
        address_or_offset="0x140001000",
        patch_hex="90 ZZ",
        session_store=store,
    )
    assert err_hex1["ok"] is False
    assert err_hex1["error"]["code"] == ErrorCode.INVALID_PARAMETER.value

    err_hex2 = patch_memory_impl(
        session_id=sid,
        address_or_offset="0x140001000",
        patch_hex="909",
        session_store=store,
    )
    assert err_hex2["ok"] is False
    assert err_hex2["error"]["code"] == ErrorCode.INVALID_PARAMETER.value

    # 3. 空补丁字符串
    err_empty = patch_memory_impl(
        session_id=sid,
        address_or_offset="0x140001000",
        patch_hex="",
        session_store=store,
    )
    assert err_empty["ok"] is False
    assert err_empty["error"]["code"] == ErrorCode.INVALID_PARAMETER.value

    # 4. 地址越界
    err_addr = patch_memory_impl(
        session_id=sid,
        address_or_offset="0xFFFFFFFFFFF",
        patch_hex="90 90",
        session_store=store,
    )
    assert err_addr["ok"] is False
    assert err_addr["error"]["code"] == ErrorCode.ADDRESS_OR_SYMBOL_NOT_FOUND.value

    # 5. 回滚不存在的补丁 ID
    err_rev = revert_patch_impl(
        session_id=sid,
        patch_id="patch_9999",
        session_store=store,
    )
    assert err_rev["ok"] is False
    assert err_rev["error"]["code"] == ErrorCode.INVALID_PARAMETER.value
