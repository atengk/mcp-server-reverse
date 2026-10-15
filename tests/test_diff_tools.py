"""跨会话二阶结构化差异画像 (diff_sessions) MCP 工具端到端测试套件

遵循单一最高阶测试缝隙 (server.call_tool) 进行端到端黑盒验证。

@author Ateng
@since 2026-10-15
"""

import json
from pathlib import Path
from typing import Any

import pytest

from mcp_server_reverse.core.config import ServerConfig
from mcp_server_reverse.core.diff import compute_fuzzy_hash_similarity
from mcp_server_reverse.core.models import ErrorCode
from mcp_server_reverse.core.session import SessionStore
from mcp_server_reverse.server import create_mcp_server
from tests.fixtures.synthetic import (
    build_synthetic_elf64,
    build_synthetic_pe64,
)


def _unpack(res: Any) -> dict[str, Any]:
    """从 MCP 工具返回结果中解包响应字典"""
    if hasattr(res, "content") and res.content:
        return json.loads(res.content[0].text)
    return res


def test_fuzzy_hash_similarity_scoring() -> None:
    """验证 SSDEEP 模糊哈希分值计算在完全一致、倍数步长与不相关时的行为"""
    # 1. 完全一致或空值
    assert compute_fuzzy_hash_similarity(None, None) == 0
    assert compute_fuzzy_hash_similarity("384:abc:def", None) == 0
    assert compute_fuzzy_hash_similarity("384:abc:def", "384:abc:def") == 100

    # 2. 格式非法
    assert compute_fuzzy_hash_similarity("invalid_hash", "384:abc:def") == 0
    assert compute_fuzzy_hash_similarity("abc:def:ghi", "384:abc:def") == 0

    # 3. 相同步长编辑距离分值
    h1 = f"96:{'A' * 64}:{'B' * 32}"
    h2 = f"96:{'A' * 63}C:{'B' * 32}"
    score = compute_fuzzy_hash_similarity(h1, h2)
    assert 90 <= score <= 100

    # 4. 步长差超过 2 倍无相似度
    h_small = "48:AAAA:BBBB"
    h_large = "192:AAAA:BBBB"
    assert compute_fuzzy_hash_similarity(h_small, h_large) == 0


@pytest.mark.asyncio
async def test_diff_sessions_session_not_found(tmp_path: Path) -> None:
    """验证 diff_sessions 针对不存在的基准或目标会话返回标准 SESSION_NOT_FOUND 错误"""
    pe_file = tmp_path / "valid.exe"
    build_synthetic_pe64(pe_file)

    server = create_mcp_server(ServerConfig())
    open_res = await server.call_tool("open_binary", {"file_path": str(pe_file)})
    valid_sid = _unpack(open_res)["session_id"]

    # 1. 基准会话不存在
    bad_a = await server.call_tool(
        "diff_sessions",
        {"session_id_a": "non_existent_a", "session_id_b": valid_sid},
    )
    data_bad_a = _unpack(bad_a)
    assert data_bad_a["ok"] is False
    assert data_bad_a["error"]["code"] == ErrorCode.SESSION_NOT_FOUND.value

    # 2. 目标会话不存在
    bad_b = await server.call_tool(
        "diff_sessions",
        {"session_id_a": valid_sid, "session_id_b": "non_existent_b"},
    )
    data_bad_b = _unpack(bad_b)
    assert data_bad_b["ok"] is False
    assert data_bad_b["error"]["code"] == ErrorCode.SESSION_NOT_FOUND.value


@pytest.mark.asyncio
async def test_diff_sessions_identical_binaries(tmp_path: Path) -> None:
    """验证比对两个相同文件会话时相似度为 100 且全部增删集合均为空列表"""
    pe_file = tmp_path / "sample.exe"
    build_synthetic_pe64(pe_file)

    store = SessionStore()
    server = create_mcp_server(ServerConfig(), session_store=store)

    res1 = await server.call_tool("open_binary", {"file_path": str(pe_file)})
    sid1 = _unpack(res1)["session_id"]

    res2 = await server.call_tool("open_binary", {"file_path": str(pe_file), "force_reload": True})
    sid2 = _unpack(res2)["session_id"]

    diff_res = await server.call_tool("diff_sessions", {"session_id_a": sid1, "session_id_b": sid2})
    data = _unpack(diff_res)
    assert data["ok"] is True
    diff = data["data"]

    # 1. 同源相似度分值达到 100%
    assert diff["similarity_score"] == 100

    # 2. 基础文件信息完全匹配且尺寸增量为 0
    finfo = diff["file_info"]
    assert finfo["format"]["match"] is True
    assert finfo["arch"]["match"] is True
    assert finfo["bits"]["match"] is True
    assert finfo["endian"]["match"] is True
    assert finfo["size"]["delta"] == 0

    # 3. 节区增删变动集合为空
    secs = diff["sections"]
    assert secs["added"] == []
    assert secs["removed"] == []
    assert secs["modified"] == []
    assert secs["newly_high_entropy_sections"] == []
    assert len(secs["common"]) >= 1

    # 4. 导入导出表增删集合为空
    imps = diff["imports"]
    assert imps["added"] == []
    assert imps["removed"] == []
    assert imps["added_suspicious_categories"] == []

    exps = diff["exports"]
    assert exps["added"] == []
    assert exps["removed"] == []

    # 5. 符号变动与基址重定位偏移为 0x0
    syms = diff["symbols"]
    assert syms["added_functions"] == []
    assert syms["removed_functions"] == []
    assert syms["modified_functions"] == []
    assert syms["base_relocation_offset"] == "0x0"


@pytest.mark.asyncio
async def test_diff_sessions_patched_variant_and_aliases(tmp_path: Path) -> None:
    """验证对会话应用虚拟补丁后能准确检测差异，并测试参数别名 (session_a, session_b)"""
    pe_file = tmp_path / "original.exe"
    build_synthetic_pe64(pe_file)

    store = SessionStore()
    server = create_mcp_server(ServerConfig(), session_store=store)

    res_orig = await server.call_tool("open_binary", {"file_path": str(pe_file)})
    sid_orig = _unpack(res_orig)["session_id"]

    res_mod = await server.call_tool(
        "open_binary", {"file_path": str(pe_file), "force_reload": True}
    )
    sid_mod = _unpack(res_mod)["session_id"]

    # 对第二个会话应用内存虚拟补丁
    patch_res = await server.call_tool(
        "patch_memory",
        {"session_id": sid_mod, "address_or_offset": "0x140001000", "patch_hex": "CC CC CC CC"},
    )
    assert _unpack(patch_res)["ok"] is True

    # 使用别名 session_a / session_b 发起对比
    diff_res = await server.call_tool(
        "diff_sessions",
        {"session_a": sid_orig, "session_b": sid_mod},
    )
    data = _unpack(diff_res)
    assert data["ok"] is True
    diff = data["data"]

    assert "similarity_score" in diff
    assert 0 <= diff["similarity_score"] <= 100
    assert diff["file_info"]["format"]["match"] is True


@pytest.mark.asyncio
async def test_diff_sessions_cross_architecture(tmp_path: Path) -> None:
    """验证比对不同架构与不同格式二进制时正确标记差异与增删集合"""
    pe_file = tmp_path / "sample_pe64.exe"
    elf_file = tmp_path / "sample_elf64.elf"
    build_synthetic_pe64(pe_file)
    build_synthetic_elf64(elf_file)

    store = SessionStore()
    server = create_mcp_server(ServerConfig(), session_store=store)

    sid_pe = _unpack(await server.call_tool("open_binary", {"file_path": str(pe_file)}))[
        "session_id"
    ]
    sid_elf = _unpack(await server.call_tool("open_binary", {"file_path": str(elf_file)}))[
        "session_id"
    ]

    # 使用别名 source / target 进行比对
    diff_res = await server.call_tool("diff_sessions", {"source": sid_pe, "target": sid_elf})
    data = _unpack(diff_res)
    assert data["ok"] is True
    diff = data["data"]

    # 1. 架构与格式不匹配
    assert diff["file_info"]["format"]["match"] is False
    assert diff["file_info"]["format"]["a"] == "PE"
    assert diff["file_info"]["format"]["b"] == "ELF"

    # 2. 存在节区与导入导出增删
    assert "sections" in diff
    assert "imports" in diff
    assert "exports" in diff
    assert "symbols" in diff
