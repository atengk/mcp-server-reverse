"""会话管理与全景取证 MCP Tools 测试套件

@author Ateng
@since 2026-10-13
"""

import json
from pathlib import Path

import pytest

from mcp_server_reverse.core.config import ServerConfig
from mcp_server_reverse.server import create_mcp_server
from tests.fixtures.synthetic import build_synthetic_pe64


@pytest.mark.asyncio
async def test_open_binary_and_session_lifecycle(tmp_path: Path) -> None:
    pe_file = tmp_path / "valid_sample.exe"
    build_synthetic_pe64(pe_file)

    config = ServerConfig(allowed_dirs=[tmp_path])
    server = create_mcp_server(config)

    # 1. 首次打开二进制文件
    res = await server.call_tool("open_binary", {"file_path": str(pe_file)})
    assert res.is_error is False
    payload = json.loads(res.content[0].text)

    assert payload["ok"] is True
    assert payload["error"] is None
    session_id = payload["session_id"]
    assert session_id is not None
    assert len(session_id) == 12

    # 校验 data 结构
    data = payload["data"]
    assert data["session_id"] == session_id
    assert "file_info" in data
    assert "format_info" in data
    assert "triage_overview" in data
    assert "forensic_metadata" in data

    # 2. 再次打开相同的二进制，命中缓存
    res_cached = await server.call_tool("open_binary", {"file_path": str(pe_file)})
    payload_cached = json.loads(res_cached.content[0].text)
    assert payload_cached["ok"] is True
    assert payload_cached["session_id"] == session_id

    # 3. 列出当前活跃会话
    res_list = await server.call_tool("list_sessions", {})
    payload_list = json.loads(res_list.content[0].text)
    assert payload_list["ok"] is True
    sessions = payload_list["data"]["sessions"]
    assert len(sessions) == 1
    assert sessions[0]["session_id"] == session_id

    # 4. 关闭不存在的会话
    res_fail = await server.call_tool("close_session", {"session_id": "non_existent"})
    payload_fail = json.loads(res_fail.content[0].text)
    assert payload_fail["ok"] is False
    assert payload_fail["error"]["code"] == "SESSION_NOT_FOUND"

    # 5. 关闭已存在会话
    res_close = await server.call_tool("close_session", {"session_id": session_id})
    payload_close = json.loads(res_close.content[0].text)
    assert payload_close["ok"] is True
    assert payload_close["data"]["closed_count"] == 1
    assert payload_close["data"]["remaining_sessions"] == 0

    # 再次查询应为空
    res_list_empty = await server.call_tool("list_sessions", {})
    payload_list_empty = json.loads(res_list_empty.content[0].text)
    assert len(payload_list_empty["data"]["sessions"]) == 0


@pytest.mark.asyncio
async def test_open_binary_sandbox_forbidden(tmp_path: Path) -> None:
    sandbox = tmp_path / "allowed_dir"
    sandbox.mkdir()
    outside_file = tmp_path / "forbidden.exe"
    build_synthetic_pe64(outside_file)

    config = ServerConfig(allowed_dirs=[sandbox])
    server = create_mcp_server(config)

    res = await server.call_tool("open_binary", {"file_path": str(outside_file)})
    payload = json.loads(res.content[0].text)
    assert payload["ok"] is False
    assert payload["error"]["code"] == "SANDBOX_PATH_FORBIDDEN"


@pytest.mark.asyncio
async def test_open_binary_lru_eviction_end_to_end(tmp_path: Path) -> None:
    # 配置最大会话容量为 2
    config = ServerConfig(allowed_dirs=[tmp_path], max_sessions=2)
    server = create_mcp_server(config)

    sids = []
    for i in range(3):
        bin_file = tmp_path / f"sample_{i}.exe"
        build_synthetic_pe64(bin_file)
        # 为确保每个文件哈希不同，在末尾追加不同字节
        with bin_file.open("ab") as f:
            f.write(f"UNIQUE_SALT_{i}".encode())

        res = await server.call_tool("open_binary", {"file_path": str(bin_file)})
        payload = json.loads(res.content[0].text)
        assert payload["ok"] is True
        sids.append(payload["session_id"])

    # 验证当前 list_sessions 中驻留的仅有后 2 个会话，第 0 个已被淘汰
    res_list = await server.call_tool("list_sessions", {})
    payload_list = json.loads(res_list.content[0].text)
    active_ids = [s["session_id"] for s in payload_list["data"]["sessions"]]

    assert len(active_ids) == 2
    assert sids[0] not in active_ids
    assert sids[1] in active_ids
    assert sids[2] in active_ids
