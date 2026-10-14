"""反汇编、交叉引用、内存检视与反编译 MCP 工具端到端测试套件

@author Ateng
@since 2026-10-13
"""

import asyncio
from pathlib import Path

import pytest

from mcp_server_reverse.core.config import ServerConfig
from mcp_server_reverse.core.locator import ToolLocator
from mcp_server_reverse.core.models import ErrorCode, ExternalCapability
from mcp_server_reverse.core.parser import BinaryParser
from mcp_server_reverse.core.security import SecurityGuard
from mcp_server_reverse.core.session import SessionStore
from mcp_server_reverse.tools.disasm import (
    convert_address_impl,
    decompile_function_impl,
    disassemble_impl,
    find_xrefs_impl,
    read_memory_impl,
)
from mcp_server_reverse.tools.session import open_binary_impl
from tests.fixtures.synthetic import build_synthetic_pe64


@pytest.fixture
def active_store_and_sid(tmp_path: Path) -> tuple[SessionStore, str]:
    pe_file = tmp_path / "target_disasm_tools.exe"
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
    return store, resp["session_id"]


def test_convert_address_and_read_memory_tools(
    active_store_and_sid: tuple[SessionStore, str],
) -> None:
    store, sid = active_store_and_sid

    # 1. convert_address 正常换算
    conv_resp = convert_address_impl(
        session_id=sid,
        address="0x140001000",
        address_type="va",
        session_store=store,
    )
    assert conv_resp["ok"] is True
    assert conv_resp["data"]["rva"] == "0x1000"
    assert conv_resp["data"]["offset"] == 0x200
    assert conv_resp["data"]["section"] == ".text"

    # 1.1 convert_address 越界拦截
    oob_resp = convert_address_impl(
        session_id=sid,
        address="0x140999000",
        address_type="va",
        session_store=store,
    )
    assert oob_resp["ok"] is False
    assert oob_resp["error"]["code"] == ErrorCode.ADDRESS_OR_SYMBOL_NOT_FOUND.value

    # 2. read_memory 正常读取
    mem_resp = read_memory_impl(
        session_id=sid,
        address="0x140002250",
        size=32,
        address_type="va",
        session_store=store,
    )
    assert mem_resp["ok"] is True
    assert mem_resp["data"]["size"] == 32
    assert "https://api.exam" in mem_resp["data"]["hexdump_lines"][0]


@pytest.mark.asyncio
async def test_disassemble_and_find_xrefs_tools(
    active_store_and_sid: tuple[SessionStore, str],
) -> None:
    store, sid = active_store_and_sid

    # 1. disassemble 按导出符号名反汇编
    dis_resp = disassemble_impl(
        session_id=sid,
        target="reverse_test_entry",
        count=16,
        stop_at_ret=True,
        session_store=store,
    )
    assert dis_resp["ok"] is True
    assert dis_resp["data"]["stopped_at_ret"] is True
    assert dis_resp["data"]["instruction_count"] == 4
    first_line = dis_resp["data"]["compact_lines"][0]
    assert "https://api.example.com/v1/token" in first_line

    # 1.1 disassemble 未知符号报错
    bad_dis = disassemble_impl(
        session_id=sid,
        target="unknown_func_999",
        count=16,
        stop_at_ret=True,
        session_store=store,
    )
    assert bad_dis["ok"] is False
    assert bad_dis["error"]["code"] == ErrorCode.ADDRESS_OR_SYMBOL_NOT_FOUND.value

    # 2. find_xrefs 异步构建惰性索引并命中
    xref_resp = await find_xrefs_impl(
        session_id=sid,
        target="0x140002250",
        xref_type="all",
        offset=0,
        limit=50,
        session_store=store,
    )
    assert xref_resp["ok"] is True
    assert xref_resp["pagination"]["total"] >= 1
    xrefs = xref_resp["data"]["xrefs"]
    assert xrefs[0]["from_address"] == "0x140001000"
    assert xrefs[0]["type"] == "rip_relative"


@pytest.mark.asyncio
async def test_decompile_function_unavailable_and_timeout(
    active_store_and_sid: tuple[SessionStore, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, sid = active_store_and_sid

    # 1. 模拟 radare2 未安装，返回 EXTERNAL_TOOL_UNAVAILABLE
    unavail_cap = ExternalCapability(
        name="radare2",
        available=False,
        install_guide="winget install radare2",
        recommended_action="请改用 disassemble",
    )
    monkeypatch.setattr(ToolLocator, "locate_tool", lambda self, name: unavail_cap)

    resp_unavail = await decompile_function_impl(
        session_id=sid,
        target="0x140001000",
        timeout_seconds=5,
        session_store=store,
    )
    assert resp_unavail["ok"] is False
    assert resp_unavail["error"]["code"] == ErrorCode.EXTERNAL_TOOL_UNAVAILABLE.value

    # 2. 模拟 radare2 已安装但执行超时，返回 EXTERNAL_TOOL_TIMEOUT
    avail_cap = ExternalCapability(
        name="radare2",
        available=True,
        path="/usr/bin/r2",
    )
    monkeypatch.setattr(ToolLocator, "locate_tool", lambda self, name: avail_cap)

    class SlowProc:
        def kill(self) -> None:
            pass

        async def communicate(self) -> tuple[bytes, bytes]:
            await asyncio.sleep(10)
            return b"", b""

    async def fake_exec(*args: object, **kwargs: object) -> SlowProc:
        return SlowProc()

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)

    resp_timeout = await decompile_function_impl(
        session_id=sid,
        target="0x140001000",
        timeout_seconds=1,
        session_store=store,
    )
    assert resp_timeout["ok"] is False
    assert resp_timeout["error"]["code"] == ErrorCode.EXTERNAL_TOOL_TIMEOUT.value


@pytest.mark.asyncio
async def test_mcp_server_registers_all_tools() -> None:
    from mcp_server_reverse.server import create_mcp_server

    server = create_mcp_server(ServerConfig())
    tools = await server.list_tools()
    tool_names = {t.name for t in tools}

    expected_tools = {
        "get_capabilities",
        "open_binary",
        "list_sessions",
        "close_session",
        "get_sections",
        "get_imports",
        "get_exports",
        "get_symbols",
        "search_strings",
        "search_bytes_and_constants",
        "convert_address",
        "read_memory",
        "disassemble",
        "find_xrefs",
        "decompile_function",
        "patch_memory",
        "list_patches",
        "revert_patch",
        "analyze_cfg",
    }
    assert tool_names == expected_tools
    assert len(tool_names) == 19
