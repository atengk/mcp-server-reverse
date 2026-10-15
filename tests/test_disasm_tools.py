"""反汇编、交叉引用、内存检视与反编译 MCP 工具端到端测试套件

@author Ateng
@since 2026-10-13
"""

import asyncio
import json
from pathlib import Path
from typing import Any

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
        "export_patched_binary",
        "analyze_cfg",
        "audit_mitigations",
        "scan_yara",
    }
    assert tool_names == expected_tools
    assert len(tool_names) == 22


@pytest.mark.asyncio
async def test_arm32_thumb_mode_auto_and_explicit(tmp_path: Path) -> None:
    from mcp_server_reverse.server import create_mcp_server
    from tests.fixtures.synthetic import build_synthetic_arm32_elf

    def _unpack(res: Any) -> dict[str, Any]:
        if hasattr(res, "content") and res.content:
            return json.loads(res.content[0].text)
        return res

    arm_elf = tmp_path / "target_arm32.elf"
    build_synthetic_arm32_elf(arm_elf)

    server = create_mcp_server(ServerConfig())
    open_res = await server.call_tool("open_binary", {"file_path": str(arm_elf)})
    open_dict = _unpack(open_res)
    sid = open_dict["session_id"]
    assert sid is not None

    # 1. disassemble 奇数地址 (0x10001) 自动对齐至 0x10000 并切换 Thumb 模式反汇编
    dis_odd = await server.call_tool(
        "disassemble", {"session_id": sid, "target": "0x10001", "count": 2}
    )
    data_odd = _unpack(dis_odd)
    assert data_odd["ok"] is True
    assert data_odd["data"]["start_address"] == "0x10000"
    assert data_odd["data"]["thumb_mode"] is True
    insns_odd = data_odd["data"]["instructions"]
    assert len(insns_odd) >= 2
    assert insns_odd[0]["mnemonic"] == "nop"
    assert insns_odd[1]["mnemonic"] == "bx"

    # 2. disassemble 偶数地址 (0x10000) 显式传入 thumb=True 强制按 Thumb 模式反汇编
    dis_even_thumb = await server.call_tool(
        "disassemble", {"session_id": sid, "target": "0x10000", "count": 2, "thumb": True}
    )
    data_even = _unpack(dis_even_thumb)
    assert data_even["ok"] is True
    assert data_even["data"]["start_address"] == "0x10000"
    assert data_even["data"]["thumb_mode"] is True
    insns_even = data_even["data"]["instructions"]
    assert insns_even[0]["mnemonic"] == "nop"
    assert insns_even[1]["mnemonic"] == "bx"

    # 3. convert_address 奇数地址自动对齐并标记 thumb_mode
    conv_odd = await server.call_tool(
        "convert_address", {"session_id": sid, "address": "0x10001", "address_type": "va"}
    )
    conv_data_odd = _unpack(conv_odd)
    assert conv_data_odd["ok"] is True
    assert conv_data_odd["data"]["va"] == "0x10000"
    assert conv_data_odd["data"]["thumb_mode"] is True

    # 4. convert_address 偶数地址显式指定 thumb=True
    conv_even = await server.call_tool(
        "convert_address",
        {"session_id": sid, "address": "0x10000", "address_type": "va", "thumb": True},
    )
    conv_data_even = _unpack(conv_even)
    assert conv_data_even["ok"] is True
    assert conv_data_even["data"]["va"] == "0x10000"
    assert conv_data_even["data"]["thumb_mode"] is True


@pytest.mark.asyncio
async def test_disasm_annotation_cache_lifecycle(tmp_path: Path) -> None:
    from mcp_server_reverse.server import create_mcp_server
    from tests.fixtures.synthetic import build_synthetic_pe64

    def _unpack(res: Any) -> dict[str, Any]:
        if hasattr(res, "content") and res.content:
            return json.loads(res.content[0].text)
        return res

    pe_file = tmp_path / "target_cache.exe"
    build_synthetic_pe64(pe_file)

    store = SessionStore()
    server = create_mcp_server(ServerConfig(), session_store=store)
    open_res = await server.call_tool("open_binary", {"file_path": str(pe_file)})
    sid = _unpack(open_res)["session_id"]

    session = store.get(sid)
    assert session is not None
    assert session._annotation_cache is None

    # 1. 首次反汇编，构建并命中缓存
    dis_res = await server.call_tool(
        "disassemble", {"session_id": sid, "target": "reverse_test_entry"}
    )
    assert _unpack(dis_res)["ok"] is True
    assert session._annotation_cache is not None
    cache_id = id(session._annotation_cache)

    # 2. 二次反汇编，复用同内存实例缓存
    dis_res2 = await server.call_tool(
        "disassemble", {"session_id": sid, "target": "reverse_test_entry"}
    )
    assert _unpack(dis_res2)["ok"] is True
    assert id(session._annotation_cache) == cache_id

    # 3. 内存打补丁，注销注释缓存
    patch_res = await server.call_tool(
        "patch_memory",
        {"session_id": sid, "address_or_offset": "0x140001000", "patch_hex": "90 90"},
    )
    assert _unpack(patch_res)["ok"] is True
    assert session._annotation_cache is None

    # 4. 再次反汇编，重新构建缓存
    await server.call_tool("disassemble", {"session_id": sid, "target": "reverse_test_entry"})
    assert session._annotation_cache is not None

    # 5. 回滚补丁，再次清空缓存
    revert_res = await server.call_tool("revert_patch", {"session_id": sid})
    assert _unpack(revert_res)["ok"] is True
    assert session._annotation_cache is None


@pytest.mark.asyncio
async def test_find_xrefs_group_by_function_and_validation(tmp_path: Path) -> None:
    from mcp_server_reverse.server import create_mcp_server
    from tests.fixtures.synthetic import build_synthetic_pe64

    def _unpack(res: Any) -> dict[str, Any]:
        if hasattr(res, "content") and res.content:
            return json.loads(res.content[0].text)
        return res

    pe_file = tmp_path / "target_xrefs_grp.exe"
    build_synthetic_pe64(pe_file)

    server = create_mcp_server(ServerConfig())
    open_res = await server.call_tool("open_binary", {"file_path": str(pe_file)})
    sid = _unpack(open_res)["session_id"]

    # 1. 非法 group_by 校验
    bad_res = await server.call_tool(
        "find_xrefs",
        {"session_id": sid, "target": "0x140002250", "group_by": "unsupported_mode"},
    )
    bad_data = _unpack(bad_res)
    assert bad_data["ok"] is False
    assert bad_data["error"]["code"] == ErrorCode.INVALID_PARAMETER.value

    # 2. 默认 group_by="none" 返回向后兼容扁平列表
    flat_res = await server.call_tool(
        "find_xrefs",
        {"session_id": sid, "target": "0x140002250", "group_by": "none"},
    )
    flat_data = _unpack(flat_res)
    assert flat_data["ok"] is True
    assert "xrefs" in flat_data["data"]
    assert len(flat_data["data"]["xrefs"]) >= 1

    # 3. group_by="function" 按调用函数聚合折叠
    grp_res = await server.call_tool(
        "find_xrefs",
        {"session_id": sid, "target": "0x140002250", "group_by": "function"},
    )
    grp_data = _unpack(grp_res)
    assert grp_data["ok"] is True
    assert grp_data["data"]["group_by"] == "function"
    assert "functions" in grp_data["data"]
    funcs = grp_data["data"]["functions"]
    assert len(funcs) >= 1
    first_func = funcs[0]
    assert "function_name" in first_func
    assert "function_va" in first_func
    assert "ref_count" in first_func
    assert "references" in first_func
    assert first_func["ref_count"] == len(first_func["references"])
    assert first_func["function_name"] == "reverse_test_entry"

    # 4. 支持别名 group="function"
    alias_res = await server.call_tool(
        "find_xrefs",
        {"session_id": sid, "target": "0x140002250", "group": "function"},
    )
    alias_data = _unpack(alias_res)
    assert alias_data["ok"] is True
    assert alias_data["data"]["group_by"] == "function"
