"""结构与符号检视 MCP Tools 端到端测试套件

@author Ateng
@since 2026-10-13
"""

import json
from pathlib import Path
from typing import Any

import pytest

from mcp_server_reverse.core.config import ServerConfig
from mcp_server_reverse.core.models import ErrorCode
from mcp_server_reverse.core.session import SessionStore
from mcp_server_reverse.server import create_mcp_server
from mcp_server_reverse.tools.session import open_binary_impl
from mcp_server_reverse.tools.symbols import (
    get_exports_impl,
    get_imports_impl,
    get_sections_impl,
    get_symbols_impl,
)
from tests.fixtures.synthetic import (
    build_synthetic_elf64,
    build_synthetic_elf_with_eh_frame,
    build_synthetic_pe32,
    build_synthetic_pe64,
)


def test_symbol_tools_pe64_end_to_end(tmp_path: Path) -> None:
    pe_file = tmp_path / "target_pe.exe"
    build_synthetic_pe64(pe_file)

    config = ServerConfig()
    store = SessionStore()
    from mcp_server_reverse.core.parser import BinaryParser
    from mcp_server_reverse.core.security import SecurityGuard

    guard = SecurityGuard()
    parser = BinaryParser()

    # 1. 打开二进制创建会话
    open_resp = open_binary_impl(
        file_path=str(pe_file),
        target_arch=None,
        config=config,
        session_store=store,
        security_guard=guard,
        parser=parser,
    )
    assert open_resp["ok"] is True
    sid = open_resp["session_id"]
    assert sid is not None

    # 2. 验证 get_sections
    sec_resp = get_sections_impl(session_id=sid, session_store=store)
    assert sec_resp["ok"] is True
    assert sec_resp["session_id"] == sid
    assert "sections" in sec_resp["data"]
    sections = sec_resp["data"]["sections"]
    assert len(sections) >= 2
    names = [s["name"] for s in sections]
    assert ".text" in names
    assert ".rdata" in names

    text_sec = next(s for s in sections if s["name"] == ".text")
    assert text_sec["permissions"] == "r-x"
    assert "virtual_address" in text_sec
    assert text_sec["is_high_entropy"] is False

    # 3. 验证 get_imports 及分类和正则过滤
    # 3.1 全量导入
    imp_resp = get_imports_impl(
        session_id=sid,
        library_filter=None,
        name_filter=None,
        category=None,
        offset=0,
        limit=50,
        session_store=store,
    )
    assert imp_resp["ok"] is True
    assert imp_resp["pagination"]["total"] >= 2
    imp_items = imp_resp["data"]["imports"]
    func_names = [i["name"] for i in imp_items]
    assert "VirtualAllocEx" in func_names
    assert "WSAStartup" in func_names

    # 3.2 敏感标签分类过滤与名称正则匹配
    cat_resp = get_imports_impl(
        session_id=sid,
        library_filter=None,
        name_filter="^WSA",
        category="network",
        offset=0,
        limit=50,
        session_store=store,
    )
    assert cat_resp["ok"] is True
    assert cat_resp["pagination"]["total"] == 1
    assert cat_resp["data"]["imports"][0]["name"] == "WSAStartup"
    assert cat_resp["data"]["imports"][0]["type"] == "import"

    # 3.3 库名正则过滤与分页
    page_resp = get_imports_impl(
        session_id=sid,
        library_filter=r"KERNEL32",
        name_filter=r"VirtualAlloc.*",
        category=None,
        offset=0,
        limit=1,
        session_store=store,
    )
    assert page_resp["ok"] is True
    assert page_resp["pagination"]["total"] == 1
    assert page_resp["pagination"]["limit"] == 1
    assert page_resp["pagination"]["has_more"] is False
    assert len(page_resp["data"]["imports"]) == 1
    assert page_resp["data"]["imports"][0]["library"] == "KERNEL32.dll"

    # 4. 验证 get_exports
    exp_resp = get_exports_impl(
        session_id=sid,
        name_filter=r"^reverse_test",
        offset=0,
        limit=50,
        session_store=store,
    )
    assert exp_resp["ok"] is True
    assert exp_resp["pagination"]["total"] == 1
    exp_items = exp_resp["data"]["exports"]
    assert exp_items[0]["name"] == "reverse_test_entry"
    assert exp_items[0]["ordinal"] == 1
    assert "140001000" in exp_items[0]["address"]

    # 5. 验证 get_symbols 包含 .pdata 恢复与 name_filter / symbol_type=None
    sym_resp = get_symbols_impl(
        session_id=sid,
        name_filter=r"^sub_14000",
        symbol_type=None,
        offset=0,
        limit=50,
        session_store=store,
    )
    assert sym_resp["ok"] is True
    symbols = sym_resp["data"]["symbols"]
    assert len(symbols) >= 1
    # 查找由异常目录恢复的函数 sub_140001000
    recovered = [s for s in symbols if s["type"] == "exception_frame"]
    assert len(recovered) >= 1
    rec_func = recovered[0]
    assert rec_func["name"].startswith("sub_")
    assert rec_func["size"] == 16
    assert "140001000" in rec_func["address"]
    assert rec_func["type"] == "exception_frame"

    # 5.1 按 symbol_type="exception_frame" 过滤
    sym_ef_resp = get_symbols_impl(
        session_id=sid,
        name_filter=None,
        symbol_type="exception_frame",
        offset=0,
        limit=50,
        session_store=store,
    )
    assert sym_ef_resp["ok"] is True
    assert all(s["type"] == "exception_frame" for s in sym_ef_resp["data"]["symbols"])


def test_symbol_tools_error_handling(tmp_path: Path) -> None:
    pe_file = tmp_path / "err_test.exe"
    build_synthetic_pe64(pe_file)

    config = ServerConfig()
    store = SessionStore()
    from mcp_server_reverse.core.parser import BinaryParser
    from mcp_server_reverse.core.security import SecurityGuard

    open_resp = open_binary_impl(
        file_path=str(pe_file),
        target_arch=None,
        config=config,
        session_store=store,
        security_guard=SecurityGuard(),
        parser=BinaryParser(),
    )
    valid_sid = open_resp["session_id"]
    assert valid_sid is not None

    # 1. 不存在的 session_id
    bad_sid_resp = get_sections_impl(session_id="deadbeef0000", session_store=store)
    assert bad_sid_resp["ok"] is False
    assert bad_sid_resp["error"]["code"] == ErrorCode.SESSION_NOT_FOUND.value

    # 2. 非法正则表达式
    bad_re_resp = get_imports_impl(
        session_id=valid_sid,
        library_filter=r"[unclosed(",
        name_filter=None,
        category=None,
        offset=0,
        limit=50,
        session_store=store,
    )
    assert bad_re_resp["ok"] is False
    assert bad_re_resp["error"]["code"] == ErrorCode.INVALID_PARAMETER.value

    bad_re_exp = get_exports_impl(
        session_id=valid_sid,
        name_filter=r"[unclosed(",
        offset=0,
        limit=50,
        session_store=store,
    )
    assert bad_re_exp["ok"] is False
    assert bad_re_exp["error"]["code"] == ErrorCode.INVALID_PARAMETER.value

    bad_re_sym = get_symbols_impl(
        session_id=valid_sid,
        name_filter=r"[unclosed(",
        symbol_type="all",
        offset=0,
        limit=50,
        session_store=store,
    )
    assert bad_re_sym["ok"] is False
    assert bad_re_sym["error"]["code"] == ErrorCode.INVALID_PARAMETER.value

    # 3. 不支持的 symbol_type
    bad_type_resp = get_symbols_impl(
        session_id=valid_sid,
        name_filter=None,
        symbol_type="invalid_type",
        offset=0,
        limit=50,
        session_store=store,
    )
    assert bad_type_resp["ok"] is False
    assert bad_type_resp["error"]["code"] == ErrorCode.INVALID_PARAMETER.value

    # 4. 无匹配结果返回空列表 []
    empty_resp = get_imports_impl(
        session_id=valid_sid,
        library_filter="non_existent_dll_regex",
        name_filter=None,
        category=None,
        offset=0,
        limit=50,
        session_store=store,
    )
    assert empty_resp["ok"] is True
    assert empty_resp["data"]["imports"] == []
    assert empty_resp["pagination"]["total"] == 0


def test_symbol_tools_elf64(tmp_path: Path) -> None:
    elf_file = tmp_path / "target_elf"
    build_synthetic_elf64(elf_file)

    config = ServerConfig()
    store = SessionStore()
    from mcp_server_reverse.core.parser import BinaryParser
    from mcp_server_reverse.core.security import SecurityGuard

    open_resp = open_binary_impl(
        file_path=str(elf_file),
        target_arch=None,
        config=config,
        session_store=store,
        security_guard=SecurityGuard(),
        parser=BinaryParser(),
    )
    assert open_resp["ok"] is True
    sid = open_resp["session_id"]

    # ELF 节区提取
    sec_resp = get_sections_impl(session_id=sid, session_store=store)
    assert sec_resp["ok"] is True
    assert isinstance(sec_resp["data"]["sections"], list)

    # ELF 导入与导出提取不崩溃且返回列表
    imp_resp = get_imports_impl(
        session_id=sid,
        library_filter=None,
        name_filter=None,
        category=None,
        offset=0,
        limit=50,
        session_store=store,
    )
    assert imp_resp["ok"] is True
    assert isinstance(imp_resp["data"]["imports"], list)

    exp_resp = get_exports_impl(
        session_id=sid,
        name_filter=None,
        offset=0,
        limit=50,
        session_store=store,
    )
    assert exp_resp["ok"] is True
    assert isinstance(exp_resp["data"]["exports"], list)


@pytest.mark.asyncio
async def test_symbol_recovery_elf_eh_frame(tmp_path: Path) -> None:
    def _unpack(res: Any) -> dict[str, Any]:
        if hasattr(res, "content") and res.content:
            return json.loads(res.content[0].text)
        return res

    elf_file = tmp_path / "stripped_eh.elf"
    build_synthetic_elf_with_eh_frame(elf_file)

    server = create_mcp_server(ServerConfig())
    open_res = await server.call_tool("open_binary", {"file_path": str(elf_file)})
    open_dict = _unpack(open_res)
    sid = open_dict["session_id"]
    assert sid is not None

    # 1. 查询 symbol_type="eh_frame"
    sym_res = await server.call_tool("get_symbols", {"session_id": sid, "symbol_type": "eh_frame"})
    sym_data = _unpack(sym_res)
    assert sym_data["ok"] is True
    symbols = sym_data["data"]["symbols"]
    assert len(symbols) >= 1
    target = next((s for s in symbols if s["address"] == "0x401000"), None)
    assert target is not None
    assert target["name"] == "sub_401000"
    assert target["type"] == "eh_frame"
    assert target["size"] == 32

    # 2. 查询 symbol_type="all"，确保包含 eh_frame 恢复符号
    sym_all = await server.call_tool("get_symbols", {"session_id": sid, "symbol_type": "all"})
    all_data = _unpack(sym_all)
    assert any(
        s["name"] == "sub_401000" and s["type"] == "eh_frame" for s in all_data["data"]["symbols"]
    )


@pytest.mark.asyncio
async def test_symbol_recovery_pe32_prologue(tmp_path: Path) -> None:
    def _unpack(res: Any) -> dict[str, Any]:
        if hasattr(res, "content") and res.content:
            return json.loads(res.content[0].text)
        return res

    pe32_file = tmp_path / "target_pe32.exe"
    build_synthetic_pe32(pe32_file)

    server = create_mcp_server(ServerConfig())
    open_res = await server.call_tool("open_binary", {"file_path": str(pe32_file)})
    open_dict = _unpack(open_res)
    sid = open_dict["session_id"]
    assert sid is not None

    # 1. 查询 symbol_type="prologue"
    sym_res = await server.call_tool("get_symbols", {"session_id": sid, "symbol_type": "prologue"})
    sym_data = _unpack(sym_res)
    assert sym_data["ok"] is True
    symbols = sym_data["data"]["symbols"]
    assert len(symbols) >= 1
    target = next((s for s in symbols if s["address"] == "0x401000"), None)
    assert target is not None
    assert target["name"] == "sub_401000"
    assert target["type"] == "prologue"
    assert target["size"] == 5

    # 2. 查询 symbol_type="all"，确保包含 prologue 恢复符号
    sym_all = await server.call_tool("get_symbols", {"session_id": sid, "symbol_type": "all"})
    all_data = _unpack(sym_all)
    assert any(
        s["name"] == "sub_401000" and s["type"] == "prologue" for s in all_data["data"]["symbols"]
    )
