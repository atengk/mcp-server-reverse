"""核心逆向工具参数 Pydantic 别名容错测试套件 (Issue #20)

@author Ateng
@since 2026-10-15
"""

import json
from pathlib import Path

import pytest

from mcp_server_reverse.core.config import ServerConfig
from mcp_server_reverse.server import create_mcp_server
from tests.fixtures.synthetic import build_synthetic_pe64


def _unpack(result) -> dict:
    return json.loads(result.content[0].text)


@pytest.mark.anyio
async def test_tool_parameter_aliases(tmp_path: Path) -> None:
    pe_file = tmp_path / "target.exe"
    build_synthetic_pe64(pe_file)

    config = ServerConfig(allowed_dirs=[tmp_path])
    server = create_mcp_server(config)

    # 1. 打开会话
    open_res = await server.call_tool("open_binary", {"file_path": str(pe_file)})
    data = _unpack(open_res)
    sid = data["session_id"]
    assert sid is not None

    # 2. search_strings: 使用别名 query / filter
    res_str = await server.call_tool("search_strings", {"session_id": sid, "query": "https"})
    payload_str = _unpack(res_str)
    assert payload_str["ok"] is True
    assert any("https" in item["value"] for item in payload_str["data"]["strings"])

    # 3. search_bytes_and_constants: 使用别名 pattern
    res_bytes = await server.call_tool(
        "search_bytes_and_constants", {"session_id": sid, "pattern": "48 89"}
    )
    payload_bytes = _unpack(res_bytes)
    assert payload_bytes["ok"] is True

    # 4. convert_address: 使用别名 target
    res_addr = await server.call_tool(
        "convert_address", {"session_id": sid, "target": "0x140001000"}
    )
    payload_addr = _unpack(res_addr)
    assert payload_addr["ok"] is True
    assert payload_addr["data"]["rva"] == "0x1000"

    # 5. read_memory: 使用别名 target
    res_mem = await server.call_tool(
        "read_memory", {"session_id": sid, "target": "0x140001000", "size": 16}
    )
    payload_mem = _unpack(res_mem)
    assert payload_mem["ok"] is True
    assert "hexdump_lines" in payload_mem["data"]

    # 6. disassemble: 使用别名 address
    res_disasm = await server.call_tool(
        "disassemble", {"session_id": sid, "address": "0x140001000", "count": 5}
    )
    payload_disasm = _unpack(res_disasm)
    assert payload_disasm["ok"] is True
    assert len(payload_disasm["data"]["instructions"]) > 0

    # 7. get_sections: 使用别名 name / query
    res_sec = await server.call_tool("get_sections", {"session_id": sid, "name": ".text"})
    payload_sec = _unpack(res_sec)
    assert payload_sec["ok"] is True
    assert len(payload_sec["data"]["sections"]) == 1
    assert payload_sec["data"]["sections"][0]["name"] == ".text"

    # 8. get_imports: 使用别名 query
    res_imp = await server.call_tool("get_imports", {"session_id": sid, "query": "VirtualAlloc"})
    payload_imp = _unpack(res_imp)
    assert payload_imp["ok"] is True
    assert any("VirtualAlloc" in entry["name"] for entry in payload_imp["data"]["imports"])

    # 9. analyze_cfg: 使用别名 entry
    res_cfg = await server.call_tool(
        "analyze_cfg", {"session_id": sid, "entry": "0x140001000", "max_blocks": 10}
    )
    payload_cfg = _unpack(res_cfg)
    assert payload_cfg["ok"] is True
    assert "mermaid_diagram" in payload_cfg["data"]
