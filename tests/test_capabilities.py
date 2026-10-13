"""get_capabilities MCP Tool 测试套件

@author Ateng
@since 2026-10-13
"""

import json
from pathlib import Path

import pytest

from mcp_server_reverse.core.config import ServerConfig
from mcp_server_reverse.core.locator import ToolLocator
from mcp_server_reverse.core.meta import get_package_version
from mcp_server_reverse.server import create_mcp_server
from mcp_server_reverse.tools.capabilities import get_capabilities_impl


def test_get_capabilities_impl_structure(tmp_path: Path) -> None:
    config = ServerConfig(
        allowed_dirs=[tmp_path],
        max_file_size_mb=64,
        max_sessions=4,
    )
    locator = ToolLocator()

    resp = get_capabilities_impl(config=config, locator=locator)
    assert resp["ok"] is True
    assert resp["error"] is None
    assert "version" in resp["data"]
    assert "python_version" in resp["data"]

    core = resp["data"]["core_engines"]
    assert "lief" in core
    assert "capstone" in core
    assert "pefile" in core

    tools = resp["data"]["external_tools"]
    assert "radare2" in tools
    assert "objdump" in tools
    assert "floss" in tools

    sandbox = resp["data"]["sandbox"]
    assert sandbox["max_file_size_mb"] == 64
    assert sandbox["max_sessions"] == 4
    assert str(tmp_path) in sandbox["allowed_dirs"]


def test_mcp_server_tool_registration() -> None:
    config = ServerConfig()
    server = create_mcp_server(config)
    tool_names = [tool.name for tool in server._tool_manager.list_tools()]
    assert "get_capabilities" in tool_names


@pytest.mark.asyncio
async def test_mcp_server_call_tool_end_to_end() -> None:
    config = ServerConfig()
    server = create_mcp_server(config)
    result = await server.call_tool("get_capabilities", {})
    assert result.is_error is False

    # 解析 content 中的 JSON 响应信封
    text = result.content[0].text
    payload = json.loads(text)
    assert payload["ok"] is True
    assert payload["error"] is None
    assert payload["data"]["version"] == get_package_version()
    assert "core_engines" in payload["data"]
