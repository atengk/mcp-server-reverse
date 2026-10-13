"""MCP 服务端工厂与工具注册中心

@author Ateng
@since 2026-10-13
"""

from typing import Any

from mcp.server.mcpserver import MCPServer

from mcp_server_reverse.core.config import ServerConfig
from mcp_server_reverse.core.locator import ToolLocator
from mcp_server_reverse.core.meta import get_package_version
from mcp_server_reverse.tools.capabilities import get_capabilities_impl


def create_mcp_server(config: ServerConfig) -> MCPServer:
    """构建并初始化配置好全部 MCP 逆向工具的 MCPServer 实例

    @param config 当前服务端运行配置
    @return MCPServer 就绪的服务端实例
    """
    server = MCPServer(
        name="mcp-server-reverse",
        version=get_package_version(),
        instructions="专为 AI Agent 设计的高性能跨平台二进制静态逆向分析与数字取证服务",
    )
    locator = ToolLocator()

    @server.tool(
        name="get_capabilities",
        description=(
            "查询当前 MCP 逆向分析服务版本、Python 运行时、"
            "核心静态分析库（LIEF/Capstone/pefile）版本、"
            "外部逆向工具（radare2/objdump/floss）四级寻址探测状态及沙箱边界配置"
        ),
    )
    def get_capabilities() -> dict[str, Any]:
        """获取当前服务所有静态逆向与取证能力元数据"""
        return get_capabilities_impl(config=config, locator=locator)

    return server
