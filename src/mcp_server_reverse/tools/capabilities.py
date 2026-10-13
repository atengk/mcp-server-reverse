"""get_capabilities MCP 工具实现

@author Ateng
@since 2026-10-13
"""

import sys
from dataclasses import asdict
from typing import Any

from mcp_server_reverse.core.config import ServerConfig
from mcp_server_reverse.core.locator import ToolLocator
from mcp_server_reverse.core.meta import get_core_engine_versions, get_package_version
from mcp_server_reverse.core.models import create_response


def get_capabilities_impl(
    config: ServerConfig,
    locator: ToolLocator | None = None,
) -> dict[str, Any]:
    """实现 get_capabilities 核心业务逻辑并返回标准信封

    @param config 当前服务端运行配置
    @param locator 外部工具寻址器实例，若未传则新建
    @return dict[str, Any] 序列化后的标准响应信封字典
    """
    active_locator = locator or ToolLocator()
    caps = active_locator.locate_all(config)

    tools_dict: dict[str, Any] = {}
    for name, cap in caps.items():
        tools_dict[name] = asdict(cap)

    data: dict[str, Any] = {
        "version": get_package_version(),
        "python_version": sys.version,
        "core_engines": get_core_engine_versions(),
        "external_tools": tools_dict,
        "sandbox": {
            "allowed_dirs": [str(d) for d in config.allowed_dirs],
            "max_file_size_mb": config.max_file_size_mb,
            "max_sessions": config.max_sessions,
        },
    }

    resp = create_response(
        summary="获取服务运行能力与外部工具探测结果成功",
        data=data,
        session_id=None,
    )
    return resp.to_dict()
