"""服务运行配置与三级优先级决议器

@author Ateng
@since 2026-10-13
"""

import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class ServerConfig:
    """逆向分析 MCP 服务运行时配置对象

    @param transport 通信传输协议 (stdio / sse / streamable-http)
    @param host 远程 HTTP/SSE 模式监听地址
    @param port 远程 HTTP/SSE 模式监听端口
    @param allowed_dirs 允许加载分析的二进制文件根目录白名单
    @param max_file_size_mb 单个二进制文件最大允许体积 (MB)
    @param max_sessions 进程内 LRU 会话池最大容量
    @param auth_token 远程 HTTP/SSE 模式 Bearer 鉴权令牌
    @param r2_path 决议后的 radare2 / rizin 可执行文件路径
    @param objdump_path 决议后的 objdump 可执行文件路径
    @param floss_path 决议后的 floss 可执行文件路径
    @param log_level 系统日志输出级别
    @param cli_r2_path 命令行直接显式指定的 r2 路径 (Tier 1 寻址来源)
    @param env_r2_path 环境变量配置的 r2 路径 (Tier 2 寻址来源)
    @param cli_objdump_path 命令行直接显式指定的 objdump 路径 (Tier 1 寻址来源)
    @param env_objdump_path 环境变量配置的 objdump 路径 (Tier 2 寻址来源)
    @param cli_floss_path 命令行直接显式指定的 floss 路径 (Tier 1 寻址来源)
    @param env_floss_path 环境变量配置的 floss 路径 (Tier 2 寻址来源)
    """

    transport: str = "stdio"
    host: str = "127.0.0.1"
    port: int = 8000
    allowed_dirs: list[Path] = field(default_factory=list)
    max_file_size_mb: int = 100
    max_sessions: int = 8
    auth_token: str | None = None
    r2_path: str | None = None
    objdump_path: str | None = None
    floss_path: str | None = None
    log_level: str = "INFO"
    cli_r2_path: str | None = None
    env_r2_path: str | None = None
    cli_objdump_path: str | None = None
    env_objdump_path: str | None = None
    cli_floss_path: str | None = None
    env_floss_path: str | None = None

    def __post_init__(self) -> None:
        """兜底处理直接实例化 ServerConfig 时的显式工具路径映射"""
        if self.r2_path and not self.cli_r2_path and not self.env_r2_path:
            self.cli_r2_path = self.r2_path
        if self.objdump_path and not self.cli_objdump_path and not self.env_objdump_path:
            self.cli_objdump_path = self.objdump_path
        if self.floss_path and not self.cli_floss_path and not self.env_floss_path:
            self.cli_floss_path = self.floss_path


def _parse_allowed_dirs(raw: str | list[str] | list[Path] | None) -> list[Path]:
    """解析白名单目录配置，支持字符串多路径分割与列表输入

    @param raw 原始输入字符串或路径列表
    @return list[Path] 规范化后的 Path 列表
    """
    if not raw:
        return []
    if isinstance(raw, list):
        return [Path(p) for p in raw if p]

    delimiters = [",", ";", os.pathsep]
    normalized_str = raw
    for d in delimiters[1:]:
        normalized_str = normalized_str.replace(d, delimiters[0])

    paths = [p.strip() for p in normalized_str.split(delimiters[0]) if p.strip()]
    return [Path(p) for p in paths]


def resolve_config(
    cli_args: Mapping[str, Any] | None = None,
    env: Mapping[str, str] | None = None,
) -> ServerConfig:
    """按照三级优先级决议最终配置：CLI 参数 > MCP_REVERSE_* 环境变量 > 默认值

    @param cli_args 命令行解析参数字典
    @param env 环境变量映射，默认读取系统 os.environ
    @return ServerConfig 决议后的最终配置实例
    """
    cli = cli_args or {}
    environment = os.environ if env is None else env

    transport = cli.get("transport") or environment.get("MCP_REVERSE_TRANSPORT") or "stdio"
    host = cli.get("host") or environment.get("MCP_REVERSE_HOST") or "127.0.0.1"

    raw_port = cli.get("port") or environment.get("MCP_REVERSE_PORT")
    port = int(raw_port) if raw_port is not None else 8000

    cli_dirs = cli.get("allowed_dir") or cli.get("allowed_dirs")
    if cli_dirs:
        allowed_dirs = _parse_allowed_dirs(cli_dirs)
    elif "MCP_REVERSE_ALLOWED_DIRS" in environment:
        allowed_dirs = _parse_allowed_dirs(environment["MCP_REVERSE_ALLOWED_DIRS"])
    else:
        allowed_dirs = []

    raw_max_size = cli.get("max_file_size_mb") or environment.get("MCP_REVERSE_MAX_FILE_SIZE_MB")
    max_file_size_mb = int(raw_max_size) if raw_max_size is not None else 100

    raw_max_sessions = cli.get("max_sessions") or environment.get("MCP_REVERSE_MAX_SESSIONS")
    max_sessions = int(raw_max_sessions) if raw_max_sessions is not None else 8

    auth_token = cli.get("auth_token") or environment.get("MCP_REVERSE_AUTH_TOKEN") or None

    cli_r2 = cli.get("r2_path")
    env_r2 = environment.get("MCP_REVERSE_R2_PATH")
    r2_path = cli_r2 or env_r2 or None

    cli_objdump = cli.get("objdump_path")
    env_objdump = environment.get("MCP_REVERSE_OBJDUMP_PATH")
    objdump_path = cli_objdump or env_objdump or None

    cli_floss = cli.get("floss_path")
    env_floss = environment.get("MCP_REVERSE_FLOSS_PATH")
    floss_path = cli_floss or env_floss or None

    log_level = cli.get("log_level") or environment.get("MCP_REVERSE_LOG_LEVEL") or "INFO"

    return ServerConfig(
        transport=str(transport),
        host=str(host),
        port=port,
        allowed_dirs=allowed_dirs,
        max_file_size_mb=max_file_size_mb,
        max_sessions=max_sessions,
        auth_token=auth_token,
        r2_path=r2_path,
        objdump_path=objdump_path,
        floss_path=floss_path,
        log_level=str(log_level),
        cli_r2_path=cli_r2,
        env_r2_path=env_r2,
        cli_objdump_path=cli_objdump,
        env_objdump_path=env_objdump,
        cli_floss_path=cli_floss,
        env_floss_path=env_floss,
    )
