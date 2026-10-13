"""CLI 命令行入口与服务启动运行时

@author Ateng
@since 2026-10-13
"""

import argparse
import logging
import sys
from collections.abc import Sequence

from mcp_server_reverse.core.config import resolve_config
from mcp_server_reverse.core.doctor import run_doctor
from mcp_server_reverse.core.meta import get_runtime_version_info
from mcp_server_reverse.server import create_mcp_server


def build_parser() -> argparse.ArgumentParser:
    """构建命令行参数解析器"""
    parser = argparse.ArgumentParser(
        prog="mcp-server-reverse",
        description="专为 AI Agent 打造的跨平台二进制静态逆向分析与数字取证 MCP Server",
    )

    parser.add_argument(
        "-v",
        "--version",
        action="version",
        version=get_runtime_version_info(),
        help="显示当前服务版本并退出",
    )
    parser.add_argument(
        "--check",
        "--doctor",
        dest="doctor",
        action="store_true",
        help="执行运行环境与外部工具四级寻址健康自检并输出诊断报告",
    )
    parser.add_argument(
        "-t",
        "--transport",
        choices=["stdio", "sse", "streamable-http"],
        default=None,
        help="传输协议类型 (stdio / sse / streamable-http，默认 stdio)",
    )
    parser.add_argument(
        "--host",
        default=None,
        help="HTTP/SSE 模式监听地址 (默认 127.0.0.1)",
    )
    parser.add_argument(
        "-p",
        "--port",
        type=int,
        default=None,
        help="HTTP/SSE 模式监听端口 (默认 8000)",
    )
    parser.add_argument(
        "--allowed-dir",
        action="append",
        dest="allowed_dir",
        help="允许加载分析的二进制文件根目录白名单 (可重复指定多个)",
    )
    parser.add_argument(
        "--max-file-size-mb",
        type=int,
        default=None,
        help="单个二进制文件最大允许体积 (MB，默认 100)",
    )
    parser.add_argument(
        "--max-sessions",
        type=int,
        default=None,
        help="进程内 LRU 会话池最大驻留数量 (默认 8)",
    )
    parser.add_argument(
        "--auth-token",
        default=None,
        help="远程 HTTP/SSE 模式可选 Bearer 鉴权令牌",
    )
    parser.add_argument(
        "--r2-path",
        default=None,
        help="显式指定 radare2 / rizin 可执行文件路径",
    )
    parser.add_argument(
        "--objdump-path",
        default=None,
        help="显式指定 llvm-objdump / objdump 可执行文件路径",
    )
    parser.add_argument(
        "--floss-path",
        default=None,
        help="显式指定 floss 可执行文件路径",
    )
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default=None,
        help="日志级别 (默认 INFO，所有日志强制输出至 stderr)",
    )

    return parser


def setup_logging(log_level: str) -> None:
    """初始化日志配置，强制所有运行日志输出至 sys.stderr

    @param log_level 日志级别名称
    """
    level = getattr(logging, log_level.upper(), logging.INFO)
    logging.basicConfig(
        level=level,
        stream=sys.stderr,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        force=True,
    )


def main(argv: Sequence[str] | None = None) -> int:
    """CLI 主入口函数

    @param argv 命令行参数切片，为 None 时读取 sys.argv[1:]
    @return int 退出码
    """
    parser = build_parser()
    args = parser.parse_args(sys.argv[1:] if argv is None else argv)

    # 提取非 None 的命令行参数
    cli_dict = {k: v for k, v in vars(args).items() if v is not None}

    # 三级配置决议
    config = resolve_config(cli_args=cli_dict)

    # 初始化受管日志系统
    setup_logging(config.log_level)

    # 处理健康自检
    if getattr(args, "doctor", False):
        return run_doctor(config)

    # 启动 MCP 服务端
    server = create_mcp_server(config)

    if config.transport == "stdio":
        server.run(transport="stdio")
    elif config.transport == "sse":
        server.run(transport="sse", host=config.host, port=config.port)
    elif config.transport == "streamable-http":
        server.run(transport="streamable-http", host=config.host, port=config.port)
    else:
        server.run(transport="stdio")

    return 0


if __name__ == "__main__":
    sys.exit(main())
