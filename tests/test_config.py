"""配置决议器三级优先级测试套件

@author Ateng
@since 2026-10-13
"""

import os
from pathlib import Path

from mcp_server_reverse.core.config import resolve_config


def test_default_config() -> None:
    config = resolve_config(cli_args={}, env={})
    assert config.transport == "stdio"
    assert config.host == "127.0.0.1"
    assert config.port == 8000
    assert config.allowed_dirs == []
    assert config.max_file_size_mb == 100
    assert config.max_sessions == 8
    assert config.auth_token is None
    assert config.r2_path is None
    assert config.objdump_path is None
    assert config.floss_path is None
    assert config.log_level == "INFO"


def test_env_override_defaults() -> None:
    env = {
        "MCP_REVERSE_TRANSPORT": "sse",
        "MCP_REVERSE_HOST": "0.0.0.0",
        "MCP_REVERSE_PORT": "9000",
        "MCP_REVERSE_ALLOWED_DIRS": f"/tmp/bin{os.pathsep}/opt/bin",
        "MCP_REVERSE_MAX_FILE_SIZE_MB": "200",
        "MCP_REVERSE_MAX_SESSIONS": "16",
        "MCP_REVERSE_AUTH_TOKEN": "secret-token",
        "MCP_REVERSE_R2_PATH": "/usr/bin/r2",
        "MCP_REVERSE_OBJDUMP_PATH": "/usr/bin/objdump",
        "MCP_REVERSE_FLOSS_PATH": "/usr/bin/floss",
        "MCP_REVERSE_LOG_LEVEL": "DEBUG",
    }
    config = resolve_config(cli_args={}, env=env)
    assert config.transport == "sse"
    assert config.host == "0.0.0.0"
    assert config.port == 9000
    assert config.allowed_dirs == [Path("/tmp/bin"), Path("/opt/bin")]
    assert config.max_file_size_mb == 200
    assert config.max_sessions == 16
    assert config.auth_token == "secret-token"
    assert config.r2_path == "/usr/bin/r2"
    assert config.objdump_path == "/usr/bin/objdump"
    assert config.floss_path == "/usr/bin/floss"
    assert config.log_level == "DEBUG"


def test_cli_overrides_env_and_defaults() -> None:
    env = {
        "MCP_REVERSE_TRANSPORT": "sse",
        "MCP_REVERSE_PORT": "9000",
        "MCP_REVERSE_MAX_FILE_SIZE_MB": "200",
        "MCP_REVERSE_R2_PATH": "/env/r2",
    }
    cli_args = {
        "transport": "streamable-http",
        "port": 9500,
        "max_file_size_mb": 50,
        "r2_path": "/cli/r2",
        "allowed_dir": ["/sandbox/a", "/sandbox/b"],
    }
    config = resolve_config(cli_args=cli_args, env=env)
    assert config.transport == "streamable-http"
    assert config.port == 9500
    assert config.max_file_size_mb == 50
    assert config.r2_path == "/cli/r2"
    assert config.allowed_dirs == [Path("/sandbox/a"), Path("/sandbox/b")]
