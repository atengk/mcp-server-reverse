"""CLI 命令行入口测试套件

@author Ateng
@since 2026-10-13
"""

import logging
import runpy
import sys
from unittest.mock import patch

import pytest

from mcp_server_reverse.cli import build_parser, main


def test_cli_help(capsys) -> None:
    parser = build_parser()
    with pytest.raises(SystemExit) as excinfo:
        parser.parse_args(["--help"])
    assert excinfo.value.code == 0

    captured = capsys.readouterr()
    assert "mcp-server-reverse" in captured.out or "transport" in captured.out


def test_cli_version(capsys) -> None:
    with pytest.raises(SystemExit) as excinfo:
        main(["--version"])
    assert excinfo.value.code == 0

    captured = capsys.readouterr()
    output = captured.out + captured.err
    assert "mcp-server-reverse" in output
    assert "0.1.0" in output


def test_cli_doctor_flag() -> None:
    with patch("mcp_server_reverse.cli.run_doctor", return_value=0) as mock_doctor:
        code = main(["--doctor"])
        assert code == 0
        mock_doctor.assert_called_once()


def test_cli_check_flag() -> None:
    with patch("mcp_server_reverse.cli.run_doctor", return_value=0) as mock_doctor:
        code = main(["--check"])
        assert code == 0
        mock_doctor.assert_called_once()


def test_cli_logging_directed_to_stderr() -> None:
    # 验证日志系统未向 stdout 输出，且 root logger handler 的 stream 是 sys.stderr
    with patch("mcp_server_reverse.cli.create_mcp_server") as mock_create:
        mock_server = mock_create.return_value
        mock_server.run.return_value = None

        main(["--transport", "stdio", "--log-level", "DEBUG"])
        logger = logging.getLogger()
        has_stderr_handler = any(getattr(h, "stream", None) is sys.stderr for h in logger.handlers)
        assert has_stderr_handler is True


def test_python_m_execution_module() -> None:
    # 模拟 python -m mcp_server_reverse 触发 __main__.py
    with (
        patch("sys.argv", ["python -m mcp_server_reverse", "--version"]),
        pytest.raises(SystemExit) as excinfo,
    ):
        runpy.run_module("mcp_server_reverse", run_name="__main__")
    assert excinfo.value.code == 0
