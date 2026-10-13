"""分级健康探针 (--doctor / --check) 测试套件

@author Ateng
@since 2026-10-13
"""

from pathlib import Path
from unittest.mock import patch

from mcp_server_reverse.core.config import ServerConfig
from mcp_server_reverse.core.doctor import run_doctor


def test_doctor_passes_on_default_clean_environment(capsys) -> None:
    config = ServerConfig()
    code = run_doctor(config)
    assert code == 0

    captured = capsys.readouterr()
    output = captured.out + captured.err
    assert "[REQUIRED]" in output
    assert "lief" in output
    assert "capstone" in output
    assert "pefile" in output


def test_doctor_fails_when_allowed_dir_not_exist(tmp_path: Path, capsys) -> None:
    non_existent = tmp_path / "does_not_exist_sandbox_dir"
    config = ServerConfig(allowed_dirs=[non_existent])

    code = run_doctor(config)
    assert code == 1

    captured = capsys.readouterr()
    output = captured.out + captured.err
    assert "[FAIL]" in output or "不存在" in output


def test_doctor_fails_when_explicit_external_tool_invalid(capsys) -> None:
    config = ServerConfig(r2_path="/non/existent/r2_binary")

    code = run_doctor(config)
    assert code == 1

    captured = capsys.readouterr()
    output = captured.out + captured.err
    assert "显式指定" in output or "不可执行" in output


def test_doctor_fails_when_core_engine_import_fails(capsys) -> None:
    config = ServerConfig()
    with patch(
        "mcp_server_reverse.core.doctor._check_core_engines",
        return_value=(False, ["lief 导入失败"]),
    ):
        code = run_doctor(config)
        assert code == 1

    captured = capsys.readouterr()
    output = captured.out + captured.err
    assert "lief 导入失败" in output
