"""四级跨平台外部工具寻址器测试套件

@author Ateng
@since 2026-10-13
"""

from pathlib import Path
from unittest.mock import patch

from mcp_server_reverse.core.config import ServerConfig
from mcp_server_reverse.core.locator import ToolLocator


def test_locate_with_explicit_valid_path(tmp_path: Path) -> None:
    fake_exe = tmp_path / "custom_r2.exe"
    fake_exe.write_text("dummy binary content")

    locator = ToolLocator()
    with patch.object(locator, "_probe_version", return_value="5.9.8"):
        cap = locator.locate_tool(
            tool_name="radare2",
            explicit_cli_path=str(fake_exe),
        )
    assert cap.available is True
    assert cap.path == str(fake_exe)
    assert cap.version == "5.9.8"
    assert cap.tier == 1


def test_locate_with_explicit_invalid_path() -> None:
    locator = ToolLocator()
    cap = locator.locate_tool(
        tool_name="radare2",
        explicit_cli_path="/non/existent/path/r2",
    )
    assert cap.available is False
    assert cap.path == "/non/existent/path/r2"
    assert cap.tier == 1
    assert cap.recommended_action is not None


def test_locate_via_env_path(tmp_path: Path) -> None:
    fake_exe = tmp_path / "env_objdump"
    fake_exe.write_text("dummy binary")

    locator = ToolLocator()
    with patch.object(locator, "_probe_version", return_value="18.1.0"):
        cap = locator.locate_tool(
            tool_name="objdump",
            env_path=str(fake_exe),
        )
    assert cap.available is True
    assert cap.path == str(fake_exe)
    assert cap.tier == 2


def test_locate_via_system_path(tmp_path: Path) -> None:
    fake_exe = tmp_path / "radare2"
    fake_exe.write_text("bin")
    locator = ToolLocator()
    with (
        patch("shutil.which", return_value=str(fake_exe)),
        patch.object(locator, "_probe_version", return_value="5.9.0"),
    ):
        cap = locator.locate_tool(tool_name="radare2")
    assert cap.available is True
    assert cap.path == str(fake_exe.resolve())
    assert cap.tier == 3
    assert cap.version == "5.9.0"


def test_locate_missing_tool_provides_fallback_instructions() -> None:
    locator = ToolLocator()
    with (
        patch("shutil.which", return_value=None),
        patch.object(locator, "_probe_level4_paths", return_value=None),
    ):
        cap = locator.locate_tool(tool_name="floss")
    assert cap.available is False
    assert cap.path is None
    assert cap.tier is None
    assert cap.install_guide is not None
    assert "pip" in cap.install_guide or "floss" in cap.install_guide
    assert cap.recommended_action is not None


def test_locate_all_returns_three_capabilities() -> None:
    locator = ToolLocator()
    config = ServerConfig()
    caps = locator.locate_all(config)
    assert "radare2" in caps
    assert "objdump" in caps
    assert "floss" in caps


def test_locate_all_distinguishes_cli_and_env_tier(tmp_path: Path) -> None:
    cli_exe = tmp_path / "cli_r2.exe"
    cli_exe.write_text("r2")
    env_exe = tmp_path / "env_objdump.exe"
    env_exe.write_text("objdump")

    config = ServerConfig(
        cli_r2_path=str(cli_exe),
        env_objdump_path=str(env_exe),
    )
    locator = ToolLocator()
    with patch.object(locator, "_probe_version", return_value="1.0.0"):
        caps = locator.locate_all(config)

    assert caps["radare2"].available is True
    assert caps["radare2"].tier == 1
    assert caps["objdump"].available is True
    assert caps["objdump"].tier == 2
