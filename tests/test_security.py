"""安全沙箱与文件守卫测试套件

@author Ateng
@since 2026-10-13
"""

from pathlib import Path

from mcp_server_reverse.core.config import ServerConfig
from mcp_server_reverse.core.models import ErrorCode
from mcp_server_reverse.core.security import SecurityGuard
from tests.fixtures.synthetic import build_synthetic_pe64


def test_validate_allowed_sandbox_success(tmp_path: Path) -> None:
    sandbox_dir = tmp_path / "sandbox"
    sandbox_dir.mkdir()
    target_pe = sandbox_dir / "valid.exe"
    build_synthetic_pe64(target_pe)

    config = ServerConfig(allowed_dirs=[sandbox_dir])
    guard = SecurityGuard()
    res = guard.validate_target_file(str(target_pe), config)

    assert res.is_valid is True
    assert res.error_code is None
    assert res.resolved_path == target_pe.resolve()


def test_validate_path_traversal_blocked(tmp_path: Path) -> None:
    sandbox_dir = tmp_path / "sandbox"
    sandbox_dir.mkdir()
    outside_dir = tmp_path / "outside"
    outside_dir.mkdir()
    target_pe = outside_dir / "secret.exe"
    build_synthetic_pe64(target_pe)

    # 通过 ../.. 穿越尝试访问 outside/secret.exe
    traversal_path = sandbox_dir / ".." / "outside" / "secret.exe"

    config = ServerConfig(allowed_dirs=[sandbox_dir])
    guard = SecurityGuard()
    res = guard.validate_target_file(str(traversal_path), config)

    assert res.is_valid is False
    assert res.resolved_path is None
    assert res.error_code == ErrorCode.SANDBOX_PATH_FORBIDDEN
    assert res.suggestion is not None


def test_validate_file_not_found(tmp_path: Path) -> None:
    config = ServerConfig()
    guard = SecurityGuard()
    res = guard.validate_target_file(
        str(tmp_path / "non_existent.exe"),
        config,
    )

    assert res.is_valid is False
    assert res.resolved_path is None
    assert res.error_code == ErrorCode.FILE_NOT_FOUND


def test_validate_file_too_large(tmp_path: Path) -> None:
    large_file = tmp_path / "huge.exe"
    large_file.write_bytes(b"MZ" + b"\x00" * (2 * 1024 * 1024))

    config = ServerConfig(max_file_size_mb=1)
    guard = SecurityGuard()
    res = guard.validate_target_file(str(large_file), config)

    assert res.is_valid is False
    assert res.resolved_path is None
    assert res.error_code == ErrorCode.FILE_TOO_LARGE


def test_validate_unsupported_format(tmp_path: Path) -> None:
    text_file = tmp_path / "plain.txt"
    text_file.write_text("Hello, this is a plain text file not a binary executable!")

    config = ServerConfig()
    guard = SecurityGuard()
    res = guard.validate_target_file(str(text_file), config)

    assert res.is_valid is False
    assert res.resolved_path is None
    assert res.error_code == ErrorCode.UNSUPPORTED_FORMAT
