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
    assert "本服务仅支持" in (res.suggestion or "")


def test_format_sniffer_swf(tmp_path: Path) -> None:
    swf_file = tmp_path / "movie.swf"
    swf_file.write_bytes(b"CWS\x08" + b"\x00" * 32)

    guard = SecurityGuard()
    res = guard.validate_target_file(str(swf_file), ServerConfig())

    assert res.is_valid is False
    assert "Adobe Flash SWF" in (res.error_message or "")
    assert "FFDec" in (res.suggestion or "")


def test_format_sniffer_dex_and_apk(tmp_path: Path) -> None:
    dex_file = tmp_path / "classes.dex"
    dex_file.write_bytes(b"dex\n035\x00" + b"\x00" * 32)

    guard = SecurityGuard()
    res = guard.validate_target_file(str(dex_file), ServerConfig())

    assert res.is_valid is False
    assert "Android APK / DEX" in (res.error_message or "")
    assert "jadx" in (res.suggestion or "")


def test_format_sniffer_wasm(tmp_path: Path) -> None:
    wasm_file = tmp_path / "module.wasm"
    wasm_file.write_bytes(b"\x00asm\x01\x00\x00\x00")

    guard = SecurityGuard()
    res = guard.validate_target_file(str(wasm_file), ServerConfig())

    assert res.is_valid is False
    assert "WebAssembly" in (res.error_message or "")
    assert "wabt" in (res.suggestion or "")


def test_format_sniffer_har(tmp_path: Path) -> None:
    har_file = tmp_path / "network.har"
    har_file.write_text('{"log": {"version": "1.2", "creator": {"name": "test"}, "entries": []}}')

    guard = SecurityGuard()
    res = guard.validate_target_file(str(har_file), ServerConfig())

    assert res.is_valid is False
    assert "HAR" in (res.error_message or "")
    assert "traffic-inspector" in (res.suggestion or "")


def test_format_sniffer_pcap(tmp_path: Path) -> None:
    pcap_file = tmp_path / "dump.pcap"
    pcap_file.write_bytes(b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00")

    guard = SecurityGuard()
    res = guard.validate_target_file(str(pcap_file), ServerConfig())

    assert res.is_valid is False
    assert "PCAP" in (res.error_message or "")
    assert "traffic-inspector" in (res.suggestion or "")
