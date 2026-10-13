"""二进制全景解析与取证内核测试套件

@author Ateng
@since 2026-10-13
"""

from pathlib import Path

from mcp_server_reverse.core.parser import BinaryParser, calculate_entropy
from tests.fixtures.synthetic import build_synthetic_elf64, build_synthetic_pe64


def test_calculate_entropy() -> None:
    # 全 0 字节熵为 0.0
    zero_bytes = b"\x00" * 1024
    assert calculate_entropy(zero_bytes) == 0.0

    # 均匀随机 256 字节熵接近 8.0
    all_bytes = bytes(range(256)) * 4
    ent = calculate_entropy(all_bytes)
    assert 7.9 <= ent <= 8.0


def test_parse_synthetic_pe64(tmp_path: Path) -> None:
    pe_file = tmp_path / "sample.exe"
    build_synthetic_pe64(pe_file)

    parser = BinaryParser()
    result = parser.parse(pe_file)

    # 1. file_info
    file_info = result.file_info
    assert file_info["size_bytes"] > 0x400
    assert len(file_info["sha256"]) == 64
    assert len(file_info["md5"]) == 32
    assert "imphash" in file_info

    # 2. format_info
    fmt = result.format_info
    assert fmt["format"] == "PE"
    assert fmt["bits"] == 64
    assert fmt["is_pie"] is True
    assert fmt["has_nx"] is True
    assert "0x140001000" in fmt["entry_point"]
    assert "0x140000000" in fmt["image_base"]

    # 3. triage_overview
    triage = result.triage_overview
    assert triage["sections_count"] >= 2
    assert "sensitive_api_categories" in triage

    # 4. forensic_metadata
    forensic = result.forensic_metadata
    assert forensic["overlay"] is not None
    assert forensic["overlay"]["size"] > 0
    assert forensic["overlay"]["entropy"] > 0
    assert isinstance(forensic["needed_libraries"], list)


def test_parse_synthetic_elf64(tmp_path: Path) -> None:
    elf_file = tmp_path / "sample.elf"
    build_synthetic_elf64(elf_file)

    parser = BinaryParser()
    result = parser.parse(elf_file)

    fmt = result.format_info
    assert fmt["format"] == "ELF"
    assert fmt["bits"] == 64
    assert "0x401000" in fmt["entry_point"]
