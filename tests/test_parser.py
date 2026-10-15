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


def test_parse_pe64_lief_fallback_to_pefile(tmp_path: Path, monkeypatch) -> None:
    """验证当 LIEF 解析失败时，PE64 能正确回退至 pefile 提取基址、入口点与节区"""
    import lief

    pe_file = tmp_path / "sample64.exe"
    build_synthetic_pe64(pe_file)

    # 模拟 LIEF 解析失败抛出异常或返回 None
    monkeypatch.setattr(lief, "parse", lambda _: None)

    parser = BinaryParser()
    result = parser.parse(pe_file)

    fmt = result.format_info
    assert fmt["format"] == "PE"
    assert fmt["arch"] == "x86_64"
    assert fmt["bits"] == 64
    assert fmt["image_base"] == "0x140000000"
    assert fmt["entry_point"] == "0x140001000"
    assert fmt["is_pie"] is True
    assert fmt["has_nx"] is True

    triage = result.triage_overview
    assert triage["sections_count"] >= 2


def test_parse_pe32_fallback_to_pefile(tmp_path: Path, monkeypatch) -> None:
    """验证 32 位 PE 在 LIEF 解析失败时，正确识别为 i386/32位且基址与入口点不为零 (Issue #17)"""
    import lief

    from tests.fixtures.synthetic import build_synthetic_pe32

    pe_file = tmp_path / "sample32.exe"
    build_synthetic_pe32(pe_file)

    # 模拟 LIEF 解析失败
    monkeypatch.setattr(lief, "parse", lambda _: None)

    parser = BinaryParser()
    result = parser.parse(pe_file)

    fmt = result.format_info
    assert fmt["format"] == "PE"
    assert fmt["arch"] == "i386"
    assert fmt["bits"] == 32
    assert fmt["image_base"] == "0x400000"
    assert fmt["entry_point"] == "0x401000"
    assert fmt["is_pie"] is True
    assert fmt["has_nx"] is True

    triage = result.triage_overview
    assert triage["sections_count"] == 1


def test_parse_dotnet_clr_pe(tmp_path: Path) -> None:
    """验证 .NET CLR 托管程序识别、运行时版本提取与专属反编译指引 (Issue #19)"""
    from tests.fixtures.synthetic import build_synthetic_dotnet_pe

    pe_file = tmp_path / "managed.exe"
    build_synthetic_dotnet_pe(pe_file)

    parser = BinaryParser()
    result = parser.parse(pe_file)

    fmt = result.format_info
    assert fmt["format"] == "PE"
    assert fmt["is_managed"] is True
    assert fmt["runtime"] == ".NET CLR"
    assert fmt["clr_runtime_version"] == "v4.0.30319"

    triage = result.triage_overview
    assert triage["is_managed"] is True
    assert triage["runtime"] == ".NET CLR"
    assert triage["clr_runtime_version"] == "v4.0.30319"
    assert triage["clr_guidance"] is not None
    assert "ILSpy" in triage["clr_guidance"]
    assert "CIL 字节码" in triage["clr_guidance"]
