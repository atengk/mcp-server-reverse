"""合成二进制测试夹具测试套件

@author Ateng
@since 2026-10-13
"""

from pathlib import Path

import lief
import pefile

from tests.fixtures.synthetic import build_synthetic_elf64, build_synthetic_pe64


def test_build_synthetic_pe64(tmp_path: Path) -> None:
    pe_file = tmp_path / "synthetic_test.exe"
    build_synthetic_pe64(pe_file)

    assert pe_file.is_file()
    data = pe_file.read_bytes()
    assert len(data) > 0x400

    # 1. 验证 pefile 解析
    pe = pefile.PE(data=data)
    assert pe.FILE_HEADER.Machine == 0x8664  # AMD64
    assert pe.OPTIONAL_HEADER.Magic == 0x20B  # PE32+
    assert len(pe.sections) >= 2
    assert hasattr(pe, "DIRECTORY_ENTRY_EXPORT")
    assert hasattr(pe, "DIRECTORY_ENTRY_IMPORT")
    assert len(pe.DIRECTORY_ENTRY_IMPORT) >= 2  # KERNEL32 + WS2_32
    assert pe.OPTIONAL_HEADER.DATA_DIRECTORY[3].VirtualAddress == 0x2200
    assert pe.OPTIONAL_HEADER.DATA_DIRECTORY[3].Size == 12

    # 2. 验证 LIEF 解析
    l_bin = lief.parse(str(pe_file))
    assert l_bin.format == lief.Binary.FORMATS.PE
    assert l_bin.optional_header.magic == lief.PE.PE_TYPE.PE32_PLUS

    # 3. 验证包含测试特征数据 (URL, IPv4, AES S-Box, Overlay)
    assert b"https://api.example.com/v1/token" in data
    assert b"192.168.10.25" in data
    assert b"OVERLAY_PAYLOAD_DATA" in data


def test_build_synthetic_elf64(tmp_path: Path) -> None:
    elf_file = tmp_path / "synthetic_test.elf"
    build_synthetic_elf64(elf_file)

    assert elf_file.is_file()
    data = elf_file.read_bytes()
    assert len(data) >= 0x200
    assert data[:4] == b"\x7fELF"

    # 验证 LIEF 解析
    l_bin = lief.parse(str(elf_file))
    assert l_bin.format == lief.Binary.FORMATS.ELF
    assert l_bin.header.identity_class == lief.ELF.Header.CLASS.ELF64
