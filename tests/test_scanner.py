"""Hex 通配符与密码学特征扫描引擎测试套件

@author Ateng
@since 2026-10-13
"""

from pathlib import Path

import pytest

from mcp_server_reverse.core.parser import BinaryParser
from mcp_server_reverse.core.scanner import (
    compile_ida_hex_pattern,
    scan_crypto_signatures,
    search_hex_pattern,
)
from mcp_server_reverse.core.session import BinarySession
from tests.fixtures.synthetic import build_synthetic_pe64


@pytest.fixture
def pe_session(tmp_path: Path) -> BinarySession:
    pe_file = tmp_path / "test_scanner.exe"
    build_synthetic_pe64(pe_file)
    parser = BinaryParser()
    res = parser.parse(pe_file)

    return BinarySession(
        session_id="scanner123456",
        file_path=pe_file,
        file_sha256="dummy_sha256",
        file_size=pe_file.stat().st_size,
        format=res.format_info["format"],
        arch=res.format_info["arch"],
        bits=res.format_info["bits"],
        entry_point=int(res.format_info["entry_point"], 16),
        image_base=int(res.format_info["image_base"], 16),
        file_info=res.file_info,
        format_info=res.format_info,
        triage_overview=res.triage_overview,
        forensic_metadata=res.forensic_metadata,
        lief_binary=res.lief_binary,
        pefile_binary=res.pefile_binary,
    )


def test_compile_ida_hex_pattern() -> None:
    # 1. 正常编译带有通配符的模式
    regex = compile_ida_hex_pattern("48 8D 0D ? ? ? ?")
    assert regex.search(b"\x48\x8d\x0d\x49\x12\x00\x00") is not None
    assert regex.search(b"\x48\x8d\x00\x00\x00\x00\x00") is None

    # 2. 编译 ?? 通配符
    regex2 = compile_ida_hex_pattern("31 C0 C3 ??")
    assert regex2.search(b"\x31\xc0\xc3\xcc") is not None

    # 3. 非法十六进制报错
    with pytest.raises(ValueError):
        compile_ida_hex_pattern("48 GG 24")

    with pytest.raises(ValueError):
        compile_ida_hex_pattern("")


def test_search_hex_pattern_pe64(pe_session: BinarySession) -> None:
    # 检索 synthetic.py 中 .text 的指令序列:
    # 48 8d 0d 49 12 00 00 e8 00 00 00 00 31 c0 c3 cc
    matches, total = search_hex_pattern(
        session=pe_session,
        pattern_str="48 8D 0D ?? ?? ?? ?? E8",
        offset=0,
        limit=50,
    )
    assert total >= 1
    hit = matches[0]
    assert hit.section == ".text"
    assert "140001000" in hit.virtual_address
    assert "48 8D 0D" in hit.matched_hex.upper()


def test_scan_crypto_signatures_aes_sbox(pe_session: BinarySession) -> None:
    # synthetic.py 的 .rdata 中内嵌了完整的 256 字节 AES S-Box 表
    signatures, total = scan_crypto_signatures(pe_session)
    assert total >= 1
    aes_sig = next(s for s in signatures if s.name == "AES S-Box")
    assert aes_sig.algorithm == "AES"
    assert aes_sig.section == ".rdata"
    assert aes_sig.confidence == 1.0
    assert aes_sig.file_offset > 0
    assert "14000" in aes_sig.virtual_address


def test_scan_crypto_signatures_des_sbox(tmp_path: Path) -> None:
    # 验证 DES S-Box 常量识别
    from mcp_server_reverse.core.scanner import DES_SBOX1_BYTES

    des_file = tmp_path / "des_test.bin"
    des_file.write_bytes(b"\x90" * 64 + DES_SBOX1_BYTES + b"\x90" * 64)

    dummy_session = BinarySession(
        session_id="des123456",
        file_path=des_file,
        file_sha256="dummy",
        file_size=des_file.stat().st_size,
        format="RAW",
        arch="x86_64",
    )
    sigs, total = scan_crypto_signatures(dummy_session)
    assert total >= 1
    assert any(s.name == "DES S-Box 1" for s in sigs)
