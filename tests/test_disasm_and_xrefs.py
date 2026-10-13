"""多架构反汇编、RIP-relative 内联注释与惰性交叉引用引擎测试套件

@author Ateng
@since 2026-10-13
"""

import struct
from pathlib import Path

import pytest

from mcp_server_reverse.core.disasm import (
    disassemble_at,
    query_xrefs,
    scan_code_section_xrefs,
)
from mcp_server_reverse.core.parser import BinaryParser
from mcp_server_reverse.core.session import BinarySession
from tests.fixtures.synthetic import build_synthetic_pe64


@pytest.fixture
def pe_session(tmp_path: Path) -> BinarySession:
    pe_file = tmp_path / "test_disasm.exe"
    build_synthetic_pe64(pe_file)
    parser = BinaryParser()
    res = parser.parse(pe_file)

    return BinarySession(
        session_id="disasm123456",
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


def test_disassemble_stop_at_ret_and_rip_comment(pe_session: BinarySession) -> None:
    # 1. 开启 stop_at_ret=True
    res = disassemble_at(pe_session, target_va=0x140001000, count=32, stop_at_ret=True)
    assert res["stopped_at_ret"] is True
    insns = res["instructions"]
    assert len(insns) == 4  # lea, call, xor, ret (在 ret 处停止，不包含后面的 int3)
    assert insns[-1].mnemonic == "ret"

    # 验证第一条 RIP-relative 指令自动内联了目标 URL 字符串注释
    first = insns[0]
    assert first.mnemonic == "lea"
    assert first.comment is not None
    assert "https://api.example.com/v1/token" in first.comment
    assert "; " in first.formatted

    # 2. 关闭 stop_at_ret=False，继续反汇编后面的 int3 和 nop
    res_full = disassemble_at(pe_session, target_va=0x140001000, count=6, stop_at_ret=False)
    assert res_full["stopped_at_ret"] is False
    mnemonics = [i.mnemonic for i in res_full["instructions"]]
    assert "int3" in mnemonics


def test_find_xrefs_rip_relative_and_call(pe_session: BinarySession) -> None:
    # 1. 查询 URL 字符串地址 0x140002250 的交叉引用
    xrefs_url, total_url = query_xrefs(pe_session, target_va=0x140002250, xref_type="all")
    assert total_url >= 1
    hit = xrefs_url[0]
    assert hit.from_address == "0x140001000"
    assert hit.to_address == "0x140002250"
    assert hit.xref_type == "rip_relative"
    assert hit.category == "code"
    assert pe_session._xref_index is not None

    # 2. 查询 call 目标地址 0x14000100C 的交叉引用
    xrefs_call, total_call = query_xrefs(pe_session, target_va=0x14000100C, xref_type="code")
    assert total_call >= 1
    assert xrefs_call[0].from_address == "0x140001007"
    assert xrefs_call[0].xref_type == "call"


def test_arm64_sliding_window_adrp_add_xrefs() -> None:
    # 构造 ARM64 指令流:
    # 0x400000: adrp x16, #0x400000 (0x90000010)
    # 0x400004: nop                 (0xD503201F)
    # 0x400008: add x0, x16, #0x250 (0x91094200)
    code_bytes = struct.pack("<III", 0x90000010, 0xD503201F, 0x91094200)
    index: dict[int, list] = {}
    scan_code_section_xrefs(
        code_bytes=code_bytes,
        section_va=0x400000,
        section_name=".text",
        arch="arm64",
        bits=64,
        index=index,
    )
    assert 0x400250 in index
    records = index[0x400250]
    assert len(records) == 1
    assert records[0].from_address == "0x400008"
    assert records[0].to_address == "0x400250"
    assert records[0].xref_type == "pc_relative"
    assert records[0].category == "code"
