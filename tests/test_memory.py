"""地址双向换算、符号地址决议与内存 Hexdump 引擎测试套件

@author Ateng
@since 2026-10-13
"""

from pathlib import Path

import pytest

from mcp_server_reverse.core.memory import (
    convert_address_core,
    read_memory_core,
    resolve_target_address,
)
from mcp_server_reverse.core.parser import BinaryParser
from mcp_server_reverse.core.session import BinarySession
from tests.fixtures.synthetic import build_synthetic_pe64


@pytest.fixture
def pe_session(tmp_path: Path) -> BinarySession:
    pe_file = tmp_path / "test_mem.exe"
    build_synthetic_pe64(pe_file)
    parser = BinaryParser()
    res = parser.parse(pe_file)

    return BinarySession(
        session_id="mem123456789",
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


def test_convert_address_bidirectional(pe_session: BinarySession) -> None:
    # 1. VA -> RVA / Offset
    res_va = convert_address_core(pe_session, "0x140001000", "va")
    assert res_va["va"] == "0x140001000"
    assert res_va["rva"] == "0x1000"
    assert res_va["offset"] == 0x200
    assert res_va["section"] == ".text"
    assert res_va["permissions"] == "r-x"

    # 2. RVA -> VA / Offset
    res_rva = convert_address_core(pe_session, "0x1000", "rva")
    assert res_rva["va"] == "0x140001000"
    assert res_rva["offset"] == 0x200
    assert res_rva["section"] == ".text"

    # 3. Offset -> VA / RVA
    res_off = convert_address_core(pe_session, 0x200, "offset")
    assert res_off["va"] == "0x140001000"
    assert res_off["rva"] == "0x1000"
    assert res_off["section"] == ".text"

    # 4. 越界地址拦截
    with pytest.raises(LookupError):
        convert_address_core(pe_session, "0x140999000", "va")


def test_read_memory_hexdump(pe_session: BinarySession) -> None:
    # 0x140002250 处存放了 "https://api.example.com/v1/token\x00"
    mem_data = read_memory_core(pe_session, "0x140002250", size=32, address_type="va")
    assert mem_data["start_address"] == "0x140002250"
    assert mem_data["size"] == 32
    assert mem_data["section"] == ".rdata"
    assert len(mem_data["hexdump_lines"]) == 2
    assert "https://api.exam" in mem_data["hexdump_lines"][0]


def test_resolve_target_address(pe_session: BinarySession) -> None:
    # 1. 十六进制字面量
    assert resolve_target_address(pe_session, "0x140001000") == 0x140001000
    # 2. 导出函数名
    assert resolve_target_address(pe_session, "reverse_test_entry") == 0x140001000
    # 3. .pdata 恢复函数名
    assert resolve_target_address(pe_session, "sub_140001000") == 0x140001000
    # 4. entry 别名
    assert resolve_target_address(pe_session, "entry") == 0x140001000
    # 5. 不存在的符号名
    with pytest.raises(LookupError):
        resolve_target_address(pe_session, "non_existent_symbol_xyz")
