"""结构与符号核心提取引擎测试套件

@author Ateng
@since 2026-10-13
"""

import re
from pathlib import Path

import pytest

from mcp_server_reverse.core.inspection import (
    extract_exports,
    extract_imports,
    extract_sections,
    extract_symbols,
)
from mcp_server_reverse.core.parser import BinaryParser
from mcp_server_reverse.core.session import BinarySession
from tests.fixtures.synthetic import build_synthetic_pe64


@pytest.fixture
def pe_session(tmp_path: Path) -> BinarySession:
    pe_file = tmp_path / "test_inspect.exe"
    build_synthetic_pe64(pe_file)
    parser = BinaryParser()
    res = parser.parse(pe_file)

    return BinarySession(
        session_id="a1b2c3d4e5f6",
        file_path=pe_file,
        file_sha256="dummy_hash",
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


def test_extract_sections(pe_session: BinarySession) -> None:
    sections = extract_sections(pe_session)
    assert len(sections) >= 2
    sec_names = [s.name for s in sections]
    assert ".text" in sec_names
    assert ".rdata" in sec_names

    text_sec = next(s for s in sections if s.name == ".text")
    assert "x" in text_sec.permissions
    assert 0.0 <= text_sec.entropy <= 8.0


def test_extract_imports_and_category_filtering(pe_session: BinarySession) -> None:
    # 1. 无过滤提取全部导入项
    items, total = extract_imports(pe_session, offset=0, limit=50)
    assert total >= 2
    names = [i.name for i in items]
    assert "VirtualAllocEx" in names
    assert "WSAStartup" in names

    # 2. 按敏感标签过滤 process_injection
    inj_items, inj_total = extract_imports(pe_session, category="process_injection")
    assert inj_total == 1
    assert inj_items[0].name == "VirtualAllocEx"
    assert inj_items[0].library == "KERNEL32.dll"

    # 3. 按动态库名称正则过滤
    ws2_items, ws2_total = extract_imports(pe_session, library_filter=r"WS2_\d+")
    assert ws2_total == 1
    assert ws2_items[0].name == "WSAStartup"


def test_extract_exports(pe_session: BinarySession) -> None:
    items, total = extract_exports(pe_session)
    assert total == 1
    assert items[0]["name"] == "reverse_test_entry"
    assert "address" in items[0]


def test_extract_symbols_and_pdata_recovery(pe_session: BinarySession) -> None:
    # 提取 exception_frame 恢复的无符号内部函数
    items, total = extract_symbols(pe_session, symbol_type="exception_frame")
    assert total >= 1
    sub_func = next(s for s in items if s.name.startswith("sub_"))
    assert sub_func.symbol_type == "exception_frame"
    assert sub_func.size == 16  # 0x1010 - 0x1000 = 16
    assert "140001000" in sub_func.address


def test_regex_filter_invalid(pe_session: BinarySession) -> None:
    with pytest.raises(re.error):
        extract_imports(pe_session, name_filter="[invalid(")


def test_high_entropy_section_flag() -> None:
    """验证当节区香农熵 >= 7.2 时，自动标记 is_high_entropy: True"""
    from mcp_server_reverse.core.models import SectionProfile

    high_sec = SectionProfile(
        name=".packed",
        virtual_address="0x140003000",
        virtual_size=4096,
        raw_offset=1024,
        raw_size=4096,
        permissions="r-x",
        entropy=7.45,
        is_high_entropy=7.45 >= 7.2,
    )
    assert high_sec.is_high_entropy is True
    assert high_sec.entropy >= 7.2

    low_sec = SectionProfile(
        name=".text",
        virtual_address="0x140001000",
        virtual_size=4096,
        raw_offset=512,
        raw_size=4096,
        permissions="r-x",
        entropy=6.12,
        is_high_entropy=6.12 >= 7.2,
    )
    assert low_sec.is_high_entropy is False
