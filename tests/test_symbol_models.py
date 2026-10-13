"""SectionProfile 与 SymbolEntry 数据模型测试套件

@author Ateng
@since 2026-10-13
"""

from mcp_server_reverse.core.models import SectionProfile, SymbolEntry


def test_section_profile_structure() -> None:
    profile = SectionProfile(
        name=".text",
        virtual_address="0x140001000",
        virtual_size=0x200,
        raw_offset=0x200,
        raw_size=0x200,
        permissions="r-x",
        entropy=6.5,
        is_high_entropy=False,
    )
    d = profile.to_dict()
    assert d["name"] == ".text"
    assert d["permissions"] == "r-x"
    assert d["entropy"] == 6.5
    assert d["is_high_entropy"] is False


def test_symbol_entry_structure() -> None:
    sym = SymbolEntry(
        name="VirtualAllocEx",
        demangled_name=None,
        library="KERNEL32.dll",
        address="0x140002150",
        size=0,
        symbol_type="import",
        category="process_injection",
    )
    d = sym.to_dict()
    assert d["name"] == "VirtualAllocEx"
    assert d["library"] == "KERNEL32.dll"
    assert d["symbol_type"] == "import"
    assert d["category"] == "process_injection"
