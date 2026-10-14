"""漏洞缓解机制加固审计与安全评分 (audit_mitigations) MCP 工具端到端测试套件

@author Ateng
@since 2026-10-14
"""

from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from mcp_server_reverse.core.config import ServerConfig
from mcp_server_reverse.core.models import ErrorCode
from mcp_server_reverse.core.parser import BinaryParser
from mcp_server_reverse.core.security import SecurityGuard
from mcp_server_reverse.core.session import BinarySession, SessionStore
from mcp_server_reverse.tools.mitigations import audit_mitigations_impl
from mcp_server_reverse.tools.session import open_binary_impl
from tests.fixtures.synthetic import (
    build_synthetic_elf64,
    build_synthetic_macho64,
    build_synthetic_pe64,
)


@pytest.fixture
def pe_session(tmp_path: Path) -> tuple[SessionStore, str, Path]:
    pe_file = tmp_path / "target_mitigation.exe"
    build_synthetic_pe64(pe_file)

    config = ServerConfig()
    store = SessionStore()
    resp = open_binary_impl(
        file_path=str(pe_file),
        target_arch=None,
        config=config,
        session_store=store,
        security_guard=SecurityGuard(),
        parser=BinaryParser(),
    )
    return store, resp["session_id"], pe_file


@pytest.fixture
def elf_session(tmp_path: Path) -> tuple[SessionStore, str, Path]:
    elf_file = tmp_path / "target_mitigation.elf"
    build_synthetic_elf64(elf_file)

    config = ServerConfig()
    store = SessionStore()
    resp = open_binary_impl(
        file_path=str(elf_file),
        target_arch=None,
        config=config,
        session_store=store,
        security_guard=SecurityGuard(),
        parser=BinaryParser(),
    )
    return store, resp["session_id"], elf_file


@pytest.fixture
def macho_session(tmp_path: Path) -> tuple[SessionStore, str, Path]:
    macho_file = tmp_path / "target_mitigation.macho"
    build_synthetic_macho64(macho_file)

    config = ServerConfig()
    store = SessionStore()
    resp = open_binary_impl(
        file_path=str(macho_file),
        target_arch="arm64",
        config=config,
        session_store=store,
        security_guard=SecurityGuard(),
        parser=BinaryParser(),
    )
    return store, resp["session_id"], macho_file


def test_audit_mitigations_pe64(pe_session: tuple[SessionStore, str, Path]) -> None:
    store, sid, _ = pe_session

    resp = audit_mitigations_impl(session_id=sid, session_store=store)
    assert resp["ok"] is True
    data = resp["data"]

    assert data["format"] == "PE"
    assert data["arch"] == "x86_64"
    assert 0 <= data["score"] <= 100
    assert data["exploit_difficulty"] in ("Low", "Medium", "High", "Extreme")

    mits: dict[str, Any] = data["mitigations"]
    assert mits["aslr"] is True
    assert mits["dep_nx"] is True
    assert "cfg" in mits
    assert "cet_shadow_stack" in mits
    assert "safe_seh" in mits
    assert "authenticode_signed" in mits

    assert isinstance(data["recommendations"], list)
    assert "加固" in data["summary"]


def test_audit_mitigations_elf64(elf_session: tuple[SessionStore, str, Path]) -> None:
    store, sid, _ = elf_session

    resp = audit_mitigations_impl(session_id=sid, session_store=store)
    assert resp["ok"] is True
    data = resp["data"]

    assert data["format"] == "ELF"
    assert data["arch"] in ("x86_64", "i386")
    assert 0 <= data["score"] <= 100
    assert data["exploit_difficulty"] in ("Low", "Medium", "High", "Extreme")

    mits: dict[str, Any] = data["mitigations"]
    assert "nx" in mits
    assert "pie" in mits
    assert "relro" in mits
    assert "canary" in mits
    assert "fortify_source" in mits
    assert mits["relro"] in ("Full", "Partial", "None")

    assert isinstance(data["recommendations"], list)


def test_audit_mitigations_macho_and_difficulty_rating(
    macho_session: tuple[SessionStore, str, Path],
) -> None:
    store, sid, _ = macho_session

    resp = audit_mitigations_impl(session_id=sid, session_store=store)
    assert resp["ok"] is True
    data = resp["data"]
    assert data["format"] == "Mach-O"
    assert data["arch"] == "arm64"
    assert data["mitigations"]["pie"] is True
    assert data["mitigations"]["nx"] is True
    assert 0 <= data["score"] <= 100
    assert data["exploit_difficulty"] in ("Low", "Medium", "High", "Extreme")
    assert isinstance(data["recommendations"], list)


def test_audit_mitigations_invalid_session() -> None:
    store = SessionStore()
    resp = audit_mitigations_impl(session_id="non_exist_session", session_store=store)
    assert resp["ok"] is False
    assert resp["error"]["code"] == ErrorCode.SESSION_NOT_FOUND.value


def test_exploit_difficulty_calculation() -> None:
    from mcp_server_reverse.core.mitigations import _calculate_exploit_difficulty

    assert _calculate_exploit_difficulty(100) == "Extreme"
    assert _calculate_exploit_difficulty(80) == "Extreme"
    assert _calculate_exploit_difficulty(79) == "High"
    assert _calculate_exploit_difficulty(60) == "High"
    assert _calculate_exploit_difficulty(59) == "Medium"
    assert _calculate_exploit_difficulty(40) == "Medium"
    assert _calculate_exploit_difficulty(39) == "Low"
    assert _calculate_exploit_difficulty(0) == "Low"


def test_audit_mitigations_pe_guard_and_cet() -> None:
    session = BinarySession(
        session_id="mock_pe_full",
        file_path=Path("mock.exe"),
        file_sha256="aa" * 32,
        file_size=4096,
        format="PE",
        arch="x86_64",
        bits=64,
    )
    # mock pefile_binary 具有 DYNAMIC_BASE | NX_COMPAT | GUARD_CF | CET_COMPAT
    mock_pe = MagicMock()
    mock_pe.OPTIONAL_HEADER.DllCharacteristics = 0x0040 | 0x0100 | 0x4000 | 0x1000 | 0x0020
    mock_pe.OPTIONAL_HEADER.DATA_DIRECTORY = [MagicMock() for _ in range(12)]
    # 设置 Security Directory (index 4) 有效
    mock_pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].VirtualAddress = 0x2000
    mock_pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].Size = 0x400

    session.pefile_binary = mock_pe
    store = SessionStore()
    store.put(session)

    resp = audit_mitigations_impl(session_id="mock_pe_full", session_store=store)
    assert resp["ok"] is True
    data = resp["data"]
    assert data["mitigations"]["aslr"] is True
    assert data["mitigations"]["high_entropy_va"] is True
    assert data["mitigations"]["dep_nx"] is True
    assert data["mitigations"]["cfg"] is True
    assert data["mitigations"]["cet_shadow_stack"] is True
    assert data["mitigations"]["authenticode_signed"] is True
    assert data["score"] >= 80
    assert data["exploit_difficulty"] == "Extreme"


def test_audit_mitigations_elf_full_relro_and_canary() -> None:
    session = BinarySession(
        session_id="mock_elf_full",
        file_path=Path("mock.elf"),
        file_sha256="bb" * 32,
        file_size=4096,
        format="ELF",
        arch="x86_64",
        bits=64,
    )
    mock_lief = MagicMock()
    mock_lief.has_nx = True
    mock_lief.is_pie = True
    mock_lief.has_canary = True

    # mock PT_GNU_RELRO segment
    seg_relro = MagicMock()
    seg_relro.type = "GNU_RELRO"
    mock_lief.segments = [seg_relro]

    # mock BIND_NOW dynamic tag
    dyn_now = MagicMock()
    dyn_now.tag = "BIND_NOW"
    mock_lief.dynamic_entries = [dyn_now]

    # mock symbols with _chk
    sym1 = MagicMock()
    sym1.name = "__printf_chk"
    mock_lief.symbols = [sym1]

    session.lief_binary = mock_lief
    store = SessionStore()
    store.put(session)

    resp = audit_mitigations_impl(session_id="mock_elf_full", session_store=store)
    assert resp["ok"] is True
    data = resp["data"]
    assert data["mitigations"]["nx"] is True
    assert data["mitigations"]["pie"] is True
    assert data["mitigations"]["relro"] == "Full"
    assert data["mitigations"]["canary"] is True
    assert data["mitigations"]["fortify_source"] is True
    assert data["score"] == 100
    assert data["exploit_difficulty"] == "Extreme"
