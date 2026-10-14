"""YARA 规则匹配扫描与优雅降级 (scan_yara) 端到端测试套件

@author Ateng
@since 2026-10-14
"""

from pathlib import Path
from unittest.mock import patch

import pytest

from mcp_server_reverse.core.config import ServerConfig
from mcp_server_reverse.core.models import ErrorCode
from mcp_server_reverse.core.parser import BinaryParser
from mcp_server_reverse.core.security import SecurityGuard
from mcp_server_reverse.core.session import SessionStore
from mcp_server_reverse.tools.patch import patch_memory_impl
from mcp_server_reverse.tools.session import open_binary_impl
from mcp_server_reverse.tools.yara import scan_yara_impl
from tests.fixtures.synthetic import build_synthetic_pe64


@pytest.fixture
def pe_session(tmp_path: Path) -> tuple[SessionStore, str, Path]:
    pe_file = tmp_path / "target_yara.exe"
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


def test_scan_yara_with_rule_text_success(pe_session: tuple[SessionStore, str, Path]) -> None:
    store, sid, _ = pe_session

    rule_text = """
    rule detect_synthetic_pe : test_malware_tag {
        meta:
            description = "Detect synthetic reverse PE binary"
            author = "Ateng"
            version = "1.0"
        strings:
            $dll = "KERNEL32.dll" ascii
            $func = "VirtualAllocEx" ascii
            $entry = "reverse_test_entry" ascii
        condition:
            all of them
    }
    """

    resp = scan_yara_impl(session_id=sid, rule_text=rule_text, session_store=store)
    assert resp["ok"] is True
    data = resp["data"]
    assert data["total"] == 1
    assert len(data["matches"]) == 1

    match = data["matches"][0]
    assert match["rule"] == "detect_synthetic_pe"
    assert "test_malware_tag" in match["tags"]
    assert match["meta"]["author"] == "Ateng"
    assert match["namespace"] == "default"

    # 校验字符串命中细节与地址映射
    strings = match["strings"]
    assert len(strings) >= 3
    identifiers = [s["identifier"] for s in strings]
    assert "$dll" in identifiers
    assert "$func" in identifiers
    assert "$entry" in identifiers

    for s in strings:
        assert s["offset"] > 0
        assert s["length"] > 0
        assert s["virtual_address"] is not None
        assert s["virtual_address"].startswith("0x14000")


def test_scan_yara_with_rule_file_success(
    pe_session: tuple[SessionStore, str, Path],
    tmp_path: Path,
) -> None:
    store, sid, _ = pe_session

    yar_file = tmp_path / "rules" / "sample.yar"
    yar_file.parent.mkdir(parents=True, exist_ok=True)
    yar_file.write_text(
        """
        rule file_loaded_rule {
            strings:
                $sbox_frag = { 63 7C 77 7B F2 6B 6F C5 }
            condition:
                $sbox_frag
        }
        """,
        encoding="utf-8",
    )

    resp = scan_yara_impl(
        session_id=sid,
        rule_file=str(yar_file),
        session_store=store,
    )
    assert resp["ok"] is True
    assert resp["data"]["total"] == 1
    hit = resp["data"]["matches"][0]
    assert hit["rule"] == "file_loaded_rule"
    assert len(hit["strings"]) == 1
    assert hit["strings"][0]["identifier"] == "$sbox_frag"


def test_scan_yara_perceives_cow_virtual_patch(
    pe_session: tuple[SessionStore, str, Path],
) -> None:
    store, sid, _ = pe_session

    # 1. 前置验证：未打补丁前不匹配自定义特征
    rule_text = """
    rule detect_virtual_patch {
        strings:
            $patch_sig = "MALICIOUS_IMPLANT_TOKEN_999" ascii
        condition:
            $patch_sig
    }
    """
    resp_before = scan_yara_impl(session_id=sid, rule_text=rule_text, session_store=store)
    assert resp_before["ok"] is True
    assert resp_before["data"]["total"] == 0

    # 2. 通过虚拟补丁将特征字节注入内存
    patch_token = b"MALICIOUS_IMPLANT_TOKEN_999"
    patch_hex = patch_token.hex()
    patch_resp = patch_memory_impl(
        session_id=sid,
        address_or_offset="0x140001050",
        patch_hex=patch_hex,
        address_type="va",
        session_store=store,
    )
    assert patch_resp["ok"] is True

    # 3. 后置验证：YARA 扫描透明感知内存虚拟补丁并命中特征
    resp_after = scan_yara_impl(session_id=sid, rule_text=rule_text, session_store=store)
    assert resp_after["ok"] is True
    assert resp_after["data"]["total"] == 1

    hit = resp_after["data"]["matches"][0]
    assert hit["rule"] == "detect_virtual_patch"
    assert len(hit["strings"]) == 1
    str_hit = hit["strings"][0]
    assert str_hit["identifier"] == "$patch_sig"
    assert str_hit["virtual_address"] == "0x140001050"


def test_scan_yara_syntax_error(pe_session: tuple[SessionStore, str, Path]) -> None:
    store, sid, _ = pe_session

    invalid_rule = "rule broken_syntax { strings: condition: }"
    resp = scan_yara_impl(session_id=sid, rule_text=invalid_rule, session_store=store)
    assert resp["ok"] is False
    assert resp["error"]["code"] == ErrorCode.INVALID_PARAMETER.value
    assert "语法" in resp["error"]["message"]


def test_scan_yara_invalid_parameters(pe_session: tuple[SessionStore, str, Path]) -> None:
    store, sid, _ = pe_session

    # 1. 既未提供 rule_text 也未提供 rule_file
    resp1 = scan_yara_impl(session_id=sid, session_store=store)
    assert resp1["ok"] is False
    assert resp1["error"]["code"] == ErrorCode.INVALID_PARAMETER.value

    # 2. 同时提供 rule_text 与 rule_file
    resp2 = scan_yara_impl(
        session_id=sid,
        rule_text="rule t { condition: true }",
        rule_file="some_path.yar",
        session_store=store,
    )
    assert resp2["ok"] is False
    assert resp2["error"]["code"] == ErrorCode.INVALID_PARAMETER.value

    # 3. 指定不存在的 rule_file
    resp3 = scan_yara_impl(
        session_id=sid,
        rule_file="non_existent_rule_file.yar",
        session_store=store,
    )
    assert resp3["ok"] is False
    assert resp3["error"]["code"] == ErrorCode.FILE_NOT_FOUND.value


def test_scan_yara_invalid_session() -> None:
    store = SessionStore()
    resp = scan_yara_impl(
        session_id="invalid_session_id",
        rule_text="rule t { condition: true }",
        session_store=store,
    )
    assert resp["ok"] is False
    assert resp["error"]["code"] == ErrorCode.SESSION_NOT_FOUND.value


def test_scan_yara_graceful_degradation_when_unavailable(
    pe_session: tuple[SessionStore, str, Path],
) -> None:
    store, sid, _ = pe_session

    with patch("mcp_server_reverse.core.yara_engine.is_yara_available", return_value=False):
        resp = scan_yara_impl(
            session_id=sid,
            rule_text="rule t { condition: true }",
            session_store=store,
        )
        assert resp["ok"] is False
        assert resp["error"]["code"] == ErrorCode.EXTERNAL_TOOL_UNAVAILABLE.value
        assert "yara-python" in resp["error"]["message"]
        assert "pip install" in resp["error"]["suggestion"]
