"""字符串提取与 IOC 威胁情报识别测试套件

@author Ateng
@since 2026-10-13
"""

from pathlib import Path

import pytest

from mcp_server_reverse.core.parser import BinaryParser
from mcp_server_reverse.core.session import BinarySession
from mcp_server_reverse.core.strings import (
    classify_ioc,
    extract_ascii_strings,
    extract_strings,
    extract_utf16le_strings,
)
from tests.fixtures.synthetic import build_synthetic_pe64


@pytest.fixture
def pe_session(tmp_path: Path) -> BinarySession:
    pe_file = tmp_path / "test_strings.exe"
    build_synthetic_pe64(pe_file)
    parser = BinaryParser()
    res = parser.parse(pe_file)

    return BinarySession(
        session_id="strings123456",
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


def test_classify_ioc() -> None:
    assert classify_ioc("https://malware.example.com/c2") == "url"
    assert classify_ioc("http://1.2.3.4:8080/drop") == "url"
    assert classify_ioc("192.168.1.100") == "ipv4"
    assert classify_ioc("C:\\Windows\\System32\\cmd.exe") == "filepath"
    assert classify_ioc("/usr/bin/python3") == "filepath"
    assert classify_ioc("Software\\Microsoft\\Windows\\CurrentVersion\\Run") == "registry"
    assert classify_ioc("HKEY_LOCAL_MACHINE\\SYSTEM") == "registry"
    assert classify_ioc("attacker@evil.org") == "email"
    assert classify_ioc("BEGIN RSA PRIVATE KEY") == "crypto_or_key"
    assert classify_ioc("powershell.exe -enc AAAA") == "suspicious_cmd"
    assert classify_ioc("just a normal string") is None


def test_extract_ascii_and_utf16le_primitives() -> None:
    data = b"Hello World!\x00\x00" + "UnicodeString\x00\x00".encode("utf-16le")
    ascii_res = extract_ascii_strings(data, min_length=4)
    assert any(val == "Hello World!" for offset, val in ascii_res)

    utf16_res = extract_utf16le_strings(data, min_length=4)
    assert any("UnicodeString" in val for offset, val in utf16_res)


def test_extract_strings_synthetic_pe(pe_session: BinarySession) -> None:
    # 1. 全量提取
    items, total, floss_status = extract_strings(pe_session, min_length=4)
    assert total >= 4
    values = [item.value for item in items]

    # 包含 synthetic.py 植入的 URL、IP 与注册表键
    assert any("api.example.com" in v for v in values)
    assert any("192.168.10.25" in v for v in values)
    assert any("ReverseTest" in v for v in values)

    # 2. 按 IOC 类别过滤 url
    url_items, url_total, _ = extract_strings(pe_session, ioc_category="url")
    assert url_total >= 1
    assert any("https://" in u.value for u in url_items)
    assert all(u.ioc_category == "url" for u in url_items)

    # 3. 按 IOC 类别过滤 ipv4
    ip_items, ip_total, _ = extract_strings(pe_session, ioc_category="ipv4")
    assert ip_total >= 1
    assert any("192.168.10.25" in ip.value for ip in ip_items)

    # 4. 按 pattern 正则过滤
    reg_items, reg_total, _ = extract_strings(pe_session, pattern=r"ReverseTest")
    assert reg_total >= 1
    assert reg_items[0].encoding == "utf16le"
    assert reg_items[0].ioc_category == "registry"


def test_extract_strings_floss_soft_fallback(pe_session: BinarySession) -> None:
    # 模拟开启 use_floss=True，若本机未安装则安全软降级
    items, total, floss_status = extract_strings(pe_session, use_floss=True)
    assert total >= 1
    assert floss_status is not None


def test_strings_dynamic_cache_granularity(pe_session: BinarySession) -> None:
    # 1. 首次按 min_length=10 提取
    items10, total10, _ = extract_strings(pe_session, min_length=10)
    # 2. 紧接着按更小粒度 min_length=2 提取，验证自动重新扫描且未发生短串截断
    items2, total2, _ = extract_strings(pe_session, min_length=2)
    assert total2 > total10


def test_strings_floss_active_execution(
    pe_session: BinarySession, monkeypatch: pytest.MonkeyPatch
) -> None:
    import subprocess

    from mcp_server_reverse.core.locator import ToolLocator
    from mcp_server_reverse.core.models import ExternalCapability

    mock_cap = ExternalCapability(
        name="floss",
        available=True,
        path="/usr/bin/floss",
    )
    monkeypatch.setattr(ToolLocator, "locate_tool", lambda self, name: mock_cap)

    mock_res = subprocess.CompletedProcess(
        args=["floss"],
        returncode=0,
        stdout="DECODED_STACK_STRING_IOC\nANOTHER_STACK_KEY",
        stderr="",
    )
    monkeypatch.setattr(subprocess, "run", lambda *args, **kwargs: mock_res)

    items, total, status = extract_strings(pe_session, use_floss=True)
    assert any(s.value == "DECODED_STACK_STRING_IOC" for s in items)
    assert any(s.encoding == "floss_stack" for s in items)
    assert "已合并解码出 2 条栈字符串" in (status or "")
