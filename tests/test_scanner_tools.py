"""字符串与特征扫描 MCP 工具端到端测试套件

@author Ateng
@since 2026-10-13
"""

from pathlib import Path

from mcp_server_reverse.core.config import ServerConfig
from mcp_server_reverse.core.models import ErrorCode
from mcp_server_reverse.core.parser import BinaryParser
from mcp_server_reverse.core.security import SecurityGuard
from mcp_server_reverse.core.session import SessionStore
from mcp_server_reverse.tools.scanner import (
    search_bytes_and_constants_impl,
    search_strings_impl,
)
from mcp_server_reverse.tools.session import open_binary_impl
from tests.fixtures.synthetic import build_synthetic_elf64, build_synthetic_pe64


def test_search_strings_tools_pe64(tmp_path: Path) -> None:
    pe_file = tmp_path / "target_strings.exe"
    build_synthetic_pe64(pe_file)

    config = ServerConfig()
    store = SessionStore()
    guard = SecurityGuard()
    parser = BinaryParser()

    open_resp = open_binary_impl(
        file_path=str(pe_file),
        target_arch=None,
        config=config,
        session_store=store,
        security_guard=guard,
        parser=parser,
    )
    sid = open_resp["session_id"]
    assert sid is not None

    # 1. 全量搜索
    all_resp = search_strings_impl(
        session_id=sid,
        pattern=None,
        min_length=4,
        encoding="all",
        ioc_category=None,
        section_name=None,
        use_floss=False,
        offset=0,
        limit=50,
        session_store=store,
    )
    assert all_resp["ok"] is True
    assert all_resp["pagination"]["total"] >= 4
    strings = all_resp["data"]["strings"]
    vals = [s["value"] for s in strings]
    assert any("api.example.com" in v for v in vals)

    # 2. IOC 过滤 url
    url_resp = search_strings_impl(
        session_id=sid,
        pattern=None,
        min_length=4,
        encoding="all",
        ioc_category="url",
        section_name=None,
        use_floss=False,
        offset=0,
        limit=50,
        session_store=store,
    )
    assert url_resp["ok"] is True
    assert url_resp["pagination"]["total"] >= 1
    assert url_resp["data"]["strings"][0]["ioc_category"] == "url"

    # 3. 启用 use_floss=True 软降级
    floss_resp = search_strings_impl(
        session_id=sid,
        pattern=None,
        min_length=4,
        encoding="all",
        ioc_category=None,
        section_name=None,
        use_floss=True,
        offset=0,
        limit=50,
        session_store=store,
    )
    assert floss_resp["ok"] is True
    assert "floss_status" in floss_resp["data"]
    assert floss_resp["data"]["floss_status"] is not None

    # 4. 错误防御
    # 4.1 非法会话 ID
    bad_sid_resp = search_strings_impl(
        session_id="deadbeef0000",
        pattern=None,
        min_length=4,
        encoding="all",
        ioc_category=None,
        section_name=None,
        use_floss=False,
        offset=0,
        limit=50,
        session_store=store,
    )
    assert bad_sid_resp["ok"] is False
    assert bad_sid_resp["error"]["code"] == ErrorCode.SESSION_NOT_FOUND.value

    # 4.2 非法编码
    bad_enc_resp = search_strings_impl(
        session_id=sid,
        pattern=None,
        min_length=4,
        encoding="gbk",
        ioc_category=None,
        section_name=None,
        use_floss=False,
        offset=0,
        limit=50,
        session_store=store,
    )
    assert bad_enc_resp["ok"] is False
    assert bad_enc_resp["error"]["code"] == ErrorCode.INVALID_PARAMETER.value

    # 4.3 非法 ioc_category
    bad_ioc_resp = search_strings_impl(
        session_id=sid,
        pattern=None,
        min_length=4,
        encoding="all",
        ioc_category="invalid_category",
        section_name=None,
        use_floss=False,
        offset=0,
        limit=50,
        session_store=store,
    )
    assert bad_ioc_resp["ok"] is False
    assert bad_ioc_resp["error"]["code"] == ErrorCode.INVALID_PARAMETER.value

    # 4.4 非法 pattern 正则
    bad_re_resp = search_strings_impl(
        session_id=sid,
        pattern=r"[unclosed(",
        min_length=4,
        encoding="all",
        ioc_category=None,
        section_name=None,
        use_floss=False,
        offset=0,
        limit=50,
        session_store=store,
    )
    assert bad_re_resp["ok"] is False
    assert bad_re_resp["error"]["code"] == ErrorCode.INVALID_PARAMETER.value


def test_search_bytes_and_constants_tools(tmp_path: Path) -> None:
    pe_file = tmp_path / "target_scanner.exe"
    build_synthetic_pe64(pe_file)

    config = ServerConfig()
    store = SessionStore()
    open_resp = open_binary_impl(
        file_path=str(pe_file),
        target_arch=None,
        config=config,
        session_store=store,
        security_guard=SecurityGuard(),
        parser=BinaryParser(),
    )
    sid = open_resp["session_id"]

    # 1. 类 IDA 十六进制通配符搜索
    hex_resp = search_bytes_and_constants_impl(
        session_id=sid,
        hex_pattern="48 8D 0D ? ? ? ?",
        scan_crypto=False,
        section_name=None,
        offset=0,
        limit=50,
        session_store=store,
    )
    assert hex_resp["ok"] is True
    assert len(hex_resp["data"]["hex_matches"]) >= 1
    hit = hex_resp["data"]["hex_matches"][0]
    assert hit["section"] == ".text"
    assert "140001000" in hit["virtual_address"]

    # 2. 密码学魔数常量扫描
    crypto_resp = search_bytes_and_constants_impl(
        session_id=sid,
        hex_pattern=None,
        scan_crypto=True,
        section_name=None,
        offset=0,
        limit=50,
        session_store=store,
    )
    assert crypto_resp["ok"] is True
    sigs = crypto_resp["data"]["crypto_signatures"]
    assert len(sigs) >= 1
    aes_sig = next(s for s in sigs if s["name"] == "AES S-Box")
    assert aes_sig["algorithm"] == "AES"
    assert aes_sig["section"] == ".rdata"

    # 2.5 联合检索全局分页验证 (limit=1 时总返回数不超过 1)
    combined_resp = search_bytes_and_constants_impl(
        session_id=sid,
        hex_pattern="48 8D 0D ? ? ? ?",
        scan_crypto=True,
        section_name=None,
        offset=0,
        limit=1,
        session_store=store,
    )
    assert combined_resp["ok"] is True
    assert (
        len(combined_resp["data"]["hex_matches"]) + len(combined_resp["data"]["crypto_signatures"])
    ) == 1
    assert combined_resp["pagination"]["limit"] == 1
    assert combined_resp["pagination"]["has_more"] is True

    # 3. 错误防御
    # 3.1 两项均未指定
    empty_resp = search_bytes_and_constants_impl(
        session_id=sid,
        hex_pattern=None,
        scan_crypto=False,
        section_name=None,
        offset=0,
        limit=50,
        session_store=store,
    )
    assert empty_resp["ok"] is False
    assert empty_resp["error"]["code"] == ErrorCode.INVALID_PARAMETER.value

    # 3.2 非法 hex_pattern
    bad_hex_resp = search_bytes_and_constants_impl(
        session_id=sid,
        hex_pattern="48 GG 24",
        scan_crypto=False,
        section_name=None,
        offset=0,
        limit=50,
        session_store=store,
    )
    assert bad_hex_resp["ok"] is False
    assert bad_hex_resp["error"]["code"] == ErrorCode.INVALID_PARAMETER.value


def test_scanner_tools_elf64(tmp_path: Path) -> None:
    elf_file = tmp_path / "target_scan_elf"
    build_synthetic_elf64(elf_file)

    config = ServerConfig()
    store = SessionStore()
    open_resp = open_binary_impl(
        file_path=str(elf_file),
        target_arch=None,
        config=config,
        session_store=store,
        security_guard=SecurityGuard(),
        parser=BinaryParser(),
    )
    sid = open_resp["session_id"]

    # 字符串提取
    str_resp = search_strings_impl(
        session_id=sid,
        pattern=None,
        min_length=4,
        encoding="all",
        ioc_category=None,
        section_name=None,
        use_floss=False,
        offset=0,
        limit=50,
        session_store=store,
    )
    assert str_resp["ok"] is True
    assert isinstance(str_resp["data"]["strings"], list)

    # 密码学常量扫描
    crypto_resp = search_bytes_and_constants_impl(
        session_id=sid,
        hex_pattern=None,
        scan_crypto=True,
        section_name=None,
        offset=0,
        limit=50,
        session_store=store,
    )
    assert crypto_resp["ok"] is True
    assert any(s["name"] == "AES S-Box" for s in crypto_resp["data"]["crypto_signatures"])


def test_search_strings_xor_and_base64_deobfuscation(tmp_path: Path) -> None:
    from mcp_server_reverse.tools.patch import patch_memory_impl

    pe_file = tmp_path / "target_deobf.exe"
    build_synthetic_pe64(pe_file)

    config = ServerConfig()
    store = SessionStore()
    open_resp = open_binary_impl(
        file_path=str(pe_file),
        target_arch=None,
        session_store=store,
        security_guard=SecurityGuard(),
        parser=BinaryParser(),
        config=config,
    )
    sid = open_resp["session_id"]

    # 1. 植入以 0x5A 异或加密的 "super_secret_token"
    plain_xor = b"super_secret_token"
    enc_xor = bytes(b ^ 0x5A for b in plain_xor)
    patch_memory_impl(
        session_id=sid,
        address_or_offset="0x140001000",
        patch_hex=enc_xor.hex(" "),
        session_store=store,
    )

    # 1.1 指定 xor_key=0x5A 提取
    res_key = search_strings_impl(
        session_id=sid,
        xor_key=0x5A,
        session_store=store,
    )
    assert res_key["ok"] is True
    deobf_list = res_key["data"]["deobfuscated_strings"]
    assert any("super_secret_token" in d["value"] for d in deobf_list)
    assert any(d["xor_key"] == 0x5A for d in deobf_list)

    # 2. 植入以 0x33 异或加密的 URL "https://c2.evil.com/beacon"
    url_plain = b"https://c2.evil.com/beacon"
    url_enc = bytes(b ^ 0x33 for b in url_plain)
    patch_memory_impl(
        session_id=sid,
        address_or_offset="0x140001100",
        patch_hex=url_enc.hex(" "),
        session_store=store,
    )

    # 2.1 未知 key，启用 xor_scan=True 盲扫并带 pattern="evil.com"
    res_blind = search_strings_impl(
        session_id=sid,
        xor_scan=True,
        pattern="evil.com",
        session_store=store,
    )
    assert res_blind["ok"] is True
    blind_list = res_blind["data"]["deobfuscated_strings"]
    assert len(blind_list) >= 1
    hit = next((d for d in blind_list if "evil.com" in d["value"]), None)
    assert hit is not None
    assert hit["xor_key"] == 0x33
    assert hit["ioc_category"] == "url"

    # 2.2 启用 xor_scan=True 但未提供 pattern，触发防爆拦截
    res_no_pat = search_strings_impl(
        session_id=sid,
        xor_scan=True,
        pattern=None,
        session_store=store,
    )
    assert res_no_pat["ok"] is False
    assert res_no_pat["error"]["code"] == ErrorCode.INVALID_PARAMETER.value

    # 3. 植入 Base64 编码的 "powershell.exe -enc AAAA"
    # b"powershell.exe -enc AAAA" 的 base64 为 "cG93ZXJzaGVsbC5leGUgLWVuYyBBQUFB"
    b64_str = b"cG93ZXJzaGVsbC5leGUgLWVuYyBBQUFB"
    patch_b64_res = patch_memory_impl(
        session_id=sid,
        address_or_offset="0x140002100",
        patch_hex=b64_str.hex(" "),
        session_store=store,
    )
    assert patch_b64_res["ok"] is True

    # 3.1 启用 detect_base64=True 自动识别与解码
    res_b64 = search_strings_impl(
        session_id=sid,
        detect_base64=True,
        session_store=store,
    )
    assert res_b64["ok"] is True
    b64_deobf = res_b64["data"]["deobfuscated_strings"]
    assert any("powershell.exe" in d["value"] for d in b64_deobf)
    b64_hit = next((d for d in b64_deobf if "powershell.exe" in d["value"]), None)
    assert b64_hit is not None
    assert b64_hit["method"] == "base64"
    assert b64_hit["ioc_category"] == "suspicious_cmd"
