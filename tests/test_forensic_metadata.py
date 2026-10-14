"""深度取证元数据扩展 (PE Rich Header、SSDEEP 模糊哈希、Mach-O Entitlements) 端到端测试

@author Ateng
@since 2026-10-14
"""

import json
from pathlib import Path

import pytest

from mcp_server_reverse.core.config import ServerConfig
from mcp_server_reverse.core.forensic import compute_fuzzy_hash
from mcp_server_reverse.core.parser import BinaryParser
from mcp_server_reverse.server import create_mcp_server
from tests.fixtures.synthetic import (
    build_synthetic_elf64,
    build_synthetic_macho_with_entitlements,
    build_synthetic_pe_with_rich_header,
)


def test_fuzzy_hash_algorithm() -> None:
    """验证 SSDEEP / CTPH 纯 Python 模糊哈希计算的准确性与边界容错"""
    # 1. 空字节边界测试
    assert compute_fuzzy_hash(b"") is None

    # 2. 正常数据模糊哈希测试
    data1 = b"Reverse engineering forensics SSDEEP fuzzy hashing test string payload " * 16
    hash1 = compute_fuzzy_hash(data1)
    assert hash1 is not None
    assert hash1.count(":") == 2

    block_size_str, part1, part2 = hash1.split(":")
    block_size = int(block_size_str)
    assert block_size >= 3
    assert len(part1) > 0
    assert len(part2) > 0

    # 3. 类似变异数据测试
    data2 = data1 + b"\x90\x90\x90"
    hash2 = compute_fuzzy_hash(data2)
    assert hash2 is not None
    assert hash2.count(":") == 2


def test_pe_rich_header_parsing(tmp_path: Path) -> None:
    """验证 Windows PE Rich Header 条目提取与 ProdID 编译器版本映射"""
    pe_path = tmp_path / "rich_sample.exe"
    build_synthetic_pe_with_rich_header(pe_path)

    parser = BinaryParser()
    result = parser.parse(pe_path)

    forensic = result.forensic_metadata
    assert "rich_header_entries" in forensic
    assert "fuzzy_hash" in forensic
    assert "entitlements" in forensic

    # 验证模糊哈希已生成
    assert forensic["fuzzy_hash"] is not None
    assert forensic["fuzzy_hash"].count(":") == 2

    # 验证 Rich Header 工具链条目
    entries = forensic["rich_header_entries"]
    assert len(entries) >= 2

    prod_names = [e["prod_name"] for e in entries]
    prod_ids = [e["prod_id"] for e in entries]

    assert 257 in prod_ids
    assert "Utc1900_C" in prod_names
    assert 259 in prod_ids
    assert "Linker1400" in prod_names

    # 验证提取出的 Rich Header 散列值
    rich_hash = forensic["debug_info"].get("rich_header_hash")
    assert rich_hash is not None
    assert len(rich_hash) == 32  # 32 字符 MD5 十六进制串


def test_macho_code_signing_and_entitlements(tmp_path: Path) -> None:
    """验证 macOS Mach-O 代码签名结构与 XML Entitlements 权限清单解析"""
    macho_path = tmp_path / "signed_sample.macho"
    expected_entitlements = {
        "com.apple.security.app-sandbox": True,
        "com.apple.security.network.client": True,
        "com.apple.security.files.user-selected.read-write": True,
        "keychain-access-groups": ["TEAMID123.com.example.app"],
    }
    build_synthetic_macho_with_entitlements(macho_path, expected_entitlements)

    parser = BinaryParser()
    result = parser.parse(macho_path)

    forensic = result.forensic_metadata
    assert "code_signing" in forensic
    assert "entitlements" in forensic
    assert "fuzzy_hash" in forensic

    # 验证签名元数据
    cs = forensic["code_signing"]
    assert cs.get("is_signed") is True
    assert cs.get("data_offset") == 0x100
    assert cs.get("data_size") > 0

    # 验证权限字典提取
    ents = forensic["entitlements"]
    assert isinstance(ents, dict)
    assert ents.get("com.apple.security.app-sandbox") is True
    assert ents.get("com.apple.security.network.client") is True
    assert ents.get("com.apple.security.files.user-selected.read-write") is True
    assert ents.get("keychain-access-groups") == ["TEAMID123.com.example.app"]

    # 验证模糊哈希
    assert forensic["fuzzy_hash"] is not None


@pytest.mark.asyncio
async def test_open_binary_tool_forensic_metadata_integration(tmp_path: Path) -> None:
    """验证 open_binary MCP Tool 返回的信封中完整包含全景取证扩展画像"""
    pe_file = tmp_path / "test_forensic.exe"
    build_synthetic_pe_with_rich_header(pe_file)

    elf_file = tmp_path / "test_forensic.elf"
    build_synthetic_elf64(elf_file)

    config = ServerConfig(allowed_dirs=[tmp_path])
    server = create_mcp_server(config)

    # 1. 验证 PE 的 open_binary 输出
    res_pe = await server.call_tool("open_binary", {"file_path": str(pe_file)})
    assert res_pe.is_error is False
    payload_pe = json.loads(res_pe.content[0].text)
    assert payload_pe["ok"] is True
    pe_forensic = payload_pe["data"]["forensic_metadata"]
    assert "rich_header_entries" in pe_forensic
    assert len(pe_forensic["rich_header_entries"]) >= 2
    assert pe_forensic["fuzzy_hash"] is not None
    assert isinstance(pe_forensic["entitlements"], dict)

    # 2. 验证 ELF 的 open_binary 输出 (向后兼容且包含模糊哈希)
    res_elf = await server.call_tool("open_binary", {"file_path": str(elf_file)})
    assert res_elf.is_error is False
    payload_elf = json.loads(res_elf.content[0].text)
    assert payload_elf["ok"] is True
    elf_forensic = payload_elf["data"]["forensic_metadata"]
    assert elf_forensic["rich_header_entries"] == []
    assert elf_forensic["entitlements"] == {}
    assert elf_forensic["fuzzy_hash"] is not None
