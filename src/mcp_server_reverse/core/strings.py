"""跨格式二进制字符串提取与 IOC 威胁情报分类引擎

支持 ASCII 与 UTF-16LE 提取、节区与虚拟地址映射、7 类威胁情报标签识别以及 floss 异步调用与软降级。

@author Ateng
@since 2026-10-13
"""

import base64
import ipaddress
import logging
import re
import subprocess
from pathlib import Path

from mcp_server_reverse.core.inspection import extract_sections
from mcp_server_reverse.core.locator import ToolLocator
from mcp_server_reverse.core.models import (
    DeobfuscatedString,
    SectionProfile,
    StringArtifact,
    resolve_offset_to_section_and_va,
)
from mcp_server_reverse.core.session import BinarySession

logger = logging.getLogger(__name__)

# IOC 识别匹配规则库
IPV4_REGEX: re.Pattern[str] = re.compile(
    r"\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\."
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\."
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\."
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
)
EMAIL_REGEX: re.Pattern[str] = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")
FILEPATH_REGEX: re.Pattern[str] = re.compile(
    r"(?:^[A-Za-z]:\\[^/:*?\"<>|\r\n]+)|"
    r"(?:^/(?:usr|etc|bin|sbin|var|tmp|home|opt)/[^\s\x00]+)|"
    r"(?:\\System32\\[^/:*?\"<>|\r\n]+)"
)
SUSPICIOUS_CMD_KEYWORDS: tuple[str, ...] = (
    "powershell",
    "cmd.exe",
    "/bin/sh",
    "/bin/bash",
    "whoami",
    "net user",
    "curl ",
    "wget ",
    "-executionpolicy",
)
CRYPTO_OR_KEY_KEYWORDS: tuple[str, ...] = (
    "begin rsa private key",
    "begin private key",
    "begin certificate",
    "secret_key",
    "api_key",
    "private_key",
    "password",
    "access_token",
)


def classify_ioc(text: str) -> str | None:
    """启发式识别字符串并标记 7 类威胁情报标签之一

    @param text 待检测的文本字符串
    @return str | None 命中的类别标识，未命中返回 None
    """
    lower = text.lower()

    # 1. URL 协议检测
    if lower.startswith(("http://", "https://", "ftp://")) or "://api." in lower:
        return "url"

    # 2. Email 检测
    if "@" in text and EMAIL_REGEX.search(text):
        return "email"

    # 3. 注册表键检测
    if lower.startswith("hkey_") or lower.startswith("software\\") or "\\currentversion\\" in lower:
        return "registry"

    # 4. 文件路径检测
    if FILEPATH_REGEX.search(text):
        return "filepath"

    # 5. IPv4 地址检测
    match_ip = IPV4_REGEX.search(text)
    if match_ip:
        ip_str = match_ip.group(0)
        try:
            ipaddress.IPv4Address(ip_str)
            return "ipv4"
        except ValueError:
            pass

    # 6. 可疑命令或命令行工具检测
    if any(cmd in lower for cmd in SUSPICIOUS_CMD_KEYWORDS):
        return "suspicious_cmd"

    # 7. 密码学私钥与令牌凭据检测
    if any(k in lower for k in CRYPTO_OR_KEY_KEYWORDS):
        return "crypto_or_key"

    return None


def extract_ascii_strings(data: bytes, min_length: int = 4) -> list[tuple[int, str]]:
    """从二进制数据流中提取指定最小长度的 ASCII 打印字符串

    @param data 原始字节数据流
    @param min_length 最小连续字符长度
    @return list[tuple[int, str]] (物理偏移量, 提取的字符串) 列表
    """
    safe_min = max(1, min_length)
    pattern = rb"[\x20-\x7E]{" + str(safe_min).encode() + rb",}"
    results: list[tuple[int, str]] = []
    for match in re.finditer(pattern, data):
        results.append((match.start(), match.group(0).decode("ascii", errors="ignore")))
    return results


def extract_utf16le_strings(data: bytes, min_length: int = 4) -> list[tuple[int, str]]:
    """从二进制数据流中提取指定最小长度的 UTF-16LE 宽字符字符串

    @param data 原始字节数据流
    @param min_length 最小连续字符长度
    @return list[tuple[int, str]] (物理偏移量, 提取的字符串) 列表
    """
    safe_min = max(1, min_length)
    pattern = rb"(?:[\x20-\x7E]\x00){" + str(safe_min).encode() + rb",}"
    results: list[tuple[int, str]] = []
    for match in re.finditer(pattern, data):
        try:
            val = match.group(0).decode("utf-16le", errors="ignore")
            results.append((match.start(), val))
        except Exception:
            continue
    return results


def _build_string_artifacts(
    raw_tuples: list[tuple[int, str]],
    encoding: str,
    sections: list[SectionProfile],
    image_base: int,
) -> list[StringArtifact]:
    """统一批量映射构造 StringArtifact 工件列表，消除重复循环逻辑

    @param raw_tuples 原始 (文件偏移, 字符串) 列表
    @param encoding 编码格式标识
    @param sections 节区分布画像列表
    @param image_base 镜像基址数值
    @return list[StringArtifact] 构造后的字符串工件列表
    """
    artifacts: list[StringArtifact] = []
    for off, s_val in raw_tuples:
        sec_name, va_str = resolve_offset_to_section_and_va(off, sections, image_base)
        artifacts.append(
            StringArtifact(
                value=s_val,
                encoding=encoding,
                file_offset=off,
                virtual_address=va_str,
                section=sec_name,
                ioc_category=classify_ioc(s_val),
                length=len(s_val),
            )
        )
    return artifacts


def run_floss_extraction(floss_path: str, target_file: Path) -> list[str]:
    """调用外部 floss 工具抓取提取的栈字符串

    @param floss_path floss 可执行文件的物理绝对路径
    @param target_file 目标待分析二进制物理路径
    @return list[str] 解码出的栈字符串列表
    """
    try:
        cmd = [floss_path, "--only", "stack", str(target_file)]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        lines = [line.strip() for line in res.stdout.splitlines() if line.strip()]
        return lines
    except Exception as exc:
        logger.debug("执行外部 floss 提取栈字符串失败: %s", exc)
        return []


def extract_strings(
    session: BinarySession,
    min_length: int = 4,
    encoding: str = "all",
    pattern: str | None = None,
    ioc_category: str | None = None,
    section_name: str | None = None,
    offset: int = 0,
    limit: int = 50,
    use_floss: bool = False,
    locator: ToolLocator | None = None,
) -> tuple[list[StringArtifact], int, str | None]:
    """提取二进制全量字符串并支持 7 类 IOC 过滤、正则匹配、编码过滤与 floss 软降级

    @param session 当前激活的二进制分析会话
    @param min_length 最小字符串长度
    @param encoding 编码格式 ("ascii", "utf16le", "all")
    @param pattern 字符串正则过滤表达式
    @param ioc_category 7 类威胁情报标签之一
    @param section_name 所属节区过滤
    @param offset 分页偏移量
    @param limit 单页最大数量
    @param use_floss 是否尝试使用 floss 解码栈字符串
    @param locator 工具定位器实例
    @return tuple[list[StringArtifact], int, str | None] 当前页字符串列表、匹配总数与 floss 状态说明
    """
    regex = re.compile(pattern, re.IGNORECASE) if pattern else None

    # 1. 动态缓存决议：保存 (cached_min_len, artifacts)
    # 当本次请求 min_length < cached_min_len 时重新全量扫描，避免遗漏更短字符串
    all_artifacts: list[StringArtifact]
    cached_payload = session.strings_cache
    if (
        isinstance(cached_payload, tuple)
        and len(cached_payload) == 2
        and cached_payload[0] <= min_length
    ):
        all_artifacts = cached_payload[1]
    else:
        raw_bytes = session.read_effective_bytes(0, None)
        sections = extract_sections(session)
        target_min = min(min_length, 4)

        ascii_raw = extract_ascii_strings(raw_bytes, min_length=target_min)
        utf16_raw = extract_utf16le_strings(raw_bytes, min_length=target_min)

        artifacts = _build_string_artifacts(ascii_raw, "ascii", sections, session.image_base)
        artifacts.extend(
            _build_string_artifacts(utf16_raw, "utf16le", sections, session.image_base)
        )

        artifacts.sort(key=lambda x: x.file_offset)
        session.strings_cache = (target_min, artifacts)
        all_artifacts = list(artifacts)

    # 2. 处理外部 floss 与栈字符串解码合并
    floss_status: str | None = None
    if use_floss:
        floss_locator = locator or ToolLocator()
        floss_cap = floss_locator.locate_tool("floss")
        if floss_cap.available and floss_cap.path:
            stack_strings = run_floss_extraction(floss_cap.path, session.file_path)
            for s_text in stack_strings:
                if len(s_text) >= min_length:
                    all_artifacts.append(
                        StringArtifact(
                            value=s_text,
                            encoding="floss_stack",
                            file_offset=0,
                            virtual_address="0x0",
                            section=None,
                            ioc_category=classify_ioc(s_text),
                            length=len(s_text),
                        )
                    )
            floss_status = f"floss 已就绪，已合并解码出 {len(stack_strings)} 条栈字符串"
        else:
            floss_status = "未检测到外部工具 floss，已自动软降级为内置静态提取"

    # 3. 执行过滤筛选
    matched_artifacts: list[StringArtifact] = []
    for art in all_artifacts:
        if art.length < min_length:
            continue

        if encoding != "all" and art.encoding != encoding:
            continue

        if ioc_category and art.ioc_category != ioc_category:
            continue

        if section_name and art.section != section_name:
            continue

        if regex and not regex.search(art.value):
            continue

        matched_artifacts.append(art)

    total = len(matched_artifacts)
    safe_offset = max(0, offset)
    safe_limit = max(1, min(limit, 500))
    paged = matched_artifacts[safe_offset : safe_offset + safe_limit] if safe_offset < total else []

    return paged, total, floss_status


BASE64_PATTERN: re.Pattern[bytes] = re.compile(rb"[A-Za-z0-9+/]{8,}={0,2}")


def _expand_printable_xor_span(
    data: bytes, key: int, match_start: int, match_end: int
) -> tuple[int, str]:
    """以匹配区间为锚点，向左和向右扩展最大连续可打印 ASCII 范围"""
    left = match_start
    while left > 0 and (0x20 <= (data[left - 1] ^ key) <= 0x7E):
        left -= 1

    right = match_end
    data_len = len(data)
    while right < data_len and (0x20 <= (data[right] ^ key) <= 0x7E):
        right += 1

    text = bytes(b ^ key for b in data[left:right]).decode("ascii", errors="ignore")
    return left, text


def extract_xor_strings_with_pattern(
    data: bytes,
    key: int,
    pattern: str,
    min_length: int = 4,
) -> list[tuple[int, str, int]]:
    """针对指定密钥搜索命中了 pattern 关键字的 XOR 字符串片段并扩展还原"""
    pat_bytes = pattern.encode("utf-8", errors="ignore")
    if not pat_bytes:
        return []

    results: list[tuple[int, str, int]] = []
    xor_pat = bytes(b ^ key for b in pat_bytes)

    start_pos = 0
    data_len = len(data)
    while start_pos < data_len:
        pos = data.find(xor_pat, start_pos)
        if pos == -1:
            break
        off, expanded = _expand_printable_xor_span(data, key, pos, pos + len(xor_pat))
        if len(expanded) >= min_length:
            results.append((off, expanded, key))
        start_pos = pos + len(xor_pat)
        if len(results) >= 50:
            break

    return results


def extract_xor_strings_known_key(
    data: bytes,
    key: int,
    min_length: int = 4,
    pattern: str | None = None,
) -> list[tuple[int, str, int]]:
    """对已知 key 进行异或解密并提取 ASCII 字符串"""
    if pattern:
        return extract_xor_strings_with_pattern(data, key, pattern, min_length)

    xor_bytes = bytes(b ^ key for b in data)
    raw_ascii = extract_ascii_strings(xor_bytes, min_length=min_length)
    return [(off, s_val, key) for off, s_val in raw_ascii]


def extract_base64_strings(
    data: bytes,
    min_length: int = 4,
    pattern: str | None = None,
) -> list[tuple[int, str]]:
    """从二进制数据流中识别并解码合法的 Base64 文本块"""
    results: list[tuple[int, str]] = []
    reg = re.compile(pattern, re.IGNORECASE) if pattern else None

    for m in BASE64_PATTERN.finditer(data):
        b64_raw = m.group(0)
        try:
            decoded = base64.b64decode(b64_raw, validate=True)
        except Exception:
            continue

        if len(decoded) < min_length:
            continue

        printable_count = sum(1 for b in decoded if 0x20 <= b <= 0x7E or b in (0x09, 0x0A, 0x0D))
        if printable_count / len(decoded) < 0.85:
            continue

        try:
            text = decoded.decode("utf-8", errors="ignore").strip()
        except Exception:
            continue

        if len(text) < min_length:
            continue

        if reg and not reg.search(text):
            continue

        results.append((m.start(), text))
        if len(results) >= 100:
            break

    return results


def extract_deobfuscated_strings(
    session: BinarySession,
    xor_scan: bool = False,
    xor_key: int | None = None,
    detect_base64: bool = False,
    pattern: str | None = None,
    min_length: int = 4,
) -> list[DeobfuscatedString]:
    """执行单字节 XOR 异或与 Base64 反混淆提取并构造 DeobfuscatedString 工件"""
    raw_bytes = session.read_effective_bytes(0, None)
    sections = extract_sections(session)
    results: list[DeobfuscatedString] = []

    # 1. 处理单字节 XOR
    if xor_key is not None:
        hits = extract_xor_strings_known_key(raw_bytes, xor_key, min_length, pattern)
        for off, val, k in hits:
            sec_name, va_str = resolve_offset_to_section_and_va(off, sections, session.image_base)
            results.append(
                DeobfuscatedString(
                    value=val,
                    method="xor",
                    xor_key=k,
                    file_offset=off,
                    virtual_address=va_str,
                    section=sec_name,
                    ioc_category=classify_ioc(val),
                    length=len(val),
                )
            )
    elif xor_scan and pattern:
        for k in range(1, 256):
            hits = extract_xor_strings_with_pattern(raw_bytes, k, pattern, min_length)
            for off, val, used_k in hits:
                sec_name, va_str = resolve_offset_to_section_and_va(
                    off, sections, session.image_base
                )
                results.append(
                    DeobfuscatedString(
                        value=val,
                        method="xor",
                        xor_key=used_k,
                        file_offset=off,
                        virtual_address=va_str,
                        section=sec_name,
                        ioc_category=classify_ioc(val),
                        length=len(val),
                    )
                )

    # 2. 处理 Base64 解码
    if detect_base64:
        b64_hits = extract_base64_strings(raw_bytes, min_length, pattern)
        for off, val in b64_hits:
            sec_name, va_str = resolve_offset_to_section_and_va(off, sections, session.image_base)
            results.append(
                DeobfuscatedString(
                    value=val,
                    method="base64",
                    xor_key=None,
                    file_offset=off,
                    virtual_address=va_str,
                    section=sec_name,
                    ioc_category=classify_ioc(val),
                    length=len(val),
                )
            )

    results.sort(key=lambda x: x.file_offset)
    return results
