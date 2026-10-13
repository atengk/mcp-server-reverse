"""十六进制通配符与密码学特征扫描引擎

支持类 IDA 十六进制通配符模式匹配与常见密码学魔数常量表 (AES/SHA/MD5/CRC32/DES) 深度扫描。

@author Ateng
@since 2026-10-13
"""

import logging
import re
import struct

from mcp_server_reverse.core.inspection import extract_sections
from mcp_server_reverse.core.models import (
    CryptoSignature,
    HexMatch,
    resolve_offset_to_section_and_va,
)
from mcp_server_reverse.core.session import BinarySession

logger = logging.getLogger(__name__)

# 标准 AES S-Box (256 字节，每行排布 12 字节以控制行宽)
AES_SBOX_BYTES: bytes = bytes(
    [
        0x63,
        0x7C,
        0x77,
        0x7B,
        0xF2,
        0x6B,
        0x6F,
        0xC5,
        0x30,
        0x01,
        0x67,
        0x2B,
        0xFE,
        0xD7,
        0xAB,
        0x76,
        0xCA,
        0x82,
        0xC9,
        0x7D,
        0xFA,
        0x59,
        0x47,
        0xF0,
        0xAD,
        0xD4,
        0xA2,
        0xAF,
        0x9C,
        0xA4,
        0x72,
        0xC0,
        0xB7,
        0xFD,
        0x93,
        0x26,
        0x36,
        0x3F,
        0xF7,
        0xCC,
        0x34,
        0xA5,
        0xE5,
        0xF1,
        0x71,
        0xD8,
        0x31,
        0x15,
        0x04,
        0xC7,
        0x23,
        0xC3,
        0x18,
        0x96,
        0x05,
        0x9A,
        0x07,
        0x12,
        0x80,
        0xE2,
        0xEB,
        0x27,
        0xB2,
        0x75,
        0x09,
        0x83,
        0x2C,
        0x1A,
        0x1B,
        0x6E,
        0x5A,
        0xA0,
        0x52,
        0x3B,
        0xD6,
        0xB3,
        0x29,
        0xE3,
        0x2F,
        0x84,
        0x53,
        0xD1,
        0x00,
        0xED,
        0x20,
        0xFC,
        0xB1,
        0x5B,
        0x6A,
        0xCB,
        0xBE,
        0x39,
        0x4A,
        0x4C,
        0x58,
        0xCF,
        0xD0,
        0xEF,
        0xAA,
        0xFB,
        0x43,
        0x4D,
        0x33,
        0x85,
        0x45,
        0xF9,
        0x02,
        0x7F,
        0x50,
        0x3C,
        0x9F,
        0xA8,
        0x51,
        0xA3,
        0x40,
        0x8F,
        0x92,
        0x9D,
        0x38,
        0xF5,
        0xBC,
        0xB6,
        0xDA,
        0x21,
        0x10,
        0xFF,
        0xF3,
        0xD2,
        0xCD,
        0x0C,
        0x13,
        0xEC,
        0x5F,
        0x97,
        0x44,
        0x17,
        0xC4,
        0xA7,
        0x7E,
        0x3D,
        0x64,
        0x5D,
        0x19,
        0x73,
        0x60,
        0x81,
        0x4F,
        0xDC,
        0x22,
        0x2A,
        0x90,
        0x88,
        0x46,
        0xEE,
        0xB8,
        0x14,
        0xDE,
        0x5E,
        0x0B,
        0xDB,
        0xE0,
        0x32,
        0x3A,
        0x0A,
        0x49,
        0x06,
        0x24,
        0x5E,
        0xC2,
        0xD3,
        0xAC,
        0x62,
        0x91,
        0x95,
        0xE4,
        0x79,
        0xE7,
        0xC8,
        0x37,
        0x6D,
        0x8D,
        0xD5,
        0x4E,
        0xA9,
        0x6C,
        0x56,
        0xF4,
        0xEA,
        0x65,
        0x7A,
        0xAE,
        0x08,
        0xBA,
        0x78,
        0x25,
        0x2E,
        0x1C,
        0xA6,
        0xB4,
        0xC6,
        0xE8,
        0xDD,
        0x74,
        0x1F,
        0x4B,
        0xBD,
        0x8B,
        0x8A,
        0x70,
        0x3E,
        0xB5,
        0x66,
        0x48,
        0x03,
        0xF6,
        0x0E,
        0x61,
        0x35,
        0x57,
        0xB9,
        0x86,
        0xC1,
        0x1D,
        0x9E,
        0xE1,
        0xF8,
        0x98,
        0x11,
        0x69,
        0xD9,
        0x8E,
        0x94,
        0x9B,
        0x1E,
        0x87,
        0xE9,
        0xCE,
        0x55,
        0x28,
        0xDF,
        0x8C,
        0xA1,
        0x89,
        0x0D,
        0xBF,
        0xE6,
        0x42,
        0x68,
        0x41,
        0x99,
        0x2D,
        0x0F,
        0xB0,
        0x54,
        0xBB,
        0x16,
    ]
)

# 标准 AES Rcon 轮常数表 (10 字节)
AES_RCON_BYTES: bytes = bytes([0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36])

# SHA-256 初始 IV 常量 (32 字节)
SHA256_IV_BE: bytes = struct.pack(
    ">8I",
    0x6A09E667,
    0xBB67AE85,
    0x3C6EF372,
    0xA54FF53A,
    0x510E527F,
    0x9B05688C,
    0x1F83D9AB,
    0x5BE0CD19,
)
SHA256_IV_LE: bytes = struct.pack(
    "<8I",
    0x6A09E667,
    0xBB67AE85,
    0x3C6EF372,
    0xA54FF53A,
    0x510E527F,
    0x9B05688C,
    0x1F83D9AB,
    0x5BE0CD19,
)

# SHA-1 初始 IV 常量 (20 字节)
SHA1_IV_BE: bytes = struct.pack(">5I", 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0)
SHA1_IV_LE: bytes = struct.pack("<5I", 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0)

# MD5 初始 IV 常量 (16 字节)
MD5_IV_LE: bytes = struct.pack("<4I", 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476)

# CRC32 经典多项式生成表前 16 字节
CRC32_TABLE_PREFIX: bytes = struct.pack("<4I", 0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA)

# 标准 DES S-Box 1 置换表 (64 字节)
DES_SBOX1_BYTES: bytes = bytes(
    [
        14,
        4,
        13,
        1,
        2,
        15,
        11,
        8,
        3,
        10,
        6,
        12,
        5,
        9,
        0,
        7,
        0,
        15,
        7,
        4,
        14,
        2,
        13,
        1,
        10,
        6,
        12,
        11,
        9,
        5,
        3,
        8,
        4,
        1,
        14,
        8,
        13,
        6,
        2,
        11,
        15,
        12,
        9,
        7,
        3,
        10,
        5,
        0,
        15,
        12,
        8,
        2,
        4,
        9,
        1,
        7,
        5,
        11,
        3,
        14,
        10,
        0,
        6,
        13,
    ]
)

# 已知密码学签名常量注册表
KNOWN_CRYPTO_TABLES: list[tuple[str, str, bytes, float]] = [
    ("AES", "AES S-Box", AES_SBOX_BYTES, 1.0),
    ("AES", "AES Rcon Constants", AES_RCON_BYTES, 0.9),
    ("SHA-256", "SHA-256 Initial State (Big-Endian)", SHA256_IV_BE, 1.0),
    ("SHA-256", "SHA-256 Initial State (Little-Endian)", SHA256_IV_LE, 1.0),
    ("SHA-1", "SHA-1 Initial State (Big-Endian)", SHA1_IV_BE, 1.0),
    ("SHA-1", "SHA-1 Initial State (Little-Endian)", SHA1_IV_LE, 1.0),
    ("MD5", "MD5 Initial State", MD5_IV_LE, 1.0),
    ("CRC32", "CRC32 Table Prefix", CRC32_TABLE_PREFIX, 0.95),
    ("DES", "DES S-Box 1", DES_SBOX1_BYTES, 1.0),
]


def compile_ida_hex_pattern(pattern_str: str) -> re.Pattern[bytes]:
    """将类 IDA 十六进制通配符模式编译为二进制正则表达式

    @param pattern_str IDA 风格十六进制模式字符串
    @return re.Pattern[bytes] 编译后的字节流正则表达式
    @throws ValueError 当输入为空或包含无效十六进制字符时抛出
    """
    raw_str = pattern_str.strip()
    if not raw_str:
        raise ValueError("十六进制搜索模式不能为空")

    tokens = [t.strip() for t in raw_str.split() if t.strip()]
    if not tokens:
        raise ValueError("十六进制搜索模式不能为空")

    regex_parts: list[bytes] = []
    for token in tokens:
        if token in ("?", "??"):
            regex_parts.append(rb".")
        elif len(token) == 2 and re.fullmatch(r"[0-9a-fA-F]{2}", token):
            regex_parts.append(re.escape(bytes.fromhex(token)))
        else:
            raise ValueError(f"无效的十六进制字节标记: '{token}'")

    return re.compile(b"".join(regex_parts), re.DOTALL)


def search_hex_pattern(
    session: BinarySession,
    pattern_str: str,
    section_name: str | None = None,
    offset: int = 0,
    limit: int = 50,
) -> tuple[list[HexMatch], int]:
    """在目标二进制原始文件中执行类 IDA 十六进制通配符搜索

    @param session 当前激活的二进制分析会话
    @param pattern_str 类 IDA 十六进制搜索模式
    @param section_name 可选的指定节区过滤
    @param offset 分页偏移量
    @param limit 单页最大匹配数
    @return tuple[list[HexMatch], int] 匹配项列表与匹配总数
    """
    regex = compile_ida_hex_pattern(pattern_str)
    raw_bytes = session.file_path.read_bytes()
    sections = extract_sections(session)

    matches: list[HexMatch] = []
    for match in regex.finditer(raw_bytes):
        file_offset = match.start()
        matched_slice = raw_bytes[file_offset : match.end()]
        matched_hex = matched_slice.hex(" ").upper()

        sec_name, va_str = resolve_offset_to_section_and_va(
            file_offset, sections, session.image_base
        )
        if section_name and sec_name != section_name:
            continue

        matches.append(
            HexMatch(
                virtual_address=va_str,
                file_offset=file_offset,
                section=sec_name,
                matched_hex=matched_hex,
            )
        )

    total = len(matches)
    safe_offset = max(0, offset)
    safe_limit = max(1, min(limit, 500))
    paged = matches[safe_offset : safe_offset + safe_limit] if safe_offset < total else []
    return paged, total


def scan_crypto_signatures(
    session: BinarySession,
    section_name: str | None = None,
    offset: int = 0,
    limit: int = 50,
) -> tuple[list[CryptoSignature], int]:
    """在目标二进制原始数据中深度扫描已知密码学魔数常量表与初始化向量

    @param session 当前激活的二进制分析会话
    @param section_name 可选的所属节区过滤
    @param offset 分页偏移量
    @param limit 单页最大匹配数
    @return tuple[list[CryptoSignature], int] 匹配的密码学特征签名列表与匹配总数
    """
    raw_bytes = session.file_path.read_bytes()
    sections = extract_sections(session)
    signatures: list[CryptoSignature] = []

    for algo, name, needle, confidence in KNOWN_CRYPTO_TABLES:
        start_idx = 0
        while True:
            found_idx = raw_bytes.find(needle, start_idx)
            if found_idx == -1:
                break

            sec_name, va_str = resolve_offset_to_section_and_va(
                found_idx, sections, session.image_base
            )
            if section_name and sec_name != section_name:
                start_idx = found_idx + 1
                continue

            signatures.append(
                CryptoSignature(
                    algorithm=algo,
                    name=name,
                    virtual_address=va_str,
                    file_offset=found_idx,
                    section=sec_name,
                    confidence=confidence,
                )
            )
            start_idx = found_idx + len(needle)

    total = len(signatures)
    safe_offset = max(0, offset)
    safe_limit = max(1, min(limit, 500))
    paged = signatures[safe_offset : safe_offset + safe_limit] if safe_offset < total else []
    return paged, total
