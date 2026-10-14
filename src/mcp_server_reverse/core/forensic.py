"""深度取证分析引擎：PE Rich Header、SSDEEP 模糊哈希与 Mach-O 签名清单提取

@author Ateng
@since 2026-10-14
"""

import logging
import plistlib
import re
import struct
from typing import Any

from mcp_server_reverse.core.models import RichHeaderEntry

logger = logging.getLogger(__name__)

# Base64 编码字符集 (用于 SSDEEP / CTPH 模糊哈希表示)
B64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
SPAMSUM_LENGTH = 64
MIN_BLOCKSIZE = 3
ROLLING_WINDOW = 7
FNV_PRIME = 0x01000193
FNV_INIT = 0x28021967

# Apple Mach-O Code Directory 与 SuperBlob 魔法常数
CSMAGIC_EMBEDDED_SIGNATURE = 0xFADE0CC0
CSMAGIC_EMBEDDED_ENTITLEMENTS = 0xFADE7171
CSSLOT_ENTITLEMENTS = 5

# 已知 Microsoft Visual Studio 工具链 ProdID 映射表
KNOWN_PROD_IDS: dict[int, str] = {
    0: "Unknown",
    1: "Import0",
    2: "Linker510",
    3: "Cvtomf510",
    4: "Linker600",
    5: "Cvtomf600",
    6: "Cvtres500",
    7: "Utc11_LTCG_C",
    8: "Utc11_LTCG_CPP",
    9: "Utc11_LTCG_MSIL",
    10: "Utc12_LTCG_C",
    11: "Utc12_LTCG_CPP",
    12: "Utc12_LTCG_MSIL",
    13: "Utc12_C",
    14: "Utc12_CPP",
    15: "Utc12_C_CV",
    16: "Utc12_CPP_CV",
    19: "Cvtres501",
    25: "Linker601",
    26: "Cvtomf601",
    27: "Utc12_1_C",
    28: "Utc12_1_CPP",
    93: "Linker700",
    94: "Export600",
    95: "Export700",
    96: "Cvtres700",
    97: "Utc1300_C",
    98: "Utc1300_CPP",
    122: "Linker710",
    123: "Export710",
    124: "Cvtres710",
    125: "Utc1310_C",
    126: "Utc1310_CPP",
    144: "Linker800",
    145: "Export800",
    146: "Cvtres800",
    147: "Utc1400_C",
    148: "Utc1400_CPP",
    173: "Linker900",
    174: "Export900",
    175: "Cvtres900",
    176: "Utc1500_C",
    177: "Utc1500_CPP",
    198: "Linker1000",
    199: "Export1000",
    200: "Cvtres1000",
    201: "Utc1600_C",
    202: "Utc1600_CPP",
    218: "Linker1100",
    219: "Export1100",
    220: "Cvtres1100",
    221: "Utc1700_C",
    222: "Utc1700_CPP",
    237: "Linker1200",
    238: "Export1200",
    239: "Cvtres1200",
    240: "Utc1800_C",
    241: "Utc1800_CPP",
    257: "Utc1900_C",
    258: "Utc1900_CPP",
    259: "Linker1400",
    260: "Cvtres1400",
    261: "Utc1900_MSIL",
    262: "Export1400",
    263: "Linker1410",
    264: "Utc1910_C",
    265: "Utc1910_CPP",
    266: "Cvtres1410",
    267: "Export1410",
    268: "Linker1420",
    269: "Utc1920_C",
    270: "Utc1920_CPP",
    271: "Cvtres1420",
    272: "Export1420",
    273: "Linker1430",
    274: "Utc1930_C",
    275: "Utc1930_CPP",
    276: "Cvtres1430",
    277: "Export1430",
}


def extract_rich_header_entries(pe_obj: Any) -> list[RichHeaderEntry]:
    """解析并提取 PE Rich Header 中的工具链组件信息

    Args:
        pe_obj: pefile.PE 解析对象

    Returns:
        list[RichHeaderEntry]: 工具链组件列表；无 Rich Header 或异常时返回空列表
    """
    if not pe_obj:
        return []

    entries: list[RichHeaderEntry] = []
    try:
        rich_data = pe_obj.parse_rich_header()
        if not rich_data or "values" not in rich_data:
            return []

        values = rich_data.get("values", [])
        for i in range(0, len(values), 2):
            comp_id = values[i]
            use_count = values[i + 1] if i + 1 < len(values) else 0

            prod_id = (comp_id >> 16) & 0xFFFF
            build_number = comp_id & 0xFFFF
            prod_name = KNOWN_PROD_IDS.get(prod_id, f"ProdID_{prod_id}")

            entries.append(
                RichHeaderEntry(
                    comp_id=comp_id,
                    prod_id=prod_id,
                    prod_name=prod_name,
                    build_number=build_number,
                    use_count=use_count,
                )
            )
    except Exception as exc:
        logger.debug("解析 Rich Header 条目失败: %s", exc)
        return []

    return entries


def compute_fuzzy_hash(data: bytes) -> str | None:
    """计算字节流的上下文触发分段模糊哈希 (SSDEEP / CTPH)

    采用 7 字节 Adler-like 滚动哈希与 32 位 FNV-1 分块哈希，生成标准
    `<blocksize>:<h1>:<h2>` 格式的模糊哈希签名，用于家族相似度辨识。

    Args:
        data: 待计算模糊哈希的原始字节流

    Returns:
        str | None: 计算出的模糊哈希字符串；数据为空或异常时返回 None
    """
    if not data or len(data) == 0:
        return None

    try:
        # 1. 决议起始分块大小
        block_size = MIN_BLOCKSIZE
        while block_size * SPAMSUM_LENGTH < len(data):
            block_size *= 2

        # 2. 迭代计算分段模糊哈希
        while True:
            rolling_sum_a = 0
            rolling_sum_b = 0
            rolling_sum_c = 0
            window = [0] * ROLLING_WINDOW
            window_idx = 0

            fnv_hash_1 = FNV_INIT
            fnv_hash_2 = FNV_INIT
            hash1: list[str] = []
            hash2: list[str] = []

            double_block_size = block_size * 2

            for b in data:
                # 滚动哈希更新
                rolling_sum_b = (rolling_sum_b - rolling_sum_a + ROLLING_WINDOW * b) & 0xFFFFFFFF
                rolling_sum_a = (rolling_sum_a + b - window[window_idx]) & 0xFFFFFFFF
                window[window_idx] = b
                window_idx = (window_idx + 1) % ROLLING_WINDOW
                rolling_sum_c = ((rolling_sum_c << 5) ^ b) & 0xFFFFFFFF
                roll_sum = (rolling_sum_a + rolling_sum_b + rolling_sum_c) & 0xFFFFFFFF

                # FNV-1 分块哈希累加
                fnv_hash_1 = ((fnv_hash_1 * FNV_PRIME) ^ b) & 0xFFFFFFFF
                fnv_hash_2 = ((fnv_hash_2 * FNV_PRIME) ^ b) & 0xFFFFFFFF

                # 判定 block_size 触发点
                if roll_sum % block_size == (block_size - 1):
                    if len(hash1) < SPAMSUM_LENGTH - 1:
                        hash1.append(B64_ALPHABET[fnv_hash_1 % 64])
                    fnv_hash_1 = FNV_INIT

                # 判定 block_size * 2 触发点
                if roll_sum % double_block_size == (double_block_size - 1):
                    if len(hash2) < (SPAMSUM_LENGTH // 2) - 1:
                        hash2.append(B64_ALPHABET[fnv_hash_2 % 64])
                    fnv_hash_2 = FNV_INIT

            # 若主哈希过短且 block_size 仍可细分，则缩小步长重新计算
            if len(hash1) < (SPAMSUM_LENGTH // 2) and block_size > MIN_BLOCKSIZE:
                block_size //= 2
                continue

            if fnv_hash_1 != FNV_INIT or not hash1:
                hash1.append(B64_ALPHABET[fnv_hash_1 % 64])
            if fnv_hash_2 != FNV_INIT or not hash2:
                hash2.append(B64_ALPHABET[fnv_hash_2 % 64])

            return f"{block_size}:{''.join(hash1)}:{''.join(hash2)}"

    except Exception as exc:
        logger.debug("计算 SSDEEP 模糊哈希失败: %s", exc)
        return None


def extract_macho_code_signing_and_entitlements(
    macho_bin: Any,
    raw_bytes: bytes,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """从 Mach-O 二进制中提取代码签名信息与 Entitlements XML 权限清单

    Args:
        macho_bin: LIEF Mach-O 解析后的单个二进制或 Fat 切片对象
        raw_bytes: 文件原始字节流

    Returns:
        tuple[dict[str, Any], dict[str, Any]]: (code_signing 元数据, entitlements 字典)
    """
    code_signing: dict[str, Any] = {"is_signed": False}
    entitlements: dict[str, Any] = {}

    if not macho_bin:
        return code_signing, entitlements

    try:
        has_sig = getattr(macho_bin, "has_code_signature", False)
        if not has_sig:
            return code_signing, entitlements

        cs = getattr(macho_bin, "code_signature", None)
        if not cs:
            return {"is_signed": True}, entitlements

        data_offset = getattr(cs, "data_offset", 0)
        data_size = getattr(cs, "data_size", 0)

        code_signing = {
            "is_signed": True,
            "data_offset": data_offset,
            "data_size": data_size,
        }

        # 检查边界与 Fat 切片偏移适应
        slice_offset = getattr(macho_bin, "fat_offset", 0)
        actual_offset = slice_offset + data_offset
        if actual_offset + data_size <= len(raw_bytes):
            sig_data = raw_bytes[actual_offset : actual_offset + data_size]
        elif data_offset + data_size <= len(raw_bytes):
            sig_data = raw_bytes[data_offset : data_offset + data_size]
        else:
            return code_signing, entitlements

        if len(sig_data) < 12:
            return code_signing, entitlements

        # 解析 SuperBlob 头部: magic (4), length (4), count (4)
        magic, total_len, count = struct.unpack_from(">III", sig_data, 0)
        if magic != CSMAGIC_EMBEDDED_SIGNATURE:
            # 尝试通过正则兜底探测嵌入的 XML Entitlements
            entitlements = _extract_entitlements_by_regex(sig_data)
            return code_signing, entitlements

        # 遍历 SuperBlob 子 Blob 索引
        curr_offset = 12
        for _ in range(count):
            if curr_offset + 8 > len(sig_data):
                break
            blob_type, blob_offset = struct.unpack_from(">II", sig_data, curr_offset)
            curr_offset += 8

            if blob_type == CSSLOT_ENTITLEMENTS:
                if blob_offset + 8 <= len(sig_data):
                    ent_magic, ent_len = struct.unpack_from(">II", sig_data, blob_offset)
                    xml_start = blob_offset + 8
                    xml_end = blob_offset + ent_len
                    if xml_end <= len(sig_data):
                        xml_bytes = sig_data[xml_start:xml_end]
                        try:
                            parsed_plist = plistlib.loads(xml_bytes)
                            if isinstance(parsed_plist, dict):
                                entitlements = parsed_plist
                        except Exception as p_exc:
                            logger.debug("plistlib 解析 entitlements 失败: %s", p_exc)
                            entitlements = _extract_entitlements_by_regex(xml_bytes)
                break

        if not entitlements:
            entitlements = _extract_entitlements_by_regex(sig_data)

    except Exception as exc:
        logger.debug("提取 Mach-O 代码签名与 Entitlements 异常: %s", exc)

    return code_signing, entitlements


def _extract_entitlements_by_regex(data: bytes) -> dict[str, Any]:
    """通过正则匹配兜底提取 XML 格式的 Entitlements 字典"""
    try:
        match = re.search(rb"<\?xml[\s\S]*?<plist[\s\S]*?<\/plist>", data)
        if match:
            xml_chunk = match.group(0)
            parsed = plistlib.loads(xml_chunk)
            if isinstance(parsed, dict):
                return parsed
    except Exception as exc:
        logger.debug("正则兜底提取 Entitlements 失败: %s", exc)
    return {}
