"""结构与符号检视核心引擎

提供节区画像、导入表分类与正则检索、导出表枚举及基于 PE .pdata 的无符号函数恢复能力。

@author Ateng
@since 2026-10-13
"""

import logging
import re
import struct
from typing import Any

from mcp_server_reverse.core.models import LocalEntropyBlock, SectionProfile, SymbolEntry
from mcp_server_reverse.core.parser import SENSITIVE_API_KEYWORDS, calculate_entropy
from mcp_server_reverse.core.session import BinarySession

logger = logging.getLogger(__name__)

# PE 节区权限标志常量
PE_SECTION_MEM_EXECUTE: int = 0x20000000
PE_SECTION_MEM_READ: int = 0x40000000
PE_SECTION_MEM_WRITE: int = 0x80000000

# ELF 节区标志常量
ELF_SHF_WRITE: int = 0x1
ELF_SHF_EXECINSTR: int = 0x4

# 香农熵高熵判定阈值
HIGH_ENTROPY_THRESHOLD: float = 7.2

# PE 数据目录与异常项结构尺寸
IMAGE_DIRECTORY_ENTRY_EXCEPTION_INDEX: int = 3
RUNTIME_FUNCTION_ENTRY_SIZE: int = 12


def scan_local_entropy_blocks(
    data: bytes,
    raw_offset: int,
    base_va: int | None,
    window_size: int = 2048,
    step: int = 1024,
) -> list[LocalEntropyBlock]:
    """使用滑动窗口对数据块进行细粒度香农熵扫描并合并重叠连续高熵区间

    @param data 待分析的数据字节串 (包含有效 COW 补丁)
    @param raw_offset 数据在物理文件中的绝对起始偏移量
    @param base_va 数据对应的基准虚拟内存地址 (若不可映射则为 None)
    @param window_size 滑动窗口字节尺寸 (缺省 2048)
    @param step 滑动步长 (缺省 1024)
    @return list[LocalEntropyBlock] 探测合并后的局部高熵块列表，无匹配时返回空列表
    """
    if not data:
        return []

    # 1. 防御性校验与参数自适应规整
    actual_window = 2048 if window_size <= 0 else window_size
    actual_step = 1024 if step <= 0 else step

    total_len = len(data)
    if total_len < actual_window:
        return []

    # 超大节区防 DoS 步长自适应提升与采样熔断
    max_iterations = 4096
    if total_len > 16 * 1024 * 1024:
        actual_step = max(actual_step, 4096)
    if total_len // actual_step > max_iterations:
        actual_step = max(actual_step, total_len // max_iterations)

    # 2. 收集所有命中高熵阈值的滑动窗口
    offsets: list[int] = list(range(0, total_len - actual_window + 1, actual_step))
    last_offset = total_len - actual_window
    if last_offset > 0 and (not offsets or offsets[-1] != last_offset):
        offsets.append(last_offset)

    high_windows: list[tuple[int, int, float]] = []
    for start_rel in offsets:
        chunk = data[start_rel : start_rel + actual_window]
        ent = calculate_entropy(chunk)
        if ent >= HIGH_ENTROPY_THRESHOLD:
            high_windows.append((start_rel, start_rel + actual_window, ent))

    if not high_windows:
        return []

    # 3. 连续与重叠高熵区间合并
    merged: list[tuple[int, int, float]] = []
    cur_start, cur_end, cur_max_ent = high_windows[0]

    for w_start, w_end, w_ent in high_windows[1:]:
        if w_start <= cur_end:
            cur_end = max(cur_end, w_end)
            cur_max_ent = max(cur_max_ent, w_ent)
        else:
            merged.append((cur_start, cur_end, cur_max_ent))
            cur_start, cur_end, cur_max_ent = w_start, w_end, w_ent

    merged.append((cur_start, cur_end, cur_max_ent))

    # 4. 构建结构化局部高熵块列表
    blocks: list[LocalEntropyBlock] = []
    for start, end, max_ent in merged:
        block_offset = raw_offset + start
        block_size = end - start
        va_str = f"0x{base_va + start:X}" if base_va is not None else None
        blocks.append(
            LocalEntropyBlock(
                offset=block_offset,
                virtual_address=va_str,
                size=block_size,
                max_entropy=round(max_ent, 4),
            )
        )

    return blocks


def _detect_section_local_entropy(
    session: BinarySession,
    raw_offset: int,
    raw_size: int,
    base_va: int | None,
    detect_local_entropy: bool,
    window_size: int,
    step: int,
) -> list[LocalEntropyBlock]:
    """读取节区物理有效字节并执行局部高熵块探测

    @param session 当前激活的二进制分析会话
    @param raw_offset 节区文件物理起始偏移量
    @param raw_size 节区物理字节尺寸
    @param base_va 节区基准虚拟内存地址
    @param detect_local_entropy 是否启用局部高熵块探测
    @param window_size 滑动窗口尺寸
    @param step 滑动步长
    @return list[LocalEntropyBlock] 探测结果列表，未启用或异常时返回空列表
    """
    if not detect_local_entropy or raw_size <= 0 or raw_offset < 0:
        return []

    try:
        sec_data = session.read_effective_bytes(raw_offset, raw_size)
        return scan_local_entropy_blocks(
            data=sec_data,
            raw_offset=raw_offset,
            base_va=base_va,
            window_size=window_size,
            step=step,
        )
    except Exception as exc:
        logger.debug("节区局部高熵块探测异常: %s", exc)
        return []


def _format_rwx(readable: bool, writable: bool, executable: bool) -> str:
    """格式化三段式 rwx 访问权限字符串

    @param readable 是否具备读权限
    @param writable 是否具备写权限
    @param executable 是否具备执行权限
    @return str 规范化的权限字符串，如 'r-x', 'rw-'
    """
    r_chr = "r" if readable else "-"
    w_chr = "w" if writable else "-"
    x_chr = "x" if executable else "-"
    return f"{r_chr}{w_chr}{x_chr}"


def _parse_pe_permissions(characteristics: int) -> str:
    """根据 PE 节区 Characteristics 标志解析 rwx 权限字符串

    @param characteristics 32 位节区属性标志掩码
    @return str 规范化的权限字符串，如 'r-x', 'rw-'
    """
    readable = bool(characteristics & PE_SECTION_MEM_READ)
    writable = bool(characteristics & PE_SECTION_MEM_WRITE)
    executable = bool(characteristics & PE_SECTION_MEM_EXECUTE)
    return _format_rwx(readable, writable, executable)


def extract_sections(
    session: BinarySession,
    detect_local_entropy: bool = True,
    window_size: int = 2048,
    step: int = 1024,
) -> list[SectionProfile]:
    """提取二进制全量节区/段分布画像与香农熵

    @param session 当前激活的二进制分析会话
    @param detect_local_entropy 是否启用基于滑动窗口的细粒度局部高熵块探测 (缺省 True)
    @param window_size 滑动窗口字节尺寸 (缺省 2048)
    @param step 滑动步长 (缺省 1024)
    @return list[SectionProfile] 节区画像列表，无节区时返回空列表
    """
    profiles: list[SectionProfile] = []

    # 1. 优先使用 LIEF 提取结构
    if session.lief_binary and hasattr(session.lief_binary, "sections"):
        for sec in session.lief_binary.sections:
            sec_name = sec.name.rstrip("\x00") if sec.name else ""
            v_size = int(getattr(sec, "virtual_size", 0))
            raw_offset = int(getattr(sec, "offset", 0))
            raw_size = int(getattr(sec, "size", 0))

            # 虚拟地址解析
            v_addr = int(getattr(sec, "virtual_address", 0))
            if session.format == "PE" and v_addr < session.image_base:
                abs_va = session.image_base + v_addr
            else:
                abs_va = v_addr
            va_str = f"0x{abs_va:X}"

            # 权限解析
            if session.format == "PE":
                chars = int(getattr(sec, "characteristics", 0))
                perms = _parse_pe_permissions(chars)
            elif session.format == "ELF":
                flags = int(getattr(sec, "flags", 0))
                readable = True  # ELF 段映射内存通常具备可读性
                writable = bool(flags & ELF_SHF_WRITE)
                executable = bool(flags & ELF_SHF_EXECINSTR)
                perms = _format_rwx(readable, writable, executable)
            else:
                perms = "r-x"

            # 香农熵计算
            ent = getattr(sec, "entropy", 0.0)
            if ent == 0.0 and hasattr(sec, "content"):
                content = bytes(sec.content)
                if content:
                    ent = calculate_entropy(content)
            entropy = round(float(ent), 4)
            is_high_entropy = entropy >= HIGH_ENTROPY_THRESHOLD

            local_blocks = _detect_section_local_entropy(
                session=session,
                raw_offset=raw_offset,
                raw_size=raw_size,
                base_va=abs_va if abs_va != 0 else None,
                detect_local_entropy=detect_local_entropy,
                window_size=window_size,
                step=step,
            )

            profiles.append(
                SectionProfile(
                    name=sec_name,
                    virtual_address=va_str,
                    virtual_size=v_size,
                    raw_offset=raw_offset,
                    raw_size=raw_size,
                    permissions=perms,
                    entropy=entropy,
                    is_high_entropy=is_high_entropy,
                    local_high_entropy_blocks=local_blocks,
                )
            )
        return profiles

    # 2. 针对 PE 格式降级使用 pefile 提取
    if session.pefile_binary and hasattr(session.pefile_binary, "sections"):
        for sec in session.pefile_binary.sections:
            raw_name = getattr(sec, "Name", b"")
            if isinstance(raw_name, bytes):
                sec_name = raw_name.rstrip(b"\x00").decode("utf-8", errors="ignore")
            else:
                sec_name = str(raw_name)

            v_addr = getattr(sec, "VirtualAddress", 0)
            abs_va = session.image_base + v_addr
            va_str = f"0x{abs_va:X}"
            v_size = getattr(sec, "Misc_VirtualSize", 0)
            raw_offset = getattr(sec, "PointerToRawData", 0)
            raw_size = getattr(sec, "SizeOfRawData", 0)

            chars = getattr(sec, "Characteristics", 0)
            perms = _parse_pe_permissions(chars)

            ent = sec.get_entropy()
            entropy = round(float(ent), 4)
            is_high_entropy = entropy >= HIGH_ENTROPY_THRESHOLD

            local_blocks = _detect_section_local_entropy(
                session=session,
                raw_offset=raw_offset,
                raw_size=raw_size,
                base_va=abs_va if abs_va != 0 else None,
                detect_local_entropy=detect_local_entropy,
                window_size=window_size,
                step=step,
            )

            profiles.append(
                SectionProfile(
                    name=sec_name,
                    virtual_address=va_str,
                    virtual_size=v_size,
                    raw_offset=raw_offset,
                    raw_size=raw_size,
                    permissions=perms,
                    entropy=entropy,
                    is_high_entropy=is_high_entropy,
                    local_high_entropy_blocks=local_blocks,
                )
            )

    return profiles


def _classify_single_api(api_name: str) -> str | None:
    """启发式匹配单个 API 的敏感行为分类

    @param api_name API 函数名称
    @return str | None 命中的敏感类别标识，未命中返回 None
    """
    lower_name = api_name.lower()
    for cat, keywords in SENSITIVE_API_KEYWORDS.items():
        for kw in keywords:
            if kw in lower_name:
                return cat
    return None


def extract_imports(
    session: BinarySession,
    library_filter: str | None = None,
    name_filter: str | None = None,
    category: str | None = None,
    offset: int = 0,
    limit: int = 50,
) -> tuple[list[SymbolEntry], int]:
    """提取导入函数表并支持正则与敏感行为标签过滤及分页

    @param session 当前激活的分析会话
    @param library_filter 动态库名称正则过滤表达式
    @param name_filter 函数符号名称正则过滤表达式
    @param category 8 类启发式敏感行为标签之一
    @param offset 分页偏移量
    @param limit 单页最大数量
    @return tuple[list[SymbolEntry], int] 当前页导入项列表与匹配总数
    """
    # 1. 预编译正则表达式（语法错误将抛出 re.error）
    lib_regex = re.compile(library_filter, re.IGNORECASE) if library_filter else None
    name_regex = re.compile(name_filter, re.IGNORECASE) if name_filter else None

    all_entries: list[SymbolEntry] = []

    # 2. 从 LIEF 提取导入表
    if session.lief_binary and hasattr(session.lief_binary, "imports"):
        for imp in session.lief_binary.imports:
            lib_name = imp.name if imp.name else ""
            if lib_regex and not lib_regex.search(lib_name):
                continue

            for entry in imp.entries:
                func_name = entry.name
                if not func_name and getattr(entry, "is_ordinal", False):
                    func_name = f"Ordinal_{entry.ordinal}"
                if not func_name:
                    continue

                if name_regex and not name_regex.search(func_name):
                    continue

                matched_cat = _classify_single_api(func_name)
                if category and matched_cat != category:
                    continue

                iat_addr = getattr(entry, "iat_address", 0)
                if session.format == "PE" and iat_addr and iat_addr < session.image_base:
                    iat_addr += session.image_base
                addr_str = f"0x{iat_addr:X}" if iat_addr else "0x0"

                demangled = getattr(entry, "demangled_name", None)
                if demangled == func_name:
                    demangled = None

                all_entries.append(
                    SymbolEntry(
                        name=func_name,
                        demangled_name=demangled,
                        library=lib_name,
                        address=addr_str,
                        size=0,
                        symbol_type="import",
                        category=matched_cat,
                    )
                )

    # 3. 降级使用 pefile 提取导入表（若 LIEF 未提供条目）
    elif session.pefile_binary and hasattr(session.pefile_binary, "DIRECTORY_ENTRY_IMPORT"):
        for entry in session.pefile_binary.DIRECTORY_ENTRY_IMPORT:
            raw_dll = getattr(entry, "dll", b"")
            if isinstance(raw_dll, bytes):
                dll_name = raw_dll.decode("utf-8", errors="ignore")
            else:
                dll_name = str(raw_dll)
            if lib_regex and not lib_regex.search(dll_name):
                continue

            for imp in getattr(entry, "imports", []):
                raw_imp_name = imp.name
                if raw_imp_name and isinstance(raw_imp_name, bytes):
                    func_name = raw_imp_name.decode("utf-8", errors="ignore")
                elif imp.ordinal is not None:
                    func_name = f"Ordinal_{imp.ordinal}"
                else:
                    continue

                if name_regex and not name_regex.search(func_name):
                    continue

                matched_cat = _classify_single_api(func_name)
                if category and matched_cat != category:
                    continue

                addr = imp.address or 0
                all_entries.append(
                    SymbolEntry(
                        name=func_name,
                        demangled_name=None,
                        library=dll_name,
                        address=f"0x{addr:X}",
                        size=0,
                        symbol_type="import",
                        category=matched_cat,
                    )
                )

    total = len(all_entries)
    paged = all_entries[offset : offset + limit] if offset < total else []
    return paged, total


def extract_exports(
    session: BinarySession,
    name_filter: str | None = None,
    offset: int = 0,
    limit: int = 50,
) -> tuple[list[dict[str, Any]], int]:
    """提取导出符号表并支持名称正则过滤与分页

    @param session 当前激活的分析会话
    @param name_filter 符号名称正则过滤表达式
    @param offset 分页偏移量
    @param limit 单页最大数量
    @return tuple[list[dict[str, Any]], int] 导出项字典列表与匹配总数
    """
    name_regex = re.compile(name_filter, re.IGNORECASE) if name_filter else None
    all_exports: list[dict[str, Any]] = []

    # 1. 优先使用 LIEF 提取导出表
    if session.lief_binary:
        # PE 导出表
        if hasattr(session.lief_binary, "get_export"):
            exp_table = session.lief_binary.get_export()
            if exp_table and hasattr(exp_table, "entries"):
                for entry in exp_table.entries:
                    func_name = entry.name if entry.name else ""
                    if name_regex and not name_regex.search(func_name):
                        continue

                    addr = entry.address
                    if session.format == "PE" and addr < session.image_base:
                        addr += session.image_base

                    forwarder = entry.forward_information if entry.is_forwarded else None
                    all_exports.append(
                        {
                            "name": func_name,
                            "ordinal": entry.ordinal,
                            "address": f"0x{addr:X}",
                            "forwarder": forwarder,
                        }
                    )
        # ELF / Mach-O 导出函数
        elif hasattr(session.lief_binary, "exported_functions"):
            for func in session.lief_binary.exported_functions:
                func_name = func.name if func.name else ""
                if name_regex and not name_regex.search(func_name):
                    continue

                all_exports.append(
                    {
                        "name": func_name,
                        "ordinal": None,
                        "address": f"0x{func.address:X}",
                        "forwarder": None,
                    }
                )

    # 2. 降级使用 pefile 提取导出表
    elif session.pefile_binary and hasattr(session.pefile_binary, "DIRECTORY_ENTRY_EXPORT"):
        exp_table = session.pefile_binary.DIRECTORY_ENTRY_EXPORT
        for sym in getattr(exp_table, "symbols", []):
            raw_name = sym.name
            if isinstance(raw_name, bytes):
                func_name = raw_name.decode("utf-8", errors="ignore")
            else:
                func_name = str(raw_name)
            if name_regex and not name_regex.search(func_name):
                continue

            forwarder = sym.forwarder.decode("utf-8", errors="ignore") if sym.forwarder else None
            addr = session.image_base + sym.address
            all_exports.append(
                {
                    "name": func_name,
                    "ordinal": sym.ordinal,
                    "address": f"0x{addr:X}",
                    "forwarder": forwarder,
                }
            )

    total = len(all_exports)
    paged = all_exports[offset : offset + limit] if offset < total else []
    return paged, total


def _read_uleb128(data: bytes, offset: int) -> tuple[int, int]:
    """从二进制数据流中读取无符号 LEB128 整数"""
    result = 0
    shift = 0
    while offset < len(data):
        b = data[offset]
        offset += 1
        result |= (b & 0x7F) << shift
        if (b & 0x80) == 0:
            break
        shift += 7
    return result, offset


def _read_sleb128(data: bytes, offset: int) -> tuple[int, int]:
    """从二进制数据流中读取有符号 LEB128 整数"""
    result = 0
    shift = 0
    while offset < len(data):
        b = data[offset]
        offset += 1
        result |= (b & 0x7F) << shift
        shift += 7
        if (b & 0x80) == 0:
            if shift < 64 and (b & 0x40):
                result |= -(1 << shift)
            break
    return result, offset


def _read_encoded_ptr(
    data: bytes,
    offset: int,
    encoding: int,
    ptr_size: int,
    pc: int,
) -> tuple[int | None, int]:
    """根据 DWARF 指针编码标准解析指针值"""
    if encoding == 0xFF:
        return None, offset
    fmt_code = encoding & 0x0F
    val: int | None = None
    if fmt_code == 0x00:
        if ptr_size == 8:
            if offset + 8 > len(data):
                return None, offset
            val = struct.unpack_from("<Q", data, offset)[0]
            offset += 8
        else:
            if offset + 4 > len(data):
                return None, offset
            val = struct.unpack_from("<I", data, offset)[0]
            offset += 4
    elif fmt_code == 0x02:
        if offset + 2 > len(data):
            return None, offset
        val = struct.unpack_from("<H", data, offset)[0]
        offset += 2
    elif fmt_code == 0x03:
        if offset + 4 > len(data):
            return None, offset
        val = struct.unpack_from("<I", data, offset)[0]
        offset += 4
    elif fmt_code == 0x04:
        if offset + 8 > len(data):
            return None, offset
        val = struct.unpack_from("<Q", data, offset)[0]
        offset += 8
    elif fmt_code == 0x0A:
        if offset + 2 > len(data):
            return None, offset
        val = struct.unpack_from("<h", data, offset)[0]
        offset += 2
    elif fmt_code == 0x0B:
        if offset + 4 > len(data):
            return None, offset
        val = struct.unpack_from("<i", data, offset)[0]
        offset += 4
    elif fmt_code == 0x0C:
        if offset + 8 > len(data):
            return None, offset
        val = struct.unpack_from("<q", data, offset)[0]
        offset += 8
    elif fmt_code == 0x01:
        val, offset = _read_uleb128(data, offset)
    elif fmt_code == 0x09:
        val, offset = _read_sleb128(data, offset)
    else:
        return None, offset

    rel = encoding & 0x70
    if rel == 0x10 and val is not None:
        val = (pc + val) & (0xFFFFFFFFFFFFFFFF if ptr_size == 8 else 0xFFFFFFFF)
    return val, offset


def parse_eh_frame_functions(
    data: bytes,
    base_va: int,
    bits: int,
) -> list[tuple[int, int]]:
    """解析 ELF .eh_frame 节区中的 CIE/FDE 记录，恢复所有有效内部函数的 (起始VA, 字节大小)

    @param data .eh_frame 节区完整原始字节序列
    @param base_va .eh_frame 节区在内存中的绝对基准虚拟地址
    @param bits 目标架构指针位宽 (32 或 64)
    @return list[tuple[int, int]] 恢复的函数列表 [(func_va, func_size)]
    """
    ptr_size = 8 if bits == 64 else 4
    cies: dict[int, dict[str, Any]] = {}
    functions: list[tuple[int, int]] = []
    offset = 0
    total_len = len(data)

    while offset + 4 <= total_len:
        entry_start = offset
        length = struct.unpack_from("<I", data, offset)[0]
        offset += 4
        if length == 0:
            break
        if length == 0xFFFFFFFF:
            if offset + 8 > total_len:
                break
            length = struct.unpack_from("<Q", data, offset)[0]
            offset += 8

        entry_end = offset + length
        if entry_end > total_len:
            break

        if offset + 4 > entry_end:
            offset = entry_end
            continue

        cie_id = struct.unpack_from("<I", data, offset)[0]
        offset += 4

        if cie_id == 0:
            # CIE (Common Information Entry)
            cie_info: dict[str, Any] = {"fde_encoding": 0x00, "has_z": False}
            try:
                if offset < entry_end:
                    ver = data[offset]
                    offset += 1
                    null_idx = data.find(b"\x00", offset, entry_end)
                    if null_idx != -1:
                        aug_str = data[offset:null_idx].decode("ascii", errors="ignore")
                        offset = null_idx + 1
                        _, offset = _read_uleb128(data, offset)
                        _, offset = _read_sleb128(data, offset)
                        if ver == 1:
                            offset += 1
                        else:
                            _, offset = _read_uleb128(data, offset)
                        if "z" in aug_str:
                            cie_info["has_z"] = True
                            aug_len, offset = _read_uleb128(data, offset)
                            aug_end = offset + aug_len
                            for ch in aug_str:
                                if ch == "z":
                                    continue
                                elif ch == "R":
                                    if offset < aug_end:
                                        cie_info["fde_encoding"] = data[offset]
                                        offset += 1
                                elif ch == "P":
                                    if offset < aug_end:
                                        p_enc = data[offset]
                                        offset += 1
                                        _, offset = _read_encoded_ptr(
                                            data, offset, p_enc, ptr_size, base_va + offset
                                        )
                                elif ch == "L":
                                    if offset < aug_end:
                                        offset += 1
                            offset = aug_end
            except Exception:
                pass
            cies[entry_start] = cie_info
            offset = entry_end
        else:
            # FDE (Frame Description Entry)
            try:
                cie_offset = (entry_start + 4) - cie_id
                cie_info = cies.get(cie_offset, {"fde_encoding": 0x00, "has_z": False})
                enc = cie_info.get("fde_encoding", 0x00)
                pc = base_va + offset
                func_va, offset = _read_encoded_ptr(data, offset, enc, ptr_size, pc)
                func_size, offset = _read_encoded_ptr(data, offset, enc & 0x0F, ptr_size, 0)
                if func_va is not None and func_size is not None and func_size > 0:
                    functions.append((func_va, func_size))
            except Exception:
                pass
            offset = entry_end

    return functions


def extract_symbols(
    session: BinarySession,
    name_filter: str | None = None,
    symbol_type: str = "all",
    offset: int = 0,
    limit: int = 50,
) -> tuple[list[SymbolEntry], int]:
    """提取静态/动态符号，并针对 64 位 PE 自动通过 .pdata 异常目录恢复内部无符号函数，
    针对 32 位 PE 扫描经典序言恢复内部函数，针对 ELF 解析 .eh_frame 恢复内部函数

    @param session 当前激活的分析会话
    @param name_filter 符号名称正则过滤表达式
    @param symbol_type 符号类型过滤 ("function", "object", "exception_frame",
        "eh_frame", "prologue", "all")
    @param offset 分页偏移量
    @param limit 单页最大数量
    @return tuple[list[SymbolEntry], int] 符号条目列表与匹配总数
    """
    name_regex = re.compile(name_filter, re.IGNORECASE) if name_filter else None
    all_symbols: list[SymbolEntry] = []

    # 1. 针对 64 位 PE 通过 .pdata 异常目录自动恢复无符号内部函数
    # 仅当 symbol_type 为 all 或 exception_frame 时提取，保障类型纯净度
    if (
        session.format == "PE"
        and session.bits == 64
        and symbol_type in ("all", "exception_frame")
        and session.pefile_binary
    ):
        try:
            opt_hdr = session.pefile_binary.OPTIONAL_HEADER
            data_dirs = getattr(opt_hdr, "DATA_DIRECTORY", [])
            if len(data_dirs) > IMAGE_DIRECTORY_ENTRY_EXCEPTION_INDEX:
                exc_dir = data_dirs[IMAGE_DIRECTORY_ENTRY_EXCEPTION_INDEX]
                rva = getattr(exc_dir, "VirtualAddress", 0)
                size = getattr(exc_dir, "Size", 0)
                if rva > 0 and size >= RUNTIME_FUNCTION_ENTRY_SIZE:
                    pdata_bytes = session.pefile_binary.get_data(rva, size)
                    entry_count = len(pdata_bytes) // RUNTIME_FUNCTION_ENTRY_SIZE
                    for i in range(entry_count):
                        (
                            begin_rva,
                            end_rva,
                            _unwind_rva,
                        ) = struct.unpack_from("<III", pdata_bytes, i * RUNTIME_FUNCTION_ENTRY_SIZE)
                        va = session.image_base + begin_rva
                        func_len = end_rva - begin_rva
                        func_name = f"sub_{va:X}"

                        if name_regex and not name_regex.search(func_name):
                            continue

                        all_symbols.append(
                            SymbolEntry(
                                name=func_name,
                                demangled_name=None,
                                library=None,
                                address=f"0x{va:X}",
                                size=func_len,
                                symbol_type="exception_frame",
                                category=None,
                            )
                        )
        except Exception as exc:
            logger.debug("从 .pdata 恢复无符号函数失败: %s", exc)

    # 2. 针对 32 位 PE 缺乏 .pdata 时执行函数序言特征扫描 (Prologue Scanning)
    if session.format == "PE" and session.bits == 32 and symbol_type in ("all", "prologue"):
        try:
            sections = extract_sections(session)
            for sec in sections:
                if "x" in sec.permissions or sec.name in (".text", "CODE"):
                    if sec.raw_size <= 0:
                        continue
                    sec_data = session.read_effective_bytes(sec.raw_offset, sec.raw_size)
                    sec_va = int(sec.virtual_address, 16)
                    found_offsets: set[int] = set()
                    for pat in (b"\x55\x8b\xec", b"\x55\x89\xe5"):
                        start = 0
                        while True:
                            idx = sec_data.find(pat, start)
                            if idx == -1:
                                break
                            found_offsets.add(idx)
                            start = idx + 1
                    for off in sorted(found_offsets):
                        va = sec_va + off
                        func_name = f"sub_{va:X}"
                        if name_regex and not name_regex.search(func_name):
                            continue
                        ret_idx = sec_data.find(b"\xc3", off)
                        func_len = (ret_idx + 1) - off if ret_idx != -1 else 0
                        all_symbols.append(
                            SymbolEntry(
                                name=func_name,
                                demangled_name=None,
                                library=None,
                                address=f"0x{va:X}",
                                size=func_len,
                                symbol_type="prologue",
                                category=None,
                            )
                        )
        except Exception as exc:
            logger.debug("PE32 序言特征扫描恢复函数失败: %s", exc)

    # 3. 针对 Linux ELF 通过 .eh_frame DWARF 展开表恢复无符号内部函数
    if session.format == "ELF" and symbol_type in ("all", "eh_frame"):
        try:
            sections = extract_sections(session)
            eh_sec = next((s for s in sections if s.name == ".eh_frame"), None)
            if eh_sec and eh_sec.raw_size > 0:
                eh_bytes = session.read_effective_bytes(eh_sec.raw_offset, eh_sec.raw_size)
                eh_va = int(eh_sec.virtual_address, 16)
                recovered_funcs = parse_eh_frame_functions(eh_bytes, eh_va, session.bits)
                for f_va, f_sz in recovered_funcs:
                    func_name = f"sub_{f_va:X}"
                    if name_regex and not name_regex.search(func_name):
                        continue
                    all_symbols.append(
                        SymbolEntry(
                            name=func_name,
                            demangled_name=None,
                            library=None,
                            address=f"0x{f_va:X}",
                            size=f_sz,
                            symbol_type="eh_frame",
                            category=None,
                        )
                    )
        except Exception as exc:
            logger.debug("ELF .eh_frame 展开表恢复函数失败: %s", exc)

    # 2. 提取 LIEF 中的符号表 (静态与动态符号)
    if session.lief_binary and hasattr(session.lief_binary, "symbols"):
        for sym in session.lief_binary.symbols:
            sym_name = sym.name if sym.name else ""
            if not sym_name:
                continue

            if name_regex and not name_regex.search(sym_name):
                continue

            # 判断符号类型
            cur_type = "function"
            if hasattr(sym, "type"):
                raw_type = str(sym.type).lower()
                if "object" in raw_type:
                    cur_type = "object"
                elif "func" in raw_type:
                    cur_type = "function"

            if symbol_type != "all" and symbol_type != cur_type:
                continue

            addr = sym.value
            if session.format == "PE" and addr < session.image_base:
                addr += session.image_base

            demangled = getattr(sym, "demangled_name", None)
            if demangled == sym_name:
                demangled = None

            all_symbols.append(
                SymbolEntry(
                    name=sym_name,
                    demangled_name=demangled,
                    library=None,
                    address=f"0x{addr:X}",
                    size=getattr(sym, "size", 0),
                    symbol_type=cur_type,
                    category=None,
                )
            )

    total = len(all_symbols)
    paged = all_symbols[offset : offset + limit] if offset < total else []
    return paged, total
