"""结构与符号检视核心引擎

提供节区画像、导入表分类与正则检索、导出表枚举及基于 PE .pdata 的无符号函数恢复能力。

@author Ateng
@since 2026-10-13
"""

import logging
import re
import struct
from typing import Any

from mcp_server_reverse.core.models import SectionProfile, SymbolEntry
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


def extract_sections(session: BinarySession) -> list[SectionProfile]:
    """提取二进制全量节区/段分布画像与香农熵

    @param session 当前激活的二进制分析会话
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


def extract_symbols(
    session: BinarySession,
    name_filter: str | None = None,
    symbol_type: str = "all",
    offset: int = 0,
    limit: int = 50,
) -> tuple[list[SymbolEntry], int]:
    """提取静态/动态符号，并针对 64 位 PE 自动通过 .pdata 异常目录恢复内部无符号函数

    @param session 当前激活的分析会话
    @param name_filter 符号名称正则过滤表达式
    @param symbol_type 符号类型过滤 ("function", "object", "exception_frame", "all")
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
