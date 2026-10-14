"""地址双向换算、符号地址决议与内存 Hexdump 检视引擎

提供 VA/RVA/Offset 双向精确换算、目标符号虚拟地址解析以及带 ASCII 对照列的 Hexdump 内存读取能力。

@author Ateng
@since 2026-10-13
"""

from typing import Any

from mcp_server_reverse.core.inspection import (
    extract_exports,
    extract_imports,
    extract_sections,
    extract_symbols,
)
from mcp_server_reverse.core.session import BinarySession

# 单次内存读取最大字节上限
MAX_READ_MEMORY_SIZE: int = 1024
HEXDUMP_ROW_WIDTH: int = 16


def _parse_numeric_address(address: str | int) -> int:
    """将字符串或整型地址统一解析为非负整数

    @param address 十六进制字符串 (如 '0x140001000')、十进制字符串或整数
    @return int 解析后的数值地址
    @throws ValueError 当地址格式非法或为负数时抛出
    """
    if isinstance(address, int):
        if address < 0:
            raise ValueError("地址或偏移量不能为负数")
        return address

    clean = str(address).strip()
    if not clean:
        raise ValueError("地址不能为空字符串")

    if clean.lower().startswith("0x"):
        val = int(clean, 16)
    elif clean.isdigit():
        val = int(clean, 10)
    else:
        val = int(clean, 16)

    if val < 0:
        raise ValueError("地址或偏移量不能为负数")
    return val


def convert_address_core(
    session: BinarySession,
    address: str | int,
    address_type: str = "va",
) -> dict[str, Any]:
    """在虚拟地址 (va)、相对虚拟地址 (rva) 与文件物理偏移 (offset) 之间双向精确换算

    @param session 当前激活的二进制分析会话
    @param address 待换算的地址或偏移量
    @param address_type 输入地址类型 ("va", "rva", "offset")
    @return dict[str, Any] 包含 va, rva, offset, section, permissions 的换算结果字典
    @throws ValueError 当入参类型或格式非法时抛出
    @throws LookupError 当地址越界未落在任何节区时抛出
    """
    addr_type = address_type.lower().strip() if address_type else "va"
    if addr_type not in ("va", "rva", "offset"):
        raise ValueError(f"不支持的 address_type: '{address_type}'，可选值为 va, rva, offset")

    val = _parse_numeric_address(address)
    sections = extract_sections(session)
    image_base = session.image_base

    # 1. 按 VA 或 RVA 换算
    if addr_type in ("va", "rva"):
        target_va = val if addr_type == "va" else (image_base + val)
        for sec in sections:
            sec_va = int(sec.virtual_address, 16)
            sec_span = max(sec.virtual_size, sec.raw_size)
            if sec_va <= target_va < (sec_va + sec_span):
                delta = target_va - sec_va
                rva_val = (target_va - image_base) if target_va >= image_base else target_va
                file_off = (sec.raw_offset + delta) if delta < sec.raw_size else None
                return {
                    "va": f"0x{target_va:X}",
                    "rva": f"0x{rva_val:X}",
                    "offset": file_off,
                    "section": sec.name,
                    "permissions": sec.permissions,
                }
        raise LookupError(f"虚拟地址 0x{target_va:X} 超出二进制已知节区映射范围")

    # 2. 按物理文件偏移 Offset 换算
    for sec in sections:
        if sec.raw_offset <= val < (sec.raw_offset + sec.raw_size):
            delta = val - sec.raw_offset
            sec_va = int(sec.virtual_address, 16)
            target_va = sec_va + delta
            rva_val = (target_va - image_base) if target_va >= image_base else target_va
            return {
                "va": f"0x{target_va:X}",
                "rva": f"0x{rva_val:X}",
                "offset": val,
                "section": sec.name,
                "permissions": sec.permissions,
            }

    raise LookupError(f"文件物理偏移 0x{val:X} 未落在任何已知映射节区内")


def format_hexdump_lines(data: bytes, base_address: int) -> list[str]:
    """将原始字节序列格式化为标准 16 字节宽度的 Hexdump + ASCII 对照行列表

    @param data 待展示的原始字节序列
    @param base_address 起始虚拟地址数值
    @return list[str] 格式化后的 Hexdump 字符串行列表
    """
    lines: list[str] = []
    for i in range(0, len(data), HEXDUMP_ROW_WIDTH):
        row = data[i : i + HEXDUMP_ROW_WIDTH]
        row_addr = base_address + i

        left_part = " ".join(f"{b:02X}" for b in row[:8])
        right_part = " ".join(f"{b:02X}" for b in row[8:])
        hex_col = f"{left_part:<23}  {right_part:<23}"

        ascii_col = "".join(chr(b) if 0x20 <= b <= 0x7E else "." for b in row)
        lines.append(f"0x{row_addr:X}  {hex_col}  |{ascii_col}|")

    return lines


def read_memory_core(
    session: BinarySession,
    address: str | int,
    size: int = 64,
    address_type: str = "va",
) -> dict[str, Any]:
    """按 va、rva 或 offset 读取指定长度的原始字节并生成 Hexdump 对照视图

    @param session 当前激活的二进制分析会话
    @param address 起始地址或偏移量
    @param size 读取字节长度 (1 ~ 1024)
    @param address_type 地址类型 ("va", "rva", "offset")
    @return dict[str, Any] 包含 hex_bytes 与 hexdump_lines 的内存检视载荷
    @throws ValueError 当地址格式或参数非法时抛出
    @throws LookupError 当地址越界或无对应物理数据时抛出
    """
    safe_size = max(1, min(size, MAX_READ_MEMORY_SIZE))
    conv = convert_address_core(session, address, address_type)
    file_off = conv["offset"]
    if file_off is None:
        raise LookupError(f"地址 {conv['va']} 位于未初始化数据段 (BSS)，无磁盘物理字节可读取")

    if file_off >= session.file_size:
        raise LookupError(f"计算出的物理偏移 0x{file_off:X} 超出文件字节长度")

    chunk = session.read_effective_bytes(file_off, safe_size)
    start_va_int = int(conv["va"], 16)
    hexdump_lines = format_hexdump_lines(chunk, start_va_int)

    return {
        "start_address": conv["va"],
        "file_offset": file_off,
        "size": len(chunk),
        "section": conv["section"],
        "permissions": conv["permissions"],
        "hex_bytes": chunk.hex(" ").upper(),
        "hexdump_lines": hexdump_lines,
    }


def resolve_target_address(session: BinarySession, target: str | int) -> int:
    """将十六进制地址、入口点别名、导出/导入函数名或 .pdata 符号名统一决议为绝对虚拟地址 (VA)

    @param session 当前激活的二进制分析会话
    @param target 十六进制地址字符串或符号/函数名称
    @return int 解析出的绝对虚拟地址整数值
    @throws LookupError 当目标符号不存在或地址越界时抛出
    """
    if isinstance(target, int):
        return target

    clean = str(target).strip()
    if not clean:
        raise LookupError("目标地址或符号名不能为空")

    # 1. 入口点快捷别名
    if clean.lower() in ("entry", "entrypoint", "_start"):
        ep = session.entry_point
        if session.format == "PE" and ep < session.image_base:
            ep += session.image_base
        return ep

    # 2. 显式十六进制或纯数字地址
    if clean.lower().startswith("0x") or clean.isdigit():
        try:
            return _parse_numeric_address(clean)
        except ValueError as exc:
            raise LookupError(f"无效的数值地址: '{clean}'") from exc

    # 3. 针对 sub_<hex_va> 命名约定直接解析
    if clean.lower().startswith("sub_"):
        hex_part = clean[4:]
        try:
            return int(hex_part, 16)
        except ValueError as exc:
            raise LookupError(f"无效的 sub_ 函数地址格式: '{clean}'") from exc

    # 4. 检索导出函数表（提升检索容量上限以避免大文件截断）
    exports, _ = extract_exports(session, limit=100000)
    for exp in exports:
        if exp["name"] == clean:
            return int(exp["address"], 16)

    # 5. 检索静态/动态符号表与 .pdata 恢复函数
    symbols, _ = extract_symbols(session, limit=100000)
    for sym in symbols:
        if sym.name == clean or sym.demangled_name == clean:
            return int(sym.address, 16)

    # 6. 检索导入函数表
    imports, _ = extract_imports(session, limit=100000)
    for imp in imports:
        if imp.name == clean or imp.demangled_name == clean:
            return int(imp.address, 16)

    raise LookupError(f"未找到匹配的符号或有效地址: '{clean}'")
