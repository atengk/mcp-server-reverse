"""多架构反汇编、相对寻址内联注释与惰性交叉引用引擎

支持 x86/x86_64/ARM64 反汇编、RIP-relative 自动内联注释、
ARM64 4 指令滑动窗口 ADRP+ADD/LDR 配对及会话级惰性交叉引用索引。

@author Ateng
@since 2026-10-13
"""

import struct
from typing import Any

import capstone

from mcp_server_reverse.core.inspection import (
    extract_exports,
    extract_imports,
    extract_sections,
    extract_symbols,
)
from mcp_server_reverse.core.memory import convert_address_core
from mcp_server_reverse.core.models import DisasmInstruction, XrefRecord
from mcp_server_reverse.core.session import BinarySession
from mcp_server_reverse.core.strings import extract_strings

# 单次反汇编最大指令数与单可执行节区最大交叉引用扫描字节上限 (16MB)
MAX_DISASM_COUNT: int = 256
MAX_EXEC_SECTION_SCAN_SIZE: int = 16 * 1024 * 1024
ARM64_ADRP_WINDOW_SIZE: int = 4
RET_MNEMONICS: tuple[str, ...] = ("ret", "retn", "retf", "retq")


def _create_capstone_engine(arch: str, bits: int) -> capstone.Cs:
    """根据架构与位宽创建开启 detail 模式的 Capstone 反汇编引擎实例

    @param arch 架构名称 (x86_64, i386, arm64 等)
    @param bits 指针位宽 (32 或 64)
    @return capstone.Cs 初始化完毕的 Capstone 实例
    """
    arch_lower = arch.lower()
    if "arm64" in arch_lower or "aarch64" in arch_lower:
        cs_arch = capstone.CS_ARCH_ARM64
        cs_mode = capstone.CS_MODE_ARM
    elif "arm" in arch_lower:
        cs_arch = capstone.CS_ARCH_ARM
        cs_mode = capstone.CS_MODE_ARM
    else:
        cs_arch = capstone.CS_ARCH_X86
        cs_mode = capstone.CS_MODE_64 if bits == 64 else capstone.CS_MODE_32

    md = capstone.Cs(cs_arch, cs_mode)
    md.detail = True
    return md


def _build_annotation_map(session: BinarySession) -> dict[int, str]:
    """构建虚拟地址到已知字符串、导入/导出函数及符号的快速内联注释映射表

    @param session 当前激活的二进制分析会话
    @return dict[int, str] 虚拟地址数值到可读注释字符串的映射字典
    """
    annotations: dict[int, str] = {}

    # 1. 静态字符串字面量
    strings, _, _ = extract_strings(session, min_length=4, limit=100000)
    for s_art in strings:
        if s_art.virtual_address and s_art.virtual_address != "0x0":
            va_int = int(s_art.virtual_address, 16)
            preview = s_art.value if len(s_art.value) <= 48 else f"{s_art.value[:45]}..."
            annotations[va_int] = f'"{preview}"'

    # 2. 导入函数表 (IAT)
    imports, _ = extract_imports(session, limit=100000)
    for imp in imports:
        if imp.address and imp.address != "0x0":
            va_int = int(imp.address, 16)
            annotations[va_int] = f"{imp.library}!{imp.name}" if imp.library else imp.name

    # 3. 导出函数表
    exports, _ = extract_exports(session, limit=100000)
    for exp in exports:
        if exp.get("address"):
            va_int = int(exp["address"], 16)
            annotations[va_int] = exp["name"]

    # 4. 符号表与 .pdata 恢复函数
    symbols, _ = extract_symbols(session, limit=100000)
    for sym in symbols:
        if sym.address and sym.address != "0x0":
            va_int = int(sym.address, 16)
            if va_int not in annotations:
                annotations[va_int] = sym.demangled_name or sym.name

    return annotations


def _extract_x86_insn_target(insn: Any) -> tuple[int | None, str | None]:
    """提取 x86/x86_64 单条指令中的 RIP-relative 内存引用或直接分支目标地址

    @param insn Capstone 指令对象
    @return tuple[int | None, str | None] (目标虚拟地址, 引用类型)
    """
    mnem = insn.mnemonic.lower()
    for op in insn.operands:
        if op.type == capstone.CS_OP_MEM and op.mem.base == capstone.x86.X86_REG_RIP:
            ref_va = (insn.address + insn.size + op.mem.disp) & 0xFFFFFFFFFFFFFFFF
            return ref_va, "rip_relative"
        if op.type == capstone.CS_OP_IMM:
            if mnem.startswith("call"):
                return op.imm & 0xFFFFFFFFFFFFFFFF, "call"
            if mnem.startswith("j"):
                return op.imm & 0xFFFFFFFFFFFFFFFF, "branch"
    return None, None


def _extract_arm64_insn_target(
    insn: Any,
    seq_idx: int,
    adrp_window: dict[int, tuple[int, int]],
) -> tuple[int | None, str | None]:
    """提取 ARM64 指令中的 ADRP+ADD/LDR 滑动窗口 PC-relative 引用或直接分支目标地址

    @param insn Capstone 指令对象
    @param seq_idx 当前指令在序列中的序号
    @param adrp_window ARM64 4 指令滑动窗口状态表
    @return tuple[int | None, str | None] (目标虚拟地址, 引用类型)
    """
    mnem = insn.mnemonic.lower()
    if mnem == "adrp" and len(insn.operands) >= 2:
        dst_reg = insn.operands[0].reg
        page_base = insn.operands[1].imm
        adrp_window[dst_reg] = (page_base, seq_idx)
        return None, None

    if mnem == "adr" and len(insn.operands) >= 2 and insn.operands[1].type == capstone.CS_OP_IMM:
        return insn.operands[1].imm, "pc_relative"

    if mnem == "add" and len(insn.operands) >= 3:
        src_reg = insn.operands[1].reg
        imm_op = insn.operands[2]
        if src_reg in adrp_window and imm_op.type == capstone.CS_OP_IMM:
            page_base, adrp_idx = adrp_window[src_reg]
            if (seq_idx - adrp_idx) <= ARM64_ADRP_WINDOW_SIZE:
                return page_base + imm_op.imm, "pc_relative"

    if mnem.startswith("ldr") and len(insn.operands) >= 2:
        mem_op = insn.operands[1]
        if mem_op.type == capstone.CS_OP_MEM and mem_op.mem.base in adrp_window:
            page_base, adrp_idx = adrp_window[mem_op.mem.base]
            if (seq_idx - adrp_idx) <= ARM64_ADRP_WINDOW_SIZE:
                return page_base + mem_op.mem.disp, "pc_relative"

    if mnem.startswith(("bl", "b")) and len(insn.operands) >= 1:
        op0 = insn.operands[0]
        if op0.type == capstone.CS_OP_IMM:
            x_type = "call" if mnem.startswith("bl") else "branch"
            return op0.imm, x_type

    return None, None


def disassemble_at(
    session: BinarySession,
    target_va: int,
    count: int = 32,
    stop_at_ret: bool = True,
) -> dict[str, Any]:
    """从指定虚拟地址开始执行反汇编，输出紧凑单行指令流并自动追加相对寻址注释

    @param session 当前激活的二进制分析会话
    @param target_va 起始绝对虚拟地址整数
    @param count 最大反汇编指令条数 (上限 256)
    @param stop_at_ret 遇到 ret 系列指令时是否自动停止
    @return dict[str, Any] 反汇编结果载荷字典
    @throws LookupError 当目标地址越界或无对应物理字节时抛出
    """
    safe_count = max(1, min(count, MAX_DISASM_COUNT))
    conv = convert_address_core(session, target_va, "va")
    file_off = conv["offset"]
    if file_off is None:
        raise LookupError(f"虚拟地址 0x{target_va:X} 无对应物理文件字节")

    code_slice = session.read_effective_bytes(file_off, safe_count * 16)
    if not code_slice:
        raise LookupError(f"虚拟地址 0x{target_va:X} 处无法读取有效指令字节")

    md = _create_capstone_engine(session.arch, session.bits)
    annotations = _build_annotation_map(session)
    arch_lower = session.arch.lower()
    is_arm64 = "arm64" in arch_lower or "aarch64" in arch_lower
    adrp_window: dict[int, tuple[int, int]] = {}

    instructions: list[DisasmInstruction] = []
    stopped_at_ret = False

    for seq_idx, insn in enumerate(md.disasm(code_slice, target_va)):
        if is_arm64:
            ref_va, _ = _extract_arm64_insn_target(insn, seq_idx, adrp_window)
        else:
            ref_va, _ = _extract_x86_insn_target(insn)

        comment: str | None = None
        if ref_va is not None:
            if ref_va in annotations:
                comment = f"{annotations[ref_va]} (0x{ref_va:X})"
            else:
                comment = f"0x{ref_va:X}"

        hex_str = insn.bytes.hex(" ")
        asm_text = f"{insn.mnemonic} {insn.op_str}".strip()
        formatted_line = f"0x{insn.address:X}: {hex_str:<22}  {asm_text}"
        if comment:
            formatted_line += f"  ; {comment}"

        instructions.append(
            DisasmInstruction(
                address=f"0x{insn.address:X}",
                hex_bytes=hex_str,
                mnemonic=insn.mnemonic,
                op_str=insn.op_str,
                comment=comment,
                formatted=formatted_line,
            )
        )

        if stop_at_ret and insn.mnemonic.lower() in RET_MNEMONICS:
            stopped_at_ret = True
            break

        if len(instructions) >= safe_count:
            break

    return {
        "start_address": f"0x{target_va:X}",
        "section": conv["section"],
        "instruction_count": len(instructions),
        "stopped_at_ret": stopped_at_ret,
        "instructions": instructions,
        "compact_lines": [i.formatted for i in instructions],
    }


def _append_xref(
    index: dict[int, list[XrefRecord]],
    target_va: int,
    record: XrefRecord,
) -> None:
    """向倒排交叉引用索引表中追加一条记录"""
    if target_va not in index:
        index[target_va] = []
    index[target_va].append(record)


def scan_code_section_xrefs(
    code_bytes: bytes,
    section_va: int,
    section_name: str,
    arch: str,
    bits: int,
    index: dict[int, list[XrefRecord]],
) -> None:
    """扫描单个可执行代码节区，提取 x86 RIP-relative、分支调用及 ARM64 ADRP 滑动窗口交叉引用

    @param code_bytes 节区原始机器码字节序列 (已截断至最大扫描上限)
    @param section_va 节区起始绝对虚拟地址
    @param section_name 节区名称
    @param arch 目标架构名称
    @param bits 指针位宽
    @param index 待填充的倒排索引字典 (target_va -> list[XrefRecord])
    """
    md = _create_capstone_engine(arch, bits)
    arch_lower = arch.lower()
    is_arm64 = "arm64" in arch_lower or "aarch64" in arch_lower

    # ARM64 4 指令滑动窗口状态表: reg_id -> (page_base_va, insn_seq_index)
    adrp_window: dict[int, tuple[int, int]] = {}

    for seq_idx, insn in enumerate(md.disasm(code_bytes, section_va)):
        asm_str = f"{insn.mnemonic} {insn.op_str}".strip()
        from_str = f"0x{insn.address:X}"

        if is_arm64:
            ref_va, x_type = _extract_arm64_insn_target(insn, seq_idx, adrp_window)
        else:
            ref_va, x_type = _extract_x86_insn_target(insn)

        if ref_va is not None and x_type is not None:
            _append_xref(
                index,
                ref_va,
                XrefRecord(
                    from_address=from_str,
                    to_address=f"0x{ref_va:X}",
                    xref_type=x_type,
                    category="code",
                    instruction=asm_str,
                    section=section_name,
                ),
            )


def _scan_data_section_pointers(
    data_bytes: bytes,
    section_va: int,
    section_name: str,
    bits: int,
    min_valid_va: int,
    max_valid_va: int,
    index: dict[int, list[XrefRecord]],
) -> None:
    """扫描数据节区中的对齐全局指针，识别指向有效节区地址范围的 data_pointer 引用"""
    step = 8 if bits == 64 else 4
    fmt = "<Q" if bits == 64 else "<I"
    limit_len = (len(data_bytes) // step) * step

    for off in range(0, limit_len, step):
        (ptr_val,) = struct.unpack_from(fmt, data_bytes, off)
        if min_valid_va <= ptr_val < max_valid_va:
            from_va = section_va + off
            directive = "dq" if bits == 64 else "dd"
            _append_xref(
                index,
                ptr_val,
                XrefRecord(
                    from_address=f"0x{from_va:X}",
                    to_address=f"0x{ptr_val:X}",
                    xref_type="data_pointer",
                    category="data",
                    instruction=f"{directive} 0x{ptr_val:X}",
                    section=section_name,
                ),
            )


def build_xref_index(session: BinarySession) -> dict[int, list[XrefRecord]]:
    """构建或返回会话级惰性交叉引用倒排索引 (_xref_index)

    @param session 当前激活的二进制分析会话
    @return dict[int, list[XrefRecord]] 目标虚拟地址到交叉引用记录列表的映射字典
    """
    if isinstance(session._xref_index, dict):
        return session._xref_index

    raw_bytes = session.read_effective_bytes()
    sections = extract_sections(session)
    index: dict[int, list[XrefRecord]] = {}

    if not sections:
        session._xref_index = index
        return index

    va_list = [int(s.virtual_address, 16) for s in sections]
    min_va = min(va_list)
    max_va = max(int(s.virtual_address, 16) + max(s.virtual_size, s.raw_size) for s in sections)

    for sec in sections:
        if sec.raw_size <= 0 or sec.raw_offset >= len(raw_bytes):
            continue

        sec_va = int(sec.virtual_address, 16)
        scan_size = min(sec.raw_size, MAX_EXEC_SECTION_SCAN_SIZE)
        sec_bytes = raw_bytes[sec.raw_offset : sec.raw_offset + scan_size]

        if "x" in sec.permissions or sec.name in (".text", "__text"):
            scan_code_section_xrefs(
                code_bytes=sec_bytes,
                section_va=sec_va,
                section_name=sec.name,
                arch=session.arch,
                bits=session.bits,
                index=index,
            )
        else:
            _scan_data_section_pointers(
                data_bytes=sec_bytes,
                section_va=sec_va,
                section_name=sec.name,
                bits=session.bits,
                min_valid_va=min_va,
                max_valid_va=max_va,
                index=index,
            )

    session._xref_index = index
    return index


def query_xrefs(
    session: BinarySession,
    target_va: int,
    xref_type: str = "all",
    offset: int = 0,
    limit: int = 50,
) -> tuple[list[XrefRecord], int]:
    """查询指向指定目标虚拟地址的全部静态交叉引用记录

    @param session 当前激活的二进制分析会话
    @param target_va 被引用的目标绝对虚拟地址
    @param xref_type 过滤类型 ("all", "code", "data")
    @param offset 分页偏移量
    @param limit 单页最大返回数
    @return tuple[list[XrefRecord], int] 当前页交叉引用记录列表与匹配总数
    """
    index = build_xref_index(session)
    raw_hits = index.get(target_va, [])

    filter_cat = xref_type.lower().strip() if xref_type else "all"
    if filter_cat == "all":
        matched = list(raw_hits)
    else:
        matched = [r for r in raw_hits if r.category == filter_cat or r.xref_type == filter_cat]

    total = len(matched)
    safe_offset = max(0, offset)
    safe_limit = max(1, min(limit, 500))
    paged = matched[safe_offset : safe_offset + safe_limit] if safe_offset < total else []
    return paged, total
