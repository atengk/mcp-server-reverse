"""函数控制流图 (CFG) 静态分析、基本块抽取与 Mermaid 流程图生成引擎

基于 Capstone 分支分析，根据条件/无条件跳转及返回指令切割单入口单出口基本块，
计算圈复杂度并生成原生 Mermaid 流程图语法。

@author Ateng
@since 2026-10-14
"""

from typing import Any

import capstone

from mcp_server_reverse.core.disasm import RET_MNEMONICS, _create_capstone_engine
from mcp_server_reverse.core.memory import convert_address_core
from mcp_server_reverse.core.models import BasicBlock, CFGEdge
from mcp_server_reverse.core.session import BinarySession

MAX_CFG_INSTRUCTIONS: int = 2048


def _is_arm64(arch: str) -> bool:
    """判断当前指令集架构是否为 ARM64 / AArch64"""
    arch_lower = arch.lower()
    return "arm64" in arch_lower or "aarch64" in arch_lower


def _is_ret(insn: capstone.CsInsn) -> bool:
    """判断指令是否为返回指令 (RET 系列)"""
    return insn.mnemonic.lower() in RET_MNEMONICS


def _is_unconditional_jump(insn: capstone.CsInsn, arch: str) -> bool:
    """判断指令是否为无条件跳转指令 (JMP / B / BR)"""
    m = insn.mnemonic.lower()
    if _is_arm64(arch):
        return m in ("b", "br")
    return m == "jmp"


def _is_conditional_jump(insn: capstone.CsInsn, arch: str) -> bool:
    """判断指令是否为条件分支跳转指令 (JZ, JNZ, B.EQ, CBZ 等)"""
    m = insn.mnemonic.lower()
    if _is_arm64(arch):
        return m.startswith("b.") or m in ("cbz", "cbnz", "tbz", "tbnz")
    return (m.startswith("j") and m != "jmp") or m in ("loop", "loope", "loopne")


def _parse_int_literal(text: str) -> int | None:
    """安全解析十六进制或十进制地址字面量 (前置验证，避免空异常处理)"""
    clean = text.strip().split(",")[0].strip()
    if clean.lower().startswith("0x"):
        digits = clean[2:]
        if digits and all(c in "0123456789abcdefABCDEF" for c in digits):
            return int(digits, 16)
    elif clean.startswith("#0x"):
        digits = clean[3:]
        if digits and all(c in "0123456789abcdefABCDEF" for c in digits):
            return int(digits, 16)
    elif clean.isdigit():
        return int(clean, 10)
    return None


def _extract_jump_target(insn: capstone.CsInsn, arch: str) -> int | None:
    """提取分支跳转指令的目标绝对虚拟地址 (VA)"""
    # 1. 优先从 Capstone 操作数 detail 提取立即数
    if hasattr(insn, "operands") and len(insn.operands) > 0:
        if _is_arm64(arch):
            for op in reversed(insn.operands):
                if hasattr(op, "type") and op.type == capstone.arm64.ARM64_OP_IMM:
                    return int(op.imm)
        else:
            op0 = insn.operands[0]
            if hasattr(op0, "type") and op0.type == capstone.x86.X86_OP_IMM:
                return int(op0.imm)

    # 2. 回退解析操作数字符串
    return _parse_int_literal(insn.op_str)


def _format_mermaid_diagram(
    blocks: list[BasicBlock],
    block_id_by_addr: dict[str, str],
) -> str:
    """生成原生 Mermaid 流程图文本 (flowchart TD)

    @param blocks 结构化基本块列表
    @param block_id_by_addr 地址到 block_id 的映射字典
    @return str 规范格式的 Mermaid 流程图文本
    """
    lines: list[str] = ["flowchart TD"]

    # 1. 声明节点与块内指令文本 (转义特殊字符防 Mermaid 解析崩溃)
    for b in blocks:
        sanitized_insns = []
        for line in b.instructions[:8]:
            clean = line.replace('"', "'").replace("[", "(").replace("]", ")")
            sanitized_insns.append(clean)
        if len(b.instructions) > 8:
            sanitized_insns.append(f"... 剩余 {len(b.instructions) - 8} 条指令 ...")

        label_content = f"{b.start_address} ({b.block_id})\\n" + "\\n".join(sanitized_insns)
        lines.append(f'    {b.block_id}["{label_content}"]')

    lines.append("")

    # 2. 声明分支跳转有向边
    for b in blocks:
        for succ in b.successors:
            target_addr = (
                succ.target_address if isinstance(succ, CFGEdge) else succ["target_address"]
            )
            target_id = block_id_by_addr.get(target_addr)
            if not target_id:
                continue

            b_type = (
                succ.branch_type
                if isinstance(succ, CFGEdge)
                else succ.get("branch_type", "unconditional")
            )
            if b_type == "true_branch":
                edge_label = f'|"true ({b.terminator_mnemonic or "jmp"})"|'
                lines.append(f"    {b.block_id} -->{edge_label} {target_id}")
            elif b_type == "false_branch":
                lines.append(f'    {b.block_id} -->|"false"| {target_id}')
            else:
                lines.append(f"    {b.block_id} --> {target_id}")

    return "\n".join(lines)


def build_cfg_core(
    session: BinarySession,
    target_va: int,
    max_blocks: int = 100,
) -> dict[str, Any]:
    """抽取函数控制流图、基本块拓扑与圈复杂度

    @param session 当前激活的分析会话 (支持透明叠加 COW 内存虚拟补丁)
    @param target_va 目标函数起始虚拟地址
    @param max_blocks 最大基本块数量上限 (防止超大恶意样本死循环)
    @return dict[str, Any] 包含 blocks 与 mermaid_diagram 的结构化字典
    @throws LookupError 当目标地址越界或无对应可执行字节时抛出
    """
    md = _create_capstone_engine(session.arch, session.bits)
    arch = session.arch

    # 1. 递归/工作流队列探索收集所有可达机器指令
    worklist: list[int] = [target_va]
    all_insns: dict[int, capstone.CsInsn] = {}
    visited_starts: set[int] = set()

    while worklist and len(all_insns) < MAX_CFG_INSTRUCTIONS:
        curr_va = worklist.pop(0)
        if curr_va in visited_starts or curr_va in all_insns:
            continue
        visited_starts.add(curr_va)

        try:
            conv = convert_address_core(session, curr_va, "va")
        except (ValueError, LookupError):
            continue

        file_off = conv["offset"]
        if file_off is None:
            continue

        # 读取一段连续机器码 (最大 512 字节)
        code_bytes = session.read_effective_bytes(file_off, 512)
        if not code_bytes:
            continue

        last_insn: capstone.CsInsn | None = None
        for insn in md.disasm(code_bytes, curr_va):
            all_insns[insn.address] = insn
            last_insn = insn

            if _is_ret(insn):
                break
            if _is_unconditional_jump(insn, arch):
                jmp_target = _extract_jump_target(insn, arch)
                if jmp_target is not None and jmp_target not in visited_starts:
                    worklist.append(jmp_target)
                break
            if _is_conditional_jump(insn, arch):
                jmp_target = _extract_jump_target(insn, arch)
                fallthrough = insn.address + insn.size
                if jmp_target is not None and jmp_target not in visited_starts:
                    worklist.append(jmp_target)
                if fallthrough not in visited_starts:
                    worklist.append(fallthrough)
                break
        else:
            # 当 512 字节连续指令未遇跳转或返回指令时，将末尾 fallthrough 重新入队继续探索
            if last_insn is not None:
                next_fallthrough = last_insn.address + last_insn.size
                if next_fallthrough not in visited_starts and next_fallthrough not in all_insns:
                    worklist.append(next_fallthrough)

    if not all_insns:
        raise LookupError(f"在虚拟地址 0x{target_va:X} 处未反汇编到任何有效可执行指令")

    # 2. Textbook 划分基本块 Leaders
    leaders: set[int] = {target_va}
    for insn in all_insns.values():
        if _is_conditional_jump(insn, arch) or _is_unconditional_jump(insn, arch):
            target = _extract_jump_target(insn, arch)
            if target is not None and target in all_insns:
                leaders.add(target)
            fallthrough = insn.address + insn.size
            if fallthrough in all_insns:
                leaders.add(fallthrough)
        elif _is_ret(insn):
            fallthrough = insn.address + insn.size
            if fallthrough in all_insns:
                leaders.add(fallthrough)

    sorted_leaders = sorted(leaders)
    raw_blocks: list[BasicBlock] = []
    block_id_by_addr: dict[str, str] = {}

    for idx, l_addr in enumerate(sorted_leaders):
        if len(raw_blocks) >= max_blocks:
            break

        b_id = f"bb_{idx}"
        b_start_str = f"0x{l_addr:X}"
        block_id_by_addr[b_start_str] = b_id

        # 收集当前基本块内的顺序指令
        curr_addr = l_addr
        block_insns: list[capstone.CsInsn] = []
        while curr_addr in all_insns:
            insn = all_insns[curr_addr]
            block_insns.append(insn)

            # 遇到下一个 Leader 或自身是终结指令时停止
            next_addr = insn.address + insn.size
            if (
                _is_ret(insn)
                or _is_unconditional_jump(insn, arch)
                or _is_conditional_jump(insn, arch)
                or next_addr in leaders
            ):
                break
            curr_addr = next_addr

        if not block_insns:
            continue

        terminator = block_insns[-1]
        term_m = terminator.mnemonic.lower()
        successors: list[CFGEdge] = []

        if _is_conditional_jump(terminator, arch):
            tgt = _extract_jump_target(terminator, arch)
            if tgt is not None and tgt in all_insns:
                successors.append(
                    CFGEdge(
                        target_address=f"0x{tgt:X}",
                        branch_type="true_branch",
                    )
                )
            fallthrough = terminator.address + terminator.size
            if fallthrough in all_insns:
                successors.append(
                    CFGEdge(
                        target_address=f"0x{fallthrough:X}",
                        branch_type="false_branch",
                    )
                )
        elif _is_unconditional_jump(terminator, arch):
            tgt = _extract_jump_target(terminator, arch)
            if tgt is not None and tgt in all_insns:
                successors.append(
                    CFGEdge(
                        target_address=f"0x{tgt:X}",
                        branch_type="unconditional",
                    )
                )
        elif not _is_ret(terminator):
            # 顺序流向下一个 Leader
            fallthrough = terminator.address + terminator.size
            if fallthrough in all_insns:
                successors.append(
                    CFGEdge(
                        target_address=f"0x{fallthrough:X}",
                        branch_type="unconditional",
                    )
                )

        insn_lines = [
            f"0x{ins.address:X}: {ins.bytes.hex(' '):<14} {ins.mnemonic} {ins.op_str}".strip()
            for ins in block_insns
        ]
        b_size = sum(ins.size for ins in block_insns)
        b_end_str = f"0x{terminator.address:X}"

        block = BasicBlock(
            block_id=b_id,
            start_address=b_start_str,
            end_address=b_end_str,
            size=b_size,
            instruction_count=len(block_insns),
            instructions=insn_lines,
            successors=successors,
            terminator_mnemonic=term_m
            if (
                _is_ret(terminator)
                or _is_conditional_jump(terminator, arch)
                or _is_unconditional_jump(terminator, arch)
            )
            else None,
        )
        raw_blocks.append(block)

    # 3. 计算圈复杂度: 基于 McCabe 判定节点计数法 M = P + 1 (P 为出度 >= 2 的判定分支节点数)
    predicate_nodes = sum(1 for b in raw_blocks if len(b.successors) > 1)
    complexity = predicate_nodes + 1

    # 4. 生成 Mermaid 流程图
    mermaid_diagram = _format_mermaid_diagram(raw_blocks, block_id_by_addr)

    return {
        "entry_point": f"0x{target_va:X}",
        "block_count": len(raw_blocks),
        "cyclomatic_complexity": complexity,
        "blocks": [b.to_dict() for b in raw_blocks],
        "mermaid_diagram": mermaid_diagram,
    }
