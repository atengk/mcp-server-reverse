"""全平台二进制漏洞缓解机制加固审计与安全评分引擎

支持深度审计 Windows PE、Linux ELF 与 macOS Mach-O 平台的内核与编译器加固防护特性，
计算 0~100 加权安全评分并给出利用难度评级与针对性修复建议。

@author Ateng
@since 2026-10-14
"""

import logging
from collections.abc import Callable
from typing import Any

from mcp_server_reverse.core.models import (
    ExploitDifficulty,
    MitigationProfile,
    RelroStatus,
)
from mcp_server_reverse.core.session import BinarySession

logger = logging.getLogger(__name__)


def _has_symbol_matching(symbols: Any, predicate: Callable[[str], bool]) -> bool:
    """检查符号集合中是否存在满足匹配条件的符号名称

    @param symbols 可迭代符号列表
    @param predicate 名称判定函数
    @return bool 是否存在匹配项
    """
    if not symbols:
        return False
    for sym in symbols:
        name = getattr(sym, "name", "") or ""
        if predicate(name):
            return True
    return False


def _audit_pe_mitigations(session: BinarySession) -> tuple[dict[str, Any], int, list[str]]:
    """审计 Windows PE 二进制缓解机制

    @param session 当前激活的分析会话
    @return tuple[dict[str, Any], int, list[str]] (防护特性字典, 安全评分, 建议列表)
    """
    pe_obj = session.pefile_binary
    lief_bin = session.lief_binary
    is_64 = session.bits == 64
    opt_header = getattr(pe_obj, "OPTIONAL_HEADER", None)

    # 1. 提取 DllCharacteristics 特性
    dll_chars = 0
    if opt_header is not None:
        dll_chars = getattr(opt_header, "DllCharacteristics", 0)
    elif lief_bin and hasattr(lief_bin, "optional_header"):
        dll_chars = getattr(lief_bin.optional_header, "dll_characteristics", 0)

    aslr = bool(dll_chars & 0x0040)  # IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
    high_entropy_va = bool(dll_chars & 0x0020)  # IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA
    dep_nx = bool(dll_chars & 0x0100)  # IMAGE_DLLCHARACTERISTICS_NX_COMPAT
    cfg = bool(dll_chars & 0x4000)  # IMAGE_DLLCHARACTERISTICS_GUARD_CF
    cet_compat = bool(dll_chars & 0x1000)  # IMAGE_DLLCHARACTERISTICS_CET_COMPAT

    # 2. 深度校验 SafeSEH 异常表存在性
    safe_seh: bool | None = None
    if is_64:
        # x64 平台天然采用表驱动异常处理 (.pdata)，无传统栈帧覆盖风险
        safe_seh = True
    elif pe_obj and hasattr(pe_obj, "DIRECTORY_ENTRY_LOAD_CONFIG"):
        load_cfg = getattr(pe_obj.DIRECTORY_ENTRY_LOAD_CONFIG, "struct", None)
        se_count = getattr(load_cfg, "SEHandlerCount", 0) if load_cfg else 0
        se_table = getattr(load_cfg, "SEHandlerTable", 0) if load_cfg else 0
        if se_count > 0 and se_table > 0:
            safe_seh = True
        else:
            safe_seh = bool(dll_chars & 0x0400)  # IMAGE_DLLCHARACTERISTICS_NO_SEH
    else:
        safe_seh = bool(dll_chars & 0x0400)

    # 3. 检查代码签名 (IMAGE_DIRECTORY_ENTRY_SECURITY, 索引 4)
    authenticode_signed = False
    if opt_header is not None:
        dirs = getattr(opt_header, "DATA_DIRECTORY", [])
        if len(dirs) > 4:
            sec_dir = dirs[4]
            if getattr(sec_dir, "VirtualAddress", 0) > 0 and getattr(sec_dir, "Size", 0) > 0:
                authenticode_signed = True
    elif lief_bin and hasattr(lief_bin, "signatures"):
        authenticode_signed = len(lief_bin.signatures) > 0

    # 4. 检查 Stack Canary (__security_cookie / GS)
    has_canary = False
    if session.format_info.get("has_canary") is True:
        has_canary = True
    elif lief_bin and hasattr(lief_bin, "imports"):
        for imp in lief_bin.imports:
            entries = getattr(imp, "entries", [])
            if _has_symbol_matching(
                entries,
                lambda n: "__security_cookie" in n or "__security_check_cookie" in n,
            ):
                has_canary = True
                break

    # 5. 加权评分计算
    score = 0
    recommendations: list[str] = []

    if dep_nx:
        score += 25
    else:
        recommendations.append(
            "启用数据执行保护 (DEP/NX, 编译选项 /NXCOMPAT)，防止栈或堆内存执行 Shellcode"
        )

    if aslr:
        score += 20
        if high_entropy_va or not is_64:
            score += 5
        else:
            recommendations.append(
                "在 64 位环境下启用高熵 ASLR (编译选项 /HIGHENTROPYVA)，扩展 64 位随机化方差"
            )
    else:
        recommendations.append(
            "启用动态基址随机化 (ASLR, 编译选项 /DYNAMICBASE)，防止利用固定地址构建 ROP 链"
        )

    if safe_seh:
        score += 15
    else:
        recommendations.append(
            "在 32 位 PE 下启用 SafeSEH 异常表 (编译选项 /SAFESEH)，防止结构化异常处理覆盖劫持"
        )

    if cfg:
        score += 15
    else:
        recommendations.append(
            "启用控制流防护 (Control Flow Guard, 编译选项 /guard:cf)，校验间接跳转目标合法性"
        )

    if cet_compat:
        score += 10
    else:
        recommendations.append(
            "启用硬件级影子栈 (CET/ShadowStack, 编译选项 /CETCOMPAT)，防御前向控制流劫持与 ROP"
        )

    if authenticode_signed:
        score += 10
    else:
        recommendations.append("签署合法的 Authenticode 数字证书，防范二进制文件落地后遭篡改")

    mitigations: dict[str, Any] = {
        "dep_nx": dep_nx,
        "aslr": aslr,
        "high_entropy_va": high_entropy_va,
        "cfg": cfg,
        "cet_shadow_stack": cet_compat,
        "safe_seh": safe_seh,
        "authenticode_signed": authenticode_signed,
        "stack_canary": has_canary,
    }

    return mitigations, min(100, score), recommendations


def _audit_elf_mitigations(session: BinarySession) -> tuple[dict[str, Any], int, list[str]]:
    """审计 Linux ELF 二进制缓解机制

    @param session 当前激活的分析会话
    @return tuple[dict[str, Any], int, list[str]] (防护特性字典, 安全评分, 建议列表)
    """
    lief_bin = session.lief_binary

    # 1. NX (PT_GNU_STACK)
    has_nx = False
    if lief_bin:
        has_nx = getattr(lief_bin, "has_nx", False)
        if not has_nx and hasattr(lief_bin, "segments"):
            for seg in lief_bin.segments:
                seg_type_name = str(getattr(seg, "type", "")).upper()
                if "GNU_STACK" in seg_type_name:
                    flags = int(getattr(seg, "flags", 0))
                    if (flags & 0x1) == 0:  # PF_X 未置位
                        has_nx = True

    # 2. PIE (检测 DT_FLAGS_1 中的 DF_1_PIE 0x08000000 与 is_pie)
    is_pie = False
    has_df_1_pie = False
    if lief_bin and hasattr(lief_bin, "dynamic_entries"):
        for entry in lief_bin.dynamic_entries:
            tag_name = str(getattr(entry, "tag", "")).upper()
            if "FLAGS_1" in tag_name:
                val = int(getattr(entry, "value", 0))
                if (val & 0x08000000) != 0:  # DF_1_PIE
                    has_df_1_pie = True
                    break

    if lief_bin:
        is_pie = has_df_1_pie or getattr(lief_bin, "is_pie", False)
        if not is_pie and hasattr(lief_bin, "header"):
            hdr_type = str(getattr(lief_bin.header, "file_type", "")).upper()
            if ("DYN" in hdr_type or "DYNAMIC" in hdr_type) and has_df_1_pie:
                is_pie = True

    # 3. RELRO (PT_GNU_RELRO + BIND_NOW)
    has_relro_segment = False
    has_bind_now = False

    if lief_bin and hasattr(lief_bin, "segments"):
        for seg in lief_bin.segments:
            seg_type_name = str(getattr(seg, "type", "")).upper()
            if "GNU_RELRO" in seg_type_name:
                has_relro_segment = True
                break

    if lief_bin and hasattr(lief_bin, "dynamic_entries"):
        for entry in lief_bin.dynamic_entries:
            tag_name = str(getattr(entry, "tag", "")).upper()
            if "BIND_NOW" in tag_name:
                has_bind_now = True
            if "FLAGS" in tag_name:
                val = int(getattr(entry, "value", 0))
                if (val & 0x8) != 0 or (val & 0x1) != 0:  # DF_BIND_NOW / DF_1_NOW
                    has_bind_now = True

    relro_status = RelroStatus.NONE.value
    if has_relro_segment:
        relro_status = RelroStatus.FULL.value if has_bind_now else RelroStatus.PARTIAL.value

    # 4. Stack Canary
    has_canary = False
    if lief_bin:
        has_canary = getattr(lief_bin, "has_canary", False)
        if not has_canary and hasattr(lief_bin, "symbols"):
            has_canary = _has_symbol_matching(
                lief_bin.symbols,
                lambda n: "__stack_chk_fail" in n or "__stack_chk_guard" in n,
            )

    # 5. FORTIFY_SOURCE
    has_fortify = False
    if lief_bin and hasattr(lief_bin, "symbols"):
        has_fortify = _has_symbol_matching(
            lief_bin.symbols,
            lambda n: n.endswith("_chk") and not n.startswith("__stack_chk"),
        )

    # 6. 加权评分计算
    score = 0
    recommendations: list[str] = []

    if has_nx:
        score += 25
    else:
        recommendations.append(
            "启用不可执行栈保护 (编译选项 -z noexecstack)，防止栈上注入并执行 Shellcode"
        )

    if is_pie:
        score += 25
    else:
        recommendations.append(
            "编译为位置无关可执行文件 (编译选项 -fPIE -pie)，使代码段在内存中完全随机化加载"
        )

    if relro_status == RelroStatus.FULL.value:
        score += 20
    elif relro_status == RelroStatus.PARTIAL.value:
        score += 10
        recommendations.append(
            "提升至 Full RELRO (编译选项 -Wl,-z,relro,-z,now)，防止动态重定位 GOT 表被覆写劫持"
        )
    else:
        recommendations.append(
            "开启只读重定位保护 (RELRO, 编译选项 -Wl,-z,relro,-z,now)，防御针对 GOT 表的攻击"
        )

    if has_canary:
        score += 15
    else:
        recommendations.append(
            "启用编译器栈金丝雀保护 (编译选项 -fstack-protector-strong)，检测并拦截栈缓冲区溢出"
        )

    if has_fortify:
        score += 15
    else:
        recommendations.append(
            "开启库函数缓冲区强化检查 (编译选项 -D_FORTIFY_SOURCE=2)，防御格式化字符串与内存越界"
        )

    mitigations: dict[str, Any] = {
        "nx": has_nx,
        "pie": is_pie,
        "relro": relro_status,
        "canary": has_canary,
        "fortify_source": has_fortify,
    }

    return mitigations, min(100, score), recommendations


def _audit_macho_mitigations(session: BinarySession) -> tuple[dict[str, Any], int, list[str]]:
    """审计 macOS Mach-O 二进制缓解机制

    @param session 当前激活的分析会话
    @return tuple[dict[str, Any], int, list[str]] (防护特性字典, 安全评分, 建议列表)
    """
    lief_obj = session.lief_binary
    lief_bin = None
    if lief_obj:
        if hasattr(lief_obj, "header"):
            lief_bin = lief_obj
        else:
            try:
                for b in lief_obj:
                    cpu_type = str(getattr(b.header, "cpu_type", "")).lower()
                    if session.arch.lower() in cpu_type or (
                        session.arch == "arm64" and "aarch64" in cpu_type
                    ):
                        lief_bin = b
                        break
                if lief_bin is None and len(lief_obj) > 0:
                    lief_bin = list(lief_obj)[0]
            except Exception as exc:
                logger.debug("决议 Mach-O 切片异常: %s", exc)

    is_pie = False
    has_code_signature = False
    has_hardened_runtime = False
    allow_stack_execution = False

    if lief_bin and hasattr(lief_bin, "header"):
        flags = int(getattr(lief_bin.header, "flags", 0))
        is_pie = bool(flags & 0x200000)  # MH_PIE
        allow_stack_execution = bool(flags & 0x00020000)  # MH_ALLOW_STACK_EXECUTION

    if lief_bin and hasattr(lief_bin, "commands"):
        for cmd in lief_bin.commands:
            cmd_name = str(getattr(cmd, "command", "")).upper()
            if "CODE_SIGNATURE" in cmd_name:
                has_code_signature = True
                # 检查代码签名指令中的 CS_RUNTIME (0x10000) 强化运行时标志
                cmd_flags = int(getattr(cmd, "flags", 0))
                if (cmd_flags & 0x10000) != 0:
                    has_hardened_runtime = True
                break

    has_canary = False
    if lief_bin and hasattr(lief_bin, "symbols"):
        has_canary = _has_symbol_matching(
            lief_bin.symbols,
            lambda n: "___stack_chk_fail" in n or "___stack_chk_guard" in n,
        )

    score = 0
    recommendations: list[str] = []

    if is_pie:
        score += 25
    else:
        recommendations.append(
            "启用 Mach-O PIE (位置无关可执行，编译选项 -Wl,-pie)，避免固定基址加载"
        )

    if has_code_signature:
        score += 25
    else:
        recommendations.append("签署有效苹果代码签名 (codesign -s)，确保 Mach-O 二进制未被篡改")

    if has_hardened_runtime:
        score += 20
    else:
        recommendations.append(
            "启用苹果强化运行时 (Hardened Runtime, codesign --options runtime)，防御注入劫持"
        )

    if has_canary:
        score += 15
    else:
        recommendations.append("启用栈保护金丝雀 (-fstack-protector-strong)，拦截缓冲区溢出")

    # NX: 除非显式声明 MH_ALLOW_STACK_EXECUTION，默认具备 W^X 保护
    has_nx = not allow_stack_execution
    if has_nx:
        score += 15
    else:
        recommendations.append(
            "禁用栈执行权限 (移除 MH_ALLOW_STACK_EXECUTION 标志)，保障栈不可执行"
        )

    mitigations: dict[str, Any] = {
        "pie": is_pie,
        "code_signature": has_code_signature,
        "hardened_runtime": has_hardened_runtime,
        "canary": has_canary,
        "nx": has_nx,
    }

    return mitigations, min(100, score), recommendations


AUDIT_STRATEGIES: dict[
    str,
    Callable[[BinarySession], tuple[dict[str, Any], int, list[str]]],
] = {
    "PE": _audit_pe_mitigations,
    "ELF": _audit_elf_mitigations,
    "MACH": _audit_macho_mitigations,
}


def _calculate_exploit_difficulty(score: int) -> ExploitDifficulty:
    """根据加权安全评分映射漏洞利用难度评级

    @param score 0 ~ 100 加权综合安全评分
    @return ExploitDifficulty 利用难度级别枚举
    """
    if score >= 80:
        return ExploitDifficulty.EXTREME
    if score >= 60:
        return ExploitDifficulty.HIGH
    if score >= 40:
        return ExploitDifficulty.MEDIUM
    return ExploitDifficulty.LOW


def audit_mitigations_core(session: BinarySession) -> dict[str, Any]:
    """跨平台漏洞缓解机制审计核心实现

    @param session 当前激活的分析会话
    @return dict[str, Any] 结构化加固画像字典
    """
    fmt_key = next((k for k in AUDIT_STRATEGIES if k in session.format.upper()), None)
    if fmt_key is not None:
        auditor = AUDIT_STRATEGIES[fmt_key]
        mits, score, recs = auditor(session)
    else:
        mits = {}
        score = 0
        recs = ["未识别的目标二进制格式，无法执行专用漏洞缓解机制审计"]

    difficulty = _calculate_exploit_difficulty(score)
    summary = (
        f"完成 {session.format} ({session.arch}) 缓解机制加固审计: "
        f"综合安全评分 {score}/100，漏洞利用难度评级为 '{difficulty.value}'，"
        f"共检出 {len(recs)} 项加固建议"
    )

    profile = MitigationProfile(
        format=session.format,
        arch=session.arch,
        score=score,
        exploit_difficulty=difficulty.value,
        mitigations=mits,
        summary=summary,
        recommendations=recs,
    )
    return profile.to_dict()
