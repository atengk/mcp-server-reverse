"""跨会话二阶结构化差异画像对比引擎

负责提取并深度对齐两个活跃会话的模糊哈希同源相似度、基础架构特征、
利用缓解配置、节区拓扑与香农熵差异、导入导出敏感行为集及代码段符号重定位基址偏移。

@author Ateng
@since 2026-10-15
"""

from collections import Counter
from typing import Any

from mcp_server_reverse.core.forensic import compute_fuzzy_hash
from mcp_server_reverse.core.inspection import (
    extract_exports,
    extract_imports,
    extract_sections,
    extract_symbols,
)
from mcp_server_reverse.core.mitigations import audit_mitigations_core
from mcp_server_reverse.core.models import BinaryDiff
from mcp_server_reverse.core.session import BinarySession


def _levenshtein(s1: str, s2: str) -> int:
    """计算两个字符串之间的编辑距离 (Levenshtein Distance)

    @param s1 源字符串
    @param s2 目标字符串
    @return int 最小编辑步骤数
    """
    if len(s1) < len(s2):
        return _levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)
    prev = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        curr = [i + 1] * (len(s2) + 1)
        for j, c2 in enumerate(s2):
            insertions = prev[j + 1] + 1
            deletions = curr[j] + 1
            substitutions = prev[j] + (c1 != c2)
            curr[j + 1] = min(insertions, deletions, substitutions)
        prev = curr
    return prev[len(s2)]


def _score_strings(a: str, b: str) -> int:
    """计算两个分段哈希字符序列的归一化相似度分值 (0 ~ 100)"""
    if a == b:
        return 100
    max_len = max(len(a), len(b))
    if max_len == 0:
        return 100
    dist = _levenshtein(a, b)
    if dist >= max_len:
        return 0
    return max(0, min(100, int((1.0 - (dist / max_len)) * 100)))


def compute_fuzzy_hash_similarity(hash_a: str | None, hash_b: str | None) -> int:
    """根据标准 SSDEEP / CTPH 算法协议比对两个分段模糊哈希的相似度

    @author Ateng
    @since 2026-10-15
    @param hash_a 会话 A 的模糊哈希 (如 '384:abc:def')
    @param hash_b 会话 B 的模糊哈希
    @return int 0 ~ 100 的同源相似度分值
    """
    if not hash_a or not hash_b:
        return 0
    if hash_a == hash_b:
        return 100

    parts_a = hash_a.split(":")
    parts_b = hash_b.split(":")
    if len(parts_a) != 3 or len(parts_b) != 3:
        return 0

    try:
        bs_a = int(parts_a[0])
        bs_b = int(parts_b[0])
    except ValueError:
        return 0

    s_a1, s_a2 = parts_a[1], parts_a[2]
    s_b1, s_b2 = parts_b[1], parts_b[2]

    # 1. 相同分块步长，分别比对两个分块序列并取最大相似度
    if bs_a == bs_b:
        score1 = _score_strings(s_a1, s_b1)
        score2 = _score_strings(s_a2, s_b2)
        return max(score1, score2)

    # 2. 步长差为 2 倍关系时交叉比对对应子序列
    if bs_a * 2 == bs_b:
        return _score_strings(s_a2, s_b1)
    if bs_b * 2 == bs_a:
        return _score_strings(s_b2, s_a1)

    return 0


def compare_sessions_core(
    session_a: BinarySession,
    session_b: BinarySession,
) -> BinaryDiff:
    """执行跨会话二阶结构化差异画像对比核心算法

    @author Ateng
    @since 2026-10-15
    @param session_a 基准分析会话
    @param session_b 目标比对会话
    @return BinaryDiff 结构化差异画像实体
    """
    # 1. 获取有效模糊哈希并计算相似度分值
    # 若存在激活虚拟补丁则基于修改后的镜像重新计算
    if session_a.patches:
        hash_a = compute_fuzzy_hash(session_a.export_patched_bytes())
    else:
        hash_a = session_a.forensic_metadata.get("fuzzy_hash") or compute_fuzzy_hash(
            session_a.read_effective_bytes(0, None)
        )

    if session_b.patches:
        hash_b = compute_fuzzy_hash(session_b.export_patched_bytes())
    else:
        hash_b = session_b.forensic_metadata.get("fuzzy_hash") or compute_fuzzy_hash(
            session_b.read_effective_bytes(0, None)
        )

    # 若两个会话关联相同文件且均无补丁，直接赋予 100% 相似度
    if (
        session_a.file_path == session_b.file_path
        and not session_a.patches
        and not session_b.patches
    ):
        similarity_score = 100
    else:
        similarity_score = compute_fuzzy_hash_similarity(hash_a, hash_b)

    # 2. 基础文件信息对比
    size_a = session_a.file_info.get("size", 0)
    size_b = session_b.file_info.get("size", 0)
    file_info_diff = {
        "format": {
            "a": session_a.format,
            "b": session_b.format,
            "match": session_a.format == session_b.format,
        },
        "arch": {
            "a": session_a.arch,
            "b": session_b.arch,
            "match": session_a.arch == session_b.arch,
        },
        "bits": {
            "a": session_a.bits,
            "b": session_b.bits,
            "match": session_a.bits == session_b.bits,
        },
        "endian": {
            "a": getattr(session_a, "endianness", "little"),
            "b": getattr(session_b, "endianness", "little"),
            "match": getattr(session_a, "endianness", "little")
            == getattr(session_b, "endianness", "little"),
        },
        "size": {
            "a": size_a,
            "b": size_b,
            "delta": size_b - size_a,
        },
    }

    # 3. 漏洞缓解措施审计与加固配置对比
    prof_a = audit_mitigations_core(session_a)
    prof_b = audit_mitigations_core(session_b)
    mits_a = prof_a.get("mitigations", {})
    mits_b = prof_b.get("mitigations", {})

    changed_mitigations: dict[str, Any] = {}
    for k in sorted(set(mits_a.keys()) | set(mits_b.keys())):
        v_a = mits_a.get(k)
        v_b = mits_b.get(k)
        if v_a != v_b:
            changed_mitigations[k] = {"before": v_a, "after": v_b}

    mitigations_diff = {
        "score_a": prof_a.get("score", 0),
        "score_b": prof_b.get("score", 0),
        "score_delta": prof_b.get("score", 0) - prof_a.get("score", 0),
        "exploit_difficulty_a": prof_a.get("exploit_difficulty", "Unknown"),
        "exploit_difficulty_b": prof_b.get("exploit_difficulty", "Unknown"),
        "changed": changed_mitigations,
    }

    # 4. 节区拓扑与香农熵差异比对
    secs_a = extract_sections(session_a)
    secs_b = extract_sections(session_b)
    map_sec_a = {s.name: s for s in secs_a}
    map_sec_b = {s.name: s for s in secs_b}

    added_sections = [map_sec_b[n].to_dict() for n in map_sec_b if n not in map_sec_a]
    removed_sections = [map_sec_a[n].to_dict() for n in map_sec_a if n not in map_sec_b]

    common_sections: list[dict[str, Any]] = []
    modified_sections: list[dict[str, Any]] = []
    newly_high_entropy_sections: list[str] = []

    for name, sec_a in map_sec_a.items():
        if name in map_sec_b:
            sec_b = map_sec_b[name]
            vsize_delta = sec_b.virtual_size - sec_a.virtual_size
            rsize_delta = sec_b.raw_size - sec_a.raw_size
            entropy_delta = round(sec_b.entropy - sec_a.entropy, 4)
            is_new_high = not sec_a.is_high_entropy and sec_b.is_high_entropy
            if is_new_high:
                newly_high_entropy_sections.append(name)

            sec_item = {
                "name": name,
                "virtual_size_delta": vsize_delta,
                "raw_size_delta": rsize_delta,
                "entropy_a": round(sec_a.entropy, 4),
                "entropy_b": round(sec_b.entropy, 4),
                "entropy_delta": entropy_delta,
                "is_high_entropy_a": sec_a.is_high_entropy,
                "is_high_entropy_b": sec_b.is_high_entropy,
                "is_newly_high_entropy": is_new_high,
            }
            common_sections.append(sec_item)
            if vsize_delta != 0 or rsize_delta != 0 or entropy_delta != 0.0 or is_new_high:
                modified_sections.append(sec_item)

    for sec in added_sections:
        if sec.get("is_high_entropy"):
            newly_high_entropy_sections.append(sec["name"])

    sections_diff = {
        "added": added_sections,
        "removed": removed_sections,
        "modified": modified_sections,
        "common": common_sections,
        "newly_high_entropy_sections": sorted(list(set(newly_high_entropy_sections))),
    }

    # 5. 导入与导出 API 敏感集合比对
    imps_a, _ = extract_imports(session_a, limit=100000)
    imps_b, _ = extract_imports(session_b, limit=100000)

    map_imp_a = {f"{i.library or ''}::{i.name}": i for i in imps_a}
    map_imp_b = {f"{i.library or ''}::{i.name}": i for i in imps_b}

    added_imports = [
        {"name": imp.name, "library": imp.library, "category": imp.category}
        for k, imp in map_imp_b.items()
        if k not in map_imp_a
    ]
    removed_imports = [
        {"name": imp.name, "library": imp.library, "category": imp.category}
        for k, imp in map_imp_a.items()
        if k not in map_imp_b
    ]
    common_import_count = len(set(map_imp_a.keys()) & set(map_imp_b.keys()))

    added_suspicious_categories = sorted(
        list({imp["category"] for imp in added_imports if imp.get("category")})
    )

    imports_diff = {
        "added": added_imports,
        "removed": removed_imports,
        "common_count": common_import_count,
        "added_suspicious_categories": added_suspicious_categories,
    }

    exps_a, _ = extract_exports(session_a, limit=100000)
    exps_b, _ = extract_exports(session_b, limit=100000)
    exp_names_a = {e["name"] for e in exps_a if e.get("name")}
    exp_names_b = {e["name"] for e in exps_b if e.get("name")}

    exports_diff = {
        "added": sorted(list(exp_names_b - exp_names_a)),
        "removed": sorted(list(exp_names_a - exp_names_b)),
        "common_count": len(exp_names_a & exp_names_b),
    }

    # 6. 函数符号重定位与代码变动对比
    syms_a, _ = extract_symbols(session_a, limit=100000)
    syms_b, _ = extract_symbols(session_b, limit=100000)

    funcs_a = {
        (s.demangled_name or s.name): s
        for s in syms_a
        if s.symbol_type in ("function", "exception_frame", "eh_frame", "prologue") and s.name
    }
    funcs_b = {
        (s.demangled_name or s.name): s
        for s in syms_b
        if s.symbol_type in ("function", "exception_frame", "eh_frame", "prologue") and s.name
    }

    common_func_names = set(funcs_a.keys()) & set(funcs_b.keys())
    va_deltas: list[int] = []
    modified_functions: list[dict[str, Any]] = []

    for name in sorted(common_func_names):
        sa = funcs_a[name]
        sb = funcs_b[name]
        va_a = int(sa.address, 16) if sa.address and sa.address != "0x0" else None
        va_b = int(sb.address, 16) if sb.address and sb.address != "0x0" else None

        if va_a is not None and va_b is not None:
            delta = va_b - va_a
            va_deltas.append(delta)
            if delta != 0 or sa.size != sb.size:
                modified_functions.append(
                    {
                        "name": name,
                        "address_a": sa.address,
                        "address_b": sb.address,
                        "va_delta": delta,
                        "size_a": sa.size,
                        "size_b": sb.size,
                        "size_delta": sb.size - sa.size,
                    }
                )

    base_relocation_offset = "0x0"
    if va_deltas:
        counts = Counter(va_deltas)
        most_common_delta, count = counts.most_common(1)[0]
        if most_common_delta != 0 and count >= 1:
            if most_common_delta >= 0:
                base_relocation_offset = f"0x{most_common_delta:X}"
            else:
                base_relocation_offset = f"-0x{-most_common_delta:X}"

    added_functions = sorted(list(set(funcs_b.keys()) - set(funcs_a.keys())))
    removed_functions = sorted(list(set(funcs_a.keys()) - set(funcs_b.keys())))

    symbols_diff = {
        "base_relocation_offset": base_relocation_offset,
        "added_functions": added_functions,
        "removed_functions": removed_functions,
        "modified_functions": modified_functions,
        "common_count": len(common_func_names),
    }

    return BinaryDiff(
        session_id_a=session_a.session_id,
        session_id_b=session_b.session_id,
        similarity_score=similarity_score,
        file_info=file_info_diff,
        mitigations=mitigations_diff,
        sections=sections_diff,
        imports=imports_diff,
        exports=exports_diff,
        symbols=symbols_diff,
    )
