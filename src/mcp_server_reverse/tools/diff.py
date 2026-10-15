"""跨会话二阶结构化差异画像 MCP 工具实现

提供 diff_sessions 业务逻辑处理，对比两个活跃分析会话，
量化同源相似度分值并结构化输出双向差异画像。

@author Ateng
@since 2026-10-15
"""

from typing import Any

from mcp_server_reverse.core.diff import compare_sessions_core
from mcp_server_reverse.core.models import (
    ErrorCode,
    create_error_response,
    create_response,
)
from mcp_server_reverse.core.session import SessionStore


def diff_sessions_impl(
    session_id_a: str,
    session_id_b: str,
    session_store: SessionStore,
) -> dict[str, Any]:
    """比对两个活跃二进制分析会话的结构化差异

    @author Ateng
    @since 2026-10-15
    @param session_id_a 基准分析会话标识
    @param session_id_b 比对目标会话标识
    @param session_store 会话池实例
    @return dict[str, Any] 统一响应信封字典
    """
    session_a = session_store.get(session_id_a)
    if not session_a:
        return create_error_response(
            code=ErrorCode.SESSION_NOT_FOUND,
            message=f"基准会话 '{session_id_a}' 不存在或已过期",
            suggestion="请通过 open_binary 先行打开目标二进制或通过 list_sessions 查询有效会话列表",
            session_id=session_id_a,
        ).to_dict()

    session_b = session_store.get(session_id_b)
    if not session_b:
        return create_error_response(
            code=ErrorCode.SESSION_NOT_FOUND,
            message=f"比对目标会话 '{session_id_b}' 不存在或已过期",
            suggestion="请通过 open_binary 先行打开比对二进制或通过 list_sessions 查询有效会话列表",
            session_id=session_id_b,
        ).to_dict()

    diff_result = compare_sessions_core(session_a, session_b)
    data = diff_result.to_dict()

    mod_sec_count = len(data.get("sections", {}).get("modified", []))
    added_imp_count = len(data.get("imports", {}).get("added", []))
    removed_imp_count = len(data.get("imports", {}).get("removed", []))
    score = diff_result.similarity_score

    summary = (
        f"会话 {session_id_a} 与 {session_id_b} 差异分析完成: "
        f"同源相似度 {score}%，节区变更 {mod_sec_count} 项，"
        f"导入函数变更 +{added_imp_count}/-{removed_imp_count}"
    )

    return create_response(
        session_id=session_id_a,
        summary=summary,
        data=data,
    ).to_dict()
