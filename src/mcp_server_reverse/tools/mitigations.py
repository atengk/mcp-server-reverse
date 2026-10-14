"""全平台二进制漏洞缓解机制加固审计与安全评分 MCP 工具

@author Ateng
@since 2026-10-14
"""

from typing import Any

from mcp_server_reverse.core.mitigations import audit_mitigations_core
from mcp_server_reverse.core.models import create_response
from mcp_server_reverse.core.session import SessionStore
from mcp_server_reverse.tools.session import get_session_or_error


def audit_mitigations_impl(
    session_id: str,
    session_store: SessionStore | None = None,
) -> dict[str, Any]:
    """审计目标二进制文件的全平台漏洞缓解机制并计算加权安全评分

    @param session_id 当前激活的二进制分析会话唯一标识
    @param session_store 全局 LRU 会话缓存池
    @return dict[str, Any] 符合 MCP 规范的统一响应信封字典
    """
    store = session_store if session_store is not None else SessionStore()
    session, err_resp = get_session_or_error(session_id, store)
    if err_resp is not None or session is None:
        return err_resp or {}

    profile_data = audit_mitigations_core(session)
    summary = profile_data.get("summary", "完成漏洞缓解机制加固审计")

    return create_response(summary=summary, data=profile_data, session_id=session_id).to_dict()
