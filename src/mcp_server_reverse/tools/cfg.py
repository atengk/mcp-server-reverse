"""函数控制流图 (CFG) 与基本块分析 MCP 工具

@author Ateng
@since 2026-10-14
"""

from typing import Any

from mcp_server_reverse.core.cfg import build_cfg_core
from mcp_server_reverse.core.memory import resolve_target_address
from mcp_server_reverse.core.models import (
    ErrorCode,
    create_error_response,
    create_response,
)
from mcp_server_reverse.core.session import SessionStore
from mcp_server_reverse.tools.session import get_session_or_error


def analyze_cfg_impl(
    session_id: str,
    target: str | int,
    max_blocks: int = 100,
    session_store: SessionStore | None = None,
) -> dict[str, Any]:
    """抽取指定函数入口或符号的单入口单出口基本块、控制流拓扑与 Mermaid 流程图

    @param session_id 当前激活的二进制分析会话唯一标识
    @param target 目标函数起始虚拟地址表达式 (如 '0x140001000') 或符号名称
    @param max_blocks 最大提取基本块数量上限 (默认 100)
    @param session_store 全局 LRU 会话缓存池
    @return dict[str, Any] 符合 MCP 规范的统一响应信封字典
    """
    store = session_store if session_store is not None else SessionStore()
    session, err_resp = get_session_or_error(session_id, store)
    if err_resp is not None or session is None:
        return err_resp or {}

    if max_blocks <= 0:
        return create_error_response(
            code=ErrorCode.INVALID_PARAMETER,
            message=f"max_blocks 必须大于 0，当前传入为 {max_blocks}",
            suggestion="请传入正整数 max_blocks 参数 (如 50 或 100)",
            session_id=session_id,
        ).to_dict()

    # 1. 统一决议目标符号或地址
    try:
        target_va = resolve_target_address(session, target)
    except LookupError as exc:
        return create_error_response(
            code=ErrorCode.ADDRESS_OR_SYMBOL_NOT_FOUND,
            message=str(exc),
            suggestion="请使用 get_symbols 检索目标函数符号名或直接传入十六进制绝对地址",
            session_id=session_id,
        ).to_dict()

    # 2. 调用核心控制流图分析引擎
    try:
        cfg_data = build_cfg_core(
            session=session,
            target_va=target_va,
            max_blocks=max_blocks,
        )
    except LookupError as exc:
        return create_error_response(
            code=ErrorCode.ADDRESS_OR_SYMBOL_NOT_FOUND,
            message=str(exc),
            suggestion="请确认目标地址位于可执行代码节区 (.text / __text) 且包含有效指令",
            session_id=session_id,
        ).to_dict()

    summary = (
        f"成功分析函数 0x{target_va:X} 的控制流图: 包含 {cfg_data['block_count']} 个基本块，"
        f"圈复杂度为 {cfg_data['cyclomatic_complexity']}，已生成 Mermaid 流程图"
    )
    return create_response(summary=summary, data=cfg_data, session_id=session_id).to_dict()
