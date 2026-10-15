"""结构与符号检视 MCP 工具实现

提供 get_sections、get_imports、get_exports 与 get_symbols 工具核心业务逻辑。

@author Ateng
@since 2026-10-13
"""

import re
from typing import Any

from mcp_server_reverse.core.inspection import (
    extract_exports,
    extract_imports,
    extract_sections,
    extract_symbols,
)
from mcp_server_reverse.core.models import (
    ErrorCode,
    PaginationInfo,
    create_error_response,
    create_response,
)
from mcp_server_reverse.core.session import SessionStore
from mcp_server_reverse.tools.session import get_session_or_error


def get_sections_impl(
    session_id: str,
    session_store: SessionStore,
    name_filter: str | None = None,
    detect_local_entropy: bool = True,
    window_size: int = 2048,
    step: int = 1024,
) -> dict[str, Any]:
    """get_sections 核心业务实现

    @param session_id 目标会话唯一标识
    @param session_store 会话池实例
    @param name_filter 可选的节区名称正则过滤
    @param detect_local_entropy 是否启用基于滑动窗口的细粒度局部高熵块探测 (缺省 True)
    @param window_size 滑动窗口字节尺寸 (缺省 2048)
    @param step 滑动步长 (缺省 1024)
    @return dict[str, Any] 统一响应信封字典
    """
    session, err_resp = get_session_or_error(session_id, session_store)
    if err_resp is not None or session is None:
        return err_resp or {}

    sections = extract_sections(
        session,
        detect_local_entropy=detect_local_entropy,
        window_size=window_size,
        step=step,
    )
    if name_filter:
        try:
            pattern = re.compile(name_filter, re.IGNORECASE)
            sections = [s for s in sections if pattern.search(s.name)]
        except re.error:
            sections = [s for s in sections if name_filter.lower() in s.name.lower()]

    return create_response(
        session_id=session_id,
        summary=f"成功提取 {len(sections)} 个节区/段分布画像",
        data={"sections": [s.to_dict() for s in sections]},
    ).to_dict()


def get_imports_impl(
    session_id: str,
    library_filter: str | None,
    name_filter: str | None,
    category: str | None,
    offset: int,
    limit: int,
    session_store: SessionStore,
) -> dict[str, Any]:
    """get_imports 核心业务实现

    @param session_id 目标会话唯一标识
    @param library_filter 动态库名称正则过滤表达式
    @param name_filter 函数符号名称正则过滤表达式
    @param category 8 类启发式敏感行为标签之一
    @param offset 分页偏移量
    @param limit 单页最大条目数 (上限 500)
    @param session_store 会话池实例
    @return dict[str, Any] 统一响应信封字典
    """
    session, err_resp = get_session_or_error(session_id, session_store)
    if err_resp is not None or session is None:
        return err_resp or {}

    safe_limit = max(1, min(limit, 500))
    safe_offset = max(0, offset)

    try:
        items, total = extract_imports(
            session=session,
            library_filter=library_filter,
            name_filter=name_filter,
            category=category,
            offset=safe_offset,
            limit=safe_limit,
        )
    except re.error as exc:
        return create_error_response(
            code=ErrorCode.INVALID_PARAMETER,
            message=f"正则表达式语法错误: {exc}",
            suggestion="请检查输入的 library_filter 或 name_filter 正则表达式语法",
            session_id=session_id,
        ).to_dict()

    pagination = PaginationInfo(
        total=total,
        offset=safe_offset,
        limit=safe_limit,
        has_more=(safe_offset + len(items) < total),
    )

    return create_response(
        session_id=session_id,
        summary=f"成功检索到 {total} 个匹配导入项（当前返回 {len(items)} 条）",
        pagination=pagination,
        data={"imports": [item.to_dict() for item in items]},
    ).to_dict()


def get_exports_impl(
    session_id: str,
    name_filter: str | None,
    offset: int,
    limit: int,
    session_store: SessionStore,
) -> dict[str, Any]:
    """get_exports 核心业务实现

    @param session_id 目标会话唯一标识
    @param name_filter 符号名称正则过滤表达式
    @param offset 分页偏移量
    @param limit 单页最大条目数 (上限 500)
    @param session_store 会话池实例
    @return dict[str, Any] 统一响应信封字典
    """
    session, err_resp = get_session_or_error(session_id, session_store)
    if err_resp is not None or session is None:
        return err_resp or {}

    safe_limit = max(1, min(limit, 500))
    safe_offset = max(0, offset)

    try:
        items, total = extract_exports(
            session=session,
            name_filter=name_filter,
            offset=safe_offset,
            limit=safe_limit,
        )
    except re.error as exc:
        return create_error_response(
            code=ErrorCode.INVALID_PARAMETER,
            message=f"正则表达式语法错误: {exc}",
            suggestion="请检查输入的 name_filter 正则表达式语法",
            session_id=session_id,
        ).to_dict()

    pagination = PaginationInfo(
        total=total,
        offset=safe_offset,
        limit=safe_limit,
        has_more=(safe_offset + len(items) < total),
    )

    return create_response(
        session_id=session_id,
        summary=f"成功检索到 {total} 个匹配导出项（当前返回 {len(items)} 条）",
        pagination=pagination,
        data={"exports": items},
    ).to_dict()


def get_symbols_impl(
    session_id: str,
    name_filter: str | None,
    symbol_type: str | None,
    offset: int,
    limit: int,
    session_store: SessionStore,
) -> dict[str, Any]:
    """get_symbols 核心业务实现

    @param session_id 目标会话唯一标识
    @param name_filter 符号名称正则过滤表达式
    @param symbol_type 符号类型过滤 ("function", "object", "exception_frame", "all")
    @param offset 分页偏移量
    @param limit 单页最大条目数 (上限 500)
    @param session_store 会话池实例
    @return dict[str, Any] 统一响应信封字典
    """
    session, err_resp = get_session_or_error(session_id, session_store)
    if err_resp is not None or session is None:
        return err_resp or {}

    effective_type = symbol_type if symbol_type is not None else "all"
    valid_types = ("function", "object", "exception_frame", "eh_frame", "prologue", "all")
    if effective_type not in valid_types:
        return create_error_response(
            code=ErrorCode.INVALID_PARAMETER,
            message=f"不支持的 symbol_type: '{effective_type}'",
            suggestion=f"symbol_type 可选值为: {', '.join(valid_types)}",
            session_id=session_id,
        ).to_dict()

    safe_limit = max(1, min(limit, 500))
    safe_offset = max(0, offset)

    try:
        items, total = extract_symbols(
            session=session,
            name_filter=name_filter,
            symbol_type=effective_type,
            offset=safe_offset,
            limit=safe_limit,
        )
    except re.error as exc:
        return create_error_response(
            code=ErrorCode.INVALID_PARAMETER,
            message=f"正则表达式语法错误: {exc}",
            suggestion="请检查输入的 name_filter 正则表达式语法",
            session_id=session_id,
        ).to_dict()

    pagination = PaginationInfo(
        total=total,
        offset=safe_offset,
        limit=safe_limit,
        has_more=(safe_offset + len(items) < total),
    )

    return create_response(
        session_id=session_id,
        summary=f"成功检索到 {total} 个匹配符号（当前返回 {len(items)} 条）",
        pagination=pagination,
        data={"symbols": [item.to_dict() for item in items]},
    ).to_dict()
