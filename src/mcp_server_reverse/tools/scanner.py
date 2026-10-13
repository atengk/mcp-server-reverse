"""字符串提取与特征扫描 MCP 工具实现

提供 search_strings 与 search_bytes_and_constants 核心业务逻辑包装。

@author Ateng
@since 2026-10-13
"""

import re
from typing import Any

from mcp_server_reverse.core.locator import ToolLocator
from mcp_server_reverse.core.models import (
    ErrorCode,
    PaginationInfo,
    create_error_response,
    create_response,
)
from mcp_server_reverse.core.scanner import scan_crypto_signatures, search_hex_pattern
from mcp_server_reverse.core.session import SessionStore
from mcp_server_reverse.core.strings import extract_strings
from mcp_server_reverse.tools.session import get_session_or_error

VALID_ENCODINGS: tuple[str, ...] = ("ascii", "utf16le", "all")
VALID_IOC_CATEGORIES: tuple[str, ...] = (
    "url",
    "ipv4",
    "filepath",
    "registry",
    "email",
    "crypto_or_key",
    "suspicious_cmd",
)


def search_strings_impl(
    session_id: str,
    pattern: str | None,
    min_length: int,
    encoding: str,
    ioc_category: str | None,
    section_name: str | None,
    use_floss: bool,
    offset: int,
    limit: int,
    session_store: SessionStore,
    locator: ToolLocator | None = None,
) -> dict[str, Any]:
    """search_strings 核心业务实现

    @param session_id 目标会话唯一标识
    @param pattern 正则过滤表达式
    @param min_length 最小字符串长度
    @param encoding 编码格式 ("ascii", "utf16le", "all")
    @param ioc_category 7 类威胁情报标签之一
    @param section_name 所属节区过滤
    @param use_floss 是否启用 floss 解码
    @param offset 分页偏移量
    @param limit 单页最大条目数
    @param session_store 会话池实例
    @param locator 工具定位器实例
    @return dict[str, Any] 统一响应信封字典
    """
    # 1. 验证会话存在性
    session, err_resp = get_session_or_error(session_id, session_store)
    if err_resp is not None or session is None:
        return err_resp or {}

    # 2. 校验入参格式
    effective_encoding = encoding.lower() if encoding else "all"
    if effective_encoding not in VALID_ENCODINGS:
        return create_error_response(
            code=ErrorCode.INVALID_PARAMETER,
            message=f"不支持的字符串编码格式: '{encoding}'",
            suggestion=f"encoding 可选值为: {', '.join(VALID_ENCODINGS)}",
            session_id=session_id,
        ).to_dict()

    if ioc_category and ioc_category not in VALID_IOC_CATEGORIES:
        return create_error_response(
            code=ErrorCode.INVALID_PARAMETER,
            message=f"不支持的 IOC 威胁类别: '{ioc_category}'",
            suggestion=f"ioc_category 可选值为: {', '.join(VALID_IOC_CATEGORIES)}",
            session_id=session_id,
        ).to_dict()

    # 3. 提取与正则过滤防御
    safe_offset = max(0, offset)
    safe_limit = max(1, min(limit, 500))

    try:
        items, total, floss_status = extract_strings(
            session=session,
            min_length=min_length,
            encoding=effective_encoding,
            pattern=pattern,
            ioc_category=ioc_category,
            section_name=section_name,
            offset=safe_offset,
            limit=safe_limit,
            use_floss=use_floss,
            locator=locator,
        )
    except re.error as exc:
        return create_error_response(
            code=ErrorCode.INVALID_PARAMETER,
            message=f"字符串 pattern 正则表达式语法错误: {exc}",
            suggestion="请检查输入的 pattern 正则表达式语法",
            session_id=session_id,
        ).to_dict()

    pagination = PaginationInfo(
        total=total,
        offset=safe_offset,
        limit=safe_limit,
        has_more=(safe_offset + len(items) < total),
    )

    summary_text = f"成功检索到 {total} 条匹配字符串（当前返回 {len(items)} 条）"
    if floss_status and "软降级" in floss_status:
        summary_text += f"；[提示] {floss_status}"

    return create_response(
        session_id=session_id,
        summary=summary_text,
        pagination=pagination,
        data={
            "strings": [s.to_dict() for s in items],
            "floss_status": floss_status,
        },
    ).to_dict()


def search_bytes_and_constants_impl(
    session_id: str,
    hex_pattern: str | None,
    scan_crypto: bool,
    section_name: str | None,
    offset: int,
    limit: int,
    session_store: SessionStore,
) -> dict[str, Any]:
    """search_bytes_and_constants 核心业务实现

    @param session_id 目标会话唯一标识
    @param hex_pattern 类 IDA 十六进制通配符搜索模式
    @param scan_crypto 是否扫描内置密码学魔数常量表
    @param section_name 所属节区过滤
    @param offset 分页偏移量
    @param limit 单页最大条目数
    @param session_store 会话池实例
    @return dict[str, Any] 统一响应信封字典
    """
    # 1. 验证会话存在性
    session, err_resp = get_session_or_error(session_id, session_store)
    if err_resp is not None or session is None:
        return err_resp or {}

    # 2. 校验是否至少指定了一项检索模式
    if not hex_pattern and not scan_crypto:
        return create_error_response(
            code=ErrorCode.INVALID_PARAMETER,
            message="必须提供 hex_pattern 搜索模式或设置 scan_crypto=True",
            suggestion=(
                "请传入如 '48 89 ? 24' 的 hex_pattern 或开启 scan_crypto=True 扫描密码学魔数"
            ),
            session_id=session_id,
        ).to_dict()

    safe_offset = max(0, offset)
    safe_limit = max(1, min(limit, 500))

    all_hex_matches: list[dict[str, Any]] = []
    all_crypto_matches: list[dict[str, Any]] = []

    # 3. 执行十六进制通配符搜索（获取全量匹配以供统一全局分页）
    if hex_pattern:
        try:
            h_items, _ = search_hex_pattern(
                session=session,
                pattern_str=hex_pattern,
                section_name=section_name,
                offset=0,
                limit=10000,
            )
            all_hex_matches = [m.to_dict() for m in h_items]
        except ValueError as exc:
            return create_error_response(
                code=ErrorCode.INVALID_PARAMETER,
                message=f"十六进制模式格式错误: {exc}",
                suggestion="请检查 hex_pattern 格式，支持形式如 '48 89 5C 24 ? 57' 或 '??'",
                session_id=session_id,
            ).to_dict()

    # 4. 执行密码学魔数特征扫描（获取全量匹配以供统一全局分页）
    if scan_crypto:
        c_items, _ = scan_crypto_signatures(
            session=session,
            section_name=section_name,
            offset=0,
            limit=10000,
        )
        all_crypto_matches = [s.to_dict() for s in c_items]

    hex_total = len(all_hex_matches)
    crypto_total = len(all_crypto_matches)
    combined_total = hex_total + crypto_total

    # 5. 全局联合切片：严格限制单页返回总条目数 <= safe_limit
    paged_hex: list[dict[str, Any]] = []
    paged_crypto: list[dict[str, Any]] = []

    # 统一分配 offset 和 limit
    if safe_offset < hex_total:
        paged_hex = all_hex_matches[safe_offset : safe_offset + safe_limit]
        remaining_limit = safe_limit - len(paged_hex)
        if remaining_limit > 0:
            paged_crypto = all_crypto_matches[:remaining_limit]
    else:
        crypto_offset = safe_offset - hex_total
        paged_crypto = all_crypto_matches[crypto_offset : crypto_offset + safe_limit]

    returned_total = len(paged_hex) + len(paged_crypto)
    pagination = PaginationInfo(
        total=combined_total,
        offset=safe_offset,
        limit=safe_limit,
        has_more=(safe_offset + returned_total < combined_total),
    )

    summary_parts: list[str] = []
    if hex_pattern:
        summary_parts.append(f"Hex 匹配 {hex_total} 处")
    if scan_crypto:
        summary_parts.append(f"检出密码学签名 {crypto_total} 项")

    return create_response(
        session_id=session_id,
        summary=f"特征扫描完成: {', '.join(summary_parts)}",
        pagination=pagination,
        data={
            "hex_matches": paged_hex,
            "crypto_signatures": paged_crypto,
        },
    ).to_dict()
