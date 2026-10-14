"""会话级写时复制 (COW) 内存虚拟打补丁与原子回滚 MCP 工具

支持在进程内内存会话中对指定虚拟地址或文件物理偏移应用十六进制字节修改，
底层内存读取与反汇编接口透明叠加补丁覆写层，物理文件 100% 只读保真。

@author Ateng
@since 2026-10-14
"""

from typing import Any

from mcp_server_reverse.core.memory import convert_address_core
from mcp_server_reverse.core.models import (
    ErrorCode,
    PatchRecord,
    PatchStatus,
    create_error_response,
    create_response,
)
from mcp_server_reverse.core.session import SessionStore
from mcp_server_reverse.tools.session import get_session_or_error


def patch_memory_impl(
    session_id: str,
    address_or_offset: str,
    patch_hex: str,
    address_type: str = "va",
    session_store: SessionStore | None = None,
) -> dict[str, Any]:
    """在当前会话的内存覆写层中应用一条十六进制虚拟补丁

    @param session_id 当前激活的二进制分析会话唯一标识
    @param address_or_offset 补丁目标地址表达式或物理偏移字符串
    @param patch_hex 十六进制补丁字节字符串 (如 '90 90 CC' 或 'EB 05')
    @param address_type 输入地址类型 ('va', 'rva', 'offset'，缺省 'va')
    @param session_store 全局 LRU 会话缓存池
    @return dict[str, Any] 符合 MCP 规范的响应信封字典
    """
    store = session_store if session_store is not None else SessionStore()
    session, err_resp = get_session_or_error(session_id, store)
    if err_resp is not None or session is None:
        return err_resp or {}

    # 1. 严格校验十六进制补丁输入
    clean_hex = patch_hex.replace(" ", "").strip()
    if not clean_hex:
        return create_error_response(
            code=ErrorCode.INVALID_PARAMETER,
            message="补丁十六进制字符串不能为空",
            suggestion="请提供非空的有效十六进制字符串 (如 '90 90 CC')",
            session_id=session_id,
        ).to_dict()

    if len(clean_hex) % 2 != 0:
        return create_error_response(
            code=ErrorCode.INVALID_PARAMETER,
            message=f"补丁十六进制字符数必须为偶数，当前字符数为 {len(clean_hex)}",
            suggestion="请确保每个字节由 2 位十六进制字符组成 (如 '90' 或 'EB 05')",
            session_id=session_id,
        ).to_dict()

    try:
        patch_bytes = bytes.fromhex(clean_hex)
    except ValueError:
        return create_error_response(
            code=ErrorCode.INVALID_PARAMETER,
            message=f"补丁字符串包含非法的十六进制字符: '{patch_hex}'",
            suggestion="请只使用 0-9、A-F 范围内的十六进制字符",
            session_id=session_id,
        ).to_dict()

    # 2. 换算目标地址与节区归属
    try:
        conv = convert_address_core(session, address_or_offset, address_type)
    except ValueError as exc:
        return create_error_response(
            code=ErrorCode.INVALID_PARAMETER,
            message=str(exc),
            suggestion="请检查地址格式与 address_type (可选值为 va, rva, offset)",
            session_id=session_id,
        ).to_dict()
    except LookupError as exc:
        return create_error_response(
            code=ErrorCode.ADDRESS_OR_SYMBOL_NOT_FOUND,
            message=str(exc),
            suggestion="请确认目标地址落在合法的可映射节区范围内",
            session_id=session_id,
        ).to_dict()

    file_off = conv["offset"]
    if file_off is None:
        return create_error_response(
            code=ErrorCode.INVALID_PARAMETER,
            message=f"地址 {conv['va']} 位于未初始化的数据段 (BSS)，无物理字节可打补丁",
            suggestion="请针对具有物理文件映射的节区 (如 .text, .data, .rdata) 打补丁",
            session_id=session_id,
        ).to_dict()

    if file_off + len(patch_bytes) > session.file_size:
        return create_error_response(
            code=ErrorCode.INVALID_PARAMETER,
            message=(
                f"补丁范围超出物理文件末尾 (offset: {file_off}, "
                f"size: {len(patch_bytes)}, file_size: {session.file_size})"
            ),
            suggestion="请调整补丁地址或缩短补丁长度",
            session_id=session_id,
        ).to_dict()

    # 3. 提取被覆盖前的当前有效字节
    orig_bytes = session.read_effective_bytes(file_off, len(patch_bytes))
    orig_hex = orig_bytes.hex(" ").upper()
    patch_hex_formatted = patch_bytes.hex(" ").upper()

    # 4. 构造补丁条目并原子应用至 COW 内存覆写层
    active_count = len([p for p in session.patches if p.status == PatchStatus.ACTIVE.value])
    patch_id = f"patch_{active_count + 1:04d}"
    record = PatchRecord(
        patch_id=patch_id,
        target_address=conv["va"],
        file_offset=file_off,
        size=len(patch_bytes),
        original_bytes_hex=orig_hex,
        patch_bytes_hex=patch_hex_formatted,
        section=conv["section"],
        status=PatchStatus.ACTIVE.value,
        raw_patch_bytes=patch_bytes,
    )
    session.apply_patch(record, patch_bytes)

    data = {
        "patch_id": record.patch_id,
        "target_address": record.target_address,
        "file_offset": record.file_offset,
        "size": record.size,
        "original_bytes_hex": record.original_bytes_hex,
        "patch_bytes_hex": record.patch_bytes_hex,
        "section": record.section,
        "status": record.status,
    }
    summary = (
        f"成功在虚拟地址 {record.target_address} "
        f"(偏移 0x{record.file_offset:X}, 节区 {record.section}) "
        f"应用内存虚拟补丁 {record.patch_id} (尺寸 {record.size} 字节，物理文件保持只读)"
    )
    return create_response(summary=summary, data=data, session_id=session_id).to_dict()


def list_patches_impl(
    session_id: str,
    include_reverted: bool = False,
    session_store: SessionStore | None = None,
) -> dict[str, Any]:
    """查看当前会话中已应用的内存虚拟补丁条目

    @param session_id 当前激活的二进制分析会话唯一标识
    @param include_reverted 是否包含已撤回的历史补丁记录 (默认 False 仅展示激活补丁)
    @param session_store 全局 LRU 会话缓存池
    @return dict[str, Any] 符合 MCP 规范的响应信封字典
    """
    store = session_store if session_store is not None else SessionStore()
    session, err_resp = get_session_or_error(session_id, store)
    if err_resp is not None or session is None:
        return err_resp or {}

    if include_reverted:
        patches_list = [p.to_dict() for p in session.patches]
    else:
        patches_list = [
            p.to_dict() for p in session.patches if p.status == PatchStatus.ACTIVE.value
        ]

    data = {
        "patches": patches_list,
        "total": len(patches_list),
    }
    summary = f"当前会话已生效 {len(patches_list)} 条内存虚拟补丁 (COW 覆写层生效中，物理文件只读)"
    return create_response(summary=summary, data=data, session_id=session_id).to_dict()


def revert_patch_impl(
    session_id: str,
    patch_id: str | None = None,
    session_store: SessionStore | None = None,
) -> dict[str, Any]:
    """撤回指定 ID 的补丁或全量回滚当前会话的全部虚拟补丁

    @param session_id 当前激活的二进制分析会话唯一标识
    @param patch_id 待撤回的补丁 ID (如 'patch_0001')，缺省为 None 时全量回滚
    @param session_store 全局 LRU 会话缓存池
    @return dict[str, Any] 符合 MCP 规范的响应信封字典
    """
    store = session_store if session_store is not None else SessionStore()
    session, err_resp = get_session_or_error(session_id, store)
    if err_resp is not None or session is None:
        return err_resp or {}

    try:
        reverted_ids = session.revert_patch(patch_id)
    except LookupError as exc:
        return create_error_response(
            code=ErrorCode.INVALID_PARAMETER,
            message=str(exc),
            suggestion="请调用 list_patches 工具查看当前有效的 patch_id 列表",
            session_id=session_id,
        ).to_dict()

    remaining_count = len([p for p in session.patches if p.status == PatchStatus.ACTIVE.value])
    data = {
        "reverted_patch_ids": reverted_ids,
        "remaining_patches_count": remaining_count,
    }
    summary = (
        f"成功回滚补丁: {', '.join(reverted_ids) if reverted_ids else '无'}，"
        f"当前剩余激活补丁: {remaining_count} 条"
    )
    return create_response(summary=summary, data=data, session_id=session_id).to_dict()
