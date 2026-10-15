"""反汇编、交叉引用、内存检视与反编译 MCP 工具实现

提供 convert_address、read_memory、disassemble、find_xrefs 与 decompile_function 工具核心业务逻辑。

@author Ateng
@since 2026-10-13
"""

import asyncio
import contextlib
from typing import Any

from mcp_server_reverse.core.config import ServerConfig
from mcp_server_reverse.core.disasm import (
    build_xref_index,
    disassemble_at,
    group_xrefs_by_function,
    query_xrefs,
)
from mcp_server_reverse.core.locator import ToolLocator
from mcp_server_reverse.core.memory import (
    convert_address_core,
    read_memory_core,
    resolve_target_address,
)
from mcp_server_reverse.core.models import (
    ErrorCode,
    PaginationInfo,
    create_error_response,
    create_response,
)
from mcp_server_reverse.core.session import SessionStore
from mcp_server_reverse.tools.session import get_session_or_error

VALID_XREF_TYPES: tuple[str, ...] = (
    "all",
    "code",
    "data",
    "call",
    "branch",
    "rip_relative",
    "pc_relative",
    "data_pointer",
)


def convert_address_impl(
    session_id: str,
    address: str | int,
    address_type: str,
    session_store: SessionStore,
    thumb: bool | None = None,
) -> dict[str, Any]:
    """convert_address 核心业务实现

    @param session_id 目标活跃会话标识
    @param address 待转换的地址或偏移量
    @param address_type 输入地址类型 ("va", "rva", "offset")
    @param session_store 会话池实例
    @param thumb 可选的 ARM Thumb 模式控制开关 (None 时偶数保持 ARM、奇数自动校准为 Thumb)
    @return dict[str, Any] 统一响应信封字典
    """
    session, err_resp = get_session_or_error(session_id, session_store)
    if err_resp is not None or session is None:
        return err_resp or {}

    try:
        conv = convert_address_core(
            session=session,
            address=address,
            address_type=address_type,
            thumb=thumb,
        )
    except ValueError as exc:
        return create_error_response(
            code=ErrorCode.INVALID_PARAMETER,
            message=str(exc),
            suggestion=(
                "请检查 address 格式（支持十六进制如 '0x140001000'）"
                "与 address_type ('va', 'rva', 'offset')"
            ),
            session_id=session_id,
        ).to_dict()
    except LookupError as exc:
        return create_error_response(
            code=ErrorCode.ADDRESS_OR_SYMBOL_NOT_FOUND,
            message=str(exc),
            suggestion="请使用 get_sections 确认目标二进制的有效节区虚拟地址与文件偏移范围",
            session_id=session_id,
        ).to_dict()

    return create_response(
        session_id=session_id,
        summary=(
            f"地址换算成功: VA={conv['va']}, RVA={conv['rva']}, "
            f"Offset={conv['offset']} (节区 {conv['section']})"
        ),
        data=conv,
    ).to_dict()


def read_memory_impl(
    session_id: str,
    address: str | int,
    size: int,
    address_type: str,
    session_store: SessionStore,
) -> dict[str, Any]:
    """read_memory 核心业务实现

    @param session_id 目标活跃会话标识
    @param address 起始地址或偏移量
    @param size 读取字节长度 (上限 1024)
    @param address_type 输入地址类型 ("va", "rva", "offset")
    @param session_store 会话池实例
    @return dict[str, Any] 统一响应信封字典
    """
    session, err_resp = get_session_or_error(session_id, session_store)
    if err_resp is not None or session is None:
        return err_resp or {}

    if size <= 0:
        return create_error_response(
            code=ErrorCode.INVALID_PARAMETER,
            message=f"读取字节数 size 必须为正整数，当前值: {size}",
            suggestion="请传入 1 ~ 1024 之间的字节长度",
            session_id=session_id,
        ).to_dict()

    try:
        payload = read_memory_core(
            session=session,
            address=address,
            size=size,
            address_type=address_type,
        )
    except ValueError as exc:
        return create_error_response(
            code=ErrorCode.INVALID_PARAMETER,
            message=str(exc),
            suggestion="请检查输入的 address 与 address_type 参数格式",
            session_id=session_id,
        ).to_dict()
    except LookupError as exc:
        return create_error_response(
            code=ErrorCode.ADDRESS_OR_SYMBOL_NOT_FOUND,
            message=str(exc),
            suggestion="请使用 get_sections 检视有效映射节区范围后再读取内存",
            session_id=session_id,
        ).to_dict()

    return create_response(
        session_id=session_id,
        summary=(
            f"成功从 {payload['start_address']} ({payload['section']}) 读取 {payload['size']} 字节"
        ),
        data=payload,
    ).to_dict()


def disassemble_impl(
    session_id: str,
    target: str | int,
    count: int,
    stop_at_ret: bool,
    session_store: SessionStore,
    thumb: bool | None = None,
) -> dict[str, Any]:
    """disassemble 核心业务实现

    @param session_id 目标活跃会话标识
    @param target 起始十六进制虚拟地址或函数符号名称
    @param count 最大反汇编指令条数 (上限 256)
    @param stop_at_ret 遇到函数返回指令 (ret/retn/retf) 是否提前终止
    @param session_store 会话池实例
    @param thumb 可选的 ARM Thumb 模式控制开关 (None 时偶数保持 ARM、奇数自动校准为 Thumb)
    @return dict[str, Any] 统一响应信封字典
    """
    session, err_resp = get_session_or_error(session_id, session_store)
    if err_resp is not None or session is None:
        return err_resp or {}

    try:
        target_va = resolve_target_address(session, target)
        dis_data = disassemble_at(
            session=session,
            target_va=target_va,
            count=count,
            stop_at_ret=stop_at_ret,
            thumb=thumb,
        )
    except ValueError as exc:
        return create_error_response(
            code=ErrorCode.INVALID_PARAMETER,
            message=str(exc),
            suggestion="请传入合法的十六进制虚拟地址（如 '0x140001000'）或有效符号名称",
            session_id=session_id,
        ).to_dict()
    except LookupError as exc:
        return create_error_response(
            code=ErrorCode.ADDRESS_OR_SYMBOL_NOT_FOUND,
            message=str(exc),
            suggestion="请使用 get_symbols 或 get_exports 确认目标函数名或虚拟地址是否存在",
            session_id=session_id,
        ).to_dict()

    raw_insns = dis_data["instructions"]
    dis_data["instructions"] = [insn.to_dict() for insn in raw_insns]
    dis_data["target"] = str(target)

    return create_response(
        session_id=session_id,
        summary=(
            f"在 {dis_data['start_address']} ({dis_data['section']}) 成功反汇编 "
            f"{dis_data['instruction_count']} 条指令"
        ),
        data=dis_data,
    ).to_dict()


async def find_xrefs_impl(
    session_id: str,
    target: str | int,
    xref_type: str,
    offset: int,
    limit: int,
    session_store: SessionStore,
    group_by: str = "none",
) -> dict[str, Any]:
    """find_xrefs 异步核心业务实现

    首次调用时通过 asyncio.to_thread 在后台线程构建会话级惰性交叉引用索引 (_xref_index)，
    后续同会话查询直接 O(1) 内存命中。支持 group_by="function" 函数级折叠聚合。

    @param session_id 目标活跃会话标识
    @param target 被引用的目标虚拟地址或符号名称
    @param xref_type 交叉引用过滤类型 ("all", "code", "data")
    @param offset 分页偏移量
    @param limit 单页最大返回数
    @param session_store 会话池实例
    @param group_by 聚合折叠维度 ("none", "function")
    @return dict[str, Any] 统一响应信封字典
    """
    session, err_resp = get_session_or_error(session_id, session_store)
    if err_resp is not None or session is None:
        return err_resp or {}

    eff_type = xref_type.lower().strip() if xref_type else "all"
    if eff_type not in VALID_XREF_TYPES:
        return create_error_response(
            code=ErrorCode.INVALID_PARAMETER,
            message=f"不支持的 xref_type: '{xref_type}'",
            suggestion=f"xref_type 可选值为: {', '.join(VALID_XREF_TYPES)}",
            session_id=session_id,
        ).to_dict()

    eff_group = group_by.lower().strip() if group_by else "none"
    if eff_group not in ("none", "function"):
        return create_error_response(
            code=ErrorCode.INVALID_PARAMETER,
            message=f"不支持的 group_by: '{group_by}'，可选值为 none, function",
            suggestion=(
                "请传入 group_by='none'（默认扁平列表）或 group_by='function'（按调用函数折叠聚合）"
            ),
            session_id=session_id,
        ).to_dict()

    try:
        target_va = resolve_target_address(session, target)
    except LookupError as exc:
        return create_error_response(
            code=ErrorCode.ADDRESS_OR_SYMBOL_NOT_FOUND,
            message=str(exc),
            suggestion="请传入有效的十六进制虚拟地址或已知的导出/导入/符号名称",
            session_id=session_id,
        ).to_dict()

    # 首次构建交叉引用索引时卸载至工作线程，防止阻塞 asyncio 事件循环
    if session._xref_index is None:
        await asyncio.to_thread(build_xref_index, session)

    safe_offset = max(0, offset)
    safe_limit = max(1, min(limit, 500))

    if eff_group == "function":
        all_items, total = query_xrefs(
            session=session,
            target_va=target_va,
            xref_type=eff_type,
            offset=0,
            limit=100000,
        )
        grouped_funcs = group_xrefs_by_function(session=session, xrefs=all_items)
        paged_groups = (
            grouped_funcs[safe_offset : safe_offset + safe_limit]
            if safe_offset < len(grouped_funcs)
            else []
        )
        pagination = PaginationInfo(
            total=len(grouped_funcs),
            offset=safe_offset,
            limit=safe_limit,
            has_more=(safe_offset + len(paged_groups) < len(grouped_funcs)),
        )
        return create_response(
            session_id=session_id,
            summary=(
                f"针对目标 0x{target_va:X} 共检索到 {total} 处交叉引用，"
                f"归集折叠至 {len(grouped_funcs)} 个调用函数/节区"
            ),
            pagination=pagination,
            data={
                "target": str(target),
                "target_address": f"0x{target_va:X}",
                "group_by": "function",
                "function_count": len(grouped_funcs),
                "total_references": total,
                "functions": paged_groups,
                "grouped_xrefs": paged_groups,
            },
        ).to_dict()

    items, total = query_xrefs(
        session=session,
        target_va=target_va,
        xref_type=eff_type,
        offset=safe_offset,
        limit=safe_limit,
    )

    pagination = PaginationInfo(
        total=total,
        offset=safe_offset,
        limit=safe_limit,
        has_more=(safe_offset + len(items) < total),
    )

    return create_response(
        session_id=session_id,
        summary=f"针对目标 0x{target_va:X} 共检索到 {total} 处交叉引用（当前返回 {len(items)} 条）",
        pagination=pagination,
        data={
            "target": str(target),
            "target_address": f"0x{target_va:X}",
            "xrefs": [x.to_dict() for x in items],
        },
    ).to_dict()


async def decompile_function_impl(
    session_id: str,
    target: str | int,
    timeout_seconds: int,
    session_store: SessionStore,
    locator: ToolLocator | None = None,
    config: ServerConfig | None = None,
) -> dict[str, Any]:
    """decompile_function 异步核心业务实现

    通过受控异步子进程调用本机 radare2/rizin 生成伪代码，未安装时返回结构化降级指引。

    @param session_id 目标活跃会话标识
    @param target 目标函数虚拟地址或符号名称
    @param timeout_seconds 外部反编译子进程超时秒数 (默认 30s)
    @param session_store 会话池实例
    @param locator 外部工具寻址器实例
    @param config 服务端运行配置（用于透传 Tier 1/2 外部工具路径）
    @return dict[str, Any] 统一响应信封字典
    """
    session, err_resp = get_session_or_error(session_id, session_store)
    if err_resp is not None or session is None:
        return err_resp or {}

    try:
        target_va = resolve_target_address(session, target)
    except LookupError as exc:
        return create_error_response(
            code=ErrorCode.ADDRESS_OR_SYMBOL_NOT_FOUND,
            message=str(exc),
            suggestion="请使用 get_symbols 或 get_exports 确认目标函数地址或名称",
            session_id=session_id,
        ).to_dict()

    eff_locator = locator or ToolLocator()
    if config and (config.cli_r2_path or config.env_r2_path):
        r2_cap = eff_locator.locate_tool(
            "radare2",
            explicit_cli_path=config.cli_r2_path,
            env_path=config.env_r2_path,
        )
    else:
        r2_cap = eff_locator.locate_tool("radare2")
    if not r2_cap.available or not r2_cap.path:
        guide_suffix = f" 安装指引: {r2_cap.install_guide}" if r2_cap.install_guide else ""
        action_hint = r2_cap.recommended_action or "请改用 disassemble 工具检视目标函数汇编指令流"
        return create_error_response(
            code=ErrorCode.EXTERNAL_TOOL_UNAVAILABLE,
            message="未检测到可用的外部反编译引擎 (radare2 / rizin)",
            suggestion=f"{action_hint}。{guide_suffix}".strip(),
            session_id=session_id,
        ).to_dict()

    safe_timeout = max(1, min(timeout_seconds, 120))
    r2_cmd = f"aaa; s 0x{target_va:X}; pdc"

    try:
        proc = await asyncio.create_subprocess_exec(
            r2_cap.path,
            "-q",
            "-e",
            "scr.color=0",
            "-c",
            r2_cmd,
            str(session.file_path),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except Exception as exc:
        return create_error_response(
            code=ErrorCode.EXTERNAL_TOOL_UNAVAILABLE,
            message=f"启动外部反编译引擎失败: {exc}",
            suggestion="请检查 radare2 可执行文件权限，或改用 disassemble 工具",
            session_id=session_id,
        ).to_dict()

    try:
        stdout_bytes, stderr_bytes = await asyncio.wait_for(
            proc.communicate(),
            timeout=float(safe_timeout),
        )
    except TimeoutError:
        with contextlib.suppress(Exception):
            proc.kill()
        return create_error_response(
            code=ErrorCode.EXTERNAL_TOOL_TIMEOUT,
            message=f"外部反编译子进程执行超时 (>{safe_timeout}s)",
            suggestion=(
                "目标二进制体积较大或全量分析耗时过长，建议改用 disassemble 直接检视目标地址汇编流"
            ),
            session_id=session_id,
        ).to_dict()

    pseudocode = stdout_bytes.decode("utf-8", errors="replace").strip()
    stderr_text = stderr_bytes.decode("utf-8", errors="replace").strip()
    if not pseudocode:
        pseudocode = stderr_text or f"// 未能生成 0x{target_va:X} 处的有效伪代码"

    lines = pseudocode.splitlines()
    return create_response(
        session_id=session_id,
        summary=(
            f"成功调用 {r2_cap.name} 反编译目标函数 0x{target_va:X}（共 {len(lines)} 行伪代码）"
        ),
        data={
            "target": str(target),
            "target_address": f"0x{target_va:X}",
            "engine": r2_cap.name,
            "engine_version": r2_cap.version,
            "pseudocode": pseudocode,
            "lines": lines,
        },
    ).to_dict()
