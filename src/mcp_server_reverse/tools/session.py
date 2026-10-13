"""会话管理与全景取证分诊 MCP 工具实现

@author Ateng
@since 2026-10-13
"""

import hashlib
from typing import Any

from mcp_server_reverse.core.config import ServerConfig
from mcp_server_reverse.core.models import (
    ErrorCode,
    create_error_response,
    create_response,
)
from mcp_server_reverse.core.parser import BinaryParser
from mcp_server_reverse.core.security import SecurityGuard
from mcp_server_reverse.core.session import (
    BinarySession,
    SessionStore,
    generate_session_id,
)


def open_binary_impl(
    file_path: str,
    target_arch: str | None,
    config: ServerConfig,
    session_store: SessionStore,
    security_guard: SecurityGuard,
    parser: BinaryParser,
) -> dict[str, Any]:
    """open_binary 核心业务实现

    @param file_path 目标二进制物理文件路径
    @param target_arch 可选的多架构切片名称
    @param config 当前服务端运行配置
    @param session_store 会话池实例
    @param security_guard 安全守卫实例
    @param parser 格式解析内核实例
    @return dict[str, Any] 统一响应信封字典
    """
    # 1. 安全沙箱路径与格式校验
    sec_res = security_guard.validate_target_file(file_path, config)
    if not sec_res.is_valid or sec_res.resolved_path is None:
        return create_error_response(
            code=sec_res.error_code or ErrorCode.INVALID_PARAMETER,
            message=sec_res.error_message or "文件安全校验失败",
            suggestion=sec_res.suggestion or "请检查传入的文件路径",
        ).to_dict()

    resolved_path = sec_res.resolved_path
    raw_bytes = resolved_path.read_bytes()
    file_sha256 = hashlib.sha256(raw_bytes).hexdigest()

    # 2. 检查缓存命中 (针对入参 target_arch 的预判断)
    candidate_sid = generate_session_id(file_sha256, target_arch)
    cached_session = session_store.get(candidate_sid)
    if cached_session is not None:
        return create_response(
            session_id=cached_session.session_id,
            summary=(
                f"命中会话缓存: {resolved_path.name} "
                f"({cached_session.format} {cached_session.arch})"
            ),
            data=cached_session.to_full_data_dict(),
        ).to_dict()

    # 3. 执行深度静态逆向分析与取证
    try:
        parse_result = parser.parse(resolved_path, target_arch=target_arch)
    except Exception as exc:
        return create_error_response(
            code=ErrorCode.UNSUPPORTED_FORMAT,
            message=f"解析二进制文件内部结构失败: {exc}",
            suggestion="目标文件可能存在畸形头部或深度混淆，请检查文件完整性",
        ).to_dict()

    # 4. 基于解析决议出的实际架构生成规范化的 session_id
    fmt_info = parse_result.format_info
    resolved_arch = parse_result.resolved_arch
    is_fat_macho = (
        fmt_info.get("format") == "Mach-O" and len(fmt_info.get("available_architectures", [])) > 1
    )
    final_sid = generate_session_id(file_sha256, resolved_arch if is_fat_macho else target_arch)

    # 5. 组装 BinarySession 并放入 LRU 内存池
    session = BinarySession(
        session_id=final_sid,
        file_path=resolved_path,
        file_sha256=file_sha256,
        file_size=len(raw_bytes),
        format=fmt_info.get("format", "UNKNOWN"),
        arch=resolved_arch,
        bits=fmt_info.get("bits", 64),
        endianness=fmt_info.get("endianness", "little"),
        entry_point=int(fmt_info.get("entry_point", "0x0"), 16),
        image_base=int(fmt_info.get("image_base", "0x0"), 16),
        target_arch=target_arch,
        file_info=parse_result.file_info,
        format_info=parse_result.format_info,
        triage_overview=parse_result.triage_overview,
        forensic_metadata=parse_result.forensic_metadata,
        lief_binary=parse_result.lief_binary,
        pefile_binary=parse_result.pefile_binary,
    )
    session_store.put(session)

    return create_response(
        session_id=session.session_id,
        summary=(f"成功加载并建立分析会话: {resolved_path.name} ({session.format} {session.arch})"),
        data=session.to_full_data_dict(),
    ).to_dict()


def list_sessions_impl(session_store: SessionStore) -> dict[str, Any]:
    """list_sessions 核心业务实现

    @param session_store 会话池实例
    @return dict[str, Any] 统一响应信封字典
    """
    sessions = session_store.list_sessions()
    return create_response(
        summary=f"当前内存池中驻留 {len(sessions)} 个活跃二进制会话",
        data={"sessions": sessions},
    ).to_dict()


def close_session_impl(
    session_id: str | None,
    session_store: SessionStore,
) -> dict[str, Any]:
    """close_session 核心业务实现

    @param session_id 待释放的指定会话 ID，若为 None 则全部清空
    @param session_store 会话池实例
    @return dict[str, Any] 统一响应信封字典
    """
    if session_id is not None and not session_store.exists(session_id):
        return create_error_response(
            code=ErrorCode.SESSION_NOT_FOUND,
            message=f"指定会话 ID 未在内存池中找到: {session_id}",
            suggestion="请调用 list_sessions 查看当前全部有效的 session_id",
        ).to_dict()

    closed_cnt, remaining_cnt = session_store.close_session(session_id)
    summary_text = (
        f"成功释放会话 {session_id}，剩余 {remaining_cnt} 个会话"
        if session_id
        else f"已清空全部分析会话 ({closed_cnt} 个)"
    )
    return create_response(
        session_id=session_id,
        summary=summary_text,
        data={
            "closed_count": closed_cnt,
            "remaining_sessions": remaining_cnt,
        },
    ).to_dict()


def get_session_or_error(
    session_id: str,
    session_store: SessionStore,
) -> tuple[BinarySession | None, dict[str, Any] | None]:
    """验证并获取活跃会话，不存在时构造标准化错误响应信封

    @param session_id 目标会话唯一标识
    @param session_store 会话池实例
    @return tuple[BinarySession | None, dict[str, Any] | None] 会话实例或错误响应字典
    """
    session = session_store.get(session_id)
    if session is None:
        err_envelope = create_error_response(
            code=ErrorCode.SESSION_NOT_FOUND,
            message=f"未找到 ID 为 '{session_id}' 的活跃二进制会话",
            suggestion="请先调用 open_binary 加载目标文件以创建会话",
            session_id=session_id,
        ).to_dict()
        return None, err_envelope
    return session, None
