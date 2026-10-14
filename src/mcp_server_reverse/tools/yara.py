"""YARA 规则匹配 MCP 工具实现

提供 scan_yara 工具核心业务调度与降级逻辑。

@author Ateng
@since 2026-10-14
"""

from typing import Any

from mcp_server_reverse.core import yara_engine
from mcp_server_reverse.core.models import (
    ErrorCode,
    create_error_response,
    create_response,
)
from mcp_server_reverse.core.session import SessionStore
from mcp_server_reverse.tools.session import get_session_or_error


def _build_unavailable_response(session_id: str, message: str | None = None) -> dict[str, Any]:
    """构造 YARA 引擎缺失时的结构化优雅降级响应字典

    @param session_id 当前会话标识
    @param message 自定义错误原因描述，未提供时使用默认描述
    @return dict[str, Any] 结构化错误信封字典
    """
    return create_error_response(
        code=ErrorCode.EXTERNAL_TOOL_UNAVAILABLE,
        message=message or "宿主机未安装 yara-python 规则匹配引擎",
        suggestion=(
            "请通过 'pip install yara-python' 或 "
            "'pip install atengk-mcp-server-reverse[yara]' 安装原生 YARA 引擎"
        ),
        session_id=session_id,
    ).to_dict()


def scan_yara_impl(
    session_id: str,
    rule_text: str | None = None,
    rule_file: str | None = None,
    session_store: SessionStore | None = None,
) -> dict[str, Any]:
    """scan_yara 核心业务实现

    @param session_id 目标会话唯一标识
    @param rule_text 自定义 YARA 规则文本字符串
    @param rule_file YARA 规则文件本地物理绝对路径
    @param session_store 会话池实例
    @return dict[str, Any] 统一响应信封字典
    """
    store = session_store if session_store is not None else SessionStore()
    session, err_resp = get_session_or_error(session_id, store)
    if err_resp is not None or session is None:
        return err_resp or {}

    # 1. 检查 yara-python 可选依赖可用性
    if not yara_engine.is_yara_available():
        return _build_unavailable_response(session_id)

    # 2. 编译规则并进行语义化错误分流
    try:
        rules = yara_engine.compile_yara_rules(rule_text=rule_text, rule_file=rule_file)
    except RuntimeError as exc:
        return _build_unavailable_response(session_id, str(exc))
    except FileNotFoundError as exc:
        return create_error_response(
            code=ErrorCode.FILE_NOT_FOUND,
            message=str(exc),
            suggestion="请确认指定的 YARA 规则文件物理路径存在且具备读取权限",
            session_id=session_id,
        ).to_dict()
    except ValueError as exc:
        return create_error_response(
            code=ErrorCode.INVALID_PARAMETER,
            message=str(exc),
            suggestion="请检查 YARA 规则语法，或确保 rule_text 与 rule_file 传参正确",
            session_id=session_id,
        ).to_dict()
    except Exception as exc:
        return create_error_response(
            code=ErrorCode.INVALID_PARAMETER,
            message=f"YARA 规则编译异常: {exc}",
            suggestion="请检查 YARA 规则合法性",
            session_id=session_id,
        ).to_dict()

    # 3. 执行规则扫描
    matches = yara_engine.execute_yara_scan(session=session, compiled_rules=rules)
    serialized_matches = [m.to_dict() for m in matches]

    return create_response(
        session_id=session_id,
        summary=f"成功完成 YARA 规则扫描，共命中 {len(matches)} 个规则",
        data={"matches": serialized_matches, "total": len(matches)},
    ).to_dict()
