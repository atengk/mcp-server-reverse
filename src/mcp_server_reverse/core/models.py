"""MCP 协议响应信封、标准错误码与核心领域数据模型

@author Ateng
@since 2026-10-13
"""

from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any


class ErrorCode(StrEnum):
    """MCP 逆向分析服务 9 类标准业务错误码枚举"""

    SANDBOX_PATH_FORBIDDEN = "SANDBOX_PATH_FORBIDDEN"
    FILE_NOT_FOUND = "FILE_NOT_FOUND"
    FILE_TOO_LARGE = "FILE_TOO_LARGE"
    UNSUPPORTED_FORMAT = "UNSUPPORTED_FORMAT"
    SESSION_NOT_FOUND = "SESSION_NOT_FOUND"
    ADDRESS_OR_SYMBOL_NOT_FOUND = "ADDRESS_OR_SYMBOL_NOT_FOUND"
    INVALID_PARAMETER = "INVALID_PARAMETER"
    EXTERNAL_TOOL_UNAVAILABLE = "EXTERNAL_TOOL_UNAVAILABLE"
    EXTERNAL_TOOL_TIMEOUT = "EXTERNAL_TOOL_TIMEOUT"


@dataclass
class ErrorInfo:
    """结构化错误详情

    @param code 9 类标准错误码之一
    @param message 清晰可读的中文错误原因描述
    @param suggestion 针对 AI Agent 的针对性行动建议或补救操作
    """

    code: str
    message: str
    suggestion: str


@dataclass
class PaginationInfo:
    """游标与分页信息

    @param total 匹配的总条目数
    @param offset 当前返回切片的起始偏移量
    @param limit 单页最大返回条目数
    @param has_more 是否存在后续未返回的数据页
    """

    total: int
    offset: int
    limit: int
    has_more: bool


@dataclass
class ExternalCapability:
    """四级跨平台寻址探测到的外部工具能力元数据

    @param name 工具通用规范名称 (radare2 / objdump / floss)
    @param available 工具当前是否已就绪可用
    @param path 可执行文件在宿主机上的物理绝对路径，未找到时为 None
    @param version 探测到的工具版本号字符串，未探测到时为 None
    @param tier 命中寻址的层级 (1: CLI, 2: ENV, 3: PATH, 4: Default Paths)
    @param install_guide 当工具不可用时提供的跨平台安装指引
    @param recommended_action 当工具不可用时给 AI Agent 的建议行动方案
    """

    name: str
    available: bool
    path: str | None = None
    version: str | None = None
    tier: int | None = None
    install_guide: str | None = None
    recommended_action: str | None = None


@dataclass
class ResponseEnvelope:
    """所有 MCP Tools 统一标准响应信封

    @param ok 请求是否成功完成
    @param session_id 当前所操作的 BinarySession 唯一哈希标识
    @param summary 简明扼要的中文结果摘要说明
    @param pagination 分页信息，非列表接口时为 None
    @param data 业务返回载荷字典，集合无数据时为空列表，绝不为 null
    @param error 错误详情，操作成功时为 None
    """

    ok: bool
    session_id: str | None = None
    summary: str = ""
    pagination: PaginationInfo | None = None
    data: dict[str, Any] = field(default_factory=dict)
    error: ErrorInfo | None = None

    def to_dict(self) -> dict[str, Any]:
        """将响应信封序列化为符合 MCP 协议标准的字典

        @return dict[str, Any] 序列化字典对象
        """
        result: dict[str, Any] = {
            "ok": self.ok,
            "session_id": self.session_id,
            "summary": self.summary,
            "pagination": asdict(self.pagination) if self.pagination else None,
            "data": self.data if self.data is not None else {},
            "error": asdict(self.error) if self.error else None,
        }
        return result


def create_response(
    summary: str,
    data: dict[str, Any] | None = None,
    session_id: str | None = None,
    pagination: PaginationInfo | None = None,
) -> ResponseEnvelope:
    """构造成功的标准响应信封

    @param summary 简明中文结果摘要
    @param data 业务数据载荷，无数据时为空字典
    @param session_id 当前会话唯一 ID
    @param pagination 分页元信息
    @return ResponseEnvelope 标准成功信封对象
    """
    return ResponseEnvelope(
        ok=True,
        session_id=session_id,
        summary=summary,
        pagination=pagination,
        data=data if data is not None else {},
        error=None,
    )


def create_error_response(
    code: ErrorCode | str,
    message: str,
    suggestion: str,
    session_id: str | None = None,
) -> ResponseEnvelope:
    """构造失败的标准响应信封

    @param code 标准错误码枚举或字符串
    @param message 清晰中文错误描述
    @param suggestion 针对 AI Agent 的针对性行动建议
    @param session_id 当前会话 ID（若有）
    @return ResponseEnvelope 标准失败信封对象
    """
    code_str = code.value if isinstance(code, ErrorCode) else str(code)
    return ResponseEnvelope(
        ok=False,
        session_id=session_id,
        summary=f"操作失败: {message}",
        pagination=None,
        data={},
        error=ErrorInfo(
            code=code_str,
            message=message,
            suggestion=suggestion,
        ),
    )
