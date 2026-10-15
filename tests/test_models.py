"""统一响应信封与错误码测试套件

@author Ateng
@since 2026-10-13
"""

from mcp_server_reverse.core.models import (
    ErrorCode,
    PaginationInfo,
    create_error_response,
    create_response,
)


def test_error_code_enum_has_all_nine_standards() -> None:
    expected_codes = {
        "SANDBOX_PATH_FORBIDDEN",
        "FILE_NOT_FOUND",
        "FILE_TOO_LARGE",
        "UNSUPPORTED_FORMAT",
        "SESSION_NOT_FOUND",
        "ADDRESS_OR_SYMBOL_NOT_FOUND",
        "INVALID_PARAMETER",
        "EXTERNAL_TOOL_UNAVAILABLE",
        "EXTERNAL_TOOL_TIMEOUT",
        "FORBIDDEN_OVERWRITE_ORIGINAL",
    }
    actual_codes = {code.value for code in ErrorCode}
    assert actual_codes == expected_codes


def test_create_success_response_envelope() -> None:
    resp = create_response(
        session_id="a1b2c3d4e5f6",
        summary="分析完成",
        data={"items": []},
        pagination=PaginationInfo(total=0, offset=0, limit=50, has_more=False),
    )
    assert resp.ok is True
    assert resp.session_id == "a1b2c3d4e5f6"
    assert resp.summary == "分析完成"
    assert resp.data == {"items": []}
    assert resp.pagination is not None
    assert resp.pagination.total == 0
    assert resp.error is None

    as_dict = resp.to_dict()
    assert as_dict["ok"] is True
    assert as_dict["session_id"] == "a1b2c3d4e5f6"
    assert as_dict["error"] is None


def test_create_error_response_envelope() -> None:
    resp = create_error_response(
        code=ErrorCode.SANDBOX_PATH_FORBIDDEN,
        message="禁止访问非白名单路径",
        suggestion="请将目标目录添加至 --allowed-dir",
        session_id=None,
    )
    assert resp.ok is False
    assert resp.session_id is None
    assert resp.error is not None
    assert resp.error.code == "SANDBOX_PATH_FORBIDDEN"
    assert resp.error.message == "禁止访问非白名单路径"
    assert resp.error.suggestion == "请将目标目录添加至 --allowed-dir"
    assert resp.data == {}

    as_dict = resp.to_dict()
    assert as_dict["ok"] is False
    assert as_dict["data"] == {}
    assert as_dict["error"]["code"] == "SANDBOX_PATH_FORBIDDEN"
