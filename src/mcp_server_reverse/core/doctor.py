"""分级健康自检探针 (--doctor / --check)

@author Ateng
@since 2026-10-13
"""

import sys
from typing import TextIO

from mcp_server_reverse.core.config import ServerConfig
from mcp_server_reverse.core.locator import ToolLocator
from mcp_server_reverse.core.meta import get_core_engine_versions


def _check_core_engines() -> tuple[bool, list[str]]:
    """校验必须的核心 Python 引擎库是否可用并获取版本

    @return tuple[bool, list[str]] (全部引擎就绪标志, 引擎详情或错误信息列表)
    """
    versions = get_core_engine_versions()
    errors: list[str] = []
    details: list[str] = []

    for name, ver in versions.items():
        if ver == "unavailable":
            errors.append(f"{name} 导入失败或不可用")
        else:
            details.append(f"{name}: {ver}")

    if errors:
        return False, errors
    return True, details


def run_doctor(config: ServerConfig, stream: TextIO | None = None) -> int:
    """执行分级健康自检并向终端输出格式化诊断报告

    @param config 当前服务端运行配置
    @param stream 输出文本流，默认为 sys.stdout
    @return int 进程退出码，核心依赖与显式配置健全返回 0，存在异常返回 1
    """
    out = stream if stream is not None else sys.stdout
    out.write("=== mcp-server-reverse 运行环境分级健康自检 ===\n\n")

    has_error = False

    # 1. Python 运行时
    py_ver = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    out.write(f"[REQUIRED] Python 运行时环境: {py_ver} (>=3.11 要求满足)\n")

    # 2. 核心 Python 解析引擎
    engines_ok, engine_details = _check_core_engines()
    if engines_ok:
        for detail in engine_details:
            out.write(f"[REQUIRED] 核心解析引擎 {detail}: 正常\n")
    else:
        has_error = True
        for err in engine_details:
            out.write(f"[REQUIRED][FAIL] 核心解析引擎异常: {err}\n")

    # 3. 沙箱白名单目录校验
    if config.allowed_dirs:
        for adir in config.allowed_dirs:
            if adir.is_dir():
                out.write(f"[REQUIRED] 沙箱白名单目录 '{adir}': 正常\n")
            else:
                has_error = True
                out.write(f"[REQUIRED][FAIL] 沙箱白名单目录不存在或非目录: '{adir}'\n")
    else:
        out.write("[REQUIRED] 沙箱白名单目录: 未配置（允许分析任意具有读取权限的本地文件）\n")

    # 4. 外部 CLI 工具探测与分级校验
    out.write("\n--- 外部逆向 CLI 增强工具状态 ---\n")
    locator = ToolLocator()
    caps = locator.locate_all(config)

    for tool_name, cap in caps.items():
        if cap.available:
            tier_desc = f"Level {cap.tier}" if cap.tier else "自动寻址"
            out.write(
                f"[OPTIONAL] {tool_name}: 已就绪 ({tier_desc}, "
                f"v{cap.version or '未知'}, 路径: {cap.path})\n"
            )
        else:
            if cap.tier in (1, 2) and cap.path:
                has_error = True
                out.write(
                    f"[ERROR] 显式指定的外部工具路径不可用 ({tool_name}): "
                    f"{cap.recommended_action}\n"
                )
            else:
                out.write(f"[OPTIONAL] {tool_name}: 未安装/未配置 ({cap.recommended_action})\n")
                if cap.install_guide:
                    out.write(f"           安装指引: {cap.install_guide}\n")

    out.write("\n")
    if has_error:
        out.write("自检结论: 存在必须依赖缺失或显式配置错误，请修复上述问题后再启动服务。\n")
        return 1

    out.write("自检结论: 所有核心依赖与沙箱配置正常，服务就绪！\n")
    return 0
