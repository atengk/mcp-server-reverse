"""服务元数据与核心解析引擎版本探测工具

@author Ateng
@since 2026-10-13
"""

import sys
from importlib.metadata import PackageNotFoundError, version


def get_package_version() -> str:
    """动态获取当前分发包版本号

    @return str 规范化版本号字符串
    """
    try:
        return version("mcp-server-reverse")
    except PackageNotFoundError:
        return "0.1.0"


def get_core_engine_versions() -> dict[str, str]:
    """获取核心 Python 静态分析库的运行版本

    @return dict[str, str] 各核心库与其版本映射字典，不可用时值为 'unavailable'
    """
    versions: dict[str, str] = {}

    # 1. lief
    try:
        import lief

        versions["lief"] = getattr(lief, "__version__", "unknown")
    except Exception:
        versions["lief"] = "unavailable"

    # 2. capstone
    try:
        import capstone

        versions["capstone"] = getattr(capstone, "__version__", "unknown")
    except Exception:
        versions["capstone"] = "unavailable"

    # 3. pefile
    try:
        import pefile

        versions["pefile"] = getattr(pefile, "__version__", "unknown")
    except Exception:
        versions["pefile"] = "unavailable"

    return versions


def get_runtime_version_info() -> str:
    """获取格式化后的运行时与版本单行描述

    @return str 格式化描述字符串
    """
    pkg_ver = get_package_version()
    py_ver = sys.version.split()[0]
    return f"mcp-server-reverse v{pkg_ver} (Python {py_ver})"
