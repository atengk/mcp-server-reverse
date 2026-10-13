"""四级跨平台外部工具寻址与能力探测器

@author Ateng
@since 2026-10-13
"""

import logging
import os
import re
import shutil
import subprocess
from pathlib import Path

from mcp_server_reverse.core.config import ServerConfig
from mcp_server_reverse.core.models import ExternalCapability

logger = logging.getLogger(__name__)

# 工具候选执行文件名
TOOL_ALIASES: dict[str, list[str]] = {
    "radare2": ["radare2", "r2", "rizin"],
    "objdump": ["llvm-objdump", "objdump"],
    "floss": ["floss"],
}

# 工具安装指引说明
INSTALL_GUIDES: dict[str, str] = {
    "radare2": (
        "Windows: winget install radareorg.radare2 或 choco install radare2；"
        "macOS: brew install radare2；Linux: sudo apt install radare2 或从 GitHub 下载发布包"
    ),
    "objdump": (
        "Windows: 安装 LLVM 或 MinGW-w64 (winget install LLVM.LLVM)；"
        "macOS: xcode-select --install 或 brew install llvm；Linux: sudo apt install binutils llvm"
    ),
    "floss": (
        "跨平台: uv tool install flare-floss 或 pip install flare-floss，"
        "亦可从 https://github.com/mandiant/flare-floss/releases 下载独立免安装二进制"
    ),
}

# 工具降级行动指引
FALLBACK_ACTIONS: dict[str, str] = {
    "radare2": "已自动降级至内置纯 Python Capstone 反汇编引擎，类 C 反编译功能暂不可用",
    "objdump": "已自动降级至内置纯 Python 反汇编与节区解析引擎",
    "floss": "已自动降级至内置纯 Python ASCII 与 UTF-16LE 静态字符串提取引擎",
}


class ToolLocator:
    """四级跨平台外部工具寻址器"""

    def __init__(self) -> None:
        pass

    def locate_all(self, config: ServerConfig) -> dict[str, ExternalCapability]:
        """探测并返回所有受支持外部逆向工具的能力描述字典

        @param config 当前服务运行时配置
        @return dict[str, ExternalCapability] 各工具能力模型字典
        """
        return {
            "radare2": self.locate_tool(
                tool_name="radare2",
                explicit_cli_path=config.cli_r2_path,
                env_path=config.env_r2_path,
            ),
            "objdump": self.locate_tool(
                tool_name="objdump",
                explicit_cli_path=config.cli_objdump_path,
                env_path=config.env_objdump_path,
            ),
            "floss": self.locate_tool(
                tool_name="floss",
                explicit_cli_path=config.cli_floss_path,
                env_path=config.env_floss_path,
            ),
        }

    def _verify_explicit_path(
        self,
        tool_name: str,
        path_str: str,
        tier: int,
        source_name: str,
    ) -> ExternalCapability:
        """校验显式路径 (Tier 1 CLI 或 Tier 2 环境变量) 的有效性

        @param tool_name 工具名称
        @param path_str 目标路径字符串
        @param tier 寻址层级 (1 或 2)
        @param source_name 来源名称说明
        @return ExternalCapability 探测能力元数据
        """
        p = Path(path_str)
        if p.is_file():
            ver = self._probe_version(str(p), tool_name)
            return ExternalCapability(
                name=tool_name,
                available=True,
                path=str(p.resolve()),
                version=ver,
                tier=tier,
                install_guide=INSTALL_GUIDES.get(tool_name),
                recommended_action=None,
            )

        return ExternalCapability(
            name=tool_name,
            available=False,
            path=path_str,
            version=None,
            tier=tier,
            install_guide=INSTALL_GUIDES.get(tool_name),
            recommended_action=f"{source_name}指定的 {tool_name} 路径不存在或不可执行: {path_str}",
        )

    def locate_tool(
        self,
        tool_name: str,
        explicit_cli_path: str | None = None,
        env_path: str | None = None,
    ) -> ExternalCapability:
        """根据四级优先级探测指定工具

        @param tool_name 目标规范工具名 (radare2, objdump, floss)
        @param explicit_cli_path Level 1 显式命令行传入路径
        @param env_path Level 2 环境变量配置路径
        @return ExternalCapability 外部工具能力状态
        """
        # Level 1: CLI 显式参数
        if explicit_cli_path:
            return self._verify_explicit_path(
                tool_name=tool_name,
                path_str=explicit_cli_path,
                tier=1,
                source_name="命令行显式",
            )

        # Level 2: 环境变量
        if env_path:
            return self._verify_explicit_path(
                tool_name=tool_name,
                path_str=env_path,
                tier=2,
                source_name="环境变量",
            )

        # Level 3: 系统 PATH
        aliases = TOOL_ALIASES.get(tool_name, [tool_name])
        for alias in aliases:
            found = shutil.which(alias)
            if found:
                ver = self._probe_version(found, tool_name)
                return ExternalCapability(
                    name=tool_name,
                    available=True,
                    path=str(Path(found).resolve()),
                    version=ver,
                    tier=3,
                    install_guide=INSTALL_GUIDES.get(tool_name),
                    recommended_action=None,
                )

        # Level 4: 操作系统标准安装目录
        level4_found = self._probe_level4_paths(tool_name, aliases)
        if level4_found:
            ver = self._probe_version(level4_found, tool_name)
            return ExternalCapability(
                name=tool_name,
                available=True,
                path=str(Path(level4_found).resolve()),
                version=ver,
                tier=4,
                install_guide=INSTALL_GUIDES.get(tool_name),
                recommended_action=None,
            )

        # 未找到时生成降级描述
        return ExternalCapability(
            name=tool_name,
            available=False,
            path=None,
            version=None,
            tier=None,
            install_guide=INSTALL_GUIDES.get(tool_name),
            recommended_action=FALLBACK_ACTIONS.get(tool_name),
        )

    def _probe_level4_paths(self, tool_name: str, aliases: list[str]) -> str | None:
        """在操作系统常见包管理器与默认目录中搜索可执行文件

        @param tool_name 工具规范名称
        @param aliases 工具可执行文件候选别名列表
        @return str | None 命中的可执行文件绝对路径，未命中返回 None
        """
        candidate_dirs: list[Path] = []

        home = Path.home()
        # Windows 常见路径
        candidate_dirs.extend(
            [
                home / "scoop" / "shims",
                home / "scoop" / "apps" / tool_name / "current",
                Path(os.environ.get("LOCALAPPDATA", "")) / "Microsoft" / "WinGet" / "Links",
                Path("C:/ProgramData/chocolatey/bin"),
                Path("C:/Program Files/radare2/bin"),
                Path("C:/Program Files/LLVM/bin"),
            ]
        )

        # macOS / Linux 常见路径
        candidate_dirs.extend(
            [
                Path("/opt/homebrew/bin"),
                Path("/usr/local/bin"),
                Path("/usr/bin"),
                Path("/opt/local/bin"),
                Path("/opt/radare2/bin"),
                home / ".cargo" / "bin",
                home / ".local" / "bin",
            ]
        )

        for c_dir in candidate_dirs:
            if not c_dir.exists():
                continue
            for alias in aliases:
                # 检查直接名称或加 .exe 后缀
                for suffix in ["", ".exe", ".cmd"]:
                    target = c_dir / f"{alias}{suffix}"
                    if target.is_file():
                        return str(target)
        return None

    def _probe_version(self, executable_path: str, tool_name: str) -> str | None:
        """运行外部工具提取版本号，超时 2 秒防御

        @param executable_path 可执行文件物理绝对路径
        @param tool_name 工具名称
        @return str | None 版本号字符串
        """
        flags = ["-v"] if tool_name == "radare2" else ["--version"]
        try:
            proc = subprocess.run(
                [executable_path, *flags],
                capture_output=True,
                text=True,
                timeout=2.0,
                check=False,
            )
            output = proc.stdout.strip() or proc.stderr.strip()
            if not output:
                return None

            first_line = output.splitlines()[0].strip()
            # 常见正则提取形如 1.2.3 或 2024.1
            match = re.search(r"(\d+(\.\d+)+[a-zA-Z0-9_-]*)", first_line)
            return match.group(1) if match else first_line
        except Exception as exc:
            logger.debug("探测外部工具 %s 版本异常: %s", executable_path, exc)
            return None
