"""路径安全守卫与文件访问沙箱隔离层

@author Ateng
@since 2026-10-13
"""

import logging
from dataclasses import dataclass
from pathlib import Path

from mcp_server_reverse.core.config import ServerConfig
from mcp_server_reverse.core.models import ErrorCode

logger = logging.getLogger(__name__)

# 受支持的二进制格式魔数集合 (Mach-O 支持 32位/64位与 Universal Fat Binary)
MACHO_MAGICS = {
    b"\xfe\xed\xfa\xce",
    b"\xfe\xed\xfa\xcf",
    b"\xce\xfa\xed\xfe",
    b"\xcf\xfa\xed\xfe",
    b"\xca\xfe\xba\xbe",
    b"\xbe\xba\xfe\xca",
}


@dataclass
class SecurityValidationResult:
    """文件安全守卫校验结果对象

    @param is_valid 是否完全通过安全检查
    @param resolved_path 规范化后的绝对物理路径 (若通过)
    @param error_code 业务错误码枚举 (若失败)
    @param error_message 中文错误描述信息
    @param suggestion 针对 AI Agent 的针对性行动建议
    """

    is_valid: bool
    resolved_path: Path | None = None
    error_code: ErrorCode | None = None
    error_message: str | None = None
    suggestion: str | None = None


class SecurityGuard:
    """路径安全沙箱与文件格式校验器

    @author Ateng
    @since 2026-10-13
    """

    def __init__(self) -> None:
        pass

    def validate_output_file(
        self,
        output_path_str: str | Path,
        source_file_path: Path,
        config: ServerConfig,
        overwrite: bool = False,
    ) -> SecurityValidationResult:
        """校验导出输出文件路径：沙箱白名单、防原文件覆写与覆盖状态

        @param output_path_str 目标输出文件路径字符串或 Path
        @param source_file_path 当前会话的原始文件路径
        @param config 当前服务端运行配置
        @param overwrite 是否允许覆写已存在的输出文件 (默认 False)
        @return SecurityValidationResult 强类型校验结果对象
        """
        raw_path = Path(output_path_str)

        # 1. 规范化目标物理路径与源路径
        try:
            resolved_output = raw_path.resolve()
            resolved_source = source_file_path.resolve()
        except OSError as exc:
            return SecurityValidationResult(
                is_valid=False,
                error_code=ErrorCode.INVALID_PARAMETER,
                error_message=f"输出路径解析异常: {exc}",
                suggestion="请检查传入的目标输出文件路径格式是否合法",
            )

        # 2. 绝对防自毁安全红线：无论 overwrite 是否为 True，严禁覆写原始输入样本文件
        if resolved_output == resolved_source:
            return SecurityValidationResult(
                is_valid=False,
                error_code=ErrorCode.FORBIDDEN_OVERWRITE_ORIGINAL,
                error_message="安全守卫拦截: 严禁将修改后的二进制写回覆盖原始取证样本文件",
                suggestion="请指定不同于原始文件的独立输出路径，保障原始样本只读保真",
            )

        # 3. 沙箱白名单目录防穿越校验
        if config.allowed_dirs:
            is_allowed = False
            for allowed_dir in config.allowed_dirs:
                try:
                    resolved_allowed = allowed_dir.resolve()
                    if resolved_output.is_relative_to(resolved_allowed):
                        is_allowed = True
                        break
                except ValueError:
                    continue

            if not is_allowed:
                allowed_str = ", ".join(str(d) for d in config.allowed_dirs)
                return SecurityValidationResult(
                    is_valid=False,
                    error_code=ErrorCode.SANDBOX_PATH_FORBIDDEN,
                    error_message=(
                        f"安全沙箱拦截: 禁止将文件导出至白名单受控目录之外: {resolved_output}"
                    ),
                    suggestion=(
                        f"当前允许写入的目录白名单为 [{allowed_str}]，"
                        "请将输出路径设置在白名单目录下"
                    ),
                )

        # 4. 文件已存在且未启用 overwrite 时的保护
        if resolved_output.exists() and not overwrite:
            return SecurityValidationResult(
                is_valid=False,
                error_code=ErrorCode.INVALID_PARAMETER,
                error_message=f"目标输出文件已存在: {resolved_output}",
                suggestion="若确定覆盖已有目标文件，请显式设置 overwrite=True",
            )

        return SecurityValidationResult(
            is_valid=True,
            resolved_path=resolved_output,
        )

    def validate_target_file(
        self,
        file_path_str: str | Path,
        config: ServerConfig,
    ) -> SecurityValidationResult:
        """校验目标二进制文件路径、沙箱白名单、文件大小与文件格式

        @param file_path_str 输入的原始路径字符串或 Path 对象
        @param config 当前服务端运行配置
        @return SecurityValidationResult 强类型校验结果对象
        """
        raw_path = Path(file_path_str)

        # 1. 规范化物理路径（解析相对路径与软链接，阻断 .. 穿越）
        try:
            resolved_path = raw_path.resolve()
        except OSError as exc:
            return SecurityValidationResult(
                is_valid=False,
                error_code=ErrorCode.INVALID_PARAMETER,
                error_message=f"文件路径解析异常: {exc}",
                suggestion="请检查传入的路径格式是否合法",
            )

        # 2. 存在性与文件类型检查
        if not resolved_path.exists():
            return SecurityValidationResult(
                is_valid=False,
                error_code=ErrorCode.FILE_NOT_FOUND,
                error_message=f"目标文件不存在: {resolved_path}",
                suggestion="请确认文件物理路径拼写正确且文件已被放置在指定位置",
            )

        if not resolved_path.is_file():
            return SecurityValidationResult(
                is_valid=False,
                error_code=ErrorCode.INVALID_PARAMETER,
                error_message=f"目标路径不是普通文件（可能是目录）: {resolved_path}",
                suggestion="open_binary 仅接受单个文件，请指定具体的文件路径",
            )

        # 3. 沙箱白名单目录防穿越校验
        if config.allowed_dirs:
            is_allowed = False
            for allowed_dir in config.allowed_dirs:
                try:
                    resolved_allowed = allowed_dir.resolve()
                    if resolved_path.is_relative_to(resolved_allowed):
                        is_allowed = True
                        break
                except ValueError:
                    continue

            if not is_allowed:
                allowed_str = ", ".join(str(d) for d in config.allowed_dirs)
                return SecurityValidationResult(
                    is_valid=False,
                    error_code=ErrorCode.SANDBOX_PATH_FORBIDDEN,
                    error_message=(
                        f"安全沙箱拦截: 禁止访问白名单受控目录之外的文件: {resolved_path}"
                    ),
                    suggestion=(
                        f"当前允许访问的根目录白名单为 [{allowed_str}]，请将样本移至白名单目录下"
                    ),
                )

        # 4. 文件体积上限熔断检查
        max_bytes = config.max_file_size_mb * 1024 * 1024
        file_size = resolved_path.stat().st_size
        if file_size > max_bytes:
            size_mb = round(file_size / (1024 * 1024), 2)
            return SecurityValidationResult(
                is_valid=False,
                error_code=ErrorCode.FILE_TOO_LARGE,
                error_message=(
                    f"目标文件体积 ({size_mb} MB) 超出服务设定上限 ({config.max_file_size_mb} MB)"
                ),
                suggestion=(
                    "可通过 --max-file-size-mb 或环境变量 MCP_REVERSE_MAX_FILE_SIZE_MB 调大上限"
                ),
            )

        # 5. 二进制文件格式探测与合法性校验 (PE / ELF / Mach-O) 与轻量 Magic 嗅探 (Format Sniffer)
        is_valid_format, detected_format, custom_suggestion = self._probe_binary_format(
            resolved_path
        )
        if not is_valid_format:
            return SecurityValidationResult(
                is_valid=False,
                error_code=ErrorCode.UNSUPPORTED_FORMAT,
                error_message=f"不支持的文件格式: {detected_format}",
                suggestion=custom_suggestion
                or (
                    "本服务仅支持 Windows PE (.exe/.dll/.sys)、"
                    "Linux ELF (.so/可执行) 与 macOS Mach-O 二进制"
                ),
            )

        return SecurityValidationResult(
            is_valid=True,
            resolved_path=resolved_path,
        )

    def _probe_binary_format(self, path: Path) -> tuple[bool, str, str | None]:
        """通过文件魔数预判二进制是否为 PE、ELF 或 Mach-O，并针对非受支持格式进行轻量嗅探

        @param path 目标可执行文件绝对路径
        @return tuple[bool, str, str | None] (是否支持, 探测到的格式名称, 定制重定向建议)
        """
        try:
            with path.open("rb") as f:
                header = f.read(1024)
        except OSError as exc:
            return False, f"读取文件头部失败: {exc}", None

        if len(header) < 4:
            return False, "文件字节过短，无法解析头部", None

        # 1. ELF
        if header.startswith(b"\x7fELF"):
            return True, "ELF", None

        # 2. Mach-O 与 Java Class 区分 (0xCAFEBABE 魔数共享处理)
        magic4 = header[:4]
        if magic4 in MACHO_MAGICS:
            if magic4 == b"\xca\xfe\xba\xbe" and len(header) >= 8:
                import struct

                nfat = struct.unpack(">I", header[4:8])[0]
                if nfat >= 45 or path.suffix.lower() == ".class":
                    return (
                        False,
                        "Java Class 字节码",
                        "目标文件为 Java Class 字节码文件，"
                        "建议使用 CFR、Fernflower 或 JD-GUI 进行反编译。",
                    )
            return True, "Mach-O", None

        # 3. PE (MZ 头部且在 e_lfanew 偏移处为 PE\0\0)
        if header.startswith(b"MZ") and len(header) >= 0x40:
            import struct

            e_lfanew = struct.unpack_from("<I", header, 0x3C)[0]
            if len(header) >= e_lfanew + 4:
                pe_sig = header[e_lfanew : e_lfanew + 4]
                if pe_sig == b"PE\x00\x00":
                    return True, "PE", None
            else:
                try:
                    with path.open("rb") as f:
                        f.seek(e_lfanew)
                        if f.read(4) == b"PE\x00\x00":
                            return True, "PE", None
                except OSError as exc:
                    logger.debug("读取 PE 签名失败: %s", exc)

        # 4. 未受支持二进制的轻量 Magic 格式嗅探与工具链重定向指引 (Format Sniffer)
        # 4.1 Adobe Flash SWF
        if header.startswith(b"FWS") or header.startswith(b"CWS") or header.startswith(b"ZWS"):
            return (
                False,
                "Adobe Flash SWF",
                (
                    "目标文件为 Adobe Flash SWF 动画/程序资源（内嵌 ActionScript 1/2/3 字节码），"
                    "本服务专注于原生机器码逆向。建议使用 FFDec (JPEXS Free Flash Decompiler) "
                    "或 RABCDAsm 进行 AS3 源码反编译。"
                ),
            )

        # 4.2 Android APK / DEX
        is_apk = path.suffix.lower() == ".apk"
        is_dex = header.startswith(b"dex\n")
        if not is_dex and header.startswith(b"PK\x03\x04"):
            try:
                import zipfile

                if zipfile.is_zipfile(path):
                    with zipfile.ZipFile(path, "r") as zf:
                        names = zf.namelist()[:30]
                        if any(
                            n.endswith("classes.dex") or n == "AndroidManifest.xml" for n in names
                        ):
                            is_apk = True
            except Exception:
                pass

        if is_dex or is_apk:
            return (
                False,
                "Android APK / DEX",
                "目标文件为 Android DEX 字节码/APK 包，"
                "建议使用 jadx 或 apktool 进行反编译与资产解包。",
            )

        # 4.3 WebAssembly (WASM)
        if header.startswith(b"\x00asm"):
            return (
                False,
                "WebAssembly (WASM)",
                "目标文件为 WebAssembly 二进制模块，"
                "建议使用 wabt 套件 (wasm2wat) 或 Ghidra WASM 插件进行分析。",
            )

        # 4.4 HTTP Traffic Archive (HAR)
        stripped = header.lstrip()
        if (
            stripped.startswith(b"{")
            and (b'"log"' in header or b"'log'" in header)
            and (b'"version"' in header or b"'version'" in header)
        ):
            return (
                False,
                "HTTP Traffic Archive (HAR)",
                "目标文件为 HTTP 网络流量归档 (.har)，"
                "建议使用 traffic-inspector MCP 或 Python 流量解析脚本处理。",
            )

        # 4.5 PCAP / PCAPNG 抓包文件
        pcap_magics = (
            b"\xd4\xc3\xb2\xa1",
            b"\xa1\xb2\xc3\xd4",
            b"\x0a\x0d\x0d\x0a",
            b"\x4d\x3c\xb2\xa1",
            b"\xa1\xb2\x3c\x4d",
        )
        if any(header.startswith(m) for m in pcap_magics):
            return (
                False,
                "PCAP 网络抓包文件",
                (
                    "目标文件为网络底层抓包文件，建议使用 traffic-inspector MCP "
                    "(analyze_pcap_file) 或 tshark 进行离线流重组分析。"
                ),
            )

        return False, "非受支持的 PE/ELF/Mach-O 二进制文件", None
