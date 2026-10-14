"""YARA 规则编译与多模式规则扫描核心引擎

支持 YARA 规则即时文本编译与规则文件路径加载，并执行全量有效字节扫描与虚拟地址换算映射。

@author Ateng
@since 2026-10-14
"""

import logging
from pathlib import Path
from typing import Any

from mcp_server_reverse.core.memory import convert_address_core
from mcp_server_reverse.core.models import YaraMatch, YaraStringMatch
from mcp_server_reverse.core.session import BinarySession

logger = logging.getLogger(__name__)


def is_yara_available() -> bool:
    """检测宿主机当前运行环境中是否已安装 yara-python 原生引擎

    @return bool 若已安装且可成功导入返回 True，否则返回 False
    """
    try:
        import yara  # noqa: F401

        return True
    except ImportError:
        return False


def compile_yara_rules(
    rule_text: str | None = None,
    rule_file: str | None = None,
) -> Any:
    """编译传入的 YARA 规则文本或规则文件

    @param rule_text 自定义 YARA 规则文本字符串
    @param rule_file YARA 规则文件本地物理绝对路径
    @return Any 编译完成的 yara.Rules 对象
    @throws RuntimeError 当宿主机未安装 yara-python 时抛出
    @throws ValueError 当入参互斥或规则语法错误时抛出
    @throws FileNotFoundError 当指定的规则文件不存在时抛出
    """
    if not is_yara_available():
        raise RuntimeError("宿主机未安装 yara-python 规则匹配引擎")

    import yara

    # 1. 严格参数合法性校验
    if rule_text is None and rule_file is None:
        raise ValueError("必须提供 rule_text 或 rule_file 参数之一")
    if rule_text is not None and rule_file is not None:
        raise ValueError("rule_text 与 rule_file 参数互斥，不能同时提供")

    # 2. 从本地文件加载并编译
    if rule_file is not None:
        file_path = Path(rule_file).expanduser().resolve()
        if not file_path.is_file():
            raise FileNotFoundError(f"指定的 YARA 规则文件不存在: {rule_file}")
        try:
            return yara.compile(filepath=str(file_path))
        except yara.Error as exc:
            raise ValueError(f"YARA 规则文件语法解析错误: {exc}") from exc

    # 3. 从字符串即时编译
    if rule_text is not None:
        clean_text = rule_text.strip()
        if not clean_text:
            raise ValueError("YARA 规则文本不能为空")
        try:
            return yara.compile(source=clean_text)
        except yara.Error as exc:
            raise ValueError(f"YARA 规则文本语法解析错误: {exc}") from exc


def _resolve_virtual_address(session: BinarySession, offset: int) -> str | None:
    """尝试将物理文件偏移量换算为当前会话中的虚拟内存地址 (VA)

    @param session 当前激活的分析会话
    @param offset 文件物理绝对字节偏移量
    @return str | None 换算后的虚拟地址十六进制字符串，未映射到节区则返回 None
    """
    try:
        conv = convert_address_core(session, str(offset), "offset")
        return conv["va"]
    except LookupError:
        # 偏移落在非映射区 (如 Overlay 附加数据区或文件头未映射区)
        return None
    except Exception as exc:
        logger.debug("偏移量 0x%X 虚拟地址换算异常: %s", offset, exc)
        return None


def _format_matched_data(matched_bytes: bytes, max_len: int = 64) -> str:
    """将匹配到的原始字节序列安全格式化为可读文本或十六进制字符串

    @param matched_bytes 匹配到的原始字节
    @param max_len 最大截断长度
    @return str 规范化的字符串表示
    """
    # 截断过长字节避免响应膨胀
    truncated = matched_bytes[:max_len]
    suffix = "..." if len(matched_bytes) > max_len else ""

    try:
        text = truncated.decode("utf-8")
        if text.isprintable():
            return f"{text}{suffix}"
    except (UnicodeDecodeError, AttributeError):
        # 非文本或二进制序列降级为十六进制字符串表示
        return f"{truncated.hex(' ')}{suffix}"

    return f"{truncated.hex(' ')}{suffix}"


def _build_string_match(
    session: BinarySession,
    identifier: str,
    offset: int,
    matched_bytes: bytes,
    length: int,
) -> YaraStringMatch:
    """统一构建单个特征字符串匹配项

    @param session 当前激活的分析会话
    @param identifier 字符串规则标识符
    @param offset 物理文件绝对起始偏移量
    @param matched_bytes 匹配到的原始字节序列
    @param length 匹配字节长度
    @return YaraStringMatch 结构化匹配项
    """
    va_str = _resolve_virtual_address(session, offset)
    text_data = _format_matched_data(matched_bytes)
    return YaraStringMatch(
        identifier=identifier,
        offset=offset,
        virtual_address=va_str,
        data=text_data,
        length=length,
    )


def execute_yara_scan(session: BinarySession, compiled_rules: Any) -> list[YaraMatch]:
    """对当前会话中的有效二进制字节序列执行 YARA 匹配并解析命中元数据

    @param session 当前激活的分析会话 (自动叠加 COW 虚拟补丁)
    @param compiled_rules 预编译的 yara.Rules 对象
    @return list[YaraMatch] 命中画像列表，无匹配时返回空列表
    """
    # 1. 读取包含 COW 虚拟补丁的物理有效全量字节
    data = session.read_effective_bytes(0, None)

    # 2. 调用 YARA 规则匹配引擎
    raw_matches = compiled_rules.match(data=data)
    yara_matches: list[YaraMatch] = []

    for raw_match in raw_matches:
        rule_name = getattr(raw_match, "rule", "")
        namespace = getattr(raw_match, "namespace", "default")
        tags = list(getattr(raw_match, "tags", []))
        meta = dict(getattr(raw_match, "meta", {}))

        matched_strings: list[YaraStringMatch] = []
        raw_strings = getattr(raw_match, "strings", [])

        for string_match in raw_strings:
            ident = getattr(string_match, "identifier", str(string_match))
            if hasattr(string_match, "instances"):
                for inst in string_match.instances:
                    offset = int(getattr(inst, "offset", 0))
                    matched_bytes = getattr(inst, "matched_data", b"")
                    length = int(getattr(inst, "matched_length", len(matched_bytes)))
                    matched_strings.append(
                        _build_string_match(session, ident, offset, matched_bytes, length)
                    )
            elif isinstance(string_match, tuple) and len(string_match) >= 3:
                offset = int(string_match[0])
                ident = str(string_match[1])
                matched_bytes = (
                    string_match[2]
                    if isinstance(string_match[2], bytes)
                    else bytes(str(string_match[2]), "utf-8")
                )
                length = len(matched_bytes)
                matched_strings.append(
                    _build_string_match(session, ident, offset, matched_bytes, length)
                )

        yara_matches.append(
            YaraMatch(
                rule=rule_name,
                namespace=namespace,
                tags=tags,
                meta=meta,
                strings=matched_strings,
            )
        )

    return yara_matches
