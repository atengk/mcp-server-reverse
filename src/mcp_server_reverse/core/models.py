"""MCP 协议响应信封、标准错误码与核心领域数据模型

@author Ateng
@since 2026-10-13
"""

import time
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
    FORBIDDEN_OVERWRITE_ORIGINAL = "FORBIDDEN_OVERWRITE_ORIGINAL"


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
class LocalEntropyBlock:
    """节区内滑动窗口探测到的局部异常高熵数据块

    @author Ateng
    @since 2026-10-14
    @param offset 块在文件内的物理绝对起始偏移量
    @param virtual_address 块在内存中的虚拟地址 (十六进制字符串, 若不可用则为 None)
    @param size 连续高熵数据块的字节尺寸
    @param max_entropy 块内滑动窗口测得的最高香农熵值 (0.0 ~ 8.0)
    """

    offset: int
    virtual_address: str | None
    size: int
    max_entropy: float

    def to_dict(self) -> dict[str, Any]:
        """将局部高熵块序列化为字典对象

        @return dict[str, Any] 序列化字典对象
        """
        return asdict(self)


@dataclass
class SectionProfile:
    """节区与段静态分布元数据画像

    @param name 节区或段名称 (如 .text, .rdata, .rodata)
    @param virtual_address 映射后的虚拟地址十六进制表示
    @param virtual_size 虚拟内存中占用的字节尺寸
    @param raw_offset 在磁盘文件中的物理字节偏移
    @param raw_size 磁盘文件中占用的物理字节尺寸
    @param permissions 访问权限字符串 (如 "r-x", "rw-", "r--")
    @param entropy 香农熵数值 (0.0 ~ 8.0)
    @param is_high_entropy 是否为疑似加壳或加密的高熵节区 (>= 7.2)
    @param local_high_entropy_blocks 滑动窗口细粒度探测到的局部高熵异常块列表
    """

    name: str
    virtual_address: str
    virtual_size: int
    raw_offset: int
    raw_size: int
    permissions: str
    entropy: float
    is_high_entropy: bool
    local_high_entropy_blocks: list[LocalEntropyBlock] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """将节区画像序列化为字典对象

        @return dict[str, Any] 序列化字典对象
        """
        data = asdict(self)
        data["local_high_entropy_blocks"] = [
            b if isinstance(b, dict) else asdict(b) for b in self.local_high_entropy_blocks
        ]
        return data


@dataclass
class SymbolEntry:
    """统一抽象的导入函数、导出函数、符号或异常表恢复函数项

    @param name 原始符号或函数名称
    @param demangled_name C++ Demangle 后的可读符号名称 (若有)
    @param library 所属动态库名称 (如 KERNEL32.dll, libc.so.6)
    @param address 符号虚拟地址或导入表条目地址十六进制
    @param size 符号或函数字节长度 (若已知)
    @param symbol_type 符号类型 ("import", "export", "function", "object", "exception_frame")
    @param category 启发式敏感行为分类标签 (若命中)
    """

    name: str
    demangled_name: str | None = None
    library: str | None = None
    address: str = "0x0"
    size: int = 0
    symbol_type: str = "function"
    category: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """将符号项序列化为字典对象，包含 symbol_type 及别名 type

        @return dict[str, Any] 序列化字典对象
        """
        res = asdict(self)
        res["type"] = self.symbol_type
        return res


@dataclass
class StringArtifact:
    """提取的静态文本或解码动态字符串工件

    @param value 字符串文本内容
    @param encoding 编码格式 ("ascii", "utf16le", "floss_stack", "floss_decoded")
    @param file_offset 物理文件字节偏移量
    @param virtual_address 映射后的虚拟地址十六进制字符串
    @param section 所属节区名称 (若位于节区内)
    @param ioc_category 识别到的 7 类威胁情报标签之一 (若命中)
    @param length 字符串字符长度
    """

    value: str
    encoding: str
    file_offset: int
    virtual_address: str
    section: str | None = None
    ioc_category: str | None = None
    length: int = 0

    def to_dict(self) -> dict[str, Any]:
        """将字符串工件序列化为字典对象

        @return dict[str, Any] 序列化字典对象
        """
        return asdict(self)


@dataclass
class DeobfuscatedString:
    """经单字节 XOR 或 Base64 反混淆解码还原的字符串工件

    @param value 解密/解码后的明文字符串
    @param method 混淆还原算法类型 ("xor", "base64")
    @param xor_key 异或密钥数值 (0x01~0xFF，仅 method="xor" 时有效)
    @param file_offset 原始密文在文件中的起始物理偏移量
    @param virtual_address 映射后的虚拟地址十六进制字符串
    @param section 所属节区名称
    @param ioc_category 自动标记的 IOC 威胁情报标签
    @param length 明文字符串长度
    """

    value: str
    method: str
    xor_key: int | None = None
    file_offset: int = 0
    virtual_address: str = "0x0"
    section: str | None = None
    ioc_category: str | None = None
    length: int = 0

    def to_dict(self) -> dict[str, Any]:
        """将反混淆字符串工件序列化为字典对象

        @return dict[str, Any] 序列化字典对象
        """
        return asdict(self)


@dataclass
class CryptoSignature:
    """扫描匹配到的密码学特征魔数或常量表

    @param algorithm 所属密码学算法名称 (如 AES, SHA-256, CRC32)
    @param name 特征常量规范名称 (如 AES S-Box, SHA-256 Initial IV)
    @param virtual_address 匹配位置的虚拟地址十六进制字符串
    @param file_offset 物理文件中的字节偏移量
    @param section 所属节区名称 (若有)
    @param confidence 识别置信度 (0.0 ~ 1.0)
    """

    algorithm: str
    name: str
    virtual_address: str
    file_offset: int
    section: str | None = None
    confidence: float = 1.0

    def to_dict(self) -> dict[str, Any]:
        """将密码学特征签名序列化为字典对象

        @return dict[str, Any] 序列化字典对象
        """
        return asdict(self)


@dataclass
class HexMatch:
    """十六进制通配符搜索命中匹配项

    @param virtual_address 映射后的虚拟地址十六进制字符串
    @param file_offset 物理文件中的字节偏移量
    @param section 所属节区名称 (若有)
    @param matched_hex 实际匹配到的十六进制字节序列字符串 (空格分隔)
    """

    virtual_address: str
    file_offset: int
    section: str | None
    matched_hex: str

    def to_dict(self) -> dict[str, Any]:
        """将 Hex 匹配项序列化为字典对象

        @return dict[str, Any] 序列化字典对象
        """
        return asdict(self)


def resolve_offset_to_section_and_va(
    offset: int,
    sections: list[SectionProfile],
    image_base: int,
) -> tuple[str | None, str]:
    """根据文件物理偏移映射其所属节区名称与绝对虚拟地址

    @param offset 文件字节物理偏移
    @param sections 节区分布画像列表
    @param image_base 镜像基址数值
    @return tuple[str | None, str] (节区名, 虚拟地址字符串)
    """
    for sec in sections:
        if sec.raw_offset <= offset < (sec.raw_offset + sec.raw_size):
            delta = offset - sec.raw_offset
            va_int = int(sec.virtual_address, 16) + delta
            return sec.name, f"0x{va_int:X}"

    return None, "0x0"


@dataclass
class XrefRecord:
    """静态交叉引用记录 (Code / Data Xref)

    @author Ateng
    @since 2026-10-13
    @param from_address 发起引用的源虚拟地址十六进制字符串
    @param to_address 被引用的目标虚拟地址十六进制字符串
    @param xref_type 引用细分类型 ("call", "branch", "rip_relative", "pc_relative", "data_pointer")
    @param category 引用主类别 ("code" 或 "data")
    @param instruction 发起引用的汇编指令文本或数据指针表达式
    @param section 发起引用所在的节区名称
    """

    from_address: str
    to_address: str
    xref_type: str
    category: str
    instruction: str | None = None
    section: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """将交叉引用记录序列化为字典对象

        @return dict[str, Any] 序列化字典对象
        """
        res = asdict(self)
        res["type"] = self.xref_type
        return res


@dataclass
class DisasmInstruction:
    """单条反汇编机器指令模型

    @author Ateng
    @since 2026-10-13
    @param address 指令虚拟地址十六进制字符串
    @param hex_bytes 指令机器码字节十六进制表示
    @param mnemonic 汇编助记符 (如 lea, call, ret)
    @param op_str 操作数表达式字符串
    @param comment 自动计算的相对寻址目标、字符串字面量或符号内联注释
    @param formatted 紧凑单行汇编展示文本
    """

    address: str
    hex_bytes: str
    mnemonic: str
    op_str: str
    comment: str | None = None
    formatted: str = ""

    def to_dict(self) -> dict[str, Any]:
        """将反汇编指令序列化为字典对象

        @return dict[str, Any] 序列化字典对象
        """
        return asdict(self)


class PatchStatus(StrEnum):
    """内存虚拟补丁状态枚举"""

    ACTIVE = "active"
    REVERTED = "reverted"


@dataclass
class PatchRecord:
    """会话级写时复制 (COW) 内存虚拟补丁条目

    @param patch_id 补丁唯一标识 (如 'patch_0001')
    @param target_address 补丁应用的十六进制虚拟地址 (如 '0x140001000')
    @param file_offset 对应的物理文件偏移量
    @param size 补丁字节尺寸
    @param original_bytes_hex 被覆盖前的原始字节十六进制表示
    @param patch_bytes_hex 应用的补丁字节十六进制表示
    @param section 所属节区名称
    @param status 补丁状态 ('active' 或 'reverted')
    @param created_at 补丁创建时间戳
    """

    patch_id: str
    target_address: str
    file_offset: int
    size: int
    original_bytes_hex: str
    patch_bytes_hex: str
    section: str
    status: str = PatchStatus.ACTIVE.value
    created_at: float = field(default_factory=time.time)
    raw_patch_bytes: bytes = field(default=b"", repr=False)

    def to_dict(self) -> dict[str, Any]:
        """将补丁记录序列化为对外公开的标准字典对象

        @return dict[str, Any] 序列化字典对象
        """
        data = asdict(self)
        data.pop("raw_patch_bytes", None)
        return data


@dataclass
class CFGEdge:
    """控制流图 (CFG) 基本块之间的有向分支边模型

    @param target_address 目标基本块起始虚拟地址 (十六进制字符串, 如 '0x140001008')
    @param branch_type 分支跳转语义类型 ('true_branch', 'false_branch', 'unconditional')
    """

    target_address: str
    branch_type: str = "unconditional"

    def to_dict(self) -> dict[str, str]:
        """将分支边序列化为字典对象"""
        return asdict(self)


@dataclass
class BasicBlock:
    """控制流图 (CFG) 中的原子基本块模型

    @param block_id 块唯一标识 (如 'bb_0', 'bb_1')
    @param start_address 起始虚拟地址 (十六进制字符串, 如 '0x140001000')
    @param end_address 终止虚拟地址 (末条指令地址)
    @param size 基本块占用的总字节数
    @param instruction_count 基本块包含的指令条数
    @param instructions 格式化后的紧凑指令行列表
    @param successors 后继基本块跳转分支边列表
    @param terminator_mnemonic 终止跳转助记符 (如 'jz', 'jmp', 'ret' 等)
    """

    block_id: str
    start_address: str
    end_address: str
    size: int
    instruction_count: int
    instructions: list[str] = field(default_factory=list)
    successors: list[CFGEdge] = field(default_factory=list)
    terminator_mnemonic: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """将基本块序列化为字典对象

        @return dict[str, Any] 序列化字典对象
        """
        data = asdict(self)
        data["successors"] = [s if isinstance(s, dict) else asdict(s) for s in self.successors]
        return data


class ExploitDifficulty(StrEnum):
    """二进制漏洞利用难度评级枚举"""

    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    EXTREME = "Extreme"


class RelroStatus(StrEnum):
    """Linux ELF 重定位只读 (RELRO) 保护级别枚举"""

    FULL = "Full"
    PARTIAL = "Partial"
    NONE = "None"


@dataclass
class MitigationProfile:
    """全平台二进制漏洞缓解机制加固画像

    @author Ateng
    @since 2026-10-14
    @param format 目标二进制文件格式 ('PE', 'ELF', 'Mach-O')
    @param arch 架构名称 (x86_64, arm64, etc.)
    @param score 综合安全加固评分 (0 ~ 100)
    @param exploit_difficulty 漏洞利用难度评级 ('Low', 'Medium', 'High', 'Extreme')
    @param mitigations 平台对应的缓解机制详细开关字典
    @param summary 缓解机制审计结论总结
    @param recommendations 针对未启用防御措施的加固改进建议列表
    """

    format: str
    arch: str
    score: int
    exploit_difficulty: str
    mitigations: dict[str, Any]
    summary: str
    recommendations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """将加固画像序列化为字典对象

        @return dict[str, Any] 序列化字典对象
        """
        return asdict(self)


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


@dataclass
class YaraStringMatch:
    """YARA 规则匹配中的单个特征字符串定位记录

    @author Ateng
    @since 2026-10-14

    @param identifier 规则中定义的字符串标识符 (如 $s1, $payload)
    @param offset 匹配字符串在物理文件中的绝对起始偏移量
    @param virtual_address 匹配字符串在内存镜像中的虚拟地址 (十六进制字符串, 未映射则为 None)
    @param data 匹配的字符串可读文本或十六进制表示
    @param length 匹配字节长度
    """

    identifier: str
    offset: int
    virtual_address: str | None
    data: str
    length: int

    def to_dict(self) -> dict[str, Any]:
        """将匹配字符串记录序列化为字典对象

        @return dict[str, Any] 序列化字典对象
        """
        return asdict(self)


@dataclass
class YaraMatch:
    """YARA 规则命中画像

    @author Ateng
    @since 2026-10-14

    @param rule 命中规则名称标识
    @param namespace 规则所属命名空间 (缺省 'default')
    @param tags 规则绑定的 Tags 标签列表
    @param meta 规则内嵌的自定义元数据字典 (如 description, author)
    @param strings 激活命中的特征字符串详情列表
    """

    rule: str
    namespace: str = "default"
    tags: list[str] = field(default_factory=list)
    meta: dict[str, Any] = field(default_factory=dict)
    strings: list[YaraStringMatch] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """将 YARA 命中记录序列化为字典对象

        @return dict[str, Any] 序列化字典对象
        """
        return asdict(self)


@dataclass
class RichHeaderEntry:
    """PE Rich Header 编译构建组件记录

    @author Ateng
    @since 2026-10-14

    @param comp_id 组件 32 位唯一标识符 (ProdID << 16 | BuildNumber)
    @param prod_id 产品/工具链 ID
    @param prod_name 已知 Visual Studio 编译器或工具链产品名称 (如 "Utc1900_C", "Linker1400")
    @param build_number 内部编译器构建版本号
    @param use_count 组件在编译链接过程中的引用/对象计数
    """

    comp_id: int
    prod_id: int
    prod_name: str
    build_number: int
    use_count: int

    def to_dict(self) -> dict[str, Any]:
        """将 Rich Header 条目序列化为字典对象

        @return dict[str, Any] 序列化字典对象
        """
        return asdict(self)


@dataclass
class ForensicMetadata:
    """二进制纵深数字取证特征元数据画像

    @author Ateng
    @since 2026-10-14

    @param tls_callbacks PE TLS 回调函数虚拟地址十六进制列表
    @param debug_info 调试与符号信息 (pdb_path, timestamp, rich_header_hash)
    @param overlay 尾部未映射 Overlay 附加数据元数据 (offset, size, entropy, is_high_entropy)
    @param code_signing 代码签名状态画像 (is_signed, cert_info, signer)
    @param needed_libraries 显式依赖的动态链接库列表
    @param rich_header_entries PE Rich Header 解析出的编译器构建工具链组件列表
    @param fuzzy_hash SSDEEP / CTPH 上下文触发分段模糊哈希 (用于家族相似度比对)
    @param entitlements Apple Mach-O 代码签名中的 XML 权限清单字典
    """

    tls_callbacks: list[str] = field(default_factory=list)
    debug_info: dict[str, Any] = field(default_factory=dict)
    overlay: dict[str, Any] | None = None
    code_signing: dict[str, Any] = field(default_factory=dict)
    needed_libraries: list[str] = field(default_factory=list)
    rich_header_entries: list[RichHeaderEntry] = field(default_factory=list)
    fuzzy_hash: str | None = None
    entitlements: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """将取证元数据画像序列化为字典对象

        @return dict[str, Any] 序列化字典对象
        """
        return asdict(self)


@dataclass
class ClrMetadata:
    """Windows PE .NET CLR 托管程序与运行时指引画像

    @author Ateng
    @since 2026-10-15

    @param is_managed 是否为 .NET 托管程序
    @param runtime 运行时名称标识 (如 '.NET CLR', 未托管为 'Native')
    @param clr_runtime_version CLR 目标运行时版本 (如 'v4.0.30319')
    @param guidance 面向 AI Agent 的专用托管反编译引导建议
    """

    is_managed: bool
    runtime: str = "Native"
    clr_runtime_version: str | None = None
    guidance: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """将 CLR 画像序列化为字典对象

        @return dict[str, Any] 序列化字典对象
        """
        return asdict(self)


@dataclass
class BinaryDiff:
    """跨会话二阶结构化差异画像

    @author Ateng
    @since 2026-10-15

    @param session_id_a 基准会话标识
    @param session_id_b 目标比对会话标识
    @param similarity_score SSDEEP 模糊哈希同源相似度分值 (0 ~ 100)
    @param file_info 基础文件信息对比 (架构、位宽、端序等一致性)
    @param mitigations 漏洞缓解机制防御配置变化对比
    @param sections 节区拓扑、尺寸增减与香农熵差异 (含新增异常高熵节区)
    @param imports 导入表增删 API 集合及高危敏感行为标签
    @param exports 导出表增删 API 集合
    @param symbols 公共符号虚拟地址重定位偏移推导及独有函数列表
    """

    session_id_a: str
    session_id_b: str
    similarity_score: int
    file_info: dict[str, Any] = field(default_factory=dict)
    mitigations: dict[str, Any] = field(default_factory=dict)
    sections: dict[str, Any] = field(default_factory=dict)
    imports: dict[str, Any] = field(default_factory=dict)
    exports: dict[str, Any] = field(default_factory=dict)
    symbols: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """将差异画像序列化为字典对象

        @return dict[str, Any] 序列化字典对象
        """
        return asdict(self)
