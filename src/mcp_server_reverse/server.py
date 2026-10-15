"""MCP 服务端工厂与工具注册中心

@author Ateng
@since 2026-10-13
"""

from typing import Annotated, Any

from mcp.server.mcpserver import MCPServer
from pydantic import AliasChoices, Field

from mcp_server_reverse.core.config import ServerConfig
from mcp_server_reverse.core.locator import ToolLocator
from mcp_server_reverse.core.meta import get_package_version
from mcp_server_reverse.core.parser import BinaryParser
from mcp_server_reverse.core.security import SecurityGuard
from mcp_server_reverse.core.session import SessionStore
from mcp_server_reverse.tools.capabilities import get_capabilities_impl
from mcp_server_reverse.tools.cfg import analyze_cfg_impl
from mcp_server_reverse.tools.diff import diff_sessions_impl
from mcp_server_reverse.tools.disasm import (
    convert_address_impl,
    decompile_function_impl,
    disassemble_impl,
    find_xrefs_impl,
    read_memory_impl,
)
from mcp_server_reverse.tools.mitigations import audit_mitigations_impl
from mcp_server_reverse.tools.patch import (
    export_patched_binary_impl,
    list_patches_impl,
    patch_memory_impl,
    revert_patch_impl,
)
from mcp_server_reverse.tools.scanner import (
    search_bytes_and_constants_impl,
    search_strings_impl,
)
from mcp_server_reverse.tools.session import (
    close_session_impl,
    list_sessions_impl,
    open_binary_impl,
)
from mcp_server_reverse.tools.symbols import (
    get_exports_impl,
    get_imports_impl,
    get_sections_impl,
    get_symbols_impl,
)
from mcp_server_reverse.tools.yara import scan_yara_impl


def create_mcp_server(
    config: ServerConfig,
    session_store: SessionStore | None = None,
) -> MCPServer:
    """构建并初始化配置好全部 MCP 逆向工具的 MCPServer 实例

    @param config 当前服务端运行配置
    @param session_store 可选的外部注入会话池实例 (若为 None 则自动创建)
    @return MCPServer 就绪的服务端实例
    """
    server = MCPServer(
        name="mcp-server-reverse",
        version=get_package_version(),
        instructions="专为 AI Agent 设计的高性能跨平台二进制静态逆向分析与数字取证服务",
    )

    locator = ToolLocator()
    session_store = session_store or SessionStore(max_sessions=config.max_sessions)
    security_guard = SecurityGuard()
    parser = BinaryParser()

    @server.tool(
        name="get_capabilities",
        description=(
            "查询当前 MCP 逆向分析服务版本、Python 运行时、"
            "核心静态分析库（LIEF/Capstone/pefile）版本、"
            "外部逆向工具（radare2/objdump/floss）四级寻址探测状态及沙箱边界配置"
        ),
    )
    def get_capabilities() -> dict[str, Any]:
        """获取当前服务所有静态逆向与取证能力元数据"""
        return get_capabilities_impl(config=config, locator=locator)

    @server.tool(
        name="open_binary",
        description=(
            "加载并解析目标 PE/ELF/Mach-O 二进制文件，建立 LRU 内存分析会话；"
            "提取文件哈希 (MD5/SHA256/Imphash)、架构安全缓解特征 (PIE/NX/Canary)、"
            "逆向分诊概览 (节区熵、敏感 API 分类统计、加壳提示) 以及纵深取证特征 "
            "(TLS 回调、调试信息、尾部 Overlay 数据及代码签名)"
        ),
    )
    def open_binary(
        file_path: str,
        target_arch: str | None = None,
    ) -> dict[str, Any]:
        """加载目标二进制文件并建立进程内分析会话"""
        return open_binary_impl(
            file_path=file_path,
            target_arch=target_arch,
            config=config,
            session_store=session_store,
            security_guard=security_guard,
            parser=parser,
        )

    @server.tool(
        name="list_sessions",
        description="枚举当前驻留在进程内 LRU 内存池中的所有活跃二进制分析会话摘要列表",
    )
    def list_sessions() -> dict[str, Any]:
        """列出当前所有活跃的 BinarySession"""
        return list_sessions_impl(session_store=session_store)

    @server.tool(
        name="close_session",
        description="主动关闭并释放指定 session_id 的二进制分析会话，或清空全部驻留会话以回收内存",
    )
    def close_session(session_id: str | None = None) -> dict[str, Any]:
        """释放指定的二进制会话或清空所有会话

        @param session_id 可选的指定会话 ID，未指定时清空所有会话
        @return dict[str, Any] 释放结果响应字典
        """
        return close_session_impl(
            session_id=session_id,
            session_store=session_store,
        )

    @server.tool(
        name="get_sections",
        description=(
            "枚举指定二进制分析会话的全量节区/段分布画像，输出虚拟地址、虚拟尺寸、"
            "文件物理偏移与大小、R/W/X 访问权限、香农熵 (0.0~8.0)、高熵加壳标记 (>= 7.2) "
            "以及通过滑动窗口探测的局部异常高熵块列表；支持按节区名过滤 (name_filter)"
        ),
    )
    def get_sections(
        session_id: str,
        name_filter: Annotated[
            str | None,
            Field(
                default=None,
                description="可选的节区名称正则过滤（兼容别名: name, filter, query, pattern）",
                validation_alias=AliasChoices("name_filter", "name", "filter", "query", "pattern"),
            ),
        ] = None,
        detect_local_entropy: bool = True,
        window_size: int = 2048,
        step: int = 1024,
    ) -> dict[str, Any]:
        """提取指定二进制会话的全量节区分布画像与局部高熵块

        @param session_id 目标活跃分析会话标识
        @param name_filter 可选的节区名称正则过滤
        @param detect_local_entropy 是否启用基于滑动窗口的细粒度局部高熵块探测 (缺省 True)
        @param window_size 滑动窗口字节尺寸 (缺省 2048)
        @param step 滑动步长 (缺省 1024)
        @return dict[str, Any] 节区画像响应字典
        """
        return get_sections_impl(
            session_id=session_id,
            session_store=session_store,
            name_filter=name_filter,
            detect_local_entropy=detect_local_entropy,
            window_size=window_size,
            step=step,
        )

    @server.tool(
        name="get_imports",
        description=(
            "检索指定二进制会话的导入函数表，支持按动态库名正则 (library_filter)、"
            "函数名正则 (name_filter) 及 8 类启发式敏感行为标签 (category: process_injection, "
            "anti_debug, crypto, network, dynamic_load, execution, filesystem, registry) 过滤，"
            "并提供 offset/limit 分页"
        ),
    )
    def get_imports(
        session_id: str,
        library_filter: str | None = None,
        name_filter: Annotated[
            str | None,
            Field(
                default=None,
                description="函数符号名称正则过滤（兼容别名: name, filter, query, pattern）",
                validation_alias=AliasChoices("name_filter", "name", "filter", "query", "pattern"),
            ),
        ] = None,
        category: str | None = None,
        offset: int = 0,
        limit: int = 50,
    ) -> dict[str, Any]:
        """按正则与敏感分类检索导入函数表

        @param session_id 目标活跃分析会话标识
        @param library_filter 动态库名称正则过滤
        @param name_filter 函数符号名称正则过滤
        @param category 8 类敏感行为标签之一
        @param offset 分页偏移量
        @param limit 单页最大条数
        @return dict[str, Any] 导入表检索响应字典
        """
        return get_imports_impl(
            session_id=session_id,
            library_filter=library_filter,
            name_filter=name_filter,
            category=category,
            offset=offset,
            limit=limit,
            session_store=session_store,
        )

    @server.tool(
        name="get_exports",
        description=(
            "枚举指定二进制会话的导出函数符号表，输出导出名称、序号 (ordinal)、"
            "虚拟地址以及转发器目标 (forwarder)，支持按名称正则 (name_filter) 过滤与分页"
        ),
    )
    def get_exports(
        session_id: str,
        name_filter: Annotated[
            str | None,
            Field(
                default=None,
                description="符号名称正则过滤（兼容别名: name, filter, query, pattern）",
                validation_alias=AliasChoices("name_filter", "name", "filter", "query", "pattern"),
            ),
        ] = None,
        offset: int = 0,
        limit: int = 50,
    ) -> dict[str, Any]:
        """枚举并检索导出函数符号表

        @param session_id 目标活跃分析会话标识
        @param name_filter 符号名称正则过滤
        @param offset 分页偏移量
        @param limit 单页最大条数
        @return dict[str, Any] 导出表检索响应字典
        """
        return get_exports_impl(
            session_id=session_id,
            name_filter=name_filter,
            offset=offset,
            limit=limit,
            session_store=session_store,
        )

    @server.tool(
        name="get_symbols",
        description=(
            "检索指定二进制会话的静态与动态符号表，支持按名称正则 (name_filter) 与类型 "
            "(symbol_type: function, object, exception_frame, eh_frame, prologue, all) 过滤；"
            "针对 64 位 PE 自动通过 .pdata 异常目录恢复 exception_frame 函数，"
            "针对 32 位 PE 通过函数序言特征扫描恢复 prologue 函数，"
            "针对 Linux ELF 通过 .eh_frame 展开表恢复 eh_frame 函数"
        ),
    )
    def get_symbols(
        session_id: str,
        name_filter: Annotated[
            str | None,
            Field(
                default=None,
                description="符号名称正则过滤（兼容别名: name, filter, query, pattern）",
                validation_alias=AliasChoices("name_filter", "name", "filter", "query", "pattern"),
            ),
        ] = None,
        symbol_type: str = "all",
        offset: int = 0,
        limit: int = 50,
    ) -> dict[str, Any]:
        """检索静态/动态符号并融合 .pdata 无符号函数恢复

        @param session_id 目标活跃分析会话标识
        @param name_filter 符号名称正则过滤
        @param symbol_type 符号类型过滤
        @param offset 分页偏移量
        @param limit 单页最大条数
        @return dict[str, Any] 符号检索响应字典
        """
        return get_symbols_impl(
            session_id=session_id,
            name_filter=name_filter,
            symbol_type=symbol_type,
            offset=offset,
            limit=limit,
            session_store=session_store,
        )

    @server.tool(
        name="search_strings",
        description=(
            "提取二进制文件全量 ASCII 与 UTF-16LE 字符串，映射所属节区与虚拟地址；"
            "内置 7 类威胁情报 IOC 自动标记 (url, ipv4, filepath, registry, email, "
            "crypto_or_key, suspicious_cmd)，支持单字节 XOR 穷举/指定密钥解密、"
            "Base64 自动识别解码与外部 floss 软降级"
        ),
    )
    def search_strings(
        session_id: str,
        pattern: Annotated[
            str | None,
            Field(
                default=None,
                description="文本内容正则过滤（兼容别名: filter, query, keyword, search）",
                validation_alias=AliasChoices("pattern", "filter", "query", "keyword", "search"),
            ),
        ] = None,
        min_length: int = 4,
        encoding: str = "all",
        ioc_category: str | None = None,
        section_name: str | None = None,
        use_floss: bool = False,
        xor_scan: Annotated[
            bool,
            Field(
                default=False,
                description="是否启用 0x01~0xFF 单字节 XOR 暴力盲扫（需同时提供 pattern 过滤）",
                validation_alias=AliasChoices("xor_scan", "xor", "scan_xor"),
            ),
        ] = False,
        xor_key: Annotated[
            int | None,
            Field(
                default=None,
                description="指定的单字节 XOR 异或解密密钥 (0~255)",
                validation_alias=AliasChoices("xor_key", "key"),
            ),
        ] = None,
        detect_base64: Annotated[
            bool,
            Field(
                default=False,
                description="是否自动识别并解码二进制中的合法 Base64 编码文本块",
                validation_alias=AliasChoices("detect_base64", "base64", "b64"),
            ),
        ] = False,
        offset: int = 0,
        limit: int = 50,
    ) -> dict[str, Any]:
        """提取并检索二进制字符串及 IOC 威胁情报标签与反混淆解码

        @param session_id 目标活跃分析会话标识
        @param pattern 文本内容正则过滤
        @param min_length 最小连续字符长度 (默认 4)
        @param encoding 编码格式 ("ascii", "utf16le", "all")
        @param ioc_category 7 类威胁情报标签过滤
        @param section_name 所属节区过滤
        @param use_floss 是否启用外部 floss 解码 (未安装时自动软降级)
        @param xor_scan 是否启用 0x01~0xFF 单字节 XOR 盲扫
        @param xor_key 指定的单字节 XOR 密钥数值 (0~255)
        @param detect_base64 是否自动识别与解码 Base64 文本块
        @param offset 分页偏移量
        @param limit 单页最大条数
        @return dict[str, Any] 字符串检索响应字典
        """
        return search_strings_impl(
            session_id=session_id,
            pattern=pattern,
            min_length=min_length,
            encoding=encoding,
            ioc_category=ioc_category,
            section_name=section_name,
            use_floss=use_floss,
            xor_scan=xor_scan,
            xor_key=xor_key,
            detect_base64=detect_base64,
            offset=offset,
            limit=limit,
            session_store=session_store,
            locator=locator,
        )

    @server.tool(
        name="search_bytes_and_constants",
        description=(
            "执行类 IDA 十六进制通配符搜索 (如 '48 89 5C 24 ? 57') "
            "以及深度扫描内置常见密码学魔数常量表 (AES S-Box/Rcon, SHA-256/1, MD5, CRC32)"
        ),
    )
    def search_bytes_and_constants(
        session_id: str,
        hex_pattern: Annotated[
            str | None,
            Field(
                default=None,
                description=(
                    "类 IDA 十六进制通配符模式（兼容别名: pattern, filter, query, keyword, search）"
                ),
                validation_alias=AliasChoices(
                    "hex_pattern", "pattern", "filter", "query", "keyword", "search"
                ),
            ),
        ] = None,
        scan_crypto: bool = False,
        section_name: str | None = None,
        offset: int = 0,
        limit: int = 50,
    ) -> dict[str, Any]:
        """执行类 IDA 十六进制通配符搜索与密码学魔数扫描

        @param session_id 目标活跃分析会话标识
        @param hex_pattern 类 IDA 十六进制通配符模式 (如 '48 89 ? 24')
        @param scan_crypto 是否扫描内置已知密码学特征表
        @param section_name 所属节区过滤
        @param offset 分页偏移量
        @param limit 单页最大条数
        @return dict[str, Any] 特征扫描响应字典
        """
        return search_bytes_and_constants_impl(
            session_id=session_id,
            hex_pattern=hex_pattern,
            scan_crypto=scan_crypto,
            section_name=section_name,
            offset=offset,
            limit=limit,
            session_store=session_store,
        )

    @server.tool(
        name="convert_address",
        description=(
            "在虚拟地址 (va)、相对虚拟地址 (rva) 与磁盘文件物理偏移 (offset) 之间双向精确换算，"
            "并返回所属节区名称与 R/W/X 访问权限；"
            "针对 ARM 奇数地址自动按 2 字节对齐并切换至 Thumb 模式"
        ),
    )
    def convert_address(
        session_id: str,
        address: Annotated[
            str,
            Field(
                description="待转换的地址或偏移量（兼容别名: target, va, offset, location）",
                validation_alias=AliasChoices("address", "target", "va", "offset", "location"),
            ),
        ],
        address_type: str = "va",
        thumb: Annotated[
            bool | None,
            Field(
                default=None,
                description="是否按 ARM Thumb 模式自适应对齐奇数地址（奇数自动对齐）",
                validation_alias=AliasChoices("thumb", "thumb_mode", "is_thumb"),
            ),
        ] = None,
    ) -> dict[str, Any]:
        """在 VA、RVA 与文件物理偏移之间双向精确换算

        @param session_id 目标活跃分析会话标识
        @param address 待转换的地址或偏移量（如 '0x140001000'）
        @param address_type 输入地址类型 ('va', 'rva', 'offset')
        @param thumb 可选的 ARM Thumb 模式控制开关
        @return dict[str, Any] 地址换算响应字典
        """
        return convert_address_impl(
            session_id=session_id,
            address=address,
            address_type=address_type,
            thumb=thumb,
            session_store=session_store,
        )

    @server.tool(
        name="read_memory",
        description=(
            "按虚拟地址 (va)、相对虚拟地址 (rva) 或文件偏移 (offset) 读取指定长度的原始字节 "
            "(单次最大 1024 字节)，输出连续十六进制与标准 16 字节宽度带 ASCII 对照列的 Hexdump 视图"
        ),
    )
    def read_memory(
        session_id: str,
        address: Annotated[
            str,
            Field(
                description="起始地址或偏移量（兼容别名: target, va, offset, location）",
                validation_alias=AliasChoices("address", "target", "va", "offset", "location"),
            ),
        ],
        size: int = 64,
        address_type: str = "va",
    ) -> dict[str, Any]:
        """读取指定地址或偏移处的原始字节并生成 Hexdump 视图

        @param session_id 目标活跃分析会话标识
        @param address 起始地址或偏移量（如 '0x140002250'）
        @param size 读取字节长度（1 ~ 1024，默认 64）
        @param address_type 输入地址类型 ('va', 'rva', 'offset')
        @return dict[str, Any] 内存检视响应字典
        """
        return read_memory_impl(
            session_id=session_id,
            address=address,
            size=size,
            address_type=address_type,
            session_store=session_store,
        )

    @server.tool(
        name="disassemble",
        description=(
            "从指定十六进制虚拟地址或函数符号名 (含导出函数、符号表与 PE .pdata sub_<va>) "
            "开始执行多架构反汇编，输出紧凑单行指令流并内联标注相对寻址注释；"
            "支持 ARM Thumb 模式自适应切换与 thumb=True 显式控制"
        ),
    )
    def disassemble(
        session_id: str,
        target: Annotated[
            str,
            Field(
                description=(
                    "起始十六进制虚拟地址或符号名称（兼容别名: location, address, va, entry）"
                ),
                validation_alias=AliasChoices("target", "location", "address", "va", "entry"),
            ),
        ],
        count: int = 32,
        stop_at_ret: bool = True,
        thumb: Annotated[
            bool | None,
            Field(
                default=None,
                description="是否强制启用 ARM Thumb 指令模式（默认 None，奇数地址自动激活）",
                validation_alias=AliasChoices("thumb", "thumb_mode", "is_thumb"),
            ),
        ] = None,
    ) -> dict[str, Any]:
        """对指定地址或符号执行静态反汇编并内联追加相对寻址注释

        @param session_id 目标活跃分析会话标识
        @param target 起始十六进制虚拟地址（如 '0x140001000'）或符号名称（如 'main'）
        @param count 最大反汇编指令条数（1 ~ 256，默认 32）
        @param stop_at_ret 遇到函数返回指令 (ret/retn/retf) 是否提前终止
        @param thumb 是否开启 ARM Thumb 模式反汇编
        @return dict[str, Any] 反汇编响应字典
        """
        return disassemble_impl(
            session_id=session_id,
            target=target,
            count=count,
            stop_at_ret=stop_at_ret,
            thumb=thumb,
            session_store=session_store,
        )

    @server.tool(
        name="find_xrefs",
        description=(
            "检索指向指定目标地址或符号名称的全部静态交叉引用 (call, branch, rip_relative, "
            "ARM64 4 指令窗口 pc_relative 以及数据段全局指针 data_pointer)，支持会话级惰性索引缓存"
        ),
    )
    async def find_xrefs(
        session_id: str,
        target: Annotated[
            str,
            Field(
                description=(
                    "被引用的目标虚拟地址或符号名称（兼容别名: location, address, va, entry）"
                ),
                validation_alias=AliasChoices("target", "location", "address", "va", "entry"),
            ),
        ],
        xref_type: str = "all",
        group_by: Annotated[
            str,
            Field(
                default="none",
                description="聚合折叠维度 ('none' 为扁平列表, 'function' 按调用函数归集折叠)",
                validation_alias=AliasChoices("group_by", "group", "mode"),
            ),
        ] = "none",
        offset: int = 0,
        limit: int = 50,
    ) -> dict[str, Any]:
        """检索指向目标地址或符号的全部静态交叉引用

        @param session_id 目标活跃分析会话标识
        @param target 被引用的目标虚拟地址（如 '0x140002250'）或符号名称
        @param xref_type 交叉引用过滤类型 ('all', 'code', 'data')
        @param group_by 聚合折叠维度 ('none', 'function')
        @param offset 分页偏移量
        @param limit 单页最大条数
        @return dict[str, Any] 交叉引用检索响应字典
        """
        return await find_xrefs_impl(
            session_id=session_id,
            target=target,
            xref_type=xref_type,
            offset=offset,
            limit=limit,
            session_store=session_store,
            group_by=group_by,
        )

    @server.tool(
        name="decompile_function",
        description=(
            "调用本机外部逆向引擎 (radare2 / rizin) 对目标函数地址或符号生成类 C 伪代码；"
            "若未安装外部引擎则返回 EXTERNAL_TOOL_UNAVAILABLE 结构化安装与降级指引"
        ),
    )
    async def decompile_function(
        session_id: str,
        target: Annotated[
            str,
            Field(
                description="目标函数虚拟地址或符号名称（兼容别名: location, address, va, entry）",
                validation_alias=AliasChoices("target", "location", "address", "va", "entry"),
            ),
        ],
        timeout_seconds: int = 30,
    ) -> dict[str, Any]:
        """调用外部反编译引擎对指定函数生成类 C 伪代码

        @param session_id 目标活跃分析会话标识
        @param target 目标函数虚拟地址或符号名称
        @param timeout_seconds 外部反编译子进程最大超时秒数（默认 30）
        @return dict[str, Any] 反编译伪代码响应字典
        """
        return await decompile_function_impl(
            session_id=session_id,
            target=target,
            timeout_seconds=timeout_seconds,
            session_store=session_store,
            locator=locator,
            config=config,
        )

    @server.tool(
        name="patch_memory",
        description=(
            "在当前会话中对指定虚拟地址 (VA) 或文件偏移应用十六进制字节虚拟补丁 (COW 内存覆写层)，"
            "即时影响后续反汇编与内存读取，物理磁盘上的目标文件 100% 只读保真"
        ),
    )
    def patch_memory(
        session_id: str,
        address_or_offset: str,
        patch_hex: str,
        address_type: str = "va",
    ) -> dict[str, Any]:
        """应用会话级内存虚拟补丁

        @param session_id 目标活跃分析会话标识
        @param address_or_offset 目标虚拟地址或物理偏移字符串
        @param patch_hex 十六进制补丁字节 (如 '90 90 CC' 或 'EB 05')
        @param address_type 输入地址类型 ('va', 'rva', 'offset'，缺省 'va')
        @return dict[str, Any] 补丁应用响应字典
        """
        return patch_memory_impl(
            session_id=session_id,
            address_or_offset=address_or_offset,
            patch_hex=patch_hex,
            address_type=address_type,
            session_store=session_store,
        )

    @server.tool(
        name="list_patches",
        description="查看当前分析会话中已应用的所有写时复制 (COW) 内存虚拟补丁条目与状态",
    )
    def list_patches(
        session_id: str,
        include_reverted: bool = False,
    ) -> dict[str, Any]:
        """查看当前会话的全部虚拟补丁列表

        @param session_id 目标活跃分析会话标识
        @param include_reverted 是否包含已撤回的历史补丁记录 (缺省 False 仅返回激活补丁)
        @return dict[str, Any] 补丁列表响应字典
        """
        return list_patches_impl(
            session_id=session_id,
            include_reverted=include_reverted,
            session_store=session_store,
        )

    @server.tool(
        name="revert_patch",
        description=(
            "撤回指定 ID 的内存虚拟补丁，或在未指定 patch_id 时全量原子回滚当前会话的全部补丁，"
            "恢复至原始干净内存状态"
        ),
    )
    def revert_patch(
        session_id: str,
        patch_id: str | None = None,
    ) -> dict[str, Any]:
        """撤回指定虚拟补丁或全量回滚当前会话补丁

        @param session_id 目标活跃分析会话标识
        @param patch_id 待回滚的补丁 ID (如 'patch_0001')，缺省为 None 时全量回滚
        @return dict[str, Any] 回滚操作响应字典
        """
        return revert_patch_impl(
            session_id=session_id,
            patch_id=patch_id,
            session_store=session_store,
        )

    @server.tool(
        name="export_patched_binary",
        description=(
            "将当前会话中叠加全部已激活内存虚拟补丁后的完整二进制有效镜像导出至磁盘文件；"
            "受到受控白名单路径严格防护，绝对禁止覆写原始样本，"
            "并在 POSIX 环境下自动继承原文件执行权限"
        ),
    )
    def export_patched_binary(
        session_id: str,
        output_path: str,
        overwrite: bool = False,
    ) -> dict[str, Any]:
        """将当前会话的修补二进制有效镜像流式导出到指定磁盘文件

        @param session_id 目标活跃分析会话标识
        @param output_path 目标导出文件的物理路径
        @param overwrite 是否允许覆盖已存在的文件 (默认 False)
        @return dict[str, Any] 导出结果响应字典
        """
        return export_patched_binary_impl(
            session_id=session_id,
            output_path=output_path,
            overwrite=overwrite,
            session_store=session_store,
            security_guard=security_guard,
            config=config,
        )

    @server.tool(
        name="analyze_cfg",
        description=(
            "抽取指定函数入口或符号的控制流图 (CFG)，执行基本块划分 (Leader 算法)、"
            "后继边分支分析 (True/False/Unconditional)、圈复杂度计算并生成 Mermaid 流程图"
        ),
    )
    def analyze_cfg(
        session_id: str,
        target: Annotated[
            str,
            Field(
                description=(
                    "目标函数起始虚拟地址表达式或符号名称（兼容别名: location, address, va, entry）"
                ),
                validation_alias=AliasChoices("target", "location", "address", "va", "entry"),
            ),
        ],
        max_blocks: int = 100,
    ) -> dict[str, Any]:
        """抽取指定函数的单入口单出口基本块、控制流拓扑与 Mermaid 流程图

        @param session_id 目标活跃分析会话标识
        @param target 目标函数起始虚拟地址表达式 (如 '0x140001000') 或符号名称
        @param max_blocks 最大提取基本块数量上限 (默认 100)
        @return dict[str, Any] 控制流分析响应字典
        """
        return analyze_cfg_impl(
            session_id=session_id,
            target=target,
            max_blocks=max_blocks,
            session_store=session_store,
        )

    @server.tool(
        name="audit_mitigations",
        description=(
            "全平台 (Windows PE / Linux ELF / macOS Mach-O) 漏洞缓解机制加固审计；"
            "深度检测 ASLR/PIE、DEP/NX、SafeSEH、RELRO、Stack Canary、Control Flow Guard (CFG)、"
            "CET 影子栈、FORTIFY_SOURCE 与苹果代码签名/Hardened Runtime，"
            "计算 0~100 加权安全评分并给出利用难度评级与针对性加固修复建议"
        ),
    )
    def audit_mitigations(
        session_id: str,
    ) -> dict[str, Any]:
        """审计目标二进制全平台漏洞缓解机制并计算加权安全评分

        @param session_id 目标活跃分析会话标识
        @return dict[str, Any] 漏洞缓解机制加固审计响应字典
        """
        return audit_mitigations_impl(
            session_id=session_id,
            session_store=session_store,
        )

    @server.tool(
        name="scan_yara",
        description=(
            "对指定分析会话的二进制镜像执行多模式 YARA 规则匹配扫描；支持传入自定义规则文本 "
            "(rule_text) 或规则文件路径 (rule_file)，提取命中规则名称、Tags 标签、元数据字典"
            "以及匹配特征字符串在物理文件偏移与内存虚拟地址 (VA) 的定位。"
            "透明感知内存虚拟补丁，未安装 yara-python 时提供语义化错误码与安装指引优雅降级"
        ),
    )
    def scan_yara(
        session_id: str,
        rule_text: str | None = None,
        rule_file: str | None = None,
    ) -> dict[str, Any]:
        """执行 YARA 规则匹配扫描

        @param session_id 目标活跃分析会话标识
        @param rule_text 自定义 YARA 规则文本字符串
        @param rule_file YARA 规则文件本地物理绝对路径
        @return dict[str, Any] YARA 匹配结果响应字典
        """
        return scan_yara_impl(
            session_id=session_id,
            rule_text=rule_text,
            rule_file=rule_file,
            session_store=session_store,
        )

    @server.tool(
        name="diff_sessions",
        description=(
            "对比两个活跃二进制分析会话的二阶结构化差异画像，输出同源相似度分值 (0~100)、"
            "节区拓扑与香农熵差异 (entropy_delta)、导入导出敏感 API 增删集合及公共符号基址偏移推导"
        ),
    )
    def diff_sessions(
        session_id_a: Annotated[
            str,
            Field(
                description="基准会话唯一标识（兼容别名: session_a, source, source_session）",
                validation_alias=AliasChoices(
                    "session_id_a", "session_a", "source", "source_session"
                ),
            ),
        ],
        session_id_b: Annotated[
            str,
            Field(
                description="比对目标会话唯一标识（兼容别名: session_b, target, target_session）",
                validation_alias=AliasChoices(
                    "session_id_b", "session_b", "target", "target_session"
                ),
            ),
        ],
    ) -> dict[str, Any]:
        """对比两个活跃分析会话的二阶结构化差异画像

        @param session_id_a 基准分析会话标识
        @param session_id_b 比对目标分析会话标识
        @return dict[str, Any] 跨会话差异画像响应字典
        """
        return diff_sessions_impl(
            session_id_a=session_id_a,
            session_id_b=session_id_b,
            session_store=session_store,
        )

    return server
