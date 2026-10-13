"""MCP 服务端工厂与工具注册中心

@author Ateng
@since 2026-10-13
"""

from typing import Any

from mcp.server.mcpserver import MCPServer

from mcp_server_reverse.core.config import ServerConfig
from mcp_server_reverse.core.locator import ToolLocator
from mcp_server_reverse.core.meta import get_package_version
from mcp_server_reverse.core.parser import BinaryParser
from mcp_server_reverse.core.security import SecurityGuard
from mcp_server_reverse.core.session import SessionStore
from mcp_server_reverse.tools.capabilities import get_capabilities_impl
from mcp_server_reverse.tools.disasm import (
    convert_address_impl,
    decompile_function_impl,
    disassemble_impl,
    find_xrefs_impl,
    read_memory_impl,
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


def create_mcp_server(config: ServerConfig) -> MCPServer:
    """构建并初始化配置好全部 MCP 逆向工具的 MCPServer 实例

    @param config 当前服务端运行配置
    @return MCPServer 就绪的服务端实例
    """
    server = MCPServer(
        name="mcp-server-reverse",
        version=get_package_version(),
        instructions="专为 AI Agent 设计的高性能跨平台二进制静态逆向分析与数字取证服务",
    )

    locator = ToolLocator()
    session_store = SessionStore(max_sessions=config.max_sessions)
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
            "文件物理偏移与大小、R/W/X 访问权限、香农熵 (0.0~8.0) 以及高熵加壳标记 (>= 7.2)"
        ),
    )
    def get_sections(session_id: str) -> dict[str, Any]:
        """提取指定二进制会话的全量节区分布画像

        @param session_id 目标活跃分析会话标识
        @return dict[str, Any] 节区画像响应字典
        """
        return get_sections_impl(
            session_id=session_id,
            session_store=session_store,
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
        name_filter: str | None = None,
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
        name_filter: str | None = None,
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
            "(symbol_type: function, object, exception_frame, all) 过滤；针对 64 位 PE 自动通过 "
            ".pdata 异常目录恢复内部无符号函数 sub_<hex_va> "
            "并标注精确字节长度与 exception_frame 类型"
        ),
    )
    def get_symbols(
        session_id: str,
        name_filter: str | None = None,
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
            "crypto_or_key, suspicious_cmd)，支持正则过滤与外部 floss 软降级"
        ),
    )
    def search_strings(
        session_id: str,
        pattern: str | None = None,
        min_length: int = 4,
        encoding: str = "all",
        ioc_category: str | None = None,
        section_name: str | None = None,
        use_floss: bool = False,
        offset: int = 0,
        limit: int = 50,
    ) -> dict[str, Any]:
        """提取并检索二进制字符串及 IOC 威胁情报标签

        @param session_id 目标活跃分析会话标识
        @param pattern 文本内容正则过滤
        @param min_length 最小连续字符长度 (默认 4)
        @param encoding 编码格式 ("ascii", "utf16le", "all")
        @param ioc_category 7 类威胁情报标签过滤
        @param section_name 所属节区过滤
        @param use_floss 是否启用外部 floss 解码 (未安装时自动软降级)
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
        hex_pattern: str | None = None,
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
            "并返回所属节区名称与 R/W/X 访问权限"
        ),
    )
    def convert_address(
        session_id: str,
        address: str,
        address_type: str = "va",
    ) -> dict[str, Any]:
        """在 VA、RVA 与文件物理偏移之间双向精确换算

        @param session_id 目标活跃分析会话标识
        @param address 待转换的地址或偏移量（如 '0x140001000'）
        @param address_type 输入地址类型 ('va', 'rva', 'offset')
        @return dict[str, Any] 地址换算响应字典
        """
        return convert_address_impl(
            session_id=session_id,
            address=address,
            address_type=address_type,
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
        address: str,
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
            "开始执行多架构反汇编，输出紧凑单行指令流并内联标注相对寻址注释"
        ),
    )
    def disassemble(
        session_id: str,
        target: str,
        count: int = 32,
        stop_at_ret: bool = True,
    ) -> dict[str, Any]:
        """对指定地址或符号执行静态反汇编并内联追加相对寻址注释

        @param session_id 目标活跃分析会话标识
        @param target 起始十六进制虚拟地址（如 '0x140001000'）或符号名称（如 'main'）
        @param count 最大反汇编指令条数（1 ~ 256，默认 32）
        @param stop_at_ret 遇到函数返回指令 (ret/retn/retf) 是否提前终止
        @return dict[str, Any] 反汇编响应字典
        """
        return disassemble_impl(
            session_id=session_id,
            target=target,
            count=count,
            stop_at_ret=stop_at_ret,
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
        target: str,
        xref_type: str = "all",
        offset: int = 0,
        limit: int = 50,
    ) -> dict[str, Any]:
        """检索指向目标地址或符号的全部静态交叉引用

        @param session_id 目标活跃分析会话标识
        @param target 被引用的目标虚拟地址（如 '0x140002250'）或符号名称
        @param xref_type 交叉引用过滤类型 ('all', 'code', 'data')
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
        target: str,
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

    return server
