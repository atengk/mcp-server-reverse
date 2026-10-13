# mcp-server-reverse 领域词汇表 (Context Glossary)

面向 AI Agent / LLM 的跨平台二进制静态逆向分析、恶意代码研判与数字取证（DFIR）领域上下文。

## 领域语言 (Language)

**BinarySession (二进制会话)**:
针对单个目标二进制文件（或 Fat Mach-O 通用二进制中的特定架构切片）加载并解析后驻留在进程内 LRU 内存池中的分析上下文；单架构文件以物理文件 `SHA-256` 前 12 位作为唯一 `session_id`，多架构 Fat Binary 以 `sha256(f"{file_sha256}:{resolved_arch}")[:12]` 作为唯一 `session_id`，并在会话生命周期内惰性缓存结构元数据与交叉引用倒排索引。
_Avoid_: Connection (连接), Process (进程), Database (数据库), Instance (实例)

**ForensicMetadata (取证元数据)**:
附着于 `BinarySession` 的高价值数字取证与溯源特征集合，涵盖早于入口点执行的 `tls_callbacks`（PE TLS 回调 / ELF `.init_array`）、调试与编译指纹 `debug_info`（PDB 路径、编译时间戳、Rich Header 哈希）、文件尾部未映射附加数据 `overlay`（偏移、尺寸、香农熵）、代码签名状态 `code_signing` 及直接依赖库列表 `needed_libraries`。
_Avoid_: FileProperties (文件属性), ExtraAttributes (附加属性)

**SectionProfile (节区画像)**:
二进制文件中的节（Section）或段（Segment）静态分布元数据，包含虚拟地址、文件物理偏移、尺寸、权限标志（R/W/X）及用于识别加壳/加密的香农熵（Shannon Entropy）。
_Avoid_: Block (块), Page (内存页), Chunk (分片)

**SymbolEntry (符号与导入导出项)**:
统一抽象的导入函数、导出函数、符号表记录或基于 PE64 `.pdata` 异常目录恢复的无符号内部函数（`sub_<va>`，类型为 `exception_frame`），附带所属动态库、虚拟地址、尺寸以及启发式敏感行为标签（如 `crypto`、`network`、`anti_debug`、`process_injection`）。
_Avoid_: FunctionNode (函数节点), Variable (变量), Method (方法)

**StringArtifact (字符串制品)**:
从二进制数据区提取的可打印字符序列（ASCII/UTF-8/UTF-16LE 或外部 `floss` 解码的混淆栈字符串），附带文件偏移、虚拟地址、所属节区及 IOC 威胁情报分类标签。
_Avoid_: TextLine (文本行), LogEntry (日志项), Message (消息)

**XrefRecord (交叉引用记录)**:
机器指令或数据区指针指向目标虚拟地址（VA）的引用关系，区分代码调用（`call`）、代码分支跳转（`branch`）、指令级相对寻址数据引用（`rip_relative` / `pc_relative`，含 `ARM64` `ADRP + ADD/LDR` 双指令页偏移配对）与数据段绝对指针（`data_pointer`）。
_Avoid_: Edge (图边), Link (超链接), Reference (普通引用)

**CryptoSignature (密码学与特征签名)**:
在二进制字节流中命中的已知算法魔数常量（如 AES S-Box、SHA-256/MD5 初始向量、CRC32 多项式表）或自定义类 IDA 十六进制通配符模式匹配结果。
_Avoid_: VirusSignature (病毒特征码), FileHash (文件哈希)

**ExternalCapability (外部工具能力)**:
由四级跨平台依赖寻址器探测到的宿主机外部 CLI 逆向工具（`radare2`/`rizin`、`llvm-objdump`/`objdump`、`floss`）的可用状态、可执行文件绝对路径与版本元数据。
_Avoid_: Plugin (插件), Driver (驱动), Extension (扩展)
