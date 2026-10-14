# mcp-server-reverse 领域词汇表 (Context Glossary)

面向 AI Agent / LLM 的跨平台二进制静态逆向分析、恶意代码研判与数字取证（DFIR）领域上下文。

## 领域语言 (Language)

**BinarySession (二进制会话)**:
针对单个目标二进制文件（或 Fat Mach-O 通用二进制中的特定架构切片）加载并解析后驻留在进程内 LRU 内存池中的分析上下文；单架构文件以内容哈希前缀作为唯一会话标识，多架构 Fat Binary 以内容哈希与目标架构的复合摘要作为唯一会话标识，并在会话生命周期内惰性缓存结构元数据、已提取字符串与交叉引用倒排索引。
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

**CryptoSignature (密码学常量签名)**:
在二进制字节流中命中的内置已知密码学算法魔数常量（如 AES S-Box / Rcon、SHA-256 / SHA-1 / MD5 初始向量、CRC32 多项式表、DES S-Box），包含算法名称、常量名称、虚拟地址、文件偏移、所属节区与置信度。
_Avoid_: VirusSignature (病毒特征码), FileHash (文件哈希)

**HexMatch (十六进制通配符匹配项)**:
在二进制字节流中通过类 IDA 十六进制通配符模式（如 `"48 89 5C 24 ? 57"`）检索命中的字节片段记录，包含匹配的虚拟地址、文件物理偏移、所属节区与实际命中字节的十六进制表示。
_Avoid_: RegexMatch (文本正则匹配), StringArtifact (字符串制品)

**DisasmInstruction (反汇编机器指令)**:
单条机器码指令经静态反汇编后的结构化表示，包含指令虚拟地址、原始机器码十六进制字节、助记符（Mnemonic）、操作数表达式（Operand String）、自动解析的相对寻址目标或符号/字符串内联注释以及紧凑单行格式化文本。
_Avoid_: SourceLine (源码行), Statement (高级语言语句), Bytecode (虚拟机字节码)

**XrefRecord (交叉引用记录)**:
机器指令或数据区指针指向目标虚拟地址（VA）的引用关系，区分代码调用（`call`）、代码分支跳转（`branch`）、指令级相对寻址数据引用（`rip_relative` / `pc_relative`，含 `ARM64` `ADRP + ADD/LDR` 页偏移配对）与数据段绝对指针（`data_pointer`）。
_Avoid_: Edge (图边), Link (超链接), Reference (普通引用)

**ExternalCapability (外部工具能力)**:
由四级跨平台依赖寻址器探测到的宿主机外部 CLI 逆向工具（`radare2`/`rizin`、`llvm-objdump`/`objdump`、`floss`）的可用状态、可执行文件绝对路径与版本元数据。
_Avoid_: Plugin (插件), Driver (驱动), Extension (扩展)

**ResponseEnvelope (统一响应信封)**:
所有 MCP Tools 对外输出的标准顶层协议结构，统一承载执行成功标志（`ok`）、关联会话标识（`session_id`）、面向大语言模型的自然语言摘要（`summary`）、分页元数据（`pagination`）、结构化业务载荷（`data`）以及带可行动降级建议的标准化错误信息（`error`）。
_Avoid_: RawPayload (裸载荷), HttpResult (HTTP 响应), StatusTuple (状态元组)

**MitigationProfile (漏洞缓解加固画像)**:
目标二进制文件在操作系统级与编译器级启用的全套漏洞利用防御加固元数据，包含 Windows 平台（DEP/NX、ASLR、SafeSEH、CFG 控制流防护、CET 影子栈）、Linux/ELF 平台（NX、PIE 编译位置无关、RELRO 符号重定位只读保护、Stack Canary 栈金丝雀、FORTIFY_SOURCE）、macOS/Mach-O 平台（Hardened Runtime、沙盒化、代码签名限制）及综合利用难度安全评分。
_Avoid_: SecurityCheck (安全检查), ProtectionFlag (保护标志), HardeningConfig (加固配置), ExploitDefense (漏洞防御)

**BasicBlock (基本块)**:
控制流图（CFG）中的最小原子分析单元，由满足“单入口（仅从第一条指令进入）、单出口（仅从最后一条指令离开）”的一组顺序反汇编指令序列构成；包含起始虚拟地址（VA）、终止虚拟地址、指令字节序列及后继分支跳转关系（条件成立跳转、条件不成立跳转或无条件跳转），是函数圈复杂度计算与控制流结构可视化的基础构建块。
_Avoid_: CodeChunk (代码切片), InstructionGroup (指令组), FlowNode (流节点), BasicUnit (基本单元)

**YaraMatch (YARA 规则匹配项)**:
针对二进制文件全量字节流或特定节区执行外部 YARA 规则扫描后命中的威胁判定记录，包含规则标识符、命名空间、规则分类标签（Tags）、作者与威胁属性等元数据字典，以及所有被激活的特征字符串或十六进制模式在物理文件中的偏移量与虚拟地址（VA）定位。
_Avoid_: AntivirusAlert (杀毒警报), RuleHit (规则命中), DetectionEvent (检出事件), SignatureMatch (签名匹配)

**PatchRecord (内存虚拟补丁记录)**:
在二进制会话生命周期内实施的写时复制（COW）内存级虚拟修改条目，记录补丁应用的目标虚拟地址（VA）或物理文件偏移、原始字节序列与替换补丁字节序列；用于支持 Agent 在只读保真物理文件的同时探索分支反转、条件规避或 What-If 假设推演，并支持会话内随时查看与原子回滚。
_Avoid_: DiskWrite (磁盘覆写), HotPatch (热修复), FileDiff (文件差异), BinaryEdit (二进制编辑)

