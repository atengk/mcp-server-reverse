# 需求规格说明书 (Spec): mcp-server-reverse 跨平台二进制静态逆向分析与数字取证 MCP Server

- **状态**: 就绪可执行 (`ready-for-agent`)
- **创建日期**: 2026-10-13
- **遵循领域词汇表**: `BinarySession`, `ForensicMetadata`, `SectionProfile`, `SymbolEntry`, `StringArtifact`, `XrefRecord`, `CryptoSignature`, `ExternalCapability`
- **遵循架构决策**: ADR-0001, ADR-0002, ADR-0003, ADR-0004

---

## Problem Statement (问题陈述)

在安全研究、恶意软件分诊（Malware Triage）、CTF 逆向工程及遗留二进制资产审计场景中，AI Agent / 大语言模型（LLM）在对编译后的二进制文件（Windows PE、Linux/Android ELF、macOS/iOS Mach-O）执行静态逆向分析时面临五大核心痛点：

1. **重型逆向软件依赖门槛高，难以开箱即用**：传统逆向分析强依赖 IDA Pro、Ghidra、Binary Ninja 或本地编译的 Radare2 等庞大外部软件。在未安装这些软件的普通开发机或轻量级环境上，Agent 甚至无法完成基础的二进制文件结构探查与反汇编。
2. **现代 64 位二进制的相对寻址导致引用链断裂**：在 `x86_64` 与 `ARM64` 架构下，代码对字符串、全局变量及导入表桩函数的引用普遍采用指令指针相对寻址（如 `x86_64` 的 `RIP-relative` 或 `ARM64` 的 `ADRP + ADD/LDR` 双指令组合），而非硬编码绝对虚拟地址。单纯依靠字节搜索或 `strings` 工具无法建立字符串与函数之间的交叉引用关系（`XrefRecord`）。
3. **无符号（Stripped）与恶意样本的关键取证线索隐蔽**：生产级程序与恶意样本普遍剥离了符号表（`.symtab`），且恶意软件常将反调试与解密入口隐藏在早于 `entry_point` 执行的 PE TLS 回调函数中，或将载荷隐藏在节区末尾未映射的 Overlay 附加数据中。缺乏深度取证元数据（`ForensicMetadata`）与基于异常表（PE64 `.pdata`）的函数恢复能力，会导致 Agent 遗漏真正的核心逻辑。
4. **重复解析耗时与海量输出撑爆上下文窗口**：几十 MB 的二进制文件包含上万条导入符号、字符串与反汇编指令。若每次工具调用都从磁盘重新解析，且不加分页地返回全量数据，不仅会引发严重的 CPU/I/O 阻塞，还会瞬间撑爆大模型的 Token 上下文窗口。
5. **缺少统一的沙箱边界与远程隔离部署能力**：分析高危未知样本时需要在受控目录白名单、文件体积上限或远程隔离容器中进行，现有工具缺乏标准化的路径防穿越沙箱、双模传输（`stdio` + `sse`/`streamable-http`）与分级健康自检探针。

---

## Solution (核心解决方案)

构建 `mcp-server-reverse`——专为 AI Agent 打造的跨平台二进制静态逆向分析与数字取证（DFIR）MCP Server：

1. **纯 Python 静态分析内核 + 按需外部 CLI 混合引擎（遵循 ADR-0001）**：
   - **纯 Python 核心层（100% 兜底可用）**：基于 `lief`、`pefile` 与 `capstone`，零外部软件依赖即可原生支持 PE、ELF、Mach-O（含 Fat Universal Binary 多架构切片）三大格式的 14 项核心静态逆向分析能力。
   - **外部 CLI 增强层（按需动态激活）**：通过四级跨平台寻址器探测宿主机上的 `radare2`/`rizin`、`llvm-objdump`/`objdump` 与 `floss`（`ExternalCapability`），无缝解锁类 C 伪代码反编译（`decompile_function`）与混淆栈字符串解码；当外部工具未安装时，提供区分式优雅降级（反编译返回结构化引导，字符串提取自动软回退至内置引擎）。
2. **进程内 LRU `BinarySession` 缓存池与渐进式披露（遵循 ADR-0002）**：
   - 以文件 `SHA-256` 前 12 位（Fat Binary 结合所选架构切片生成复合哈希）作为唯一 `session_id`，在内存中驻留最多 `8` 个活跃 `BinarySession`；
   - 所有检索与列表工具强制分页（`offset`/`limit`）并统一包裹在标准响应信封中，反汇编指令采用紧凑单行格式并内联字符串/符号注释。
3. **纵深数字取证（`ForensicMetadata`）与无符号函数恢复**：
   - 在 `open_binary` 中一站式提取文件哈希（含 Imphash）、安全防护标志（PIE/NX/Canary）、节区香农熵、敏感 API 行为分类统计，以及 `ForensicMetadata`（TLS 回调列表、PDB 调试路径、编译时间戳、Rich Header 哈希、Overlay 尾部附加数据及熵值、代码签名状态、依赖库列表）；
   - 在 `get_symbols` 中自动解析 x64 PE `.pdata` 异常目录（`IMAGE_DIRECTORY_ENTRY_EXCEPTION`），为去符号二进制自动恢复 `sub_<va>`（`type="exception_frame"`）内部函数起止边界。
4. **基于 Capstone 的指令级相对寻址 `XrefRecord` 引擎与惰性索引（遵循 ADR-0003）**：
   - 支持 `x86_64` `RIP-relative`、`ARM64` 4 指令滑动窗口 `ADRP + ADD/LDR` 页偏移配对、直接分支指令（`call`/`jmp`/`bl`/`b`）及数据段绝对指针（`data_pointer`）扫描；
   - 首次调用 `find_xrefs` 时通过后台线程惰性构建会话级倒排索引并缓存，使同一会话后续交叉引用查询达到毫秒级 $O(1)$ 命中。
5. **四级跨平台寻址、分级健康探针与沙箱安全守卫（遵循 ADR-0004）**：
   - 实现 `CLI > MCP_REVERSE_* 环境变量 > PATH > OS 标准安装路径` 四级外部工具寻址与 `--check` / `--doctor` 分级探针；
   - 内置 `--allowed-dir` 目录白名单沙箱、`--max-file-size-mb` 体积熔断与远程 Bearer Token 鉴权。

---

## User Stories (用户故事)

### 一、会话管理、安全沙箱与全景取证画像 (`BinarySession` & `ForensicMetadata`)
1. 作为一名安全分析 Agent，我希望调用 `open_binary` 加载本地 PE、ELF 或 Mach-O 文件并获得唯一的 12 位 `session_id`，以便后续所有分析工具直接复用内存中的 `BinarySession` 而无需重复读取磁盘。
2. 作为一名逆向分析 Agent，当加载包含 `x86_64` 与 `arm64` 多架构切片的 macOS Fat Mach-O 文件时，我希望在 `open_binary` 的 `format_info.available_architectures` 中看到全部可用架构，并能通过 `target_arch` 参数分别打开不同架构切片的独立 `BinarySession`，以便互不干扰地对比分析各架构代码。
3. 作为一名恶意代码取证 Agent，我希望 `open_binary` 在首次加载时直接返回文件的 MD5、SHA-1、SHA-256 及 PE Imphash，以便快速对接威胁情报库进行样本定性。
4. 作为一名漏洞研究 Agent，我希望 `open_binary` 返回目标二进制的架构、位宽、端序、入口点（`entry_point`）、镜像基址（`image_base`）以及安全缓解措施状态（`is_pie`、`has_nx`、`has_canary`、`is_stripped`），以便快速评估二进制的加固强度。
5. 作为一名恶意代码取证 Agent，我希望 `open_binary` 返回 `triage_overview`（包含高熵节区列表、疑似加壳提示 `packing_hint` 以及按 `process_injection`、`anti_debug`、`crypto` 等分类统计的敏感 API 数量），以便在数秒内判断样本是否加壳及具备何种高危行为倾向。
6. 作为一名恶意代码取证 Agent，我希望 `open_binary` 返回 `forensic_metadata.tls_callbacks`（PE TLS 回调函数地址或 ELF `.init_array` 地址列表），以便第一时间审查早于 `entry_point` 执行的反调试或注入逻辑。
7. 作为一名数字取证 Agent，我希望 `open_binary` 返回 `forensic_metadata.debug_info`（包含 PDB 调试符号路径、编译时间戳与 PE Rich Header 哈希）及 `code_signing.is_signed`，以便追踪样本编译环境与签名合法性。
8. 作为一名数字取证 Agent，我希望 `open_binary` 自动检测文件末尾是否存在未映射到节区的附加数据（`forensic_metadata.overlay`，包含起始偏移、字节长度与香农熵），以便发现自解压载荷或木马释放器追加的加密数据块。
9. 作为一名安全分析 Agent，我希望调用 `list_sessions` 查看当前 LRU 内存池中驻留的所有 `BinarySession`（含文件名、格式、架构、加载时间与最后访问时间），以便在多样本协同分析时管理上下文。
10. 作为一名安全分析 Agent，我希望调用 `close_session` 释放指定 `session_id` 或一键清空全部会话，以便在完成阶段分析后主动回收内存。
11. 作为一名系统管理员，我希望通过 `--allowed-dir`（或 `MCP_REVERSE_ALLOWED_DIRS`）配置允许分析的样本根目录白名单，当 Agent 尝试访问白名单外路径或使用 `..` 路径穿越时，服务立即拦截并返回 `SANDBOX_PATH_FORBIDDEN` 错误码，以便严格保护宿主机敏感系统文件。
12. 作为一名系统管理员，我希望通过 `--max-file-size-mb`（默认 `100MB`）限制单个二进制文件体积，当目标文件超限时立即返回 `FILE_TOO_LARGE` 错误码，以便防止超大文件导致进程内存溢出。

### 二、节区、导入导出与无符号函数恢复 (`SectionProfile` & `SymbolEntry`)
13. 作为一名逆向分析 Agent，我希望调用 `get_sections` 获取二进制所有节区/段的 `SectionProfile`（名称、虚拟地址、虚拟大小、文件偏移、原始大小、R/W/X 权限、香农熵 `0.0~8.0` 及 `is_high_entropy` 标记），以便定位代码段、只读数据段及疑似加密/压缩的壳区段。
14. 作为一名安全分析 Agent，我希望调用 `get_imports` 分页检索导入表中的 `SymbolEntry`，并支持按动态库名正则（`library_filter`）、函数名正则（`name_filter`）以及 8 类敏感行为标签（`category`：`process_injection`、`anti_debug`、`crypto`、`network`、`dynamic_load`、`execution`、`filesystem`、`registry`）过滤，以便精准筛选高危系统调用。
15. 作为一名逆向分析 Agent，我希望调用 `get_exports` 分页检索导出函数表（包含函数名、序号 `ordinal`、虚拟地址与转发器 `forwarder`），以便分析动态链接库（`.dll`/`.so`/`.dylib`）对外暴露的接口。
16. 作为一名逆向分析 Agent，我希望调用 `get_symbols` 分页检索符号表（包含原始符号名、C++ Demangle 后的可读名称、虚拟地址、尺寸、类型与绑定属性），并支持按名称正则与符号类型过滤。
17. 作为一名逆向分析 Agent，当面对剥离了符号表（Stripped）且无导出函数的 64 位 Windows PE 程序时，我希望 `get_symbols` 自动从 PE `.pdata` 异常目录（`IMAGE_DIRECTORY_ENTRY_EXCEPTION`）恢复内部函数入口（生成 `sub_<va>`，标记 `type="exception_frame"` 及精确函数字节长度 `size`），以便在无符号二进制中依然能枚举所有内部非叶函数。

### 三、字符串提取、IOC 识别与密码学特征扫描 (`StringArtifact` & `CryptoSignature`)
18. 作为一名威胁情报 Agent，我希望调用 `search_strings` 提取二进制中的 ASCII 与 UTF-16LE 宽字符 `StringArtifact`，并附带每个字符串的文件偏移、虚拟地址、所属节区名称及自动识别的 IOC 标签（`url`、`ipv4`、`filepath`、`registry`、`email`、`crypto_or_key`、`suspicious_cmd`），以便快速捕获 C2 地址、注册表持久化键与敏感命令。
19. 作为一名逆向分析 Agent，我希望在 `search_strings` 中支持按正则表达式（`pattern`）、IOC 类别（`ioc_category`）、字符编码（`encoding`）、最小长度（`min_length`）及指定节区（`section_name`）组合过滤并分页返回，以便从数万条字符串中精准定位目标线索且不撑爆上下文。
20. 作为一名逆向分析 Agent，我希望在调用 `search_strings(use_floss=True)` 时，若宿主机已安装 `floss` 则自动合并解码出的混淆栈字符串（Stack Strings）；若宿主机未安装 `floss`，工具不报错中断，而是自动软降级返回内置静态字符串（保持 `ok: true`）并在 `floss_status` 中提示降级原因，以便保证分析流程连续不中断。
21. 作为一名逆向分析 Agent，我希望调用 `search_bytes_and_constants` 并传入类 IDA 风格的十六进制通配符模式（如 `"48 89 5C 24 ? 57"` 或 `"48 8D 0D ?? ?? ?? ??"`），以便在二进制中搜索特定指令序列或特征码并返回匹配的虚拟地址与文件偏移。
22. 作为一名密码学逆向 Agent，我希望调用 `search_bytes_and_constants(scan_crypto=True)` 自动扫描二进制中内置的已知密码学算法魔数常量（`CryptoSignature`，如 AES S-Box / Rcon、SHA-256 / SHA-1 / MD5 初始向量、CRC32 多项式表、DES S-Box），以便无需人工比对字节即可判定目标程序使用的加密或哈希算法。

### 四、多架构反汇编、相对寻址交叉引用与内存检视 (`XrefRecord`)
23. 作为一名逆向分析 Agent，我希望调用 `disassemble` 并传入十六进制虚拟地址（如 `"0x140001000"`）或符号/函数名称（如 `"main"`、`"reverse_test_entry"`、`"sub_140001000"`），输出紧凑单行汇编流（`VA: HexBytes | Mnemonic OpStr ; InlineComment`），以便在极低 Token 消耗下阅读机器指令。
24. 作为一名逆向分析 Agent，我希望 `disassemble` 在遇到 `RIP/PC-relative` 内存访问或直接 `call`/`jmp` 指令时，自动计算目标有效虚拟地址并在该行末尾内联追加指向的字符串字面量或导入/导出符号注释（如 `; -> 0x140003020 "https://api.example.com"`），以便无需手动二次调用地址换算即可读懂汇编语义。
25. 作为一名逆向分析 Agent，我希望 `disassemble` 支持 `stop_at_ret=True` 可选参数，使反汇编在遇到函数返回指令（`ret`/`retn`/`retf`）时自动停止，以便干净地检视短函数而不会混入函数末尾的 `int3 (0xcc)` 填充字节或下一个无关函数。
26. 作为一名逆向分析 Agent，我希望调用 `find_xrefs` 传入目标虚拟地址或符号名，精准找出所有指向该地址的 `XrefRecord`（涵盖 `x86_64` `RIP-relative`、`ARM64` `ADR` 与 `ADRP + ADD/LDR` 双指令配对、直接 `call`/`branch` 以及数据段 `data_pointer`），以便从可疑字符串或敏感 API 反向追踪到调用它的核心业务函数。
27. 作为一名逆向分析 Agent，当我在同一个 `BinarySession` 中连续多次调用 `find_xrefs` 查询不同字符串或函数的引用时，我希望首次扫描构建的倒排索引缓存在会话内存中，使后续查询在毫秒级立即返回，且后台扫描对超长可执行节区具备 `16MB` 安全上限保护。
28. 作为一名逆向分析 Agent，我希望调用 `read_memory` 按虚拟地址（`va`）、相对虚拟地址（`rva`）或文件物理偏移（`offset`）读取指定长度（最大 `1024` 字节）的原始字节，并同时获得十六进制字节串与标准 `Hexdump + ASCII` 对照行，以便检视全局变量表、结构体、虚函数表（vtable）或加密密钥块。
29. 作为一名逆向分析 Agent，我希望调用 `convert_address` 在虚拟地址（`va`）、相对虚拟地址（`rva`）与文件物理偏移（`offset`）之间进行双向换算，并同时获知该地址所属的节区名称与读写执行权限。

### 五、外部增强、能力自检与 CLI / 容器化运维 (`ExternalCapability`)
30. 作为一名逆向分析 Agent，当宿主机或 Docker 容器已安装 `radare2` 或 `rizin` 时，我希望调用 `decompile_function` 对目标函数地址或符号生成类 C 伪代码与基本块统计；当本机未安装外部反编译工具时，收到明确的 `EXTERNAL_TOOL_UNAVAILABLE` 错误码与改用 `disassemble` + `find_xrefs` 的行动建议。
31. 作为一名安全分析 Agent，我希望调用 `get_capabilities` 查看当前服务的版本号、Python 版本、核心引擎（`lief`/`capstone`/`pefile`）版本、安全沙箱配置（白名单目录、最大文件限制、最大会话数）以及四级寻址器探测到的外部 CLI 工具（`radare2`、`objdump`、`floss`）的 `ExternalCapability` 状态。
32. 作为一名运维或开发人员，我希望在命令行执行 `mcp-server-reverse --check`（或 `--doctor`）运行分级健康探针：当核心库与白名单目录正常时返回退出码 `0`（外部工具缺失仅提示 `[OPTIONAL]`），而当核心库异常或我显式传入了不存在的 `--r2-path` / `--objdump-path` / `--floss-path` 时返回退出码 `1`，以便集成至 Docker `HEALTHCHECK` 与 CI 门禁。
33. 作为一名开发者，我希望服务支持 `CLI 参数 > MCP_REVERSE_* 环境变量 > 默认值` 三级配置决议，并支持 `stdio`（本地客户端直连）与 `sse` / `streamable-http`（含可选 `--auth-token` Bearer 鉴权）双模传输，同时将所有运行日志强制输出至 `sys.stderr` 以保障 `stdio` JSON-RPC 管道绝对纯净。

---

## Implementation Decisions (实现决策)

1. **模块化分层与深模块边界**：
   - **配置与 CLI 入口层**：负责解析命令行参数（`-h/--help`、`-v/--version`、`--check/--doctor`、传输模式、沙箱边界与外部工具路径）与 `MCP_REVERSE_*` 环境变量，执行分级健康探针，并将日志流强制绑定至 `sys.stderr`。版本号通过 `importlib.metadata` 动态读取，保持 `pyproject.toml` 为单一事实源。
   - **安全守卫层 (`SecurityGuard`)**：统一拦截校验文件路径合法性（规范化真实路径、校验是否位于 `allowed_dirs` 白名单内、阻断目录访问与超过 `max_file_size_mb` 的大文件），并在远程 HTTP/SSE 传输模式下提供 ASGI Bearer Token 鉴权中间件封装。
   - **四级外部工具寻址层 (`ToolLocator`)**：按 `CLI 显式参数 > MCP_REVERSE_* 环境变量 > 系统 PATH (shutil.which) > 操作系统标准安装目录` 顺序探测 `radare2`/`rizin`、`llvm-objdump`/`objdump` 与 `floss`，缓存 `ExternalCapability` 元数据。
   - **会话缓存层 (`BinarySession` & `SessionStore`)**：基于 `OrderedDict` 实现线程安全的进程内 LRU 缓存池（默认容量 `8`）。单架构二进制以文件 `SHA-256` 前 12 位为 `session_id`；Fat Mach-O 支持 `target_arch` 选择并以 `sha256(f"{file_sha256}:{resolved_arch}")[:12]` 为 `session_id`。会话对象内聚缓存结构化元数据、已提取字符串列表及惰性交叉引用倒排索引（`_xref_index`）。
   - **跨格式结构与取证解析层 (`BinaryParser`)**：以 `lief` 作为 PE/ELF/Mach-O 统一抽象底座，提取节区、导入、导出、符号及安全缓解标志；针对 PE 格式联动 `pefile` 提取 Imphash、Rich Header 哈希、TLS 回调函数地址、PDB 路径、编译时间戳、Authenticode 签名存在性、尾部未映射 Overlay 数据及 x64 `.pdata` 异常目录函数表（合成为 `type="exception_frame"` 的 `SymbolEntry`）。
   - **反汇编与交叉引用引擎 (`DisasmEngine`)**：基于 `capstone`（开启 `detail=True`）提供多架构反汇编（支持 `stop_at_ret` 单函数截断与内联字符串/符号注释）及全节区交叉引用扫描。`x86_64` 精确计算 `RIP-relative`（`insn.address + insn.size + disp`）；`ARM64` 维护 4 指令滑动窗口寄存器状态表以配对 `ADRP + ADD/LDR` 页基址与偏移；数据节区按指针位宽扫描绝对指针引用。全节区扫描通过 `asyncio.to_thread` 卸载并设置单节区 `16MB` 安全上限。
   - **启发式特征与字符串扫描层 (`SignatureScanner`)**：实现字节流香农熵计算、ASCII/UTF-16LE 可打印字符串正则扫描、7 类 IOC 正则打标、8 类敏感导入 API 分类字典、类 IDA 十六进制通配符（`?`/`??`）字节码转正则搜索，以及内置密码学魔数常量特征库（AES S-Box / Rcon、SHA-256 / SHA-1 / MD5 IV、CRC32 表、DES S-Box）。
   - **外部子进程适配层 (`ExternalRunner`)**：通过 `asyncio.create_subprocess_exec`（禁用 `shell=True`）带超时控制调用 `radare2`/`rizin`（执行 `aaa; afllj; pdc` 获取伪代码与基本块数）和 `floss`（提取栈字符串与混淆字符串）。
   - **MCP 工具接入薄层**：按职责划分为 5 个工具组（会话与分诊、结构与符号、字符串与特征、反汇编与交叉引用、外部增强与能力自检），共暴露 15 个正交 MCP Tools，仅负责入参校验、调用核心层并封装统一响应信封。

2. **统一响应信封与标准错误码契约**：
   所有 15 个 MCP Tools 统一返回如下 JSON 结构（集合字段无匹配数据时严格返回 `[]`，绝不返回 `null`）：
   ```json
   {
     "ok": true,
     "session_id": "a1b2c3d4e5f6",
     "summary": "简明中文结果摘要",
     "pagination": {
       "total": 128,
       "offset": 0,
       "limit": 50,
       "has_more": true
     },
     "data": {},
     "error": null
   }
   ```
   当发生受控业务错误时，返回 `ok: false` 及 `error: { "code": str, "message": str, "suggestion": str }`，错误码严格限定为以下 9 个枚举值：
   - `SANDBOX_PATH_FORBIDDEN`
   - `FILE_NOT_FOUND`
   - `FILE_TOO_LARGE`
   - `UNSUPPORTED_FORMAT`
   - `SESSION_NOT_FOUND`
   - `ADDRESS_OR_SYMBOL_NOT_FOUND`
   - `INVALID_PARAMETER`
   - `EXTERNAL_TOOL_UNAVAILABLE`
   - `EXTERNAL_TOOL_TIMEOUT`

3. **15 个 MCP Tools 接口签名与响应契约**：
   - `open_binary(file_path: str, target_arch: Optional[str] = None, force_reload: bool = False)` -> 返回 `session_id`, `file_info`, `format_info`（含 `available_architectures`）, `triage_overview`, `forensic_metadata`（含 `tls_callbacks`, `debug_info`, `overlay`, `code_signing`, `needed_libraries`）。
   - `list_sessions()` -> 返回 `sessions: List[...]`。
   - `close_session(session_id: Optional[str] = None)` -> 返回 `{ closed_count, remaining_sessions }`。
   - `get_sections(session_id: str)` -> 返回 `sections: List[SectionProfile]`（含 `entropy` 与 `is_high_entropy`）。
   - `get_imports(session_id: str, library_filter: Optional[str] = None, name_filter: Optional[str] = None, category: Optional[str] = None, offset: int = 0, limit: int = 50)` -> 返回分页 `imports: List[SymbolEntry]`。
   - `get_exports(session_id: str, name_filter: Optional[str] = None, offset: int = 0, limit: int = 50)` -> 返回分页 `exports: List[...]`。
   - `get_symbols(session_id: str, name_filter: Optional[str] = None, symbol_type: Optional[str] = None, offset: int = 0, limit: int = 50)` -> 返回分页 `symbols: List[SymbolEntry]`（含 PE64 `.pdata` `exception_frame` 函数）。
   - `search_strings(session_id: str, pattern: Optional[str] = None, ioc_category: Optional[str] = None, encoding: str = "all", min_length: int = 4, section_name: Optional[str] = None, use_floss: bool = False, offset: int = 0, limit: int = 50)` -> 返回分页 `strings: List[StringArtifact]` 与 `floss_status: Optional[str]`（未安装 `floss` 时自动软降级保持 `ok: true`）。
   - `search_bytes_and_constants(session_id: str, hex_pattern: Optional[str] = None, scan_crypto: bool = True, limit: int = 50)` -> 返回 `{ pattern_matches: List[...], crypto_constants: List[CryptoSignature] }`。
   - `disassemble(session_id: str, target: str, instruction_count: int = 40, stop_at_ret: bool = False, arch_override: Optional[str] = None)` -> 返回 `{ start_address, arch, resolved_symbol, stopped_at_ret, instructions: List[str] }`。
   - `find_xrefs(session_id: str, target_address: str, xref_type: str = "all", limit: int = 50)` -> 返回分页 `xrefs: List[XrefRecord]`。
   - `read_memory(session_id: str, address_or_offset: str, address_type: str = "va", length: int = 128)` -> 返回 `{ virtual_address, file_offset, section, hex_bytes, hexdump_lines: List[str] }`。
   - `convert_address(session_id: str, value: str, from_type: str = "va")` -> 返回 `{ va, rva, file_offset, section_name, permissions }`。
   - `decompile_function(session_id: str, target: str, timeout_seconds: int = 30)` -> 返回 `{ engine, target, pseudocode, basic_blocks }`（未安装 `radare2`/`rizin` 时返回 `ok: false` 与 `EXTERNAL_TOOL_UNAVAILABLE`）。
   - `get_capabilities()` -> 返回 `{ version, python_version, core_engines, external_tools, sandbox }`。

---

## Testing Decisions (测试决策与接缝设计)

1. **好测试的核心准则（仅测试外部可见契约，不耦合内部实现细节）**：
   - 测试必须聚焦于调用者（AI Agent 或 CLI 用户）可感知的输入与输出行为：给定目标二进制文件与工具入参，断言返回的统一信封字段（`ok`、`session_id`、`pagination`、`data`、`error.code`）及 CLI 退出码，不直接断言私有缓存结构或内部解析器中间变量。
2. **最高层测试接缝 (Testing Seams)**：
   - **主接缝（MCP Tool 顶层函数边界 & CLI `main(argv)` 边界）**：所有核心逆向能力直接通过调用 15 个 MCP Tool 函数与 CLI 入口函数进行端到端验证。
   - **动态合成真实二进制夹具 (`Synthetic Binary Fixtures`)**：在测试夹具中动态构造最小合法的 64 位 **PE64** 与 **ELF64** 二进制样本文件（零外部样本文件依赖）：
     - `.text` 可执行节区：内嵌真实 `x86_64` 机器指令序列（`push rbp; mov rbp, rsp; lea rcx, [rip + disp]; call rel32; xor eax, eax; pop rbp; ret; int3`），其中 `lea rcx, [rip + disp]` 精确指向数据节区中的测试 URL 字符串 VA；
     - `.rdata` / `.rodata` 数据节区：内嵌测试 URL（`"https://api.example.com/v1/token"`）、IPv4 地址（`"192.168.10.25"`）、注册表路径、UTF-16LE 宽字符序列、指向代码入口的 64 位绝对数据指针，以及标准 256 字节 **AES S-Box** 常量表；
     - 导入表与导出表：包含敏感 API 导入项（如 `KERNEL32.dll!VirtualAllocEx`、`WS2_32.dll!WSAStartup`）与导出函数 `reverse_test_entry`；
     - PE 扩展结构：包含 `.pdata` 异常目录条目与文件尾部 Overlay 附加字节块。
   - **外部子进程轻量替身接缝 (`Subprocess Seam`)**：仅在验证外部工具（`radare2` / `floss`）的“成功输出解析”、“超时熔断（`EXTERNAL_TOOL_TIMEOUT`）”与“未安装降级（`EXTERNAL_TOOL_UNAVAILABLE` / `floss_status` 软回退）”时，在外部命令执行/寻址边界使用轻量替身，确保测试套件在无外部逆向工具的任意环境中 100% 稳定通过。
3. **测试覆盖模块矩阵**：
   - CLI 参数解析、环境变量优先级覆盖与 `--check` / `--doctor` 分级退出码测试；
   - `SecurityGuard` 目录白名单防穿越、文件超限熔断与四级外部工具寻址优先级测试；
   - `BinarySession` LRU 淘汰、取证元数据（`ForensicMetadata`）、节区熵计算、导入导出分类过滤与 `.pdata` 无符号函数恢复测试；
   - 字符串提取、IOC 分类打标、`use_floss=True` 自动软降级、AES S-Box 识别与十六进制通配符搜索测试；
   - `disassemble`（含内联相对寻址注释与 `stop_at_ret=True` 截断）、`find_xrefs`（含会话级惰性索引复用、代码/数据引用分类及 `ARM64` `ADRP+ADD` 配对）、`read_memory`、`convert_address` 及 `decompile_function` 降级测试。
4. **家族先例参考 (Prior Art)**：
   - 对齐同家族 Python + `uv` MCP 仓库（如 `mcp-server-traffic-inspector`、`mcp-server-tcp`）的 CLI `--doctor` 探针测试与 FastMCP 工具契约测试风格。

---

## Out of Scope (范围外边界)

1. **动态调试与真实恶意代码沙箱执行**：本服务严格定位于**纯静态二进制逆向分析**（Static Analysis），绝不在宿主机上直接运行、加载或动态调试（如 `ptrace`、`WinDbg`、Frida Hook）目标二进制样本，杜绝恶意样本在分析过程中触发本地感染。
2. **二进制文件补丁修改与回写 (Binary Patching)**：所有 MCP Tools 均为只读分析操作，不支持修改二进制指令或重写磁盘上的目标文件。
3. **重型商业反编译器绑定**：不绑定 IDA Pro（`idalib`）或需要商业许可证的闭源软件，也不强制内置数百 MB 的 Ghidra Headless Java 运行时。
4. **自动化脱壳器 (Automated Unpacker)**：仅提供高熵节区检测、加壳指纹提示（`packing_hint`）与 Overlay 识别，不内置针对 VMProtect / Themida 等复杂虚拟化壳的动态脱壳功能。

---

## Further Notes (补充说明)

- **工程与代码规范**：严格遵循仓库 `AGENTS.md` 与全局工程规范（Python 3.12 + `uv` 构建，类与文件级中文文档注释标注 `@author Ateng` 与 `@since 2026-10-13`，集合无数据时统一返回 `[]`，禁用 `System.out` / `print` 污染 `stdio` 标准输出）。
- **CLI 与环境变量速查**：

| CLI 参数选项 | 对应环境变量 | 默认值 | 说明 |
| :--- | :--- | :--- | :--- |
| `-h, --help` | - | - | 输出中文帮助说明并退出 |
| `-v, --version` | - | - | 输出版本及核心引擎版本并退出 |
| `--check` / `--doctor` | - | `False` | 执行运行环境与外部工具四级寻址健康自检 |
| `-t, --transport` | `MCP_REVERSE_TRANSPORT` | `stdio` | 传输协议：`stdio`、`sse`、`streamable-http` |
| `--host` | `MCP_REVERSE_HOST` | `127.0.0.1` | `sse` / `streamable-http` 监听地址 |
| `-p, --port` | `MCP_REVERSE_PORT` | `8000` | `sse` / `streamable-http` 监听端口 |
| `--allowed-dir` | `MCP_REVERSE_ALLOWED_DIRS` | 不限制 | 允许加载二进制文件的根目录白名单 |
| `--max-file-size-mb` | `MCP_REVERSE_MAX_FILE_SIZE_MB` | `100` | 单文件最大允许体积（MB） |
| `--max-sessions` | `MCP_REVERSE_MAX_SESSIONS` | `8` | 进程内 LRU 会话池最大驻留数量 |
| `--auth-token` | `MCP_REVERSE_AUTH_TOKEN` | `None` | 远程 HTTP/SSE 模式可选 Bearer 鉴权令牌 |
| `--r2-path` | `MCP_REVERSE_R2_PATH` | 自动四级寻址 | 显式指定 `radare2` / `rizin` 可执行文件路径 |
| `--objdump-path` | `MCP_REVERSE_OBJDUMP_PATH` | 自动四级寻址 | 显式指定 `llvm-objdump` / `objdump` 可执行文件路径 |
| `--floss-path` | `MCP_REVERSE_FLOSS_PATH` | 自动四级寻址 | 显式指定 `floss` 可执行文件路径 |
| `--log-level` | `MCP_REVERSE_LOG_LEVEL` | `INFO` | 日志级别（强制输出至 `sys.stderr`） |
