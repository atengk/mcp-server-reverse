# mcp-server-reverse

[![CI](https://github.com/atengk/mcp-server-reverse/actions/workflows/ci.yml/badge.svg)](https://github.com/atengk/mcp-server-reverse/actions/workflows/ci.yml)
[![Release](https://github.com/atengk/mcp-server-reverse/actions/workflows/release.yml/badge.svg)](https://github.com/atengk/mcp-server-reverse/releases)
[![PyPI](https://img.shields.io/pypi/v/atengk-mcp-server-reverse.svg)](https://pypi.org/project/atengk-mcp-server-reverse/)
[![Docker](https://ghcr-badge.egpl.dev/atengk/mcp-server-reverse/latest_tag?label=ghcr.io)](https://github.com/atengk/mcp-server-reverse/pkgs/container/mcp-server-reverse)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-Apache%202.0-green.svg)](./LICENSE)

**`mcp-server-reverse`**（PyPI 包名：**`atengk-mcp-server-reverse`**）是一款专为 AI Agent / LLM 打造的跨平台**下一代二进制静态逆向分析与纵深数字取证（DFIR）MCP Server**。

采用**“纯 Python 静态分析内核（`lief` + `capstone` + `pefile`）+ 按需外部 CLI 增强适配层（`radare2` / `objdump` / `floss` / `yara`）”**混合分层架构：无需预装庞大的商业逆向套件，开箱即可对 **PE（`.exe`/`.dll`/`.sys`）、ELF（Linux/Android `.so`）、Mach-O（macOS/iOS，含 Fat Binary 多架构切片）** 执行全景静态画像、函数控制流图（CFG）抽取、写时复制（COW）内存虚拟打补丁、滑动窗口局部高熵块探测、全平台漏洞缓解加固审计、YARA 规则匹配、PE Rich Header 编译器版本追溯、纯 Python SSDEEP 模糊哈希计算、Mach-O Entitlements 清单提取、PE64 `.pdata` 无符号函数恢复、`RIP/PC-relative` 交叉引用（Xref）定位、**.NET CLR 托管程序与运行时版本自动分诊**（[ADR-0007](./docs/adr/0007-clr-managed-assembly-triage.md)）以及**非原生格式智能魔数嗅探（Format Sniffer）**；当宿主机或容器环境存在外部工具时，自动解锁伪代码反编译与混淆栈字符串解码。

---

## ✨ 核心特性

- **100% 纯 Python 核心底座与 PE 双轨稳健解析**：基于 `lief`、`capstone`、`pefile` 构建跨格式解析内核，针对非标或加壳的 32 位（PE32）与 64 位（PE32+）样本具备 `pefile` 双轨回退解析防御，零外部 CLI 依赖即可原生运行 19 个核心逆向分析与数字取证工具。
- **.NET CLR 托管程序自动分诊与 CIL 引导**：自动检测 PE 数据目录项 `IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR`，通过 ECMA-335 `BSJB` 根元数据解析提取精准的目标运行时版本（如 `v4.0.30319`），并为 AI Agent 注入专用 CIL 反编译引导（ILSpy / dnSpy），终结在原生汇编引导桩上的盲目试错。
- **未支持格式智能魔数嗅探 (Format Sniffer)**：针对 Adobe Flash (SWF)、Android (DEX/APK)、WebAssembly (WASM)、网络流量归档 (HAR) 与底层抓包文件 (PCAP/PCAPNG)，在安全边界层自动通过特征魔数识别并返回结构化工具链重定向建议，赋能 Agent 智能自纠偏。
- **面向 Agent 的自然语言参数别名自愈容错**：在核心逆向工具中深度集成 Pydantic `AliasChoices`，原生容错 `query`/`needle`、`target`/`address`、`name`/`name_filter` 等常见大模型参数命名幻觉，赋予 Agent 零样本（Zero-Shot）工具调用的极佳鲁棒性。
- **函数控制流图 (CFG) 与 Mermaid 可视化**：自动切分单入口单出口基本块（`BasicBlock`），计算条件跳转、循环回跳边与圈复杂度，并直接输出紧凑规范的 Mermaid `flowchart TD` 流程图文本供 Agent 直观阅读与拓扑推演。
- **写时复制 (COW) 内存虚拟打补丁与只读保真机制**：物理磁盘样本保持 100% 只读保真；在分析会话内支持原子内存字节修改、分支反转 What-If 假设推演、即时反汇编与 CFG 动态重绘，并支持随时查看与一键原子回滚。
- **全平台利用缓解机制跨架构画像与安全评分**：深度审计 Windows（DEP/ASLR/SafeSEH/CFG/CET）、Linux（NX/PIE/RELRO/Canary/FORTIFY）与 macOS（PIE/代码签名/Hardened Runtime），输出加权安全评分（0~100）与利用难度量化评级。
- **节区滑动窗口局部异常高熵块细粒度探测**：突破全局香农熵容易被大节区稀释的瓶颈，以 2KB~4KB 滑动窗口敏锐捕捉代码段或只读数据段中偷渡的微型加密 Shellcode 与加壳 Payload。
- **纵深数字取证同源指纹增强**：自动解析 PE Rich Header 提取 Visual Studio 编译器工具链组件（ProdID/BuildNumber/引用计数）；基于纯 Python 滚动哈希计算标准 SSDEEP 模糊哈希（CTPH）；深度反序列化 Mach-O 代码签名 SuperBlob 提取 Entitlements XML 权限清单。
- **独立 YARA 规则匹配与优雅降级**：支持文本规则即时编译与规则文件路径加载，自动映射命中特征字符串的文件物理偏移与虚拟内存地址（VA）；未安装 `yara-python` 时提供结构化引导与平滑降级。
- **指令级 `RIP/PC-relative` 交叉引用引擎**：自动扫描 `x86_64` `RIP-relative`、`ARM64` 4 指令滑动窗口 `ADRP + ADD/LDR`、直接分支及数据段全局指针，首次查询后台线程惰性构建倒排索引并缓存，同会话后续查询毫秒级 $O(1)$ 命中。
- **四级跨平台外部工具寻址**：按 `CLI 参数 > MCP_REVERSE_* 环境变量 > 系统 PATH > 操作系统常见安装目录` 自动探测 `radare2`/`rizin`、`llvm-objdump`/`objdump` 与 `floss`，提供结构化降级指引。
- **LRU 会话池与上下文防爆**：以文件内容哈希（Fat Binary 结合架构生成复合摘要）前 12 位作为 `session_id` 驻留内存（默认最多 `8` 个会话），所有检索工具强制分页与紧凑单行格式化输出。

---

## 🧰 21 个正交 MCP Tools 矩阵

| 业务分组 | Tool 名称 | 核心职责与关键能力说明 |
| :--- | :--- | :--- |
| **1. 会话与全景画像**<br>(`Triage & Session`) | `open_binary` | 校验沙箱并加载二进制至 LRU 缓存，集成 Format Sniffer 智能魔数嗅探拦截与工具链重定向；自动识别 .NET CLR 托管程序（`is_managed`、`clr_runtime_version` 与 `clr_guidance` 转向建议）；返回哈希（含 Imphash/SSDEEP）、防护标志、高熵加壳预警及深度取证画像（TLS 回调、PDB/Rich Header 编译器指纹、Overlay 附加数据、代码签名与 Mach-O Entitlements 清单） |
| | `list_sessions` | 列出当前内存中驻留的所有二进制分析会话元数据摘要与时间戳 |
| | `close_session` | 显式释放指定 `session_id` 或一键清空全部缓存会话以回收系统内存 |
| **2. 结构与符号检视**<br>(`Structure & Symbols`) | `get_sections` | 获取所有节区/段分布、权限、全局香农熵（`0.0~8.0`），支持 `name_filter` 正则过滤，可选开启 `detect_local_entropy` 滑动窗口精准探测局部高熵隐蔽块 |
| | `get_imports` | 分页检索导入表，支持按库名、函数名正则与 8 类敏感行为标签（`crypto`、`process_injection`、`anti_debug` 等）过滤 |
| | `get_exports` | 分页检索导出函数表、序号（Ordinal）、虚拟地址与转发器（Forwarder） |
| | `get_symbols` | 分页检索静态/动态符号表；针对 64 位 PE 自动解析 `.pdata` 异常目录恢复无符号内部函数 `sub_<va>`（标注字节长度与 `exception_frame` 类型） |
| **3. 字符串与特征扫描**<br>(`Strings & Signatures`) | `search_strings` | 提取 ASCII / UTF-16LE 字符串（可选 `use_floss` 软降级解码栈字符串），内置 7 类威胁情报 IOC 自动分类与正则过滤 |
| | `search_bytes_and_constants` | 支持类 IDA 十六进制通配符搜索（如 `"48 89 5C 24 ? 57"`）及内置密码学魔数常量（AES S-Box/Rcon、SHA/MD5 IV、CRC32、DES）扫描 |
| | `scan_yara` | 传入规则文本或规则文件对会话内存或文件执行 YARA 匹配，返回命中规则元数据与特征字符串的文件偏移及虚拟内存地址（VA） |
| **4. 反汇编、交叉引用与控制流**<br>(`Disasm, Xrefs & CFG`) | `disassemble` | 多架构反汇编指定虚拟地址或符号名（支持 `stop_at_ret` 截断），自动内联标注 `RIP/PC-relative` 字符串字面量与符号注释 |
| | `find_xrefs` | 惰性构建会话级倒排索引，检索指向目标虚拟地址或符号的全部代码与数据交叉引用（`call`/`branch`/`rip_relative`/`pc_relative`/`data_pointer`） |
| | `read_memory` | 按 VA、RVA 或文件物理偏移读取原始字节（单次上限 `1024` 字节），输出连续十六进制与标准 16 字节宽度 Hexdump + ASCII 对照视图 |
| | `convert_address` | 在虚拟地址（VA）、相对虚拟地址（RVA）与文件物理偏移（Offset）之间双向精确换算并定位所属节区与权限 |
| | `analyze_cfg` | 分析函数单入口单出口基本块（`BasicBlock`）、分支跳转关系与圈复杂度，并直接输出 Mermaid `flowchart TD` 控制流流程图文本 |
| **5. 内存虚拟补丁套件**<br>(`Virtual Patching`) | `patch_memory` | 在写时复制（COW）虚拟层应用十六进制内存补丁，物理文件 100% 只读保真，即时影响后续反汇编与控制流分析 |
| | `list_patches` | 清晰列出当前会话中所有已激活的内存虚拟补丁记录、目标地址与原始/修改字节对比 |
| | `revert_patch` | 指定 `patch_id` 单项撤销补丁，或缺省一键回滚当前会话全部补丁恢复初始净室内存镜像 |
| **6. 安全加固与外部增强**<br>(`Mitigations & Capabilities`) | `audit_mitigations` | 系统化审计目标二进制的跨平台漏洞利用缓解措施，输出 0~100 安全评分与利用难度评级（Low/Medium/High/Extreme） |
| | `decompile_function` | 受控异步调用本地 `radare2`/`rizin` 生成目标函数的类 C 伪代码；未安装时返回结构化安装指引与软降级建议 |
| | `get_capabilities` | 返回核心引擎版本、安全沙箱边界配置及四级寻址器探测到的外部 CLI 工具可用状态 |

### 🤖 Agent 鲁棒性与参数别名映射 (Parameter Aliasing)

在由 LLM / AI Agent 驱动的自主逆向分析编排中，大模型常因自然语言提示的微小差异产生参数名同义词幻觉（例如习惯性传入 `query` 而非 `pattern`，或传入 `address` 而非 `target`）。本服务端基于 Pydantic `AliasChoices` 实现了**零样本调用的自愈容错机制**，原生兼容以下参数别名：

| MCP Tool | 标准参数名 | 支持的参数别名 (Validation Aliases) | 典型应用与防幻觉场景 |
| :--- | :--- | :--- | :--- |
| `search_strings` | `pattern` | `filter`, `query`, `keyword`, `search` | 兼容模型以 `query: "password"` 或 `keyword: "http"` 检索字符串 |
| `search_bytes_and_constants` | `hex_pattern` | `pattern`, `filter`, `query`, `keyword`, `search` | 兼容模型以 `pattern: "48 89 5C"` 检索十六进制特征 |
| `get_sections` | `name_filter` | `name`, `filter`, `query`, `pattern` | 兼容模型以 `name: ".text"` 或 `filter: ".rsrc"` 检索指定节区 |
| `get_imports` | `name_filter` | `name`, `filter`, `query`, `pattern` | 兼容模型以 `query: "VirtualAlloc"` 检索目标 API |
| `get_exports` | `name_filter` | `name`, `filter`, `query`, `pattern` | 兼容模型以 `name: "CreateProcess"` 筛选导出符号 |
| `get_symbols` | `name_filter` | `name`, `filter`, `query`, `pattern` | 兼容模型以 `query: "main"` 检索符号表 |
| `convert_address` | `address` | `target`, `va`, `offset`, `location` | 兼容模型以 `target: "0x140001000"` 传入待转换地址 |
| `read_memory` | `address` | `target`, `va`, `offset`, `location` | 兼容模型以 `target` 或 `va` 指定内存读取基准地址 |
| `disassemble` | `target` | `location`, `address`, `va`, `entry` | 兼容模型以 `address` 或 `entry` 指定反汇编入口 |
| `find_xrefs` | `target` | `location`, `address`, `va`, `entry` | 兼容模型以 `address` 或 `location` 指定被引用目标 |
| `analyze_cfg` | `target` | `location`, `address`, `va`, `entry` | 兼容模型以 `entry` 或 `address` 指定函数控制流分析入口 |
| `decompile_function` | `target` | `location`, `address`, `va`, `entry` | 兼容模型以 `address` 或 `entry` 指定伪代码反编译函数 |

---

## 🚀 快速开始

### 1. 使用 `uvx` 一键启动（推荐）

```bash
# 自检运行环境与可选外部逆向工具状态
uvx atengk-mcp-server-reverse --doctor

# 以默认 stdio 模式启动并限制允许分析的样本目录
uvx atengk-mcp-server-reverse --allowed-dir /path/to/samples
```

### 2. 通用 MCP 服务配置 (`mcpServers`)

在任意支持 MCP 标准协议的宿主配置文件中添加以下通用配置：

```json
{
  "mcpServers": {
    "reverse": {
      "command": "uvx",
      "args": [
        "atengk-mcp-server-reverse",
        "--allowed-dir",
        "D:/samples"
      ],
      "env": {
        "MCP_REVERSE_MAX_FILE_SIZE_MB": "100",
        "MCP_REVERSE_LOG_LEVEL": "INFO"
      }
    }
  }
}
```

### 3. Docker 容器化隔离部署（内置 `radare2` + `objdump`）

```bash
docker run -d \
  --name mcp-reverse \
  -p 8000:8000 \
  -v /path/to/samples:/samples:ro \
  -e MCP_REVERSE_AUTH_TOKEN=YOUR_API_TOKEN \
  ghcr.io/atengk/mcp-server-reverse:latest
```

---

## 💡 常用使用提示词 (Prompt Examples)

挂载本 MCP 服务后，可直接复制以下提示词驱动 AI 执行专业逆向分析、漏洞研判与数字取证：

### 场景 1：二进制全景画像与深度取证初筛 (Triage & DFIR)
> “请对 `D:/samples/suspicious.exe` 执行静态逆向初筛：
> 1. 获取它的 MD5/SHA256/Imphash、SSDEEP 模糊哈希、编译时间戳、PDB 路径、PE Rich Header 工具链编译器指纹、TLS 回调以及是否存在尾部 Overlay 附加数据；
> 2. 列出所有命中 `process_injection`、`anti_debug`、`network` 与 `execution` 类别的敏感导入 API；
> 3. 提取所有归类为 `url`、`ipv4`、`registry` 和 `suspicious_cmd` 的 IOC 字符串，给出综合威胁研判结论。”

### 场景 2：函数控制流图抽取与 Mermaid 流程图可视化 (CFG Analysis)
> “目标函数 `sub_140001000` 包含复杂的条件跳转与混淆分支：
> 1. 请调用 `analyze_cfg` 对该函数进行控制流分析，提取基本块边界、分支跳转走向与圈复杂度；
> 2. 直接渲染输出该函数的 Mermaid `flowchart TD` 流程图，指出哪一条分支是校验失败跳转，哪一条分支通向关键解密载荷。”

### 场景 3：写时复制 (COW) 内存虚拟补丁与分支反转 What-If 推演 (Virtual Patching)
> “在当前分析会话中验证绕过反调试的可能性：
> 1. 对 `0x140001050` 处的条件跳转指令（`74 12` 即 `JZ`）调用 `patch_memory`，虚拟替换为 `75 12`（`JNZ`）或 `90 90`（`NOP`）；
> 2. 重新调用 `disassemble` 和 `analyze_cfg`，观察补丁应用后指令流与控制流图的实时演变，确认是否已绕过校验；
> 3. 完成验证后调用 `list_patches` 核对补丁记录，并调用 `revert_patch` 撤销补丁恢复原始净室镜像（全程物理样本保持零磁盘改动）。”

### 场景 4：全平台漏洞缓解机制加固审计与评分 (Mitigations Audit)
> “请针对 `D:/samples/target_service.elf` 执行漏洞利用防护审计：
> 1. 调用 `audit_mitigations` 检查 NX、PIE、RELRO、Stack Canary 与 FORTIFY 编译项开启状态；
> 2. 评估该二进制的加固安全评分与利用难度评级（Low/Medium/High/Extreme），并针对未开启的防护项提出具体加固建议。”

### 场景 5：节区滑动窗口局部异常高熵块隐蔽探测 (Local Entropy Detection)
> “样本 `.text` 代码段整体香农熵仅为 5.8，疑似内部偷渡了微型加壳代码：
> 1. 调用 `get_sections` 并开启 `detect_local_entropy=True`（窗口 2048 字节、步长 1024 字节）；
> 2. 检查返回的 `local_high_entropy_blocks` 列表，定位局部熵值超过 7.2 的连续异常区间起始偏移与虚拟地址；
> 3. 使用 `read_memory` 检视该高熵区间的 Hexdump 数据，判断其为加密 Shellcode 还是压缩配置。”

### 场景 6：工业级 YARA 特征规则即时扫描 (YARA Scanning)
> “安全团队下发了针对某 APT 恶意木马家族的 YARA 规则，请协助在会话中排查：
> 1. 调用 `scan_yara` 并传入规则文本字符串，扫描当前二进制会话的内存镜像；
> 2. 若命中规则，列出所有匹配的特征字符串标识、物理文件偏移与虚拟内存地址（VA）；
> 3. 使用 `find_xrefs` 追踪是哪些函数代码引用了命中的恶意特征字符串。”

### 场景 7：关键字符串交叉引用追踪与控制流还原 (String Xrefs -> Disassembly)
> “在当前分析会话中：
> 1. 搜索包含 `http`、`token` 或 `Error` 关键字的字符串并记录其虚拟地址；
> 2. 使用 `find_xrefs` 查找是哪些代码指令引用了这些字符串；
> 3. 对发起引用的函数起始地址执行 `disassemble`，结合内联注释还原该函数的核心调用逻辑（若本机已安装 radare2，请同时调用 `decompile_function` 输出伪代码对照）。”

### 场景 8：去符号 (Stripped) 64 位 PE 内部函数恢复与密码学算法识别
> “目标文件 `D:/samples/stripped_payload.dll` 已被剥离符号表，请协助定位其加密逻辑：
> 1. 调用 `search_bytes_and_constants` 并开启 `scan_crypto=True`，检查二进制中是否包含 AES、SHA-256、MD5 或 CRC32 的特征魔数常量表；
> 2. 使用 `find_xrefs` 定位引用了该密码学常量表的代码地址；
> 3. 调用 `get_symbols(symbol_type="exception_frame")` 查看通过 `.pdata` 异常目录恢复出的 `sub_<va>` 内部函数列表，定位所属函数并反汇编分析其加密流程。”

### 场景 9：.NET CLR 托管程序自动分诊与反编译转译引导 (.NET Assembly Triage)
> “请对 `D:/samples/client_payload.exe` 进行初筛分诊：
> 1. 调用 `open_binary` 检查该文件是否为 .NET 托管程序（检查返回的 `is_managed` 与 `runtime` 字段）；
> 2. 若 `is_managed=true`，读取并汇报其目标 CLR 运行时版本（如 `clr_runtime_version: "v4.0.30319"`）与 `clr_guidance` 行动建议；
> 3. 解释为何不建议在此类文件上直接调用原生机器码反汇编（`disassemble`），并推荐合适的 CIL 反编译器（如 ILSpy、dnSpy 或 `python-net-decompiler`）以还原高质量 C# 源码。”

### 场景 10：未支持文件魔数嗅探与外部专业工具链智能导流 (Format Sniffer Redirection)
> “安全分析中捕获到一个未知文件 `D:/samples/unknown_asset.dat`，请尝试加载并研判：
> 1. 调用 `open_binary` 打开该文件；
> 2. 若返回 `UNSUPPORTED_FORMAT` 错误，检查 `FormatSniffer` 识别出的实际格式分类（如 Adobe Flash SWF、Android APK/DEX、WebAssembly WASM、HAR 流量归档或 PCAP 底层抓包）；
> 3. 根据响应中的 `guidance` 转向建议，告知对应的下一棒分析工具（如使用 `jadx` 分析 DEX，使用 `traffic-inspector` MCP 分析 HAR/PCAP，或使用 `FFDec` 分析 SWF），避免 Agent 陷入在非机器码文件上的盲目试错。”

---

## ⚙️ CLI 参数与环境变量对照表

配置优先级：**CLI 显式参数 > `MCP_REVERSE_*` 环境变量 > 内置默认值**。

| CLI 参数选项 | 对应环境变量 | 默认值 | 说明 |
| :--- | :--- | :--- | :--- |
| `-h, --help` | - | - | 输出完整中文帮助说明与示例并退出 |
| `-v, --version` | - | - | 输出版本号与核心引擎版本信息并退出 |
| `--check` / `--doctor` | - | `False` | 执行运行环境与四级外部工具寻址分级自检探针 |
| `-t, --transport` | `MCP_REVERSE_TRANSPORT` | `stdio` | 传输协议：`stdio`、`sse`、`streamable-http` |
| `--host` | `MCP_REVERSE_HOST` | `127.0.0.1` | `sse` / `streamable-http` 监听地址 |
| `-p, --port` | `MCP_REVERSE_PORT` | `8000` | `sse` / `streamable-http` 监听端口 |
| `--allowed-dir` | `MCP_REVERSE_ALLOWED_DIRS` | 不限制 | 允许加载二进制文件的根目录白名单（支持多次指定） |
| `--max-file-size-mb` | `MCP_REVERSE_MAX_FILE_SIZE_MB` | `100` | 单文件最大允许体积（MB），超出立即熔断 |
| `--max-sessions` | `MCP_REVERSE_MAX_SESSIONS` | `8` | 进程内 LRU 会话池最大驻留数量 |
| `--auth-token` | `MCP_REVERSE_AUTH_TOKEN` | `None` | 远程 HTTP/SSE 模式可选 Bearer 鉴权令牌 |
| `--r2-path` | `MCP_REVERSE_R2_PATH` | 自动四级寻址 | 显式指定 `radare2` / `rizin` 可执行文件路径 |
| `--objdump-path` | `MCP_REVERSE_OBJDUMP_PATH` | 自动四级寻址 | 显式指定 `llvm-objdump` / `objdump` 可执行文件路径 |
| `--floss-path` | `MCP_REVERSE_FLOSS_PATH` | 自动四级寻址 | 显式指定 `floss` 可执行文件路径 |
| `--log-level` | `MCP_REVERSE_LOG_LEVEL` | `INFO` | 日志级别（`DEBUG`、`INFO`、`WARNING`、`ERROR`） |

---

## 🛠️ 本地开发与工程验证

```bash
# 1. 创建 Python 3.12 虚拟环境并同步依赖
uv venv --python 3.12
uv sync

# 2. 运行完整自动化测试套件 (122 个测试项全量通过)
uv run pytest

# 3. 运行代码规范与格式静态扫描
uv run ruff check src tests
uv run ruff format --check src tests
```

---

## 📄 开源许可证

本项目基于 [Apache License 2.0](./LICENSE) 协议开源。
