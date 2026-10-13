# 0001. 纯 Python 静态分析内核与外部 CLI 混合分层架构

- **状态**: accepted

## 背景与问题

二进制逆向工程生态高度碎片化：商业或重型工具（如 IDA Pro、Ghidra、Binary Ninja、Radare2）体积庞大、跨平台安装门槛高，若作为 MCP Server 的强制前置依赖，将导致 `uvx mcp-server-reverse` 在普通开发者宿主机上无法开箱即用；反之，若仅依赖纯 Python 库，则难以提供类 C 伪代码反编译（Decompile）与混淆栈字符串解码等高阶能力。此外，在去符号（Stripped）二进制与恶意软件样本中，关键逻辑常隐藏于 TLS 回调、文件尾部 Overlay 附加数据或无符号内部函数中。

## 决策

采用**“纯 Python 核心层（100% 兜底）+ 可选外部 CLI 增强层（按需挂载）”**的混合分层架构（Hybrid Engine）：

1. **纯 Python 核心层**：
   - 基于 `lief` 实现跨 PE / ELF / Mach-O（含 Fat Binary 多架构切片）的统一结构解析；
   - 配合 `pefile` 深度提取取证元数据（`ForensicMetadata`：Imphash、Rich Header 哈希、TLS 回调函数地址列表、PDB 调试路径、编译时间戳、Overlay 尾部附加数据及其香农熵、Authenticode 数字签名存在性），并利用 x64 PE `.pdata` 异常目录（`IMAGE_DIRECTORY_ENTRY_EXCEPTION`）自动恢复无符号二进制中的内部函数起止范围（`sub_<va>`，`type="exception_frame"`）；
   - 配合 `capstone` 提供跨架构（`x86`/`x86_64`/`arm`/`arm64`/`riscv`）反汇编（支持 `stop_at_ret` 单函数边界控制）与指令级相对寻址分析，零外部 CLI 依赖即可完整支撑 14 个核心逆向分析工具。
2. **外部 CLI 增强层与区分式降级策略**：
   - 通过 `asyncio.create_subprocess_exec`（严禁 `shell=True`）隔离调用本地 `radare2`/`rizin`、`llvm-objdump`/`objdump` 与 `floss`，强制实施子进程超时控制（默认 30s）；
   - **硬依赖工具结构化报错**：当调用 `decompile_function` 而本机未安装 `radare2`/`rizin` 时，返回 `ok: false` 与 `error.code = "EXTERNAL_TOOL_UNAVAILABLE"`，指引 Agent 组合使用内置 `disassemble` 与 `find_xrefs` 完成分析；
   - **软增强工具无缝回退**：当调用 `search_strings(use_floss=True)` 而本机未安装 `floss` 时，自动软降级为内置 ASCII/UTF-16LE 提取（保持 `ok: true`），并在 `data.floss_status` 与 `summary` 中显式标注回退状态，避免中断 Agent 取证工作流。
