# mcp-server-reverse

[![CI](https://github.com/atengk/mcp-server-reverse/actions/workflows/ci.yml/badge.svg)](https://github.com/atengk/mcp-server-reverse/actions/workflows/ci.yml)
[![Release](https://github.com/atengk/mcp-server-reverse/actions/workflows/release.yml/badge.svg)](https://github.com/atengk/mcp-server-reverse/releases)
[![PyPI](https://img.shields.io/pypi/v/mcp-server-reverse.svg)](https://pypi.org/project/mcp-server-reverse/)
[![Docker](https://ghcr-badge.egpl.dev/atengk/mcp-server-reverse/latest_tag?label=ghcr.io)](https://github.com/atengk/mcp-server-reverse/pkgs/container/mcp-server-reverse)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-Apache%202.0-green.svg)](./LICENSE)

**`mcp-server-reverse`** 是一款专为 AI Agent / LLM 打造的跨平台**二进制静态逆向分析与数字取证（DFIR）MCP Server**。

采用**“纯 Python 静态分析内核（`lief` + `capstone` + `pefile`）+ 按需外部 CLI 增强适配层（`radare2` / `objdump` / `floss`）”**混合分层架构：无需预装任何庞大的商业逆向软件，开箱即可对 **PE（`.exe`/`.dll`/`.sys`）、ELF（Linux/Android `.so`）、Mach-O（macOS/iOS）** 执行全景画像、香农熵脱壳研判、导入/导出/符号检索、IOC 字符串提取、密码学常量扫描、多架构反汇编及 `RIP/PC-relative` 交叉引用（Xref）定位；当宿主机或容器环境存在 `radare2` / `floss` 时，自动解锁类 C 伪代码反编译与混淆栈字符串解码。

---

## ✨ 核心特性

- **100% 纯 Python 核心兜底**：基于 `lief`、`capstone`、`pefile` 构建跨格式解析底座，零外部 CLI 依赖即可运行 14 个核心逆向分析工具。
- **指令级 `RIP/PC-relative` 交叉引用引擎**：突破常规正则/字节匹配局限，自动扫描可执行节区中的 `x86_64` `RIP-relative`、`ARM64` `ADR/ADRP`、直接 `call`/`jmp` 及数据段指针，精准定位字符串与函数被引用位置。
- **四级跨平台外部工具寻址与优雅降级**：按 `CLI 参数 > MCP_REVERSE_* 环境变量 > 系统 PATH > 操作系统常见安装目录` 自动探测 `radare2`/`rizin`、`llvm-objdump`/`objdump` 与 `floss`；未安装时返回结构化降级指引而非报错崩溃。
- **LRU 会话池与上下文防爆**：以目标文件 `SHA-256` 前 12 位作为 `session_id` 驻留内存缓存（默认最多 `8` 个会话），所有列表工具强制分页（`offset`/`limit`）与紧凑单行输出。
- **纵深沙箱防御与双模传输**：支持 `--allowed-dir` 目录白名单防穿越、`--max-file-size-mb` 大文件熔断、远程 `sse` / `streamable-http` Bearer Token 鉴权，以及 `--check` / `--doctor` 环境自检探针。

---

## 🧰 15 个正交 MCP Tools 矩阵

| 分组 | Tool 名称 | 核心职责说明 |
| :--- | :--- | :--- |
| **1. 会话与全景画像**<br>(`Triage & Session`) | `open_binary` | 校验安全沙箱并加载二进制文件至 LRU 缓存，返回哈希（含 Imphash）、安全防护标志（PIE/NX/Canary）、高熵节区与敏感 API 概览 |
| | `list_sessions` | 列出当前内存中驻留的所有二进制分析会话元数据 |
| | `close_session` | 显式释放指定 `session_id` 或清空全部缓存会话 |
| **2. 结构与符号检视**<br>(`Structure & Symbols`) | `get_sections` | 获取所有节区/段分布、读写执行权限、香农熵（`0.0~8.0`）及高熵加壳预警 |
| | `get_imports` | 分页检索导入表，支持按库名、函数名正则与 8 类敏感行为标签（`crypto`、`process_injection`、`anti_debug` 等）过滤 |
| | `get_exports` | 分页检索导出函数表、序号（Ordinal）、虚拟地址与转发器（Forwarder） |
| | `get_symbols` | 分页检索动态符号与调试符号表（含 C++ Demangle 名称与符号类型过滤） |
| **3. 字符串与特征扫描**<br>(`Strings & Signatures`) | `search_strings` | 提取 ASCII / UTF-16LE 字符串（可选调用 `floss` 提取栈字符串），支持正则与 IOC 类型（`url`、`ipv4`、`registry` 等）过滤 |
| | `search_bytes_and_constants` | 支持类 IDA 十六进制通配符搜索（如 `"48 89 5C 24 ? 57"`）及内置密码学魔数常量（AES S-Box、SHA/MD5 IV、CRC32 等）扫描 |
| **4. 反汇编、交叉引用与内存**<br>(`Disasm, Xrefs & Memory`) | `disassemble` | 多架构反汇编指定虚拟地址或符号，自动内联解析分支符号与 `RIP-relative` 字符串注释 |
| | `find_xrefs` | 扫描指向目标虚拟地址（VA）的全部代码与数据交叉引用（`call`/`branch`/`rip_relative`/`pc_relative`/`data_pointer`） |
| | `read_memory` | 按 VA、RVA 或文件物理偏移读取原始字节，输出紧凑 Hexdump + ASCII 对照视图 |
| | `convert_address` | 在虚拟地址（VA）、相对虚拟地址（RVA）与文件物理偏移（Offset）之间双向换算并定位所属节区 |
| **5. 外部增强与能力自检**<br>(`Enhance & Capabilities`) | `decompile_function` | 调用本地 `radare2`/`rizin` 生成目标函数的类 C 伪代码与基本块统计；未安装时返回结构化降级建议 |
| | `get_capabilities` | 返回核心引擎版本、沙箱边界配置及四级寻址器探测到的外部 CLI 工具可用状态 |

---

## 🚀 快速开始

### 1. 使用 `uvx` 一键启动（推荐）

```bash
# 自检运行环境与可选外部逆向工具状态
uvx mcp-server-reverse --doctor

# 以默认 stdio 模式启动（供 Claude Desktop / Cursor / Antigravity 直接挂载）
uvx mcp-server-reverse --allowed-dir /path/to/samples
```

### 2. MCP 客户端接入配置 (`mcpServers`)

```json
{
  "mcpServers": {
    "reverse": {
      "command": "uvx",
      "args": [
        "mcp-server-reverse",
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

## ⚙️ CLI 参数与环境变量对照表

配置优先级：**CLI 显式参数 > `MCP_REVERSE_*` 环境变量 > 内置默认值**。

| CLI 参数选项 | 对应环境变量 | 默认值 | 说明 |
| :--- | :--- | :--- | :--- |
| `-h, --help` | - | - | 输出完整中文帮助说明与示例并退出 |
| `-v, --version` | - | - | 输出版本号与核心引擎版本信息并退出 |
| `--check` / `--doctor` | - | `False` | 执行运行环境与四级外部工具寻址自检探针 |
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

## 🛠️ 本地开发与工程规范

```bash
# 1. 创建 Python 3.12 虚拟环境并同步依赖
uv venv --python 3.12
uv sync --all-extras --dev

# 2. 激活本地 Conventional Commits 提交守门钩子
git config core.hooksPath .githooks

# 3. 运行静态检查与单元测试
uv run ruff check .
uv run ruff format --check .
uv run pytest --cov=mcp_server_reverse

# 4. 规范化提交与发版演练
bash scripts/commit.sh
bash scripts/release.sh --dry-run
```

详细贡献流程、CI/CD 机制与安全披露策略请参阅：
- [贡献指南 (CONTRIBUTING.md)](./CONTRIBUTING.md)
- [安全策略 (SECURITY.md)](./SECURITY.md)
- [行为准则 (CODE_OF_CONDUCT.md)](./CODE_OF_CONDUCT.md)

---

## 📄 开源协议

本项目基于 [Apache License 2.0](./LICENSE) 协议开源。
