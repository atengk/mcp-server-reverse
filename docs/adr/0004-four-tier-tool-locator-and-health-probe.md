# 0004. 四级跨平台依赖寻址与分级健康探针（`--check` / `--doctor`）

- **状态**: accepted

## 背景与问题

在不同操作系统（Windows / macOS / Linux）及受限启动环境（如 GUI 客户端拉起 `stdio` 子进程时 `PATH` 环境变量被裁剪）下，外部逆向工具（`radare2`/`rizin`、`llvm-objdump`/`objdump`、`floss`）的安装位置差异极大；同时容器编排与 CI/CD 需要轻量可靠的健康探针验证服务可用性。

## 决策

1. **四级跨平台依赖寻址器 (`ToolLocator`)**：按以下严格优先级定位外部可执行文件：
   - **Level 1**：CLI 显式参数（`--r2-path`、`--objdump-path`、`--floss-path`）；
   - **Level 2**：环境变量（`MCP_REVERSE_R2_PATH`、`MCP_REVERSE_OBJDUMP_PATH`、`MCP_REVERSE_FLOSS_PATH`）；
   - **Level 3**：系统 `PATH` 搜索（`shutil.which`，按优先级依次尝试候选别名，如 `radare2` -> `r2` -> `rizin`，`llvm-objdump` -> `objdump`）；
   - **Level 4**：操作系统常见包管理器与标准安装路径探测（Windows Scoop/Winget/Chocolatey/Program Files，macOS Homebrew `/opt/homebrew/bin`，Linux `/usr/local/bin` 等）。
2. **分级健康探针（`--check` / `--doctor`）**：
   - **核心必选项（`[REQUIRED]`）**：校验 Python 运行时、`lief`/`capstone`/`pefile` 导入与最小冒烟解析、以及 `--allowed-dir` 白名单目录存在性与可读权限；
   - **外部增强项（`[OPTIONAL]`）**：汇报外部 CLI 工具寻址结果与版本号。若用户未显式指定路径且本机未安装外部工具，仅标记为 `[OPTIONAL] 未安装（已启用纯 Python 内核兜底）`，探针整体退出码仍为 `0`；但若核心库损坏、白名单目录无效，或用户**显式指定了不存在/不可执行的外部工具路径**，探针立即报错并返回退出码 `1`。
