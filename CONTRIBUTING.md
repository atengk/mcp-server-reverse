# 贡献指南 (Contributing Guide)

感谢你关注并愿意为 `mcp-server-reverse` 贡献力量！为了保持高效协作与高质量的代码维护，请在提交代码前阅读以下规范。

---

## 1. 本地开发环境准备 (Python + uv)

本项目采用 **`uv`** 进行 Python 环境管理、依赖锁定与构建打包，推荐使用 **Python 3.12**（`lief` 与 `capstone` 底层预编译扩展支持最完善）：

```bash
# 1. 初始化 Python 3.12 虚拟环境并安装全部开发依赖
uv venv --python 3.12
uv sync --all-extras --dev

# 2. 激活本地 Git 提交守门钩子 (Conventional Commits 校验)
git config core.hooksPath .githooks

# 3. 执行代码静态检查与格式化校验
uv run ruff check .
uv run ruff format --check .

# 4. 运行自动化测试套件与覆盖率统计
uv run pytest --cov=mcp_server_reverse

# 5. 执行 CLI 健康自检探针
uv run mcp-server-reverse --doctor
```

---

## 2. 协作与分支模型

本项目遵循标准的 **GitHub Flow** 工作流：

1. **Fork 本仓库** 到你个人的 GitHub 账号；
2. **基于 `main` 分支拉取新的特性分支**：
   ```bash
   git checkout -b feat/your-feature-name
   # 或者缺陷修复分支
   git checkout -b fix/issue-description
   ```
3. 在本地完成修改，确保 `uv run ruff check .` 与 `uv run pytest` 全部通过并补充相应测试用例；
4. 提交更改并推送到你的远程分支：
   ```bash
   git push origin feat/your-feature-name
   ```
5. 在 GitHub 上向本仓库的 `main` 分支发起 **Pull Request**。

---

## 3. Commit 提交信息规范

本项目遵循 [Conventional Commits](https://www.conventionalcommits.org/zh-hans/) 规范，统一采用以下格式：

```text
<type>(<scope>): <subject>
```

### 常用类型说明

| 类型 | 说明 | 示例 |
| :--- | :--- | :--- |
| `feat` | 新增功能或特性 | `feat(xref): 支持 ARM64 ADRP/ADD 相对寻址交叉引用` |
| `fix` | 缺陷与 Bug 修复 | `fix(parser): 修复无导入表 PE 文件 Imphash 计算异常` |
| `docs` | 仅文档更新或修改 | `docs: 完善快速开始与环境配置文档` |
| `style` | 代码格式调整（不影响逻辑） | `style: 统一 Ruff 代码排版规范` |
| `refactor` | 代码重构（既非新增特性也非修复缺陷） | `refactor(core): 抽取四级跨平台寻址公共模块` |
| `perf` | 性能优化 | `perf(strings): 优化大文件 UTF-16LE 字符串正则扫描吞吐量` |
| `test` | 增加或重构单元测试与集成测试 | `test: 补充合成 ELF64 夹具与节区熵测试用例` |
| `build` | 构建系统、外部依赖或脚手架调整 | `build: 升级 lief 与 capstone 依赖版本` |
| `ci` | CI/CD 流水线与 GitHub Actions 脚本修改 | `ci: 优化 release 自动化发版流程` |
| `chore` | 其他琐碎杂项（不改动源码与测试） | `chore: 更新 .gitignore 忽略规则` |
| `revert` | 恢复或回滚此前的某次历史提交 | `revert: feat(xref): 回退交叉引用变动` |

### 🛡️ 本地 Git 提交钩子守门 (Git Hooks)

本项目通过 Git 原生钩子 [`.githooks/commit-msg`](./.githooks/commit-msg) 在本地提交阶段实时校验信息格式，零外部依赖：
- **一键激活**：在仓库根目录下执行 `git config core.hooksPath .githooks`；
- **智能放行**：自动放行分支合并 (`Merge branch...`)、代码回退 (`Revert "..."`) 以及变基临时提交 (`fixup!` / `squash!`)；
- **错误引导**：若提交信息不符合规范，钩子将中断提交、高亮输出格式诊断，并引导使用 `commit.sh` 快速组装。

### 💡 推荐：使用规范化提交助手

本项目内置了 POSIX Bash 编写的提交助手 [scripts/commit.sh](./scripts/commit.sh)，同时支持**人工交互式向导**与 **AI / 自动化非交互式调用**：

```bash
# 方式 A：交互式向导模式（适合人工日常提交）
bash scripts/commit.sh

# 方式 B：非交互式命令行模式（推荐先使用 git add <file> 显式精准暂存目标文件）
git add <file-path>
bash scripts/commit.sh -t feat -s core -m "新增 RIP-relative 交叉引用扫描" -y
```

---

## 4. Pull Request 流程

- **PR 标题规范**：PR 标题必须同样遵循 [Conventional Commits](#3-commit-提交信息规范) 格式，CI 会对其进行自动化合规校验；
- **模版填写**：发起 PR 时，请按模版完整填写变更背景、解决的问题以及关联的 Issue（如 `close #12`）；
- **CI 绿灯**：确保 CI 流水线（PR 标题检查、ShellCheck、`ruff`、`pytest`）全部处于通过状态；
- **推荐合并方式**：仓库推荐采用 **Squash and merge（压缩合并）**，合入时自动采用合规的 PR 标题作为主干提交信息，保证 Release 变更日志 100% 精确。

---

## 5. 版本发版机制与发布说明

本项目通过 GitHub Actions 实现了现代化的 **Python + `uv` 多通道自动化发版体系**：

### 🌐 方式一：GitHub Actions 网页端云端调度发版 (推荐首选)
1. 前往 GitHub 仓库页面，点击顶部 **Actions** 标签页；
2. 在左侧选择 **Release** 流水线，点击右侧 **Run workflow**；
3. 输入目标语义化版本号（如 `v1.0.0`）并启动。
GitHub Actions 将自动校验主干分支与版本号格式、对齐 `pyproject.toml` 版本、执行 `uv build` 打包 `.whl` / `.tar.gz` 与 `checksums.txt`，并通过 `git-cliff` 生成更新日志创建 GitHub Release。

### 🚀 方式二：使用本地发版防呆脚本
面向终端开发者，项目提供了具备 5 重前置防呆自检并自动调用 `uv version` 同步版本号的发版脚本 [scripts/release.sh](./scripts/release.sh)：

```bash
# 1. 安全演练模式（仅检查并打印拟执行动作，零污染 Git 历史）
bash scripts/release.sh v1.0.0 --dry-run

# 2. 交互式或指定版本号快速发版
bash scripts/release.sh
bash scripts/release.sh v1.0.0 -y
```

### 📦 生态自动分发 (PyPI & GHCR)
- **PyPI 官方源 ([`.github/workflows/publish.yml`](./.github/workflows/publish.yml))**：采用 [PyPI Trusted Publisher (OIDC)](https://docs.pypi.org/trusted-publishers/) 免密钥自动构建并发布 `atengk-mcp-server-reverse`，发布后支持 `uvx atengk-mcp-server-reverse` 一键拉起；
- **GHCR 容器镜像 ([`.github/workflows/docker.yml`](./.github/workflows/docker.yml))**：基于 `GITHUB_TOKEN` 自动构建 `linux/amd64` 与 `linux/arm64` 双架构容器镜像（内置 `radare2` 与 `binutils`），发布至 `ghcr.io/atengk/mcp-server-reverse`。
