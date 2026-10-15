# 0009. 基于 oss-template 范式的持续集成与统合发版流水线重构

- **状态**: accepted

## 背景与问题

随着项目工程规模的扩张，既有的 GitHub Actions 自动化流水线逐渐暴露出以下治理瓶颈：

1. **发版流程割裂与制品重复构建**：
   既有设计将发版过程分散在 `release.yml`（GitHub Release）、`publish.yml`（PyPI 发布）与 `docker.yml`（容器镜像构建）3 个独立文件中。发版时 3 个工作流被并发触发，各自重新拉取依赖并独立执行编译打包；这不仅浪费 GitHub Actions 运行算力，而且导致上传至 GitHub Release 的 Wheel 包、发布到 PyPI 的 Wheel 包以及打包进 Docker 镜像的 Wheel 包哈希校验和存在不一致风险（制品漂移）。
2. **缺乏发版前置熔断质量门禁**：
   发版工作流未配置严格的端到端单测回归门禁，若在存在代码缺陷或测试失败时打 Tag 发版，各任务仍会直接打包并推送坏制品至公开镜像仓库。
3. **PR 门禁缺乏短路直通与分支保护死锁**：
   CI 流水线缺乏变更路径探测（Path Filter），哪怕仅修改纯文档（`README.md`、`docs/**`）仍需执行完整的测试套件；同时，动态矩阵任务或条件跳过的任务在 GitHub 分支保护规则（Branch Protection Rules）中容易发生状态缺失，导致 PR 无法合并（分支保护死锁）。
4. **依赖治理缺乏自动化安全更新机制**：
   缺少规范的 Dependabot 依赖生命周期配置，无法自动针对 GitHub Actions 与 Python 第三方依赖的 CVE 漏洞发起修复 PR。

## 决策

全面融合开源工业级模版 `atengk/oss-template` 的 CI/CD 治理标准，并与项目原生的 `uv` 高速工具链深度结合：

1. **统合发版流水线（Build Once, Distribute Everywhere）**：
   - 将原分散的 `publish.yml` 彻底合并收敛至 `.github/workflows/release.yml`，统一由版本标签（`v*`）或手动发版分发；
   - 建立严格的 DAG 拓扑执行链：
     1. **`gate-test`**：发版前置质量门禁，强制执行全量 136 项回归测试与 Ruff 代码扫描，遇失败立即熔断终止；
     2. **`build-artifacts`**：单次调用 `uv build` 编译出不可变的发行产物（sdist 与 wheel），生成 SHA-256 `checksums.txt` 校验清单并归档为跨任务可复用 Artifact；
     3. **并行多路分发**：
        - `publish-release`：提取 `git-cliff` 规范更新日志，创建 GitHub Release 并挂载不可变制品；
        - `publish-pypi`：声明 `permissions: id-token: write`，优先通过 PyPI Trusted Publishing（OIDC 免密钥）直接上传预构建的不可变 wheel/sdist，并兼容 `PYPI_API_TOKEN` 密钥回退；
        - `publish-docker`：构建 `linux/amd64` 与 `linux/arm64` 双架构镜像并推送至 GHCR。
     4. **`summary`**：执行完毕直出富文本 Step Summary 看板，提供各平台拉取与安装指令。
2. **CI 短路直通网关与终审门禁看板**：
   - 在 `.github/workflows/ci.yml` 中引入 `dorny/paths-filter@v4`，将纯文档或配置修改（`*.md`、`docs/**` 等）秒级放行，跳过耗时依赖构建与测试；
   - 采用分层兼容性测试矩阵：PR 仅执行 Python 3.12 极速回归测试；主干推送执行 Python 3.11 与 3.12 跨版本矩阵全量覆盖；
   - 引入 **`all-checks-passed` 终审门禁**：统一聚合所有前置 Job 的执行结果，输出格式化 Markdown 判定表格，作为 GitHub 分支保护规则唯一强绑的必检状态检查，杜绝死锁。
3. **开发版 Docker 镜像构建精简化**：
   - 保留独立 `.github/workflows/docker.yml` 专门服务于主干分支（`main`/`master`）的代码推送，生成 `latest` 与 `sha-<short>` 测试镜像；内置防重复构建探针（若提交已关联 Tag 则自动跳过，让位给统一发版流程）。
4. **依赖自动化纳管与 PR 模版集成**：
   - 引入 `.github/dependabot.yml`，对 GitHub Actions 与 Python pip 依赖开启月度依赖审计与 PR 自动语义化分组打包（Minor/Patch 合并，Major 单独开 PR）；
   - 引入规范的 `.github/PULL_REQUEST_TEMPLATE.md`，对齐 Conventional Commits 与测试自检清单。
