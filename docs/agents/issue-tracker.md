# Issue 跟踪器：GitHub (Issue tracker: GitHub)

本仓库的 Issues 与规格说明（Specs）均存储在 GitHub Issues 中，所有操作统一使用 `gh` CLI。

## 操作规范 (Conventions)

- **创建 Issue**: `gh issue create --title "..." --body "..."`（多行正文建议使用 heredoc）。
- **读取 Issue**: `gh issue view <number> --comments`，结合 `jq` 过滤评论并同时获取标签（labels）。
- **列出 Issues**: `gh issue list --state open --json number,title,body,labels,comments --jq '[.[] | {number, title, body, labels: [.labels[].name], comments: [.comments[].body]}]'`，按需附加 `--label` 与 `--state` 过滤条件。
- **评论 Issue**: `gh issue comment <number> --body "..."`
- **添加 / 移除标签**: `gh issue edit <number> --add-label "..."` / `--remove-label "..."`
- **关闭 Issue**: `gh issue close <number> --comment "..."`

仓库信息直接从 `git remote -v` 推导——在克隆的工作区中运行 `gh` 时会自动识别。

## 将 Pull Requests 作为需求分诊入口 (Pull requests as a triage surface)

**PRs as a request surface: no.** _（若本仓库将外部 PR 视为特性需求入口，可设为 `yes`；`/triage` 技能会读取此开关。）_

当设为 `yes` 时，PR 将采用与 Issue 相同的标签与状态流转，并使用对应的 `gh pr` 命令：

- **读取 PR**: `gh pr view <number> --comments` 及 `gh pr diff <number>` 查看代码变更。
- **列出待分诊外部 PR**: `gh pr list --state open --json number,title,body,labels,author,authorAssociation,comments`，仅保留 `authorAssociation` 为 `CONTRIBUTOR`、`FIRST_TIME_CONTRIBUTOR` 或 `NONE` 的记录（排除 `OWNER`/`MEMBER`/`COLLABORATOR`）。
- **评论 / 标签 / 关闭**: `gh pr comment`、`gh pr edit --add-label`/`--remove-label`、`gh pr close`。

GitHub 的 Issues 与 PR 共享同一编号空间，因此裸编号 `#42` 可能是其中任意一种——优先通过 `gh pr view 42` 解析，失败时回退至 `gh issue view 42`。

## 当技能提示 "publish to the issue tracker"（发布至 Issue 跟踪器）时

创建一个新的 GitHub Issue。

## 当技能提示 "fetch the relevant ticket"（获取关联任务卡）时

运行 `gh issue view <number> --comments`。

## 探路与规划操作 (Wayfinding operations)

供 `/wayfinder` 技能使用。**Map（全景图）** 是一个主 Issue，其下的各个任务卡（tickets）作为 **Child（子 Issue）** 挂载。

- **Map（主图）**: 带有 `wayfinder:map` 标签的单一 Issue，正文维护 Notes / Decisions-so-far / Fog。通过 `gh issue create --label wayfinder:map` 创建。
- **Child ticket（子任务卡）**: 通过 GitHub sub-issue 接口（`gh api` 调用 sub-issues 端点）关联到主图 Issue。若未启用 sub-issues，则将子任务追加到主图正文的任务列表中，并在子任务正文顶部注明 `Part of #<map>`。标签格式：`wayfinder:<type>`（`research`/`prototype`/`grilling`/`task`）。认领后指派给当前开发者。
- **Blocking（阻塞依赖）**: 优先使用 GitHub **原生 Issue 依赖关系（native issue dependencies）**。通过 `gh api --method POST repos/<owner>/<repo>/issues/<child>/dependencies/blocked_by -F issue_id=<blocker-db-id>` 添加依赖边，其中 `<blocker-db-id>` 是阻塞项的数字 **数据库 ID**（通过 `gh api repos/<owner>/<repo>/issues/<n> --jq .id` 获取，注意不是 `#number` 或 `node_id`）。GitHub 会返回 `issue_dependencies_summary.blocked_by`（仅统计未关闭的阻塞项）。若不可用，回退为在子任务正文顶部声明 `Blocked by: #<n>, #<n>`。当所有前置阻塞 Issue 关闭后，当前任务卡即解除阻塞。
- **Frontier query（前沿任务查询）**: 列出主图下所有处于 open 状态的子任务（`gh issue list --state open`），剔除仍存在未关闭阻塞项（`issue_dependencies_summary.blocked_by > 0` 或 `Blocked by` 行中仍有 open 状态的 Issue）以及已被指派（assignee）的任务；按主图中的排列顺序取第一个任务。
- **Claim（认领）**: `gh issue edit <n> --add-assignee @me` —— 作为当前会话的首次写入操作。
- **Resolve（结项）**: `gh issue comment <n> --body "<answer>"`，随后执行 `gh issue close <n>`，最后将结论摘要与链接追加到主图的 Decisions-so-far 章节。
