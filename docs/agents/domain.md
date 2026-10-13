# 领域文档规范 (Domain Docs)

定义工程技能在探查代码库时如何读取与消费本仓库的领域模型文档与架构决策记录（ADR）。

## 探查代码库前必读 (Before exploring, read these)

- 仓库根目录下的 **`CONTEXT.md`**，或者
- 仓库根目录下的 **`CONTEXT-MAP.md`**（若存在）—— 它会指向各个子上下文的 `CONTEXT.md`，请阅读与当前任务相关的上下文文档。
- **`docs/adr/`** —— 阅读与你即将修改的模块相关的架构决策记录（ADR）。在多上下文仓库中，还需检查 `src/<context>/docs/adr/` 下的局部架构决策。

若上述文件尚不存在，**保持静默继续执行（proceed silently）**。不要将其缺失报告为问题，也不要提前催促创建。`/domain-modeling` 技能（可通过 `/grill-with-docs` 与 `/improve-codebase-architecture` 触发）会在领域术语或架构决策真正敲定时按需惰性创建它们。

## 目录结构 (File structure)

单上下文仓库（Single-context repo，当前仓库采用此布局）：

```text
/
├── CONTEXT.md
├── docs/adr/
│   ├── 0001-hybrid-static-analysis-engine.md
│   ├── 0002-lru-binary-session-and-pagination.md
│   └── 0003-lazy-xref-index-and-arm64-sliding-window.md
└── src/
```

多上下文仓库（Multi-context repo，以根目录存在 `CONTEXT-MAP.md` 为标志）：

```text
/
├── CONTEXT-MAP.md
├── docs/adr/                          ← 系统级全局决策
└── src/
    ├── ordering/
    │   ├── CONTEXT.md
    │   └── docs/adr/                  ← 上下文专属决策
    └── billing/
        ├── CONTEXT.md
        └── docs/adr/
```

## 严格遵循领域词汇表 (Use the glossary's vocabulary)

当你在输出中命名领域概念（无论是 Issue 标题、重构提案、排障假设还是测试用例名称）时，必须使用 `CONTEXT.md` 中定义的标准术语，切勿漂移到词汇表明确规避的同义词。

若所需的领域概念尚未收录在词汇表中，这通常是一个信号 —— 要么你正在自造项目不使用的术语（请重新审视），要么存在真实的领域模型空白（请记录下来供 `/domain-modeling` 沉淀）。

## 显式标记 ADR 冲突 (Flag ADR conflicts)

若你的方案或代码修改与现有 ADR 存在冲突，必须显式指出，严禁静默覆盖：

> _与 ADR-0001（纯 Python 内核与外部 CLI 混合分层架构）相冲突 —— 但值得重新讨论，因为……_
