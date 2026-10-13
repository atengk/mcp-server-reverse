# 分诊标签词表 (Triage Labels)

工程技能内部围绕 5 个标准分诊角色进行协作。本文件将标准角色映射为本仓库 Issue 跟踪器中实际使用的标签字符串。

| mattpocock/skills 标准角色 | 本仓库实际标签名 | 含义说明 |
| -------------------------- | ---------------- | -------- |
| `needs-triage`             | `needs-triage`   | 需要维护者评估与分诊该 Issue |
| `needs-info`               | `needs-info`     | 等待报告人补充复现步骤或上下文信息 |
| `ready-for-agent`          | `ready-for-agent`| 规格已完全明确，可交由后台 Agent 独立执行 |
| `ready-for-human`          | `ready-for-human`| 需要人类开发者介入设计或编码实现 |
| `wontfix`                  | `wontfix`        | 暂不采纳或不予处理 |

当技能提及某个分诊角色（例如“应用 AFK-ready 分诊标签”）时，统一使用上表中间列对应的标签名。

若未来仓库自定义了其他标签词表，直接修改中间列即可。
