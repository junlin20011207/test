# BoundaryGraph：创意作品赛防御性研究记录（2026-10-11）

## 研究问题
GitHub Actions 的 `workflow_run` 可能把不可信上游事件生成的 Artifact 交给高权限 Job。已有 zizmor、Poutine 等项目进行多种工作流安全检查，本项目研究“事件条件 + 真实跨执行 Artifact 接线 + 下游权限”的可复核安全路径证据。

## 研究原型核心机制
1. 解析多个 Actions 工作流 `name` 和 `workflow_run.workflows` 的跨文件依赖。
2. 标注上游 PR、issue_comment 等潜在不可信事件。
3. 不把执行成功状态和同仓库条件独立视为可信证明；支持小范围的可信 push 事件守卫。
4. 识别 `download-artifact` 是否真的通过上游 `workflow_run.id` 下载——未指定 run-id 时，默认当前执行的 artifact，不能视为跨工作流来源。
5. 输出来源、下游、token 权限、参考秘密、可能的后续执行及修复建议；复杂情况记为 unknown。

## 证据状态
- 本地完整包：22 项单元测试通过，96 组按既定语义构造的合成样本正确；**这些都是内部测试**。
- GitHub 分支源代码是供真实 Actions CI 验证的可运行简化版本，CI 成功前不能声称云端通过。
- **尚未完成**真实开源仓库人工标注、同样本 zizmor/Poutine 对照，也不能据此给出 80 分以上的可信评分。
- 原型不会运行攻击行为；工作流间只传递文本标记，消费端只读校验。

## 可挑战假设
GitHub 仓库的写权限成员视为信任边界内；复杂表达式、调用链、环境保护、私有 action、Artifact 内容的具体数据依赖未完全建模。无告警不代表安全。潜在的执行命令并不等于实际执行了下载内容。

## 竞赛与已有技术
官方公告：https://cpipc.acge.org.cn/cw/contestNews/detail/2c90800c8093eef401809d33b36f0652/2c9080199ed8b78d019ed96ceea21560?page=1
GitHub 工作流安全：https://docs.github.com/en/actions/reference/security/secure-use
Artifact 官方仓库：https://github.com/actions/download-artifact
zizmor：https://docs.zizmor.sh/audits/
Poutine：https://github.com/boostsecurityio/poutine

**赛事公开评审没有为五项评审维度公布固定权重。** 原创性、完成度、性能、应用价值、文档规范性是评估方向；80 分门槛仅属于自设的 30/25/20/15/10 模拟评分模型，不是官方分数。
