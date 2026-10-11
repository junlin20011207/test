# 第七阶段：ProofCut ContractLab 的因果时序、失败传播与修复验收研究

研究日期：2026-10-11。研究对象：`junlin20011207/test` 仓库中此前通过 274 项回归测试的独立研究原型；全部历史外部漏洞均已公开，所有运行时文件和 Git 状态均为本仓库生成的无害夹具。不得把本报告理解为对第三方仓库的安全扫描授权、漏洞发现或真实生产发布。

## 1. 最新相关技术的比较边界

- GitHub Actions 规定 `steps.<id>.outcome` 为 `continue-on-error` 生效**之前**的步骤结果，`steps.<id>.conclusion` 为生效**之后**的结果。真实失败可能因容错使下游看到 `conclusion=success`。官方文档：<https://docs.github.com/en/actions/reference/workflows-and-actions/contexts>、<https://github.com/actions/runner/blob/main/docs/adrs/0274-step-outcome-and-conclusion.md>。
- GitHub 条件表达式的默认 `success()` 行为、步骤级 `if` 和字符串语义，意味着静态修复验收不能只查找一个条件文本是否出现。官方：<https://docs.github.com/en/actions/reference/workflows-and-actions/expressions>、<https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax>。
- CodeQL 2026 年仍持续强化 GitHub Actions 的 `poisonable_steps`，已包括 Python 和 Go 等执行汇点。不能宣称简单的 Artifact 来源链条分析领先于 CodeQL。<https://github.blog/changelog/2026-05-28-codeql-2-25-5-improves-query-accuracy-for-github-actions/>。
- `actions/artifact-poisoning/critical` 仍属于官方很高精度的专用漏洞路径查询：<https://codeql.github.com/codeql-query-help/actions/actions-artifact-poisoning-critical/>。

**研究假设：** 从 CodeQL 或 ProofCut “相关漏洞告警消失”，不能推导“下载、验签、应用和推送发生在正确的依赖顺序”，也不能推导步骤失败会实际阻止错误写入。需要明确的因果契约和（有限范围的）运行时反证。

## 2. 第一轮真实对抗实验：执行顺序未被校验

在仅通过 13 项静态业务契约的旧系统上，新增 `tests/test_temporal_contract_falsification.py`，尝试 12 种顺序、跳过和失败掩盖变更，GitHub CI 的第一轮**10 个被错误接受、2 个已被旧规则拒绝**。

[原始红色 CI：10 failed / 276 passed](https://github.com/junlin20011207/test/actions/runs/38146223404)。

重要方法学修正：其中“独立可信 Checkout 在下载之前”以及“独立 Checkout 在就绪检查之前”的两个案例，**在 Artifact 被隔离到临时目录、Checkout 不消费 `present` 输出的条件下，并不必然是不安全行为**。第一版严格六步全序虽然可以拒绝这些排序，但也过度限制了合法方案。单独新增 `tests/test_safe_temporal_permutations.py` 实际复现 **2 项误拒绝**。

[严格全序误拒绝的红色 CI：2 failed / 286 passed](https://github.com/junlin20011207/test/actions/runs/38146547078)。

## 3. 第二轮改进：从刚性总顺序到依赖 DAG

`benchmarks/temporal_semantics.py` 将六个阶段定义为可检查的数据流/控制流依赖：

- Artifact 下载必须在业务检查及工件应用之前。
- 业务检查必须在工件应用之前。
- 可信 Checkout 必须在提交 SHA 校验之前。
- SHA 校验必须在应用生成产物之前，工件应用必须在 Git Push 之前。
- 当 Checkout、SHA、应用或 Push 使用 `steps.check.outputs.present == 'true'` 时，动态增加“业务检查早于该步骤”的依赖边。

这样能够允许两个没有依赖关系的步骤自由重排，而不是把单一官方历史案例的工作流步骤顺序误当成全球安全规范。因为这是**针对单个 `dist/` 修复形态的因果契约子集**，它不会也不能保证任意 Shell 脚本没有其它显式或隐式依赖。

失败传播规则则要求：关键校验、应用和 Push 步骤不能无条件跳过，也不能容忍其失败；下载允许 `continue-on-error` 的**受控合法例外**，仅当下游四个关键步骤全部由 `check.present == 'true'` 约束时成立；未知动态 `if` / `continue-on-error` 表达式一律作为“未证实”，不可冒称安全。

## 4. 第三轮反证：工作目录与 Job 级别的失败掩盖

除步骤本身的失败外，Job 级 `continue-on-error`、Job 的默认 `working-directory` 与关键步骤的独立工作目录均会改变最终执行结果。针对它们的五个变更，修复前**全部被错误接受**，真实红色 CI：

[5 failed / 296 passed](https://github.com/junlin20011207/test/actions/runs/38146751558)。

最终新增 `critical_execution_context`：对于本例中使用相对路径 Git 操作的工作流，关键 Bash 步骤必须在明确建模的工作区根目录执行，且 Job 级别不能掩盖失败；其它目录需要独立提供路径映射及业务契约，不能通过本项检查。

最终由旧版 13 项修复契约发展为 **16 项**：原 13 项 + 因果依赖顺序 + 关键失败传播 + 执行环境。历史已披露 actions/attest 修复草案 **16/16 项通过**，包含明确的因果边、实际步骤索引和容错分类证据。

[最新已验证 301 项 Pytest](https://github.com/junlin20011207/test/actions/runs/38146815859)。
[真实历史漏洞固定修复回归与机读证书](https://github.com/junlin20011207/test/actions/runs/38146815962)。

## 5. 独立无害 Git 运行时反证

`benchmarks/temporal_git_race.py` 在 GitHub 托管 Runner 的隔离临时目录建立真正的 bare Git 仓库，对两个相同的、完全无害的输入分别测试：

| 控制条件 | SHA 不匹配被检测 | 本地 Git 分支被错误写入 |
|---|---|---|
| 正确：先 SHA 校验、后尝试写入 | 是 | 否 |
| 错误：先 Git Push、再检查 SHA | 是 | 是 |

在错误方案中，最后一个 SHA 检查即使失败也无法撤销已经成功完成的本地 Git 写入。

[真实本地 Git 实验运行、逐例 SHA、分支写入结果](https://github.com/junlin20011207/test/actions/runs/38146425288)。本实验**没有远程授权、没有运行下载代码、没有模拟真实 GitHub 分支保护**；只说明检查和写入的先后关系在这个受控情景中确实改变了 Git 对象状态。

## 6. 同源 CodeQL 对照设计

在固定 SHA 的已公开 actions/attest 漏洞提交的实验修复副本中，之前已构造六类业务/授权违约，CodeQL 2.27.2 `actions-security-extended.qls` 对六份均无告警，ContractLab 拒绝了六项。相关证据：<https://github.com/junlin20011207/test/actions/runs/38144674771>。

第七阶段追加四类**时间和环境契约违约**：

- Git Push 在 SHA 校验之前；
- 工件应用在 SHA 校验之前；
- Job 级容忍失败；
- 工件应用步骤切换工作目录。

`benchmarks/contract_codeql_comparison.py` 现在统一比较**一个正常修复对照 + 十个各自独立的研究者设计的违约变体**，固定 CodeQL 官方 2.27.2 二进制和 Git Blob 校验，保留各版本 SARIF 与 `failed_obligations`。这是**定制业务协议/错误传播与通用漏洞扫描的工具互补性**实验；即使出现 CodeQL 零告警，也不得称为代码扫描漏检实际漏洞。

## 7. 仍未解决和竞赛定位

推荐延续 **ProofCut ContractLab：跨运行 CI/CD 的因果安全—业务双契约验收原型**，将创新主张缩小为“真实平台语义对齐 + 必要授权约束 + 数据流因果图 + 受控运行时合同”，而不是宣称重新发明漏洞扫描。

现阶段仍未实现的目标：

1. 完整 GitHub Actions 多 Job、重用工作流、动态矩阵、复杂 `if` 和 Shell AST 的因果建模；目前只有受限场景。
2. 跨不相干真实仓库的独立留出样本，以及证明没有过多拒绝合法运行的精确率/召回率；不能用研究者构造的负例替代。
3. 对真正的权限身份、受控组织分支保护、真实远程部署和端到端业务保持性的验证；本轮仅本地无害 Git 仓库证据。
4. 与 CodeQL + Agentic Autofix 在相同权限/预算/案例/任务下的修复成功率、审查成本和时延的对照；目前仅有 2.27.2 `security-extended` 静态对照。
5. 一套对未经建模脚本/操作返回明确 `UNKNOWN` 状态的通用形式化契约语言。目前对某些未支持情况仅作为不通过处理，尚无法自动完成企业 CI/CD 合规认证。

**因此，本阶段证明的是“原修复验收器存在可复现的时序与执行上下文错误接受，并已在固定有限样本上修复”；尚未证明对未见真实系统的泛化，不能声称已具备高水平获奖竞争力或发现新漏洞。**

独立研究 PR：<https://github.com/junlin20011207/test/pull/9>，不修改 `main`。
