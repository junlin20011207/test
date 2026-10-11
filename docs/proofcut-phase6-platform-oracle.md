# ProofCut ContractLab 第六阶段：以真实 GitHub 语义校准安全契约，并检验 CodeQL 互补性

研究日期：2026-10-11。研究状态：已完成真实 GitHub 表达式引擎对照和自动化回归；契约漂移与 CodeQL 的同源比较以 `benchmarks/contract_codeql_comparison.py` 的机器生成结果为准。

## 一、原方向的根本不足

ProofCut 从 Artifact 来源链、敏感汇点进展到合约式修复验收，但上一阶段的 248 项测试依然不能证明它对 **GitHub 实际条件语言**的解释准确；我们的逻辑解析器内部使用 Python 字符串规则及普通布尔运算，而 GitHub 的表达式规则不同。该偏差可能导致合法授权方案被错误拒绝，也可能使被错误解释的条件进入契约证明。

更重要的是，CodeQL 2.27.2 已能发现本研究两项公开历史安全问题，GitHub 2026-07 上线的 Agentic Autofix 也会建议修复并重跑 CodeQL，因此**告警检出、补丁生成和重新扫描都不能单独视为创新贡献**。新的、可证伪的研究假设是：借助目标平台真实语义校准，结合跨生产者与消费者的业务数据契约，是否能够独立拒绝部分静态安全扫描未指明的功能或授权回归？

资料核查：
- GitHub 官方表达式语义（字符串比较不区分大小写，字符串 `''` 转义，宽松等值比较、短路操作数语义及 `startsWith` 字符串化）<https://docs.github.com/en/actions/reference/workflows-and-actions/expressions>
- CodeQL 2.27.2，2026-10-07 <https://codeql.github.com/docs/codeql-overview/codeql-changelog/codeql-cli-2.27.2/>
- CodeQL Artifact Poisoning <https://codeql.github.com/codeql-query-help/actions/actions-artifact-poisoning-critical/>
- GitHub Agentic Autofix，2026-07-10 <https://github.blog/changelog/2026-07-10-agentic-autofix-for-code-scanning-alerts-in-public-preview/>

## 二、三轮对抗—修复—复验

### 路径一：大小写与字面量转义

原 `benchmarks/guard_semantics.py` 将 `'MAIN' == 'main'` 判为假，将 `startsWith('Dependabot/npm', 'dependabot/')` 判为假，且无法解析 `'It''s safe'` 的双引号转义形式。新增的 9 项针对性测试产生 **7 failed / 250 passed** 的真实红色 CI。改进后使用 Unicode `casefold()` 进行支持范围内的字符串无大小写比较，解析两个连续单引号作为一个字面量单引号，保持不支持的未知语法拒绝通过。

官方 GitHub Runner 工作流 `.github/workflows/expression-oracle.yml` 用 GitHub 自己的表达式插值求值，把结果作为环境值传入 `benchmarks/github_expression_oracle.py`，与本地表达式解析独立对照。

首次失败：<https://github.com/junlin20011207/test/actions/runs/38143799067>；修正后：<https://github.com/junlin20011207/test/actions/runs/38143910173>。

### 路径二：`&&`/`||` 返回操作数而不只是布尔结果

原解释器把 `'hit' && 'value'` 错误计算为布尔 `true`，导致组合 `startsWith(false || 'Dependabot/pkg','dependabot/')` 等表达式错误。八项控制产生 **7 failed / 258 passed** 的红色 CI。

修正后，逻辑短路只对前一个操作数判断真值，在确定需要返回下一操作数时保留其原值；有限类型模型仅显式支持字符串和布尔值。新的真值对照在 GitHub Runner 上的七项官方表达式结果与本地解释完全相同。

复验：<https://github.com/junlin20011207/test/actions/runs/38144037501>；完整回归：<https://github.com/junlin20011207/test/actions/runs/38144037503>。

### 路径三：宽松比较与内建字符串函数的类型转换

GitHub 将 `'' == false`、`'0' == false`、`'1' == true` 判真，`'hello' == true` 判假；`startsWith(true,'t')` 也成立。模型最初仅实现 Python 严格类型比较，存在明显偏差。

修订后的有限宽松比较采用合法 JSON 数字解析，将不合法转换视为 NaN；布尔值参与 `startsWith` 前转换为 `true`/`false` 字符串。不在支持范围的对象、数组、`null`、数值运算和更复杂 GitHub 函数仍不可冒称已准确解释。

结果：真实 GitHub 表达式对照 **19/19 一致**，完整回归 **274/274 通过**。

证据：<https://github.com/junlin20011207/test/actions/runs/38144186550>、<https://github.com/junlin20011207/test/actions/runs/38144186462>。

## 三、同一样本上的业务契约与 CodeQL 对照设计

对已披露的 actions/attest `GHSL-2026-225` 历史提交（原始工作流通过 Git Blob SHA 验证），先应用相同的**不部署的实验修复草案**，再在临时副本中分别引入六种单点修改：

| 变体 | 预设业务或安全约束失败 |
|---|---|
| `producer_renamed` | 生产者更改工件名称，下游仍请求旧名称 |
| `download_moved` | 下载目录改变，下游检查和读取路径不再对应 |
| `readiness_always_true` | 业务就绪被无条件赋真 |
| `sha_only_logged` | SHA 被打印但不再阻止错误版本 |
| `actor_guard_bypass` | 消费者授权条件加入 `|| true` |
| `push_failure_ignored` | Git Push 失败被 `|| true` 掩盖 |

保留无变更修复草案作为对照。每个版本使用相同的固定 SHA 来源、相同的 `codeql/actions-queries:codeql-suites/actions-security-extended.qls`，分别保存契约失败原因及官方 CodeQL SARIF。

这是一项 **工具职责互补性研究**：CodeQL 是通用漏洞扫描器，不应预期它自动理解每个应用的自定义业务文件协议；因此“CodeQL 无告警而合约失败”不能直接标注为 CodeQL 漏检漏洞，更不能得出本原型整体优于 CodeQL 的结论。

复现：`python -m benchmarks.contract_codeql_comparison`，须有经过 SHA-256 校验的官方 CodeQL 2.27.2 二进制，且只读 GitHub Raw 下载可用。工作流 `.github/workflows/codeql-compare.yml` 自动执行并保存机器可审查的 `comparison.json` 和各版本 SARIF。

### 三轮修复后的独立六变体 CodeQL 对照结果

[**真实 GitHub CodeQL 2.27.2 同样本扫描运行**](https://github.com/junlin20011207/test/actions/runs/38144366160)：官方 CodeQL Actions `security-extended` 查询集使用固定发布包和 SHA-256 校验，同样本包括历史 actions/attest 修复草案及六个独立临时变体。每例保留原始 SARIF、ContractLab 13 项约束检查和发生变化的源文件。

| 变体 | ContractLab | 失败的契约义务 | CodeQL 总告警 |
|---|---|---|---:|
| `control` 无变更草案 | 通过 | 无 | 0 |
| `producer_renamed` | 拒绝 | 命名发布 / 上下游身份不一致 | 0 |
| `download_moved` | 拒绝 | 下载隔离目录与后续读取协议不一致 | 0 |
| `readiness_always_true` | 拒绝 | 业务文件存在性未检查 | 0 |
| `sha_only_logged` | 拒绝 | HEAD SHA 不再约束当前代码版本 | 0 |
| `actor_guard_bypass` | 拒绝 | 来源仓库 / 身份 / 分支限制可被绕过 | 0 |
| `push_failure_ignored` | 拒绝 | Git Push 失败被忽略 | 0 |

**结果：** 在固定、已知的六个被人为破坏的实验性修复版本上，ContractLab 拒绝了 6/6；CodeQL 2.27.2 的 `security-extended` 在这六份文件中报告 0 条告警。这里是“**与漏洞扫描范围互补**”而非“CodeQL 发现 6 个漏洞失败”。业务路径位置或就绪检查错误并非通用漏洞扫描器应理解的用户自定义协议。这个受限定向样本没有独立盲测，不可用 6/6 作为真实世界修复准确率、召回率或竞品优势的估计。

代码与原始数据：`benchmarks/contract_codeql_comparison.py`、`baseline-results/contract-comparison/comparison.json` 及六份 SARIF（GitHub Actions Artifacts 内，按运行的保留期限访问）。比较还不能替代与 GitHub Agentic Autofix 同任务实际执行的性能和人工成本实验。

## 四、最优竞赛技术定位

建议以 **ProofCut ContractLab：基于平台语义校准的 CI/CD 跨工作流修复契约验证** 为核心，将产出分为：原始安全数据来源与敏感汇点证据、目标平台一致的有限策略证明、生产者/消费者业务协议、真实 GitHub Artifact 运行行为和独立 CodeQL 交叉验收。

与 GitHub CodeQL + Agentic Autofix 比较时，本原型最值得检验的差异是**跨工作流定制业务契约对安全扫描清零后功能退化的附加拦截能力**，而非声称首次发明静态污点分析、安全合同或自动补丁生成。

## 五、尚未解决

- 19 个实际 GitHub 表达式是有限选择集，无法证明完整 GitHub 条件表达式兼容性；等价字符串处理、数值、对象和内建函数仍存在未知行为。
- 六种业务契约变体由研究者主动设计，仍缺未参与开发的盲测和跨项目泛化评估；不能推导总体检出率或成熟度。
- 两项已披露历史案例不构成新漏洞发现；不等于真实生产授权验证或攻防利用。
- 仍没有与 GitHub Agentic Autofix 的独立同任务对照，因其需要特定商业许可与接入条件，不得虚构测试。
- 自动修复草案与实际业务保留性依然只在有限真实无害 Artifact 传输和本地无凭证 Git 环境中得到验证。
- 工程原型的静态检测、证明校验和业务修复仍高度为特定流程编写，形成高水平获奖的独立创新性尚未得到客观充分验证。

研究分支：`research/expr-oracle-20261011`；草稿 PR：<https://github.com/junlin20011207/test/pull/8>。
