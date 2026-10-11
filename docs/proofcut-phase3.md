# ProofCut 第三阶段：语义化证据、CodeQL 等样本对照与修复契约

日期：2026-10-11。**全部案例均为已公开并协调披露的历史问题**；不涉及第三方实际工作流执行、恶意产物运行或未经许可的攻击验证。

## 一、为什么上一阶段仍不足以支撑高水平创新性

1. **缺少工具差异证据。** GitHub CodeQL 的 `actions/artifact-poisoning/critical` 已提供跨工件信任路径分析；2026 年持续增强 GitHub Actions 数据流和汇点模型。不能仅凭 ProofCut 能识别 SPIRE 漏洞就宣称新增检出。
2. **自动修复同样并非独占能力。** GitHub 2026-07-10 发布 Agentic Autofix 公测，已经可以探索源码、生成修复草案、重跑 CodeQL、迭代修复、建立待审核 PR。单纯“提出补丁 + 再扫描”不能作为独创性论证。
3. **启发式见证不充分。** 原 `sinkproof.py` 仅有工作区根下载、之前检出和相对执行语句，但未验证检出范围覆盖目标；正则可能在 JavaScript 字符串、注释或 Shell 示例文本中误认为代码执行。原 `metadataproof.py` 可能把字符串相似性误当成 Artifact 读取和 Git Push 的真正数据依赖。
4. **实验适用范围小。** 先前九个项目、108 YAML 中，只有六份工作流使用 `workflow_run`；外部样本无独立真实安全标签，不能拿零告警推导精确率。

## 二、模型细化与对抗实验

新的 `sinkproof.checkout_covers` 明确检查可信 Checkout 是否把被执行文件放入工作区；支持 `sparse-checkout` 的有限静态范围判定；非工作区根目录 Checkout 或未覆盖的稀疏目录不得充当“可信文件被工件覆盖”的证据。

新的 `js_code_positions` 限制敏感导入只能来自脚本的代码位置；引号字符串和注释中的 `require` 不可充当执行证据。Shell 使用已有 `shlex` 词法切分结果，拒绝 `echo 'bash ...'` 等文本。它们并非完整 JavaScript / Bash 解析器，动态执行应留作未知。

`metadataproof` 要求工作流真的从 `dist-meta/head-ref` 读入 `head_ref` 并传入 `GITHUB_OUTPUT`，且后续 Git Push 是实际命令起始位置，不是注释或日志。现有模型不涵盖跨 Shell 变量、复杂管道或任意间接代码路径。

对原有 133 项测试新增 31 个语义正反控制，GitHub Actions 全量测试 **164 项通过**。这仅是固定测试集内表现，不能等价于现实环境准确率。

## 三、与 CodeQL 官方工具的实际同样本复验

使用 SHA-256 校验的 **CodeQL 2.27.2 官方 Actions bundle**，查询集 `codeql/actions-queries:codeql-suites/actions-security-extended.qls`。两项已公布历史漏洞的修复前后 YAML 均取自固定提交，按 Git Blob SHA 校验；使用 CodeQL `--language=actions` 建库，保存原始 SARIF。全部为真正 CLI 扫描，不是凭文档估计。

| 已披露案例 | 源码版本 | ProofCut 指定风险链 | CodeQL 告警 |
| --- | --- | ---: | --- |
| SPIRE 覆盖可信模块 | 修复前 | 1 | 1（Artifact Poisoning） |
| SPIRE 覆盖可信模块 | 官方修复版 | 0 | 0 |
| actions/attest 工件分支元数据 | 修复前 | 1 | 5（代码注入、不可信 Checkout） |
| actions/attest 工件分支元数据 | 官方修复版 | 0 | 0 |

同样本结果没有显示 ProofCut 在“漏洞检出数量”上超越 CodeQL。CodeQL 针对不同安全问题提供不同规则 ID；不能拿两种告警类别的绝对数量计算精确率。

首轮修复草案在静态 ProofCut 分析下均使目标路径变为零；CodeQL 对 SPIRE 草案为 0 条，对 actions/attest 草案**仍有 3 条中危代码注入告警**。将分支名与 head SHA 改为从经过来源约束的事件上下文、再经 Shell 环境变量引用后，第二轮曾降至 1 条中危。**这说明单一规则清零不等于安全修复完成，必须保留独立扫描残余报告。**

[CodeQL 官方与 ProofCut 四状态原始对照运行](https://github.com/junlin20011207/test/actions/runs/38138516024)；
[第一版六状态（含修复草案）运行](https://github.com/junlin20011207/test/actions/runs/38138750953)；
[改进草案六状态运行](https://github.com/junlin20011207/test/actions/runs/38138914035)。

## 四、实验性修复契约与文件系统验证

`benchmarks/repairlab.py` 在临时目录中：
- 生成两种历史漏洞特定的受限草案及统一差异；
- 比对原与修改后 `on` 触发条件、工作流权限、Job 列表，不允许此三项静默变化；
- 再运行 ProofCut 的完整复核，要求目标特定路径从 1 降到 0；
- 将草案 YAML、diff、结构检查等保留在 GitHub Actions Artifacts，**不写入第三方仓库、不合并、不自动部署**。

`benchmarks/filesystem_contract.py` 额外执行无害 ZIP 文件系统实验，使用明确的“可信模块标识字节”和“不同的非执行标识字节”来测试：
- 在工作区根目录解压时，先前已有的可信文件字节被覆盖；
- 在隔离的临时目录解压时，可信文件字节保持不变；
- 两种方式均能按各自布局读出相同的业务 JSON 数据。

这是纯 Python ZIP 解压实验，**不是 GitHub download-artifact 全部运行语义或真实利用验证**；尚未测试软链接、ZIP 路径穿越、运行凭证或端到端业务行为。

历史修复、九组反事实切断和修复草案 CI：
[实际复验](https://github.com/junlin20011207/test/actions/runs/38138683451)。

## 五、方案选择与科研不确定性

**建议保留 BoundaryGraph 的事件/工件来源模块，把 ProofCut 发展成“具有可验证前提的跨工作流修复证据评估器”，而不是继续定位成 CodeQL 的替代漏洞扫描器。**

试验中的可能差异是：具名的事件—工件—敏感汇点见证、明确的代码修复契约、静态反事实切断与第二扫描器独立复核，而非声称发现了新漏洞。GitHub Agentic Autofix 已提供自动修复和重扫能力，因此这部分差异仍需独立比较，不能认为具有技术首创性。

当前至少还缺：
- 规模更大、独立人工复核的真实正负样本与留出数据集；
- 完整的 Shell / JavaScript AST、复杂 GitHub 条件与权限/可达性建模；
- 与 CodeQL + Agentic Autofix 在**修复正确性、保留业务功能、审查成本和耗时**上的可量化对照；
- 真正验证工件上传/下载运行条件与 GitHub 凭证权限，及补丁落地运行；
- 对模型外风险的“未知”而非误写“安全”机制。

**因此不能根据当前两项旧漏洞和 164 项自编测试，推算真实世界检出率、实际可利用率、创新性排名或竞赛获奖结果。**

## 六、复现入口

研究分支：`research/proofcut-semantic-witness-20261011`；PR：[独立研究 #5](https://github.com/junlin20011207/test/pull/5)。

```bash
python -m pip install -r requirements.txt
python -m pytest -q
python proofcut.py . --json
python benchmarks/replay_advisory.py
python benchmarks/replay_metadata.py
python benchmarks/counterfactuals.py
python benchmarks/repairlab.py
python benchmarks/filesystem_contract.py
python benchmarks/scan_public.py
```

CodeQL 官方扫描由 `.github/workflows/codeql-compare.yml` 在真实 GitHub Actions 上执行，不需要第三方仓库写权限。

参考：
- <https://codeql.github.com/codeql-query-help/actions/actions-artifact-poisoning-critical/>
- <https://github.blog/changelog/2026-08-19-codeql-2-26-3-improves-github-actions-queries-and-javascript-modeling/>
- <https://github.blog/changelog/2026-07-10-agentic-autofix-for-code-scanning-alerts-in-public-preview/>
- <https://securitylab.github.com/advisories/GHSL-2026-204_spiffe_spire_repository/>
- <https://securitylab.github.com/advisories/GHSL-2026-225_actions_attest/>
