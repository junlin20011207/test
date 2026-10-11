# BoundaryGraph ProofCut：第二阶段创新性与实证研究

研究日期：2026-10-11。研究状态：防御性实验原型；历史漏洞回归验证成功，尚未证明优于成熟安全产品，更未发现新漏洞。

## 1. 现有方向的根本不足

此前 BoundaryGraph 主要判断：“低信任事件 → 上游运行 → 跨运行 Artifact → 下游高权限”。问题有四层：

1. **创新性同质化：** CodeQL 已提供 Artifact Poisoning 的路径分析规则，zizmor、Poutine 也有安全审计能力，单纯检测 `workflow_run` 或工件下载不构成独占研究贡献。
2. **缺少真正的安全效果语义：** 下载到高权限 Job 不等于代码执行，也不等于分支篡改。现有高风险报告多数停在传递边界，不能证明数据到达敏感操作。
3. **实验设计缺陷：** 最早合成样本上游未声明 Artifact 上传；已更正。原 9 项目/108 YAML 公开样本中只有 6 个工作流使用 `workflow_run`，因此通用组零告警无法计算误报率。
4. **验证不充分：** 尚缺独立人工标注、与 CodeQL 对齐威胁模型的盲测基线、复杂表达式和跨脚本跨工作流的可达性证明。

## 2. 最新研究核对与方案选择

- GitHub CodeQL Artifact Poisoning：<https://codeql.github.com/codeql-query-help/actions/actions-artifact-poisoning-critical/>
- GitHub CodeQL Actions security（2025 GA、2026 更新）：<https://github.blog/security/application-security/how-to-secure-your-github-actions-workflows-with-codeql/>
- zizmor 规则与更新：<https://docs.zizmor.sh/audits/>、<https://docs.zizmor.sh/release-notes/>
- GitHub Security Lab 的 2026-09-16 SPIRE 公告：<https://securitylab.github.com/advisories/GHSL-2026-204_spiffe_spire_repository/>
- 同期 actions/attest 公告：<https://securitylab.github.com/advisories/GHSL-2026-225_actions_attest/>
- 2026 年 agentic workflow injection 研究（TaintAWI）：<https://arxiv.org/abs/2605.07135>

优先研究定位不是重新实现通用漏洞扫描器，而是 **“跨工作流证据链 + 敏感汇点约束 + 可反事实验证的最小切断条件”**。现有 BoundaryGraph 保留生产者事件、命名工件和权限等有效数据；新增两种窄域证明路径，由 ProofCut 统一输出。

### 路线 A：工作区覆盖 → 可信可执行文件加载

`sinkproof.py` 对已有工件链增加以下证据义务：上游 PR/PR review 工件可受分叉影响、存在静态匹配上传声明、下游显式具备高权限、下载覆盖工作区根目录、之前检出可信代码、之后在 `github-script` 或受支持的 Shell 命令中加载工作区相对文件。

检出属于“潜在覆盖—加载路径”，**并不证明恶意归档已存在或实际代码执行**。将提取位置隔离到 `runner.temp`、移除相对执行依赖等能够切断此建模路径。

### 路线 B：工件元数据 → 具有写权限的 Git 分支目标

`metadataproof.py` 追踪具体数据链：Artifact 中的 `dist-meta/head-ref` → 工作流输出 `steps.check.outputs.head-ref` → checkout.ref → git push 目标，且要求 `contents: write`。

它不是一般的 Shell 注入检测，聚焦 **授权目标由低信任元数据决定** 的信任边界。将控制平面的分支身份绑定到可信 `workflow_run` 事件并进行来源限制才是安全修复思路；单纯收紧字符串正则并不能证明授权正确。

## 3. 真实历史修复前后的数据

所有测试对象都来自公开、**已协调披露**的安全公告。GitHub Actions 通过 SHA 固定的 Git Blob 对每份 YAML 进行内容校验，静态解析，不执行产物或漏洞利用代码。

| 机制 | 修复前公开提交 | 修复后公开提交 | 原 BoundaryGraph Critical | 新规则修复前 → 修复后 |
| --- | --- | --- | ---: | --- |
| SPIFFE SPIRE 工作区覆盖与模块加载 | ef8527ec91013c6c1b4741e0f6ac0786576e620e | 6d10e93a4eef9b270cba5dc6082f1c3c5bd99879 | 0 → 0 | 1 → 0 |
| actions/attest 工件分支元数据跨授权边界 | 60c80190bb1a4fb35e5724ede753db5656412b68 | 7d8b1cacecb65f487779b3b98fd5296a018d1a1b | 0 → 0 | 1 → 0 |

**严格解释：** 在两个已知案例的两个历史版本中，新规则与公开安全公告的修复状态一致；仅 4 个状态观察值，不是总体准确率/召回率的估计，不能证明 CodeQL 未检出，也不能证明本方法具有首创性。

真实回归脚本：

- `benchmarks/replay_advisory.py`
- `benchmarks/replay_metadata.py`
- SHA/字节数清单：`benchmarks/advisory_pairs.json` 与 `benchmarks/metadata_pairs.json`

云端运行及逐步结果：<https://github.com/junlin20011207/test/actions/runs/38137377527>

## 4. 反事实实验：哪些修复真正切断静态路径？

`benchmarks/counterfactuals.py` 使用已公布的两份旧版工作流，在只读临时文件副本中进行 9 组细粒度源级改动，再运行对应证据检查器。

| 来源 | 改动 | 预期与观测路径数量 |
| --- | --- | --- |
| SPIRE | 原漏洞版 | 1 → 1 |
| SPIRE | 仅修改步骤名称（安慰剂） | 1 → 1 |
| SPIRE | 将工件下载隔离到临时目录 | 0 → 0 |
| SPIRE | 不再加载工作区相对模块 | 0 → 0 |
| actions/attest | 原漏洞版 | 1 → 1 |
| actions/attest | 仅修改步骤名称（安慰剂） | 1 → 1 |
| actions/attest | Checkout 不再使用工件派生分支名 | 0 → 0 |
| actions/attest | Git Push 不再使用工件派生分支名 | 0 → 0 |
| actions/attest | 只将分支名正则长度限定更严格 | 1 → 1 |

9 组结果全部满足预定义的静态预期。**切断分析器中的路径不等于修复已功能正确且安全**：尤其分支授权还须有同仓库来源、受信身份等校验，脚本导入/路径改动可能需要同步修改业务读取逻辑。

证据：<https://github.com/junlin20011207/test/actions/runs/38137470668>。

## 5. 固定的真实项目负对照及选择偏差

现有公共样本仍是九个固定提交的公开仓库、108/108 个工作流 YAML，只有六份含 `workflow_run`，其中通用样本层 62 个文件均不适用。旧 BoundaryGraph 的 3 个有静态上传声明的路径 + 5 个条件上传候选，**新窄域 SinkProof / MetadataProof 在该批样本中均给出 0 条汇点级证明**。

该观察仅说明：新模型没有把“仅下载工件”提升为“覆盖执行”或“工件控制分支”。因为该样本未人工标注且缺乏已确认的新漏洞，0 条不能说明零误报，更不说明不会漏报。

可复现脚本：`benchmarks/scan_public.py`；固定 SHA 清单：`benchmarks/public_manifest.json`。临时 GitHub Raw 读取失败可能发生，程序会短暂重试、严格校验 Git Blob 与字节数，下载不完整即以失败状态退出，不会偷偷计为完成。

## 6. 竞赛推荐定位与技术壁垒

**推荐继续保留现有方向，升级为 BoundaryGraph ProofCut：「面向 CI/CD 跨权限工件链的可解释攻击汇点证明与反事实修复验证」。**

相较旧版本，新增可审查的多条件见证 `producer → named artifact → privileged job → import/git target`，以公布的历史漏洞—修复对作为独立于作者合成标签的纵向验证，并用局部改动验证建议能否切断具体路径。

潜在竞争力来自“安全效果归因、最小修改假设与复核流程”，而不是声称发明了 Artifact Poisoning 或静态污点分析。有关是否真正优于 CodeQL/zizmor/Poutine，**目前无有效量化比较，暂不能作为获奖依据**。

## 7. 仍未解决、禁止夸大的问题

1. **源码覆盖不足：** 动态 Shell、完整 JavaScript AST、`github-script` 间接调用、复用工作流、动态工件名称与路径别名、GitHub Actions 权限继承尚未完全建模。
2. **路径/安全语义问题：** 上传声明 ≠ 上传成功；允许分叉来源还受审批限制；存档内容与真实文件覆盖未验证；目标分支还受组织权限和分支保护策略约束。
3. **部分威胁假设保守：** `pull_request` 和 `pull_request_review` 是可能受分叉修改的工作流来源；事件文本（如 `issue_comment`）不能直接等同“攻击者能修改整个生产者工作流”，因此新规则仅针对前两类建模。
4. **数据规模不足：** 只有两项已公布漏洞的修复前/后对，没有足够独立真实案例、人工双盲标注或置信区间，不能得出高召回/高准确率。
5. **竞品尚未同任务盲测：** CodeQL 已包含 Artifact Poisoning 检测，不能声称本项目具有现有工具没有的检测覆盖。需要同修复对、同威胁定义、等价告警映射与审查。
6. **反事实验证局限：** 目前是纯静态替换+重新分析，并没有端到端验证业务功能保持。自动修复只能给候选补丁，不能宣称“自动安全修复已证明正确”。

## 8. 复现

在研究分支 `research/sink-proof-differential-20261011`：

```bash
python -m pip install -r requirements.txt
python -m pytest -q
python proofcut.py . --json
python benchmarks/replay_advisory.py
python benchmarks/replay_metadata.py
python benchmarks/counterfactuals.py
python benchmarks/scan_public.py
```

可通过 <https://github.com/junlin20011207/test/pull/4> 审查独立研究分支。所有云端工作流以只读权限运行，输出归档用于核查；任何涉及第三方仓库的历史工作流仅作为数据，不执行。
