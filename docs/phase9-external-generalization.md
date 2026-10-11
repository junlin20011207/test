# 第九阶段研究：跨项目外部验证与真实 GitHub 分支写入条件

研究时间：2026-10-11；研究仓库 `junlin20011207/test`。本阶段为防御性研究：没有运行第三方 YAML、下载的脚本或不可信 Artifact，也没有修改主分支或其他组织的业务仓库。

## 1. 两项研究缺口与技术背景

上一阶段通过 320 项作者设计的测试和 8 项本地 Git 实验，但无法据此估计未见项目的精确率/召回率；本地裸仓库的 ref 更新也不能代替真实 GitHub 写入许可或分支保护行为。

同时，GitHub 官方存在三类不能混为一谈的条件：

- GitHub REST Git Ref 更新 `force=false` 只要求快进，并不提供外部调用者的 `expectedHeadOid` 提交事务语义；
- GitHub GraphQL `createCommitOnBranch` 支持指定 `expectedHeadOid`，它将文件变更和目标分支头比较关联在同一提交调用中；
- GitHub Repository Contents API 对更新单个文件要求提供预期的**文件 Blob SHA**；这不是对整个分支头的 CAS 保证。

参考官方文档：<https://docs.github.com/en/rest/git/refs>、<https://docs.github.com/en/graphql/reference/commits>、<https://docs.github.com/en/rest/repos/contents>。实际分支保护、Branch Rulesets、审查和 Actions 令牌授权仍可能阻止任何写入。绝不能只因为支持 `expected_sha` 就认定适用于生产受保护分支。

## 2. 真实 Github 自有仓库部署兼容实验

**所有远端写操作仅在本仓库隔离的 `research/deploy-lab-20261011`、`research/ref-cas-remote-plain-20261011`、`research/ref-cas-remote-strict-20261011`、`research/ref-cas-remote-positive-20261011` 测试分支进行。** 测试内容仅为 `lab/` 目录的无害标记，无执行代码或第三方数据。

### 实验 A：GitHub Contents API 文件级乐观并发

- 对 `lab/expected-head-test.txt` 初始文件 Blob `47db679c4b3e7e31b3500e86c609c2e1e97ee855` 提交版本 B，实际新提交 `a29ac51963543c5d7d4d84a379620bc25db8600a`；
- 用同一个过时 Blob SHA 再尝试提交不同版本 C：GitHub API **409 Conflict**，明确提示文件与所需 SHA 不一致；
- 读取最终内容仍是版本 B，Blob `24814607fa536e6d9dfb4ffa0d4bcd8abce64158`。

这是**单文件更新冲突保护**，不能证明多文件一次性事务或目标 ref 的原子性。

### 实验 B：真实远端分支的快进 / 版本条件

创建无害 Git 对象，固定三个真实 commit：
- 原有基点 `E = 660213216cf3d36dd3dbc6e87079d0609eefbf6b`
- 新的上游提交 `A = ae29213a1e50e946b4a57a70f7a5d0257d4f5407`
- 无害下游候选 `C = b0fdf26829aaddd1feb3a61cc7f8b4b3c8425dab`，其父提交正是 A。

在两条新建实验分支上，从 E 快进到 A，随后使用带期望 SHA 的有权隔离实验操作回退到 E：

| 独立测试分支 | 回退后的状态 | 实际写入调用 | 观察到的结果 |
|---|---|---|---|
| `ref-cas-remote-plain-20261011` | E | 普通 `force=false` 快进更新到 C，不提供过期期望 SHA | **成功**；目标引用变为 C |
| `ref-cas-remote-strict-20261011` | E | 更新到 C，但提交过期的 `expected_sha=A` | **返回 GraphQL 通用错误**；重新读取目标引用仍为 E |
| `ref-cas-remote-positive-20261011` | A | 更新到 C，`expected_sha=A` 且 `force=true` | **成功**；目标引用变为 C |

同时测试了 `force=false` 加过时 `expected_sha=A`，同样返回 GraphQL 通用错误且引用仍保持在 E。

**重要限定：** 错误不是明确的 `409`，因此只能确认为请求失败并且引用未被修改，不能仅凭该错误证明 GitHub API 的精确拒绝机制、请求的原子线性化时刻或权限策略。正例成功，排除了“这种条件更新一律不可用”的假设；仅在实验分支验证，绝不推定受保护分支可用。仓库连接读取当前 `rulesets` 返回空数组，但 `branches/main/protection` 返回 **403 Resource not accessible by integration**，所以对主分支保护的总体判断为 **UNKNOWN**。

## 3. 独立公开项目全量抽样：负结果必须保留

在查看工作流内容和执行扫描之前，固定选择了五个**此前未用于当前原型调参**的公开开发与供应链工具项目：

| 项目 | SHA 固定 YAML |
|---|---:|
| `sigstore/cosign` | 17 |
| `anchore/syft` | 4 |
| `google/osv-scanner` | 19 |
| `astral-sh/uv` | 46 |
| `opentofu/opentofu` | 11 |
| **合计** | **97** |

所有文件依据各仓库固定提交和 Git Blob SHA、文件大小读取并通过校验：见 `benchmarks/heldout_manifest.json`、`benchmarks/heldout_scan.py`。官方 Github-hosted Actions [第一轮实际独立扫描](https://github.com/junlin20011207/test/actions/runs/38151353423) 报告 **97/97 完整、5/5 仓库完整，但 `workflow_run` 消费者为 0、跨运行明确 Artifact 传递为 0**。

这个结果**既不是零漏洞，也不是泛化分析成功**：对本项目当前专项问题而言，整个未见样本没有有效评价机会。这恰好暴露了研究的适用范围狭窄，并提示若要证明安全分析有效，应同时报告**适用覆盖率**和**在实际适用场景中的效果**，不能以所有 YAML 的数量掩盖零有效样本。

新增 `benchmarks/cross_project_contracts.py` 完全不绑定历史 `rebuild` / `commit` 等 Job 名称，只记录显式 upstream run-id、生产者声明、下载路径、写权限证据、不能证明的条件，输出 `UNKNOWN` 而不是漏洞判断。通用验收器仍不能自动修复任意项目；这是从硬编码模板向证据型适用性筛查演进的第一步。

## 4. 非独立、定向含跨运行事件的范围检验

为了避免 97 份资料没有有效跨运行案例，`benchmarks/generalization_cohort.py` 另将**以前公开语料中作者有意挑选过**的 `cloudflare/kumo`、`microsoft/fluentui`、`spiffe/spire` 做为单独的定向样本，重新按固定 Git Blob SHA 下载并运行相同通用证据分类器；全部产物保存至 `baseline-results/targeted-scope/`。

该部分只能研究动态/静态传输来源的**结构覆盖能力**，绝不是独立盲测，不能和原来五个随机外观的开发工具仓库混在一起计算误报率。若实际 CI 失败或报告无工件，则必须保留该局限，不能臆造正例。

## 5. 当前技术结论与竞赛价值

最具潜力的方向应精简为 **ProofCut ContractLab：具有适用性拒绝机制与证据等级的跨工作流修复验收**。核心能力是：将未经支持的流程判定为 `NOT_APPLICABLE` / `UNKNOWN`，有针对性地给出来源、业务、权限、因果时序、版本条件层级的证明，且主动声明不能部署时的策略阻断因素。

目前可以证明的是：单文件 GitHub API 写冲突拒绝、隔离分支上的条件更新成败行为、单独固定 SHA 公开项目的 97/97 完整扫描、通用证据清点的基础功能。

**仍未解决：**

1. 真正的**受保护分支**的认证写入实验仍没有完成；权限不足无法读取 `main` 保护设置，不能擅自修改或取消组织保护；
2. 97 份独立 YAML 无相关 `workflow_run` 样本，安全真实世界泛化效果未得到任何估计；
3. 定向公开样本已有研究选择偏差，且没有第三方专家真实安全/功能标注；
4. REST/GitHub CLI 的凭证、权限、策略与 GraphQL `createCommitOnBranch(expectedHeadOid)` 的原子事务均未在有权限的生产规则集下完成验证；
5. CodeQL、GitHub Agentic Autofix 和本项目的相同任务同权限对比仍缺乏独立基准和人工审核成本数据。

**不得宣称已解决上述所有问题。** 本阶段补足真实远端实验，并更准确地量化跨项目研究的缺口，而没有凭空将零有效样本当成获奖级泛化能力。

## 复现入口

```bash
python -m pytest -q
python -m benchmarks.heldout_scan
python -m benchmarks.generalization_cohort
```

CI：`.github/workflows/heldout-corpus.yml`；Github 远端引用/文件证据可通过公开实验分支的 Commit/Ref URL 查看，严禁在业务主分支复做回退试验。

独立草稿 PR：<https://github.com/junlin20011207/test/pull/11>，`main` 未修改。
