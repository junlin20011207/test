# BoundaryGraph — Cross-Workflow Trust Boundary Analyzer

中国研究生网络安全创新大赛创意作品赛方向的**防御性研究原型**。检查 GitHub Actions 工作流之间是否存在“低信任事件 → 上游工作流 → 跨运行 Artifact → 下游高权限 Job”的**潜在路径**，并给出可复核的见证链和修复建议。

## 第二阶段实验：BoundaryGraph ProofCut（研究分支）

在原跨工作流传递证据分析之上，新增两条**汇点级、证据受限**的路径检测：
1. `sinkproof.py`：上游可受分叉 PR 影响的已声明 Artifact → 具有权限的下游 Job → 覆盖可信检出工作区 → 随后加载本地模块。
2. `metadataproof.py`：工件元数据 `head-ref` → 工作流输出 → 具有写权限的 Checkout 和 Git Push 目标。

统一入口：`python proofcut.py . --json`；详细技术说明和数据见 [第二阶段报告](docs/proofcut-phase2.md)。

已针对 GitHub Security Lab **2026 年公开披露**的两项不同类型漏洞进行固定 SHA 的修复前/后静态复验，并执行 9 种源码级反事实变体。所有历史 YAML 仅被读取，不执行。**这不是首次发现漏洞，也不是证明优于 CodeQL。**

独立 GitHub 研究 PR：[ProofCut #4](https://github.com/junlin20011207/test/pull/4)。

## 第三阶段真实实验（2026-10-11）

- [**第三阶段完整研究报告**](docs/proofcut-phase3.md)：分析现有规则的证据漏洞、CodeQL 强基线竞争关系，以及跨工作流的修复契约和失败中间版本。
- [**官方 CodeQL 2.27.2 六状态对照**](https://github.com/junlin20011207/test/actions/runs/38139298116)：SPIRE 与 actions/attest 两项已披露安全公告，各包括漏洞旧版、官方修复版和实验性修复草案。两个最终草案均在该查询集下 0 告警，原始受影响版本分别有 1 和 5 条告警；**不代表比 CodeQL 更容易发现这些漏洞**。
- [**164 项自动化测试**](https://github.com/junlin20011207/test/actions/runs/38139298197)，包含 JS 注释/字符串、Shell 非执行文本、稀疏检出路径、工件元数据来源的对抗性控制。
- [**真实历史修复/反事实/修复草案/无害 ZIP 实验**](https://github.com/junlin20011207/test/actions/runs/38139298108)：受限草案生成、静态见证重检、限定结构保持性校验和独立文件系统隔离效果实验。**草案不自动部署，不证明运行时业务功能完全保持。**

竞赛创新性限制：GitHub CodeQL 已能识别测试中的漏洞，2026 年 GitHub Agentic Autofix 已公开支持自动补丁与 CodeQL 重扫。因此当前可验证的进展是**特定跨信任边界修复约束与证据可复核性**，并非新漏洞首发或证明检测/修复能力优于成熟工具。

## 第四阶段：真实跨运行工件契约验证（2026-10-11）

- [第四阶段中文研究报告](docs/proofcut-phase4-runtime-contract.md)：将研究焦点从“静态告警清零”推进到**跨工作流来源—消费者数据契约与受控业务保持性验证**。
- [真实 Artifact v4 端到端实验](https://github.com/junlin20011207/test/actions/runs/38140693573)：使用无害工件验证覆盖工作区、隔离路径、Python/Node.js JSON 读取、官方 `dist/` 解压布局和本地 Git 分支数据提交。
- [真实跨运行只读下载](https://github.com/junlin20011207/test/actions/runs/38140303951)：从另一条已完成 GitHub Run 读取具名工件，校验运行 ID、SHA/文件内容及目录。
- [178 项 Pytest 通过](https://github.com/junlin20011207/test/actions/runs/38140693525)：包含 13 项修复契约义务及单独破坏条件的负例。该结果仅适用于自建测试集。
- 历史 SPIRE 与 actions/attest 的修复草案由原 [CodeQL 2.27.2 复验](https://github.com/junlin20011207/test/actions/runs/38139298116) 支持，但尚未在第三方仓库部署；最新研究仍不宣称漏洞首发或 CodeQL 检测覆盖优势。

[第四阶段代码 PR #6](https://github.com/junlin20011207/test/pull/6)（独立草稿，未合并 `main`）。

## 第五阶段：先证伪，再接受修复（2026-10-11）

[**第五阶段完整研究报告**](docs/proofcut-phase5-falsification.md) ｜ [**独立研究 PR #7**](https://github.com/junlin20011207/test/pull/7)

前一阶段 **13/13** 合约通过仍存在安全错判。本轮两批由我们构造的对抗样本，先在原型上实际得到 **8/8、5/5 错误接受**（失败 CI 日志保留），随后加入受限逻辑解析、**每条 OR 分支必需授权谓词**和真实步骤检查，使这 **13 个已知错误接受样本全部被拒绝**。另增加 32 个授权上下文真值表，完整 Pytest 套件已达到 **248 项通过**。这些是自建样本指标，不是现实误报率。

新增 `benchmarks/assurance_certificate.py` 产生 **13 项跨工作流修复合约 + 13 个反证 + 3 类必要谓词证据**的 JSON 报告，由真实云端 GitHub Actions 归档。实际 GitHub Artifact v4 跨运行读取与受控业务文件验证保留。**仅支持明确的 GitHub 表达式语法子集，未建模情况不可冒称安全。**

## 第六阶段：真实 GitHub 表达式语义校准与跨工具契约差异（2026-10-11）

[**第六阶段完整中文实验报告**](docs/proofcut-phase6-platform-oracle.md) ｜ [**独立研究 PR #8**](https://github.com/junlin20011207/test/pull/8)

- 使用**真实 GitHub Actions 表达式引擎**校准受限条件解释器：大小写无关比较、字符串单引号转义、`&&`/`||` 操作数返回、布尔/字符串宽松等值比较和 `startsWith` 类型转换。**19/19** 项 GitHub 官方引擎直接对照一致；完整自动化测试 **274/274** 通过。
- [**官方 GitHub 表达式对照**](https://github.com/junlin20011207/test/actions/runs/38144186550)、[**操作数返回对照**](https://github.com/junlin20011207/test/actions/runs/38144037501)、[**测试记录**](https://github.com/junlin20011207/test/actions/runs/38144186462)。
- [**官方 CodeQL 2.27.2 同源对照**](https://github.com/junlin20011207/test/actions/runs/38144366160)：一份历史修复草案及六种单点违约修改逐例执行 `security-extended`；ContractLab 对六个修改 **6/6 拒绝**，CodeQL 对六个变体均为 **0 条**漏洞规则告警。这说明特定**业务/安全契约验收**与通用漏洞扫描具有互补性，不意味着 CodeQL 漏检了六个漏洞。
- 局限：例子全部来自同一项已披露历史项目，违约修改与表达式样本由研究者设计，不能证明未知真实项目的效果、完整平台语义兼容性、首创性或高水平获奖能力。

## 快速复现

```bash
python -m pip install -r requirements.txt
python -m pytest -q
python boundarygraph.py . --strict
python boundarygraph.py . --json
```

`.github/workflows/ci.yml` 在提交时执行真实 GitHub Actions 测试。另设 `provenance-producer.yml` 和 `provenance-consumer.yml`；前者生成预定义的无害文本，后者只在可信 push 事件完成后，以只读权限下载对应 run-id 的 Artifact 并验证固定文本，不执行文件内容或接触部署密钥。

**安全性边界：** 只执行静态分析；未覆盖的 GitHub 条件表达式、其他工件来源、复用工作流、权限环境保护等可能导致遗漏。告警是风险路径，不是已证明的漏洞。输出没有告警并不代表证明安全。


## 近期可复核结果（2026-10-11）

- [GitHub CI：59 项自动化测试通过](https://github.com/junlin20011207/test/actions/runs/38133987471)。包含 Shell 命令误报、步骤级可信条件、缺失扫描目标及 Action 名称伪装测试；属于测试样本内验证。
- [三工具独立对照 CI](https://github.com/junlin20011207/test/actions/runs/38133888059) 已运行 BoundaryGraph、zizmor 1.30.1 和 Poutine。四组自建合成工作流的原始告警类型不同，**不能依据告警数量断言优劣**。
- [对照实验的详细记录与局限](docs/differential-study.md)。当前还没有真实仓库人工标注数据集、同一评测语义下的可靠精确率/召回率。
- [公开工作流研究报告](docs/public-corpus-study.md)：9 个项目的 **108/108** 份固定提交 YAML 完成完整性校验，其中仅 **6** 份使用 `workflow_run`。原始 **8** 条候选经生产者上传证据复核，拆分为 **3 条有匹配静态上传声明的潜在路径 + 5 条条件上传、来源仍需核实的候选**；全部不是已确认漏洞。通用组 62 份工作流无目标触发器，零告警不代表低误报率。
- [最新外部扫描 CI](https://github.com/junlin20011207/test/actions/runs/38134817226)：保存了每条候选路径对应的下载步骤、工件名称与来源。

- [新：生产者 Artifact 来源证据报告](docs/publication-evidence-study.md)：修复原合成实验未声明上游上传的问题，新增上传名称、条件上传、CLI 选择器的对照验证；[GitHub 107 项回归测试通过](https://github.com/junlin20011207/test/actions/runs/38136746521)。

## 研究阶段及评分

本项目明确对照成熟的 zizmor、Poutine 和 GitHub 原生 Artifact Attestation 能力。初步实现没有证实比强基线有独占优势。**不能把 22/22 本地单元测试和 96/96 合成测试解释为真实场景的 100% 检出率，或等同正式评委打分。**

本仓库是代码与在线安全测试环境；完整沙箱原型与 96 组交叉实验单独打包留存。见 [研究文档](docs/research.md)。

- 赛事官方公告：https://cpipc.acge.org.cn/cw/contestNews/detail/2c90800c8093eef401809d33b36f0652/2c9080199ed8b78d019ed96ceea21560?page=1
- GitHub 安全使用说明：https://docs.github.com/en/actions/reference/security/secure-use
- zizmor：https://docs.zizmor.sh/audits/
- Poutine：https://github.com/boostsecurityio/poutine
