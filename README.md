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

## 第七阶段：因果顺序与失败传播的合约反证（2026-10-11）

- [**第七阶段完整研究报告**](docs/proofcut-phase7-causal-contract.md) ｜ [**独立草稿 PR #9**](https://github.com/junlin20011207/test/pull/9)。
- 从原先的“出现了 SHA 校验与 Git Push 语句”升级为“数据下载/业务就绪/源码检出/提交 SHA 校验/产物应用/推送存在明确的必要先后关系”，并将**独立的合法步骤重排**与真实的依赖违约区分开。
- 先用 [原始红色 CI](https://github.com/junlin20011207/test/actions/runs/38146223404) 证明旧检查器对 12 种变更有 10 种错误接受；之后发现过严的全顺序也会造成 [2 种误拒绝](https://github.com/junlin20011207/test/actions/runs/38146547078)，于是改为带动态输出依赖的偏序图。
- 新增 Job/Step 级容错与 `working-directory` 合同，相关 [五种此前错误接受的场景](https://github.com/junlin20011207/test/actions/runs/38146751558) 也已被覆盖；完整回归测试 [301 项通过](https://github.com/junlin20011207/test/actions/runs/38146815859)，历史修复草案 [16/16 项必要义务](https://github.com/junlin20011207/test/actions/runs/38146815962) 满足。
- [**隔离本地 Git 真实运行时双场景**](https://github.com/junlin20011207/test/actions/runs/38146425288) 确认：若目标分支已改变，先校验不会写入；先 Push 再检查会产生已经执行、无法被事后验证撤销的本地分支变更。无远程业务系统写入。
- 真实 GitHub Runner 容错步骤结果验证：`.github/workflows/step-status-oracle.yml`；同源 CodeQL 2.27.2 与十项业务/权限/时序合同扰动交叉验证：`.github/workflows/codeql-compare.yml`。

本阶段仅证明**特定跨运行 Artifact 修复模板**的必要因果合同，不是对任意 GitHub Actions 流程的完整形式化证明，也未发明 CodeQL 已有的漏洞检测能力。

## 第八阶段：在真实 Git 行为下验证修复的远端版本一致性（2026-10-11）

[**第八阶段中文研究报告**](docs/proofcut-phase8-ref-cas.md) ｜ [**研究草稿 PR #10**](https://github.com/junlin20011207/test/pull/10)

- [**真实 GitHub-hosted Runner 上的 8 项本地 Git 实验**](https://github.com/junlin20011207/test/actions/runs/38148670585)：常规 Push 只在“另一写入者将远端分支回退到已知祖先”这个有条件的场景中，额外允许旧构建重新推进引用；显式旧 SHA 的 Lease Push 则拒绝这一变化。其余远端前移/分叉场景两者均拒绝。
- [**固定历史漏洞修复 16 项/17 项双层级验证**](https://github.com/junlin20011207/test/actions/runs/38149518867)：前 16 项属于因果和业务契约；默认普通 Push 的远端原子性明确为 `UNVERIFIED`，而实验性候选要求来源 SHA、祖先检查和显式引用 CAS，严格模式 17/17 通过。
- [**320 项 Pytest 完整通过**](https://github.com/junlin20011207/test/actions/runs/38149518900)，其中额外 4 项 Shell 反证先真实失败，再修复为拒绝死分支、文本中的假命令和错误退出被取消的情形。
- [**官方 CodeQL 2.27.2 对增强候选的独立扫描**](https://github.com/junlin20011207/test/actions/runs/38149518916)：受 SHA-256 校验的发布包、真正的 Actions 源码数据库与 SARIF，`security-extended` 告警 **0**。

**严禁直接将增强候选自动部署**：显式 `--force-with-lease` 的强制写入语义可能受到 GitHub 分支保护限制，实验只在一次性本地 bare Git 仓库中验证，尚未证明第三方业务兼容性、泛化准确率或竞赛获奖级别的技术首创。

## 第九阶段：跨项目适用性与真实 GitHub 写入预检

[研究报告](docs/phase9-external-generalization.md) ｜ [独立草稿 PR #11](https://github.com/junlin20011207/test/pull/11)

固定 SHA 的五个独立公开项目共 **97/97 YAML** 完整扫描，但 **0 个 `workflow_run` 消费者**，因此无法据此验证跨工作流分析效果。另一个此前已有选择偏差的三个定向项目共 **41 份 YAML、6 个 `workflow_run`、8 条显式跨运行工件传递**，仅证明分析器的结构适用性，不给出安全精确率/召回率。

本阶段另通过自有隔离 GitHub 分支验证文件级旧 SHA 更新返回 **409 Conflict**、分支级普通快进更新与期望旧 SHA 更新的不同观察结果，并新增只读分支保护预检器。**不授权自动生产部署，不修改 `main` 或第三方业务。**

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
