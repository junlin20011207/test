# BoundaryGraph — Cross-Workflow Trust Boundary Analyzer

中国研究生网络安全创新大赛创意作品赛方向的**防御性研究原型**。检查 GitHub Actions 工作流之间是否存在“低信任事件 → 上游工作流 → 跨运行 Artifact → 下游高权限 Job”的**潜在路径**，并给出可复核的见证链和修复建议。

## 第二阶段实验：BoundaryGraph ProofCut（研究分支）

在原跨工作流传递证据分析之上，新增两条**汇点级、证据受限**的路径检测：
1. `sinkproof.py`：上游可受分叉 PR 影响的已声明 Artifact → 具有权限的下游 Job → 覆盖可信检出工作区 → 随后加载本地模块。
2. `metadataproof.py`：工件元数据 `head-ref` → 工作流输出 → 具有写权限的 Checkout 和 Git Push 目标。

统一入口：`python proofcut.py . --json`；详细技术说明和数据见 [第二阶段报告](docs/proofcut-phase2.md)。

已针对 GitHub Security Lab **2026 年公开披露**的两项不同类型漏洞进行固定 SHA 的修复前/后静态复验，并执行 9 种源码级反事实变体。所有历史 YAML 仅被读取，不执行。**这不是首次发现漏洞，也不是证明优于 CodeQL。**

独立 GitHub 研究 PR：[ProofCut #4](https://github.com/junlin20011207/test/pull/4)。

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
