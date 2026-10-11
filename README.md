# BoundaryGraph — Cross-Workflow Trust Boundary Analyzer

中国研究生网络安全创新大赛创意作品赛方向的**防御性研究原型**。检查 GitHub Actions 工作流之间是否存在“低信任事件 → 上游工作流 → 跨运行 Artifact → 下游高权限 Job”的**潜在路径**，并给出可复核的见证链和修复建议。

## 快速复现

```bash
python -m pip install -r requirements.txt
python -m pytest -q
python boundarygraph.py . --strict
python boundarygraph.py . --json
```

`.github/workflows/ci.yml` 在提交时执行真实 GitHub Actions 测试。另设 `provenance-producer.yml` 和 `provenance-consumer.yml`；前者生成预定义的无害文本，后者只在可信 push 事件完成后，以只读权限下载对应 run-id 的 Artifact 并验证固定文本，不执行文件内容或接触部署密钥。

**安全性边界：** 只执行静态分析；未覆盖的 GitHub 条件表达式、其他工件来源、复用工作流、权限环境保护等可能导致遗漏。告警是风险路径，不是已证明的漏洞。输出没有告警并不代表证明安全。

## 研究阶段及评分

本项目明确对照成熟的 zizmor、Poutine 和 GitHub 原生 Artifact Attestation 能力。初步实现没有证实比强基线有独占优势。**不能把 22/22 本地单元测试和 96/96 合成测试解释为真实场景的 100% 检出率，或等同正式评委打分。**

本仓库是代码与在线安全测试环境；完整沙箱原型与 96 组交叉实验单独打包留存。见 [研究文档](docs/research.md)。

- 赛事官方公告：https://cpipc.acge.org.cn/cw/contestNews/detail/2c90800c8093eef401809d33b36f0652/2c9080199ed8b78d019ed96ceea21560?page=1
- GitHub 安全使用说明：https://docs.github.com/en/actions/reference/security/secure-use
- zizmor：https://docs.zizmor.sh/audits/
- Poutine：https://github.com/boostsecurityio/poutine
