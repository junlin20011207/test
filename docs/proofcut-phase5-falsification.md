# BoundaryGraph ProofCut ContractLab：第五阶段的对抗性反证与受限逻辑证明

研究时间：2026-10-11。研究分支：`research/contract-falsification-20261011`。研究对象为我们自己的安全契约验证原型，并未发现或利用新漏洞。本阶段**没有运行不可信代码、没有对第三方仓库发起攻击、没有将实验修复草案部署至生产系统**。

## 1. 原型技术不足的根本原因

前一阶段声称 13/13 跨工作流修复契约成立；但代码审查发现其中部分条件使用 `in` 字符串包含或只定位第一个上传/检出步骤。这些表达式对最终执行语义的保证不足。

例如 `if: 可信身份条件 || true` 仍包含关键词，却完全不能限制身份。某个步骤中仅在注释里出现了 `index.js` 和 `GITHUB_OUTPUT`，也不能证明业务文件真的接受存在性检查。仅出现变量 `EXPECTED_SHA` 不能说明它参与了拒绝错误版本的条件分支。

**由此将研究问题明确改成：** 经过 CodeQL 重扫且静态告警清零的修复草案，是否可能仍违反跨运行的数据流契约与关键授权约束？能否为有限、明确定义的语义子集构造拒绝绕过的机器可复核证据？

这不等同于发明 Artifact Poisoning 检测，也不声称已建立完整形式化验证器。

## 2. 第一轮反证：8 个以前全部错误接受的扰动

`tests/test_contract_falsification.py` 独立构造以下不安全或失效修改，原检验器全部误判为通过：

| 反证 | 被错误认为已满足的契约 |
| --- | --- |
| 生产者身份限制加 `|| true` | 生产者可信身份约束 |
| 消费者仓库/身份/分支限制加 `|| true` | 下游授权约束 |
| Artifact 上传条件加 `|| true` | 仅业务变化才发布 |
| 文件存在性判断只出现在注释中 | 业务数据读入检查 |
| SHA 只显示、不比较 | 提交版本一致性 |
| Git Push 尾部加 `|| true` | 写入失败检测 |
| 插入第二个采用不可信分支的 Checkout | 可追溯可信检出目标 |
| 插入同名但不同目录的上传步骤 | 具名 Artifact 来源唯一性 |

真正 GitHub CI 的失败证据：<https://github.com/junlin20011207/test/actions/runs/38141507654>，**8 failed / 178 passed**。在该阶段失败是刻意设计的研究实验，并不应删除以掩盖模型缺陷。

第一版修复 `benchmarks/guard_semantics.py` 引入不执行用户表达式的受限解析，`benchmarks/contract_semantics.py` 对关键步骤进行限定格式检查和来源重复性检查。GitHub CI 全量 **186 passed**，第一个反证组全拒绝。

## 3. 第二轮反证：有限输入验证依然不充分

即便明确解析 `&&`、`||` 并对代表性主体/仓库/分支进行反例代入，仍可能出现**新 OR 分支仅放行之前没有枚举的主体、分支或仓库**。

`tests/test_guard_unseen_bypass.py` 增加 5 个此前未出现过的常量授权替代分支，第一版新检验器再次全部接受，证明**有限代入样本无法证明全域安全**。

GitHub CI 证据：<https://github.com/junlin20011207/test/actions/runs/38141808094>，**5 failed / 186 passed**。

### 方法变更：每条可成立 OR 路径的必要谓词证据

在支持的表达式语法中（变量、单引号字符串、布尔量、`==`/`!=`、`&&`/`||`、括号、`!`、`startsWith`），为每个表达式递归计算**保守的必有原子谓词集合**：

- 对 `A && B`：收集两个必须事实的并集。
- 对 `A || B`：保留两个可能为真的分支共有的必须事实，即交集；逻辑上的 `false` 分支不可达。
- 对普通字符串或未支持的高级函数：不凭关键词推导其安全约束。
- 对 `github.actor == 'dependabot[bot]'`、同仓库约束、`startsWith(head_branch,'dependabot/')` 等明确定义的原子比较建立直接的证明义务。

因此，`可信条件 || 特殊分支放行` 的后者不含必需事实，原有身份条件不再能被误认为遍历所有路径均成立。实际生产者授权还必须在受支持的逻辑路径中证明事件条件、完成状态、仓库、Actor、分支前缀各个条件不可绕开。

**保证边界：** 这是在受支持语法与指定原子模式上的**充分条件检查**，不是 GitHub Actions 完整的表达式解释器，不等同通用 SMT 定理证明。语义相同但用未支持函数/另一种等价写法表达的真实安全条件可能被保守拒绝（假阴性），必须归类为未证实，而非不安全漏洞。不能把自建的 32 状态输入检查称为穷举现实所有 GitHub 上下文。

### 第三轮测试对照

`tests/test_guard_truth_table.py` 对 5 个来源关键变量的两种预设取值执行 **32 个不同上下文**，并附带等价括号和条件变形、所有 OR 分支、未支持语法及上传限制测试。

本轮完整自动化测试从上一阶段 178 项增至 **248 项通过**；13 个反证的错误接受从 **13/13** 降至 **0/13**，并保留了正样本和修复历史回归。这是**有意构造的反证集上的结果**，不是未知真实工作流总体的误报率/漏报率。

CI：<https://github.com/junlin20011207/test/actions/runs/38142027818>。

## 4. 机器可复核的“受限修复证明凭证”

`benchmarks/assurance_certificate.py` 在两项已公布历史漏洞的隔离修复结果上额外执行：

1. 检查真实历史 actions/attest 修复草案的 **13 项生产者—工件—消费者必要义务**；
2. 输出生产者 Actor 条件、上传条件、消费者授权三个表达式的保守必有谓词集合；
3. 在同一固定版本代码上运行两个阶段共 **13 个反证扰动**；
4. 将通过/失败和必要谓词证据保存为 `baseline-results/assurance/certificate.json`，随 GitHub Actions 历史修复实验输出。因语义不支持而无法证明时应拒绝通过。

证据：<https://github.com/junlin20011207/test/actions/runs/38142157888>，日志明确显示 **13/13 契约义务、13/13 个反证被拒绝**。本文件不是加密签名的独立形式化安全证书，不提供在未建模攻击面上的运行时安全保证。

## 5. 原有有效成果保留并复验

- ProofCut 两条具体敏感汇点：工作区覆盖后执行可信模块、Artifact 分支元数据进入 Git 写入目标。
- SHA 固定的公开历史 GHSL-2026-204 / GHSL-2026-225 修复前后样本。
- CodeQL 2.27.2 官方 `actions-security-extended.qls` 六状态实验：历史漏洞版/官方修复/非部署实验草案，之前对照为 SPIRE 1/0/0、actions/attest 5/0/0 条告警。
- GitHub 官方 v4 Artifact 同次运行与**跨运行**真实下载测试；受控 JSON 仍可使用，数据不覆盖工作区；临时 bare Git 分支更新不涉及真实远程权限。

第五阶段修改集中在验证器、测试和研究报告，没有自动合并 PR，也未触及主分支。

## 6. 最新已有成果对创新性评估的影响

- GitHub **CodeQL 2.27.2** 在 2026-10-07 已发布，GitHub Actions 检测仍持续更新，含 Artifact Poisoning 专用查询。现有实验不能证明 ProofCut 检测能力超过 CodeQL：<https://codeql.github.com/docs/codeql-overview/codeql-changelog/codeql-cli-2.27.2/>。
- GitHub 2026-07 公测的 Agentic Autofix 已包含自动修复和重跑静态分析。若参赛主张仍只是修补+扫描，技术原创性较弱：<https://github.blog/changelog/2026-07-10-agentic-autofix-for-code-scanning-alerts-in-public-preview/>。
- **Granite (2025)** 已从运行时进行细粒度 GitHub Actions 权限约束，表明限制权限与运行时保证也是成熟研究方向；本项目没有同类代理或其威胁模型性能数据：<https://arxiv.org/abs/2512.11602>。
- GitHub 2026 年新引入的 Agentic Workflows 安全架构亦强调分层权限、隔离和规范符合性，不宜笼统声称“提出了安全契约”这一概念：<https://github.github.com/gh-aw/introduction/architecture/>。

**建议的参赛研究主张是更狭义、可反证的：**“针对 CI/CD 跨运行工件链的受限逻辑授权证明 + 受控业务保持性合约 + 已知反例驱动的修复验收”。重点贡献不是更多规则，而是**发现和阻断补丁看似通过静态扫描、但其来源/授权/业务约束实际被悄悄破坏的情形**。

## 7. 尚未解决的技术关键点

1. **逻辑语法尚不完整：** 暂未支持 GitHub 大量字符串转换、对象/数组、所有函数、数值/空值、复杂运算符和动态表达式；未支持语法采用保守拒绝，不是完整判决。
2. **结构充分条件并非语义等价：** 只承认已知强原子事实及 OR 分支交集，可能拒绝合法但表达方式不同的安全条件。需要完善成可审计的 DSL、规范解析器和更大规模等价测试。
3. **运行时权限/业务边界：** 现有真实 Github 实验只有自有无害工件和只读 Cross-Run；未验证目标第三方系统的真实 Dependabot 写权限、分支保护、业务保留或攻击利用行为。
4. **需要独立真实评估集：** 13 个反证由研究团队提出，32 种上下文来自有限模型，无法代表真实世界风险分布；缺乏不参与规则设计的独立盲测和专家二次标注。
5. **成熟工具直接比较不足：** CodeQL 已识别历史漏洞，GitHub Agentic Autofix 已有修复重扫流程；需要同样真实案例下比较“无效补丁拒绝率、真实功能保持率、运行开销、人工复核时间”，才能支撑高水平奖项创新性论证。

## 8. 复现命令

```bash
python -m pip install -r requirements.txt
python -m pytest -q
python benchmarks/repairlab.py
python benchmarks/assurance_certificate.py
python proofcut.py . --json
```

GitHub Actions 自动执行：
- `.github/workflows/sinkproof-regression.yml`：历史漏洞回放、9 种静态反事实、修复草案及机读证书
- `.github/workflows/codeql-compare.yml`：CodeQL 同样本扫描（真实二进制）
- `.github/workflows/artifact-contract.yml` 与 `artifact-cross-run.yml`：自有无害工件真实上传下载与读取
- `.github/workflows/public-corpus.yml`：固定公开样本的只读扫描

独立研究 PR：<https://github.com/junlin20011207/test/pull/7>。
