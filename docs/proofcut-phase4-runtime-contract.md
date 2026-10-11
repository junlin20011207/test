# ProofCut 第四阶段：跨运行工件修复的真实行为契约实验

研究日期：2026-10-11。全部外部漏洞案例均为已公开历史安全公告；本轮真实云端测试**只使用自身 GitHub 仓库的无害工件和只读权限**。实验不执行下载的 JavaScript，不使用任何真实可写生产仓库权限，未对第三方项目运行漏洞利用。

## 一、根本问题与研究假设

前一阶段仅能得出：两项修复草案让 ProofCut 对应链路变为零，同时官方 CodeQL 2.27.2 的 `actions-security-extended.qls` 扫描不再产生告警。**这仍不能推出补丁保持正常业务功能。**

假设 H1：单目录上传 `dist/` 后，官方 Artifact v4 下载会去掉最外层来源目录；已有草案 `runner.temp/incoming/dist/index.js` 的位置应与实际行为一致。

假设 H2：将工件移到独立临时目录，能防止工作区同名文件被覆盖，同时不破坏原本需要读取的业务 JSON。

假设 H3：在另一条已完成工作流的独立运行中，使用 GitHub 只读令牌与指定 `run-id` 能按名称取回工件并保持文件布局。

假设 H4：元数据修复草案所声明的上传、下载、目标目录、业务就绪检查、同仓库/Dependabot 来源、分支写入目标与权限应组成跨工作流机器可校验的必要条件。单独破坏任一必要条件应导致契约检查失败。

假设 H5：在无 GitHub 权限的临时本地 Git 仓库中，修复后的 `dist` 文件能够经过提交、更新指定依赖分支并保持文件哈希，不修改无关分支。

这五项验证的是**受控实验中的有限行为契约**，不是运行时 exploitability、生产适配性或独创性证明。

## 二、真正连接的工具和实验

### Artifact v4 实际 Runner 实验

在自身仓库的 `.github/workflows/artifact-contract.yml` 中创建四个 Job：

- `produce`：构造无执行内容的 `payload/review.json`、`payload/trusted-marker.txt`、`dist/index.js`，用官方 `actions/upload-artifact@v4` 上传两个具名工件。
- `root-layout`：下载到工作区根目录；原有同名文件被替换，同时 JSON 可读取。
- `isolated-layout`：下载到 `runner.temp/proofcut-artifact`；工作区标记保持原字节，业务 JSON 由 Python 和 Node.js 分别可读。
- `dist-layout`：上传 `dist/` 后下载至 `runner.temp/incoming/dist`，真正获得 `incoming/dist/index.js`，**不存在多余的** `incoming/dist/dist/index.js`；另外在隔离的本地 bare Git 仓库提交工件文件并推送至只存在于本地的 `dependabot/benign-source-fixture` 分支。

首次全成功的运行：<https://github.com/junlin20011207/test/actions/runs/38140205737>。增加真实 Node.js 与本地 Git 合同测试后的成功运行：<https://github.com/junlin20011207/test/actions/runs/38140693573>。

### 不同运行之间的真实工件传输

`.github/workflows/artifact-cross-run.yml` 使用 `permissions: {contents: read, actions: read}`，只从自身仓库选取**已完成成功的独立 Artifact fixture 运行**，通过官方 `actions/download-artifact@v4` 显式传入 `run-id` 和 `github-token`，然后校验来源 Run ID 不等于当前运行、文件路径与内容匹配。

来源运行 `38140205737` 的实测成功消费见 <https://github.com/junlin20011207/test/actions/runs/38140303951>。未找到历史成功源运行时的结果不能视为“通过”：后续已改为显式失败，防止静默跳过证据要求。**该实验虽然是跨运行，但未触发 `workflow_run` 高权限 Job；其能力范围仍严格有限。**

## 三、机器可检查的双工作流修复契约

`benchmarks/repair_invariants.py` 现在包含 **13 项**独立可解释的义务：

1. 命名上传 `rebuilt-dist` 且源目录仅为 `dist/`。
2. 上传仍受 `steps.diff.outputs.changed` 条件约束。
3. 生产者仍为只读 `pull_request`/受控 Dependabot 来源。
4. 生产者 Shell 中不直接插入不可信 PR 分支名表达式。
5. 具名下载、来源 `workflow_run.id`、令牌身份配对一致。
6. 目标为隔离的 `runner.temp/incoming/dist`。
7. 消费者权限保持在 Job 的显式写作用域，Workflow 为只读。
8. 业务就绪检查读取实际 `incoming/dist/index.js` 并设置两种输出状态。
9. 业务同步步骤移动的是同一下载目录。
10. Checkout 目标使用可信事件分支名。
11. Git Push 使用经环境变量传入的分支名，而非直接将表达式拼进 Shell。
12. 旧版本分支 SHA 的并发检查从可信事件提交 SHA 获取。
13. 消费者明确包含同仓库、预定 actor 及依赖分支来源限制。

实验脚本 `tests/test_repair_invariants.py` 对完整契约进行一项正例验证，并对每条规则故意破坏一个条件，构成 **13 个不同的负例**；旧 164 项自动化测试加上 14 项契约控制，最新实测 **178/178 通过**，见 <https://github.com/junlin20011207/test/actions/runs/38140693525>。

`benchmarks/repairlab.py` 现在在生成历史 actions/attest 修复草案时强制要求此契约通过，并把每条检查的布尔结论写入生成的 `summary.json`。即使 CodeQL 和 ProofCut 未报警，契约缺失也会使本研究实验失败。这是与单纯“补丁扫描清零”不同的评价维度。

注意：此版本契约高度针对已披露的 actions/attest `dist/` 流程，尚不是任意 CI/CD 业务的通用语言或形式化证明。

## 四、与最新现有工作的创新性比较

- GitHub CodeQL 官方规则 `actions/artifact-poisoning/critical` 已能检测 Artifact Poisoning，不能将历史检测作为新增覆盖：<https://codeql.github.com/codeql-query-help/actions/actions-artifact-poisoning-critical/>
- 2026-07-10 GitHub Agentic Autofix 已能生成补丁并重跑 CodeQL，不能将“自主修补、重扫描”直接作为技术首创：<https://github.blog/changelog/2026-07-10-agentic-autofix-for-code-scanning-alerts-in-public-preview/>
- GitHub upload-artifact v4 的不可变工件及路径/多文件差异见官方迁移文档：<https://github.com/actions/upload-artifact/blob/main/docs/MIGRATION.md>。

当前最有希望形成差异化、可独立研究的问题是：**针对跨工作流的生产者—工件—消费者关联自动构造并验证“安全性 + 业务行为保持性”双契约，保留修复来源与证据，明确不满足时拒绝自动接受补丁。** 这仍是研究假设，尚未证明比 CodeQL + Agentic Autofix 更快、更准确或更可靠。

## 五、反证、失败及结果的诚实解释

- 首轮新增契约回归，正样本因我构造测试 fixture 的 `runner.temp` 路径缺少 `/incoming/dist` 导致 CI **1 失败、177 通过**；这不是项目核心函数已验证失败的证据。修复夹具后，完整自动化测试 **178 通过**。保留了失败和修复的 Actions 记录。
- 原先仅 Python ZIP 解压的实验不能证明官方 Artifact Action 运行效果；本轮补上了真实 GitHub Runner 行为实测，弥补该局限。
- 本轮 Git 提交测试只推送到临时**本地 bare 仓库**，未触及 GitHub 分支权限或组织安全策略，不能冒称端到端生产运行。
- 历史两项漏洞的静态修复草案仍未在第三方仓库部署；CodeQL 2.27.2 `security-extended` 清零不是完整安全认证。
- 108 份公开 YAML 的研究样本中只有六份工作流有 `workflow_run`，不能据其零告警声称真实世界低误报。

## 六、当前最优可执行研究路线

**保留 BoundaryGraph → ProofCut 的来源链与汇点证明，进一步研究“ProofCut ContractLab：安全证明与跨运行业务契约双重验证”。**

近期最需要补足的实质验证：独立且未参与方法设计的真实缺陷/修复样本、GitHub 的真实可写权限边界在**完全授权的隔离演练仓库**中是否正确执行、跨多种 Artifact 上传下载模式的业务契约抽取与独立评审，以及与 CodeQL/Agentic Autofix 同任务下的修复有效性、运行成本与人力审查耗时对照。

不能声称已经发明了全新的 Artifact Poisoning 检测方法，也不能声称已有高水平获奖竞争力的客观证据。

## 七、复现实验入口

- `python -m pytest -q`
- `python benchmarks/repairlab.py`（联网只读下载两份公开历史源文件并生成补丁，不部署）
- `python benchmarks/repair_invariants.py /path/to/repaired/local/worktree`
- GitHub Actions：`artifact-contract.yml`、`artifact-cross-run.yml`（真实官方动作，仅使用自身仓库的无害数据）。
- CodeQL：`codeql-compare.yml`（SHA-256 校验后的官方 2.27.2 Bundle，固定版本、同样本 SARIF）。
- 代码及 PR：<https://github.com/junlin20011207/test/pull/6>。
