# 第八阶段：ProofCut ContractLab 的远端引用原子性与可证明修复层级

**日期：** 2026-10-11

**研究范围：** 独立草稿分支 `research/ref-cas-contract-20261011`；仅使用我方 GitHub 仓库中的 GitHub-hosted Actions 和临时本地 bare Git 仓库。所有候选补丁仅在临时副本中生成；**没有更新任何实际远端业务分支，没有运行不可信脚本，也没有合并主分支**。

## 摘要

上一阶段针对已公开的 `actions/attest` 历史漏洞，ProofCut 可以给出 16/16 项来源、授权、数据协议与因果顺序修复契约。但最后一种检查——“在检查 `git rev-parse HEAD` 与来源 SHA 一致后，进行普通 `git push`”——并不能证明**实际 Push 时，远端 Git 引用仍保持校验时的版本**。

本阶段发现并真实验证了一个较为狭义但实用的剩余边界：若另一名**具有引用改写权限**的写入者在检查与 Push 之间把远端分支从来源提交 A 回退到 A 的祖先 Z，那么当前消费者产生的提交 C（C 从 A 派生）对 Z 仍是快进，普通 Push 可能成功，从而重新引入已被另一写入者有意撤回的版本。而典型的远端前移/分叉情形已会被普通 Git 的非快进限制拒绝，**不能把所有竞态都错误描述为可被普通 Push 利用**。

研究依据：
- Git 官方对普通 Push 快进检查与显式 `--force-with-lease=<refname>:<expect>` 的语义：<https://git-scm.com/docs/git-push>
- GitHub Security Lab 2026-09-16 公开的 MongoDB JS 提交版本 TOCTOU 历史案例（**不同缺陷与不同利用场景，仅供说明绑定授权与不可变版本的重要性，非本研究发现的新漏洞**）：<https://securitylab.github.com/advisories/GHSL-2026-191_mongodb-js_kerberos_repository/>
- CodeQL 官方已有 `Untrusted Checkout TOCTOU` 与 `Artifact Poisoning` 等查询：<https://codeql.github.com/codeql-query-help/actions/>

## 第一轮：8 项真实 Git 引用状态试验

脚本 `benchmarks/ref_cas_oracle.py` 每次在独立临时目录建立全新 bare Git 仓库，创建根提交 Z、上游已观察提交 A、下游无害构建提交 C。第二写入者可不改变引用、使引用向前更新、强制回退至 Z，或更新至与 C 分叉的另一个提交。随后测量消费者两种方式是否成功更新相同目标：

1. `git push origin <candidate>:<ref>` ——原有普通写入策略。
2. 首先检查 `git merge-base --is-ancestor <A> <C>`，然后使用 `git push --force-with-lease=<ref>:<A> origin <candidate>:<ref>`。显式旧 SHA 要求在远端进行有条件引用更新；祖先检查用于避免 CAS 机制被滥用为无约束强制写入。

| 远端状态 | 普通 Push | 显式期望旧 SHA 的 Lease Push |
| --- | --- | --- |
| 仍为 A | 接受，并更新引用 | 接受，并更新引用 |
| 远端已向前移动到另一提交 B | 拒绝、无更新 | 拒绝、无更新 |
| 远端由 A 被其它有权写入者回退为其祖先 Z | **接受并改变引用** | **拒绝、无更新** |
| 远端转向与 C 分叉的 D | 拒绝、无更新 | 拒绝、无更新 |

**8/8 项预注册检查符合实际 Git 返回码与前后引用 SHA**；每项包含 `remote_was_still_expected_source`、`push_accepted`、`remote_changed_by_consumer` 和候选祖先检查结果。原始实验与机读 JSON：
<https://github.com/junlin20011207/test/actions/runs/38148670585>

结论的限制：Z 状态需要另一写入者有权改写历史，默认受保护的远端分支不一定存在这个风险；实验对象是 Git 本身在隔离 bare 仓库中的引用语义，不是实际 GitHub 分支保护漏洞。

## 第二轮：修复接收器的形式化声明分层

前 16 项静态验收不能升级成“已证明远端引用原子一致性”。新建 `benchmarks/ref_update_contract.py`，用明确定义的安全前提对目标历史流程进行有限检查：

- 消费者分支引用确实来自可信 `github.event.workflow_run.head_branch` 上下文；
- `EXPECTED_SHA` 来源于 `github.event.workflow_run.head_sha`，未来自工件自身；
- 带 `EXPECTED_SHA` 的 `git merge-base --is-ancestor` 在真正 Push 之前；
- Git Push 的目标分支与条件化 Lease 使用同一分支且期望 SHA 相同；
- Shell 失败不能被已知的 `|| true`、`set +e`、Job/Step `continue-on-error` 等吞掉；
- 对未知 Shell、权限和写入结构采用拒绝/未验证，而非输出证明。

默认 `check_dist_contract(...)` **保持原有 16 项声明**，并以 `ref_update_assurance.tier=ref_update_atomicity_unverified` 说明不能推导严格远端 CAS。

新选项 `--require-ref-cas` 才增加第 17 项义务，在同一历史流程下：

| 修复草案 | 16 项原契约 | 17 项含原子目标严格模式 |
| --- | --- | --- |
| 原先普通 Push 草案 | 16/16 通过 | **不通过**（缺失显式 Lease） |
| 临时生成的 CAS 候选 | 16 项继续成立 | **17/17 通过** |

除正例外，增加 11 项针对来源 SHA、分支绑定、执行顺序、失效掩盖、Shell 类型和额外 Push 的单项负例。完整回归 **314 项通过**，新严格层级还有额外 2 项正反对照。

[GitHub 全量自动化测试](https://github.com/junlin20011207/test/actions/runs/38149029324)；
[SHA 固定历史样本修复、16/16 与 17/17 的并行验收](https://github.com/junlin20011207/test/actions/runs/38149195730)。

## 第三轮：真实修复候选生成与独立扫描

`benchmarks/ref_cas_candidate.py` 从固定 Git commit 与 Git Blob SHA 校验的公开历史原文件，先执行上一阶段 `patch_metadata` 生成**未部署的普通修复草案**，再升级为历史流程专用、显式旧 SHA 约束的可比较候选。

新版必须同时通过 17/17 项具体模板契约，旧版仍被保留作为 16 项对照。机器证据：`baseline-results/ref-cas-candidate/comparison.json` 和 `consumer-candidate.yml`。

可选 `--codeql` 将本候选再交由 SHA-256 校验的官方 CodeQL 2.27.2 `actions-security-extended.qls` 查询集在独立临时工作区中扫描，并保留原始 SARIF：`.github/workflows/codeql-compare.yml`。

**关键限界：** `--force-with-lease` 的实现可以被某些 GitHub 分支保护规则视为强制推送并拒绝。即使在本地实验中正确、CodeQL 无告警，也不足以证明候选可部署至原项目。严格模式是一个**明确限定条件的研究候选**，不是可以不经审核自动写入任何仓库的生产补丁。

## 创新性和竞争力评估

现阶段有实证支撑的差异化方向是：**将修复验收从“静态路径被切断”细化为具有证据层级的来源、业务、因果和远端版本一致性契约**，把未证实的性质标成 `UNKNOWN` / `UNVERIFIED`，并通过真实 Git 和 GitHub Runner 行为反证具体误差。其价值在于避免对用户误称“扫描与 16 个条件全通过，因此写入一定安全”。

但并没有证据证明 Git 的 Lease 机制由本项目首创，或证明 CodeQL/Agentic Autofix 在其承诺覆盖的安全漏洞检测上存在弱点。最优定位应当是 ProofCut ContractLab 的**审计型验收层**，而非新漏洞扫描器或泛化形式化证明器。

仍需解决的研究不足：

1. GitHub 分支保护、规则集、组织权限、机器人写入许可对 Lease Push 的具体影响尚未完成真实授权部署实验；
2. 本轮 8 个引用状态及 11 个变体仍是研究者自建样本，不能代表真实业务总体准确率；
3. 仅对固定流程脚本与有限 GitHub 表达式语法建模，尚缺通用多 Job、跨仓库、复杂 Shell 的正确性证明；
4. 双方在相同实际修复业务上的成功率、修复耗时与误拒绝率仍无独立盲测；
5. GitHub Actions 运行时实际文件/令牌权限和业务内容完整性尚未构成端到端形式化证据。

## 复现

```bash
python -m pip install -r requirements.txt
python -m pytest -q
python benchmarks/ref_cas_oracle.py
python -m benchmarks.ref_cas_candidate
# 在一份准备好的临时历史修复工作区中使用：
python -m benchmarks.repair_invariants /path/to/repaired-workspace --require-ref-cas
```

云端真实实验入口：
- `.github/workflows/ref-cas-oracle.yml`：隔离 bare Git 的 8 个版本演练；
- `.github/workflows/sinkproof-regression.yml`：两种修复候选及 17 项严格校验；
- `.github/workflows/codeql-compare.yml`：受固定版本约束的独立 CodeQL 分析。

[独立研究 PR #10](https://github.com/junlin20011207/test/pull/10)，不合并 `main`。
