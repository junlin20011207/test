# Pinned External Workflow Study — 2026-10-11

> **更新说明（2026-10-11）：** 本文保留的是首次外部扫描的 8 条宽口径候选记录。补充生产者上传证据后，同一批样本重新归类为 **3 条匹配的静态上传声明路径 + 5 条条件上传、来源尚未完全证实的候选**。请以 [更新版研究报告](publication-evidence-study.md) 和相应 CI 证据为准。以下历史的“8 条”不是确认的漏洞数量。

## Scope and design

This is a **read-only reconnaissance study**, not vulnerability verification or a measurement of precision/recall. Source of truth: `benchmarks/public_manifest.json` records immutable commit IDs, exact workflow paths, expected byte size, and Git blob SHA-1; `benchmarks/scan_public.py` downloads only those files, checks Git blob hashes, and parses their YAML as data. No downloaded workflow or artifact is executed.

Evidence: [successful pinned public-corpus run](https://github.com/junlin20011207/test/actions/runs/38134817226) and [full results artifact](https://github.com/junlin20011207/test/actions/runs/38134817226). The results artifact is retained by GitHub Actions for 14 days. CI at this time used a synthetic- and regression-test suite; see the Checks workflow for code-version-specific test counts.

## Selection bias and coverage

The original five repositories were chosen *before* the outcome was examined. Crucially, **none of their 62 workflow files uses a `workflow_run` trigger**. Thus their 0 findings cannot be cited as evidence of low false-positive rates on applicable cases.

Four additional repositories were *purposively selected* because publicly visible examples discussed `workflow_run`; they are not a random sample of repositories. One of these four (`nf-core/actions`) currently has no `workflow_run` file in the pinned workflow directory.

| Project | Selection group | Workflow files verified | Files using `workflow_run` | Unlabelled artifact-path candidates |
| --- | --- | ---: | ---: | ---: |
| cli/cli | general | 14 | 0 | 0 |
| pypa/pip | general | 6 | 0 | 0 |
| pytest-dev/pytest | general | 6 | 0 | 0 |
| actions/runner | general | 13 | 0 | 0 |
| astral-sh/ruff | general | 23 | 0 | 0 |
| cloudflare/kumo | targeted | 13 | 2 | 2 |
| nf-core/actions | targeted | 5 | 0 | 0 |
| microsoft/fluentui | targeted | 17 | 3 | 5 |
| spiffe/spire | targeted | 11 | 1 | 1 |
| **Total** | | **108** | **6** | **8** |

All 108/108 files were retrieved and matched their pinned Git blob hashes; reported parser unknowns=0 and download errors=0 in this run. A valid parse or absent finding is **not** proof of safe runtime behavior.

## Unlabelled witness chains from the real-repository scan

Every path below is severity `high` **under the analyzer's heuristic**. None indicates a demonstrated arbitrary-code execution path or proven exploit.

| Public repository | Producer workflow | Consumer workflow and job | Download step index | Artifact name |
| --- | --- | --- | ---: | --- |
| cloudflare/kumo | docs-pr.yml | docs-preview-post-build.yml / deploy | 3 | docs-preview-dist |
| cloudflare/kumo | pullrequest.yml | pullrequest-report.yml / bundle-size | 2 | bundle-size-report |
| microsoft/fluentui | bundle-size.yml | bundle-size-comment.yml / comment | 1 | monosize-report |
| microsoft/fluentui | pr-vrt.yml | pr-vrt-comment.yml / run_vr_diff | 1 | vrscreenshot |
| microsoft/fluentui | pr-vrt.yml | pr-vrt-comment.yml / run_vr_diff | 4 | pr-number |
| microsoft/fluentui | pr-website-deploy.yml | pr-website-deploy-comment.yml / deploy | 1 | pr-website-artifacts |
| microsoft/fluentui | pr-website-deploy.yml | pr-website-deploy-comment.yml / deploy | 2 | pr-number |
| spiffe/spire | assign_reviewer_review_capture.yaml | assign_reviewer_review_apply.yaml / apply | 1 | assign-reviewer-review |

Repeated producer–consumer/job combinations correspond to **different explicit downloads**. The analysis output now records `download_step`, `artifact_action`, and `artifact_name` to keep these witnesses auditable instead of returning indistinguishable duplicates.

## Qualitative constraints from the public code

- The pinned Cloudflare Kumo docs workflow comments explicitly state its defense includes checking out trusted configuration from `main` and not executing fork-controlled code with secrets; a potential artifact influence path does **not** contradict these mitigation claims.
- The pinned SPIFFE SPIRE reviewer workflow describes re-fetching pull request information and validating untrusted artifact fields before write-scoped API calls. The mere transfer of untrusted bytes to a privileged job does **not** prove malicious use of the artifact.
- There is no complete taint analysis of JavaScript, shell scripts, `actions/github-script`, workflow calls, or API-specific validation logic. These cases must remain **unlabelled** unless independently reviewed.
- Results are tied to the exact manifest revisions, not their latest branch versions.

## Experiment conclusions

1. Static cross-file provenance analysis produces concrete, inspectable file/job/download-step candidate chains on live public project sources.
2. The separate, deliberately biased positive-case cohort demonstrates a narrower capability than overall repository security auditing.
3. Detection of a possible transfer does **not** prove that untrusted content controls a privileged operation. The tested method currently cannot estimate exploitation likelihood, true precision/recall, or effectiveness relative to zizmor/Poutine.
4. The next scientifically necessary step is an independently labeled set of actual cross-run transfers, including negative controls that contain validation, to assess whether adding downstream *data-dependency and sanitizer evidence* improves decisions.

References: [GitHub secure-use](https://docs.github.com/en/actions/reference/security/securely-using-pull_request_target), [workflow events](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows), [three-scanner synthetic comparison](differential-study.md).
