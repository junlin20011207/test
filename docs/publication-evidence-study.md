# Producer Artifact Publication Evidence Study — 2026-10-11

## Research defect and correction

Earlier test fixtures used a low-trust upstream workflow which **only echoed text** and did not declare any `upload-artifact` step. The downstream referenced `github.event.workflow_run.id`, but this alone could not establish that an artifact was ever published. Prior 4-case comparisons and unit tests therefore tested a *partial* provenance edge. They are superseded by the fixture correction in this iteration.

The new analyzer explicitly inspects the producer workflow's job/step upload declarations, the `name` input (including the documented default `artifact`), and the downstream selection (`name` or `pattern`). This establishes, at most, a **declared static publisher connection**, never a successful upload or a security vulnerability.

## Evidence levels

| Classification | Meaning | Placement in JSON |
| --- | --- | --- |
| `declared` | Known upstream upload action has a static matching name and no modeled job/step guard | `findings` |
| `conditional` | Matching declared upload exists but is conditionally guarded | `unverified`, reason in `unknowns` |
| `unresolved` | No observed publisher; mismatched/static-unknown names; unsupported uploader/CLI selector | `unverified`, reason in `unknowns` |

These levels describe *source evidence*, not exploitability or a claim that a high severity advisory has been independently established. Both `findings` and `unverified` remain candidate influence paths. No matching upload declaration is **not** a proof that uploading cannot occur through an unmodeled action, API, or reusable job.

Unconditional `uses: actions/upload-artifact@` also does not prove an artifact exists: its input path may produce zero matches (the GitHub default can warn instead of fail), upstream jobs may fail or never run, and artifact retention can expire. GitHub documents the default name `artifact` and those missing-file behaviors.

## Updated self-contained testing

- The producer fixture in `tests/test_boundarygraph.py` and `tests/test_adversarial.py` now declares a benign upload action.
- `benchmarks/generate_cases.py` likewise includes a producer upload with an explicit static artifact name. It produces YAML **outside** the actual GitHub workflows directory.
- `tests/test_publication.py` tests absent publishers, name matching and mismatches, defaults, glob patterns, conditional upload, dynamic names, unmodeled actions, and CLI named selectors.
- GitHub Actions: [107 passing tests](https://github.com/junlin20011207/test/actions/runs/38136746521), commit `9d87a8f4dbfafe8b4c64b79986e0ace8be7bc1cc`.

The original zizmor/Poutine synthetic matrix is historical and should be re-read using the corrected fixture generator. Raw audit counts are semantically different between scanners; no cross-tool false-positive claims are justified.

## Frozen public-repository corpus (9 repositories, 108 pinned YAML files)

On the same Git-blob-verified inputs used in [the public corpus study](public-corpus-study.md), the **previous** 8 unlabelled candidate chains have the following source-evidence split:

| Public project | Previously reported candidates | Static matching upstream upload without modeled conditional guard | Matching but conditional upstream upload |
| --- | ---: | ---: | ---: |
| cloudflare/kumo | 2 | 2 | 0 |
| microsoft/fluentui | 5 | 0 | 5 |
| spiffe/spire | 1 | 1 | 0 |
| Other six repositories | 0 | 0 | 0 |
| **Total** | **8** | **3** | **5** |

An earlier, narrower count of 8 is **not** eight confirmed security defects. The 5 Fluent UI cases still have matching publisher declarations but are kept `unverified` until upload conditions have a sound reachability model.

There are only **six** workflows with `workflow_run` triggers across 108 files; all 62 general-stratum workflows lack that trigger and therefore do not provide relevant negative-control coverage.

Read-only scan source: `benchmarks/scan_public.py` and `benchmarks/public_manifest.json`. GitHub Actions saves a compressed per-repository JSON artifact; no downloaded workflow is executed.

## Prioritized future checks

1. Guard-expression evaluation and event-conditioned matching: determine whether each conditional upstream upload is reachable for the untrusted producer event. Represent unknown conditions as unknown, never quietly treat them as protected.
2. Collect developer-reviewed, independent labels for each producer–consumer pair and account for unknowns and negative cases explicitly. Only then calculate precision or recall.
3. Link file-level data dependencies from downloaded content to downstream permissions or APIs and model validation/sanitization (e.g. fork PR metadata checks) to reduce false claims of exploitability.
4. Record supported and unsupported artifact actions, CLI options, reusable workflows and cross-repository sources in machine-readable result fields.

## Reproduction

Run these in the connected repository on the research branch:

```bash
python -m pip install -r requirements.txt
python -m pytest -q
python benchmarks/generate_cases.py
python boundarygraph.py benchmarks/cases/risk --json
python benchmarks/scan_public.py
```

The last command downloads only pinned public YAML through HTTPS, checks Git blob SHA-1 and byte count, then runs local static analysis; it does not execute workflows. Some sandboxes cannot access GitHub DNS, so the independent GitHub Actions run is the authoritative remote evidence rather than a claimed local clone.

Primary docs: https://github.com/actions/upload-artifact (artifact names, missing file behavior); https://docs.github.com/en/actions/how-tos/manage-workflow-runs/download-workflow-artifacts (CLI options).
