# Controlled Differential Study: BoundaryGraph vs zizmor vs Poutine

Study date: 2026-10-11. This is an illustrative synthetic control study, **not** a real-world detection rate.

## Provenance and reproducibility

- Original three-tool run: https://github.com/junlin20011207/test/actions/runs/38133888059
- Code and tests CI: https://github.com/junlin20011207/test/actions/runs/38133987471
- Latest baseline CI: https://github.com/junlin20011207/test/actions/runs/38133987446
- Generator: benchmarks/generate_cases.py; source: .github/workflows/baselines.yml
- zizmor v1.30.1 (offline, JSON-v1).
- Poutine Docker: ghcr.io/boostsecurityio/poutine:latest, pulled digest sha256:722a8e0999b583c1540fe2974e691032b2d9d21b9256a17965132b6bfd0081b0 in the original run. The latest tag may change.
- All fixture code is inert; no untrusted artifact script is executed as part of the comparison.

## Observed four-case matrix

| Synthetic fixture | BoundaryGraph cross-workflow path findings | zizmor audit identifiers | Poutine rule identifiers |
| --- | ---: | --- | --- |
| risk: PR upstream, remote run-id artifact, downstream write | 1 | dangerous-triggers, unpinned-uses | known_vulnerability_in_build_component |
| guarded: exact upstream push-origin guard | 0 | dangerous-triggers, unpinned-uses | known_vulnerability_in_build_component |
| same_run: no explicit upstream run-id binding | 0 | dangerous-triggers, unpinned-uses | known_vulnerability_in_build_component |
| read_only: read-only downstream without external secret references | 0 | dangerous-triggers, unpinned-uses | known_vulnerability_in_build_component |

These identifiers test **different hypotheses**. A workflow-run trigger audit and an action dependency audit are not evidence of the specific cross-run privileged artifact influence path defined by BoundaryGraph. Conversely, no BoundaryGraph path does **not** mean the workflow is safe in all respects. The other tools' findings should not be labeled false positives based on this table.

This is only four author-created fixtures, not independently sampled and not blind-labeled. It is inappropriate to calculate or claim statistically meaningful superiority, true precision, recall, exploitability, or reduced real-world false-positive rates from this table.

## Further adversarial controls

An additional parametrized fixture suite in tests/test_adversarial.py checks shell quoting, comments, command chaining, directory traversal, safe versus ambiguous event guards, privilege choices, absent scan roots and lookalike action identifiers. Fixture YAML files are written only into temporary test directories, not registered as executable repository workflows.

The analyzer still cannot interpret arbitrary shell evaluation, complex expression semantics, symlinks, artifact contents, reusable workflow internals or complete secret propagation. In uncertain circumstances a high-level potential path or explicit unknown is more defensible than a statement of confirmed exploitability.

## Independent evaluation plan

1. Collect real public repositories at pinned commits with preset selection rules.
2. Blind-label whether each concrete upstream-downstream pair satisfies a common four-part question: untrusted event, true cross-run artifact origin, reachable downstream job or step, privileged resource.
3. Resolve rater disagreements before scoring, and separately report unknown cases.
4. Run all tools at pinned versions and map alert categories to the same comparison question before computing any precision or recall.
5. Publish full denominators, uncertainty intervals, false positive and false negative examples, and reproduction commands.

Sources: GitHub secure-use reference https://docs.github.com/en/actions/reference/security/secure-use ; workflow_run events https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows ; zizmor https://docs.zizmor.sh/audits/ ; Poutine https://github.com/boostsecurityio/poutine .
