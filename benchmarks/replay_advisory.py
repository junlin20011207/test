"""Replay a *published* GitHub Security Lab vulnerability/fix pair read-only.

Downloads only YAML at pinned Git blobs and never executes workflow content.
The pair labels are sourced from public coordinated disclosure, not from our
scanner. This is a regression case study, not precision/recall on unseen data.
"""
import json
from pathlib import Path
import sys
import tempfile

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from benchmarks.scan_public import fetch
from boundarygraph import analyze
from sinkproof import sink_proofs

BASE=Path(__file__).parent
OUT=BASE.parent/"baseline-results"/"advisory"


def run_case(manifest,case):
    with tempfile.TemporaryDirectory(prefix="sinkproof-advisory-") as tmp:
        workspace=Path(tmp)
        for entry in case["files"]:
            raw=fetch(manifest["source"],case["commit"],entry)
            output=workspace/entry["path"]
            output.parent.mkdir(parents=True,exist_ok=True)
            output.write_bytes(raw)
        base=analyze(workspace)
        enhanced=sink_proofs(workspace)
    return {
        "label":case["label"],"revision":case["commit"],
        "expected_overlay_count":case["expected_overlay_count"],
        "files_verified":len(case["files"]),
        "baseline_declared":len(base["findings"]),
        "baseline_critical":sum(x["severity"]=="critical" for x in base["findings"]),
        "baseline_unknowns":base["unknowns"],
        "sinkproof_count":enhanced["count"],
        "witnesses":enhanced["proofs"],
        "gaps":enhanced["gaps"],
    }


def main():
    manifest=json.loads((BASE/"advisory_pairs.json").read_text("utf-8"))
    OUT.mkdir(parents=True,exist_ok=True)
    reports=[]
    for case in manifest["cases"]:
        observed=run_case(manifest,case)
        reports.append(observed)
        (OUT/(case["label"]+".json")).write_text(json.dumps(observed,indent=2)+"\n","utf8")
        print(f"{case['label']} @ {case['commit'][:12]}: "
              f"baseline_critical={observed['baseline_critical']} "
              f"sinkproof={observed['sinkproof_count']} "
              f"expected={observed['expected_overlay_count']} "
              f"files_verified={observed['files_verified']}")
    passed=all(x["sinkproof_count"]==x["expected_overlay_count"] and
               x["files_verified"]==2 for x in reports)
    summary={"study":"historical already-disclosed security-fix regression",
             "ground_truth":"GHSL-2026-204 public advisory",
             "reference":manifest["reference"],"passed":passed,
             "reports":reports,
             "limitations":"two versions of one vulnerability; no generalization claim"}
    (OUT/"summary.json").write_text(json.dumps(summary,indent=2)+"\n","utf8")
    return 0 if passed else 1


if __name__=="__main__":
    raise SystemExit(main())
