"""Independent five-repository pinned held-out transfer-contract inventory.

Corpus selected before reading scan outcomes; all *.yml and *.yaml workflow
files at the five recorded immutable commits must pass Git blob hash and size
verification. No workflows, downloaded scripts or artifacts are executed.
"""
import json
from pathlib import Path
import tempfile
from benchmarks.scan_public import fetch
from benchmarks.cross_project_contracts import examine
from boundarygraph import analyze

ROOT=Path(__file__).resolve().parents[1]
MANIFEST=ROOT/"benchmarks/heldout_manifest.json"
OUT=ROOT/"baseline-results/heldout"
MAX_TOTAL_FILES=200


def run():
    manifest=json.loads(MANIFEST.read_text("utf8"))
    assert manifest["schema_version"]==1
    assert len(manifest["repositories"])==5
    expected=sum(len(x["files"]) for x in manifest["repositories"])
    assert expected<=MAX_TOTAL_FILES
    OUT.mkdir(parents=True,exist_ok=True)
    reports=[]
    for item in manifest["repositories"]:
        repo=item["name"]
        commit=item["commit"]
        verified=0
        errors=[]
        with tempfile.TemporaryDirectory(prefix="proofcut-independent-holdout-") as tmp:
            root=Path(tmp)
            for entry in item["files"]:
                try:
                    raw=fetch(repo,commit,entry)
                    target=root/entry["path"]
                    target.parent.mkdir(parents=True,exist_ok=True)
                    target.write_bytes(raw)
                    verified+=1
                except (OSError,UnicodeError,ValueError) as exc:
                    errors.append({"path":entry["path"],
                                   "reason":type(exc).__name__,
                                   "message":str(exc)[:180]})
            independent=examine(root)
            baseline=analyze(root)
        row={
            "repo":repo,"commit":commit,"sample_group":"pre-registered-independent",
            "expected_files":len(item["files"]),"hash_verified_files":verified,
            "complete":not errors and verified==len(item["files"]),
            "fetch_errors":errors,
            "cross_project_inventory":independent["summary"],
            "analyzer_findings":len(baseline["findings"]),
            "analyzer_unverified":len(baseline["unverified"]),
            "static_unknown_count":len(baseline["unknowns"]),
            "labels":"none; cannot calculate precision, recall or vulnerability rate",
        }
        (OUT/(repo.replace("/","__")+".json")).write_text(
            json.dumps({"summary":row,"details":independent},indent=2)+"\n")
        reports.append(row)
        print(json.dumps(row,sort_keys=True))
    total={"repositories":len(reports),"expected_yaml":expected,
           "verified_yaml":sum(x["hash_verified_files"] for x in reports),
           "workflows_with_run_trigger":sum(
               x["cross_project_inventory"]["workflow_run_consumers"] for x in reports),
           "explicit_upstream_transfers":sum(
               x["cross_project_inventory"]["explicit_upstream_transfers"] for x in reports),
           "unverified_producer_identity":sum(
               x["cross_project_inventory"]["source_missing_or_ambiguous"] for x in reports),
           "static_candidates":sum(x["analyzer_findings"] for x in reports),
           "complete":all(x["complete"] for x in reports),
           "conclusion":"holdout static reconnaissance, not a labelled security benchmark",
           "selection_bias":"public GitHub developer/security tooling; all workflows at pinned commit"}
    (OUT/"summary.json").write_text(
        json.dumps({"overall":total,"repositories":reports},indent=2)+"\n")
    print("INDEPENDENT HOLDOUT:",json.dumps(total,sort_keys=True))
    if not total["complete"]:
        raise RuntimeError("incomplete hold-out coverage: no research claims")
    return 0


if __name__=="__main__":
    raise SystemExit(run())
