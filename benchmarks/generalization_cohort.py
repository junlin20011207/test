"""Purposefully enriched scope cohort, separated from the preselected hold-out.

These 3 repos came from an EARLIER author-guided corpus selection; they are
NOT a blind hold-out. They exercise transfer variants and unknown provenance.
"""
import json
from pathlib import Path
import tempfile
from benchmarks.scan_public import fetch
from benchmarks.cross_project_contracts import examine

BASE=Path(__file__).resolve().parents[1]
ALLOWED={"cloudflare/kumo","microsoft/fluentui","spiffe/spire"}
OUT=BASE/"baseline-results"/"targeted-scope"


def run():
    corpus=json.loads((BASE/"benchmarks/public_manifest.json").read_text("utf8"))
    chosen=[item for item in corpus["repositories"] if item["name"] in ALLOWED]
    assert len(chosen)==3
    OUT.mkdir(parents=True,exist_ok=True)
    rows=[]
    for source in chosen:
        with tempfile.TemporaryDirectory(prefix="proofcut-targeted-scope-") as d:
            root=Path(d)
            for file in source["files"]:
                raw=fetch(source["name"],source["commit"],file)
                target=root/file["path"]
                target.parent.mkdir(parents=True,exist_ok=True)
                target.write_bytes(raw)
            report=examine(root)
        row={"name":source["name"],"revision":source["commit"],
             "verified_files":len(source["files"]),
             "structural_summary":report["summary"],
             "labels":"NONE; no finding has been manually classified",
             "sampling":"previously author-targeted, not independent heldout"}
        rows.append(row)
        (OUT/(source["name"].replace("/","__")+".json")).write_text(
            json.dumps({"summary":row,"details":report},indent=2)+"\n")
        print(json.dumps(row,sort_keys=True))
    aggregate={
        "repositories":len(rows),
        "files":sum(r["verified_files"] for r in rows),
        "workflow_run_consumers":sum(r["structural_summary"]["workflow_run_consumers"] for r in rows),
        "explicit_upstream_transfers":sum(r["structural_summary"]["explicit_upstream_transfers"] for r in rows),
        "single_producer_links":sum(r["structural_summary"]["linked_single_producer"] for r in rows),
        "unknown_producer_links":sum(r["structural_summary"]["source_missing_or_ambiguous"] for r in rows),
        "scope":"selected non-blind cross-run workflows, structure only not vulnerabilities",
    }
    (OUT/"summary.json").write_text(json.dumps({"overall":aggregate,"repositories":rows},indent=2)+"\n")
    print("TARGETED SCOPE:",json.dumps(aggregate,sort_keys=True))
    assert aggregate["workflow_run_consumers"]>0,"enriched cohort did not contain useful cross-run examples"
    return 0

if __name__=="__main__":
    raise SystemExit(run())
