"""Read-only verification of a previously disclosed metadata authorization flaw.

No workflow or downloaded artifact is ever executed.
"""
import json
from pathlib import Path
import sys
import tempfile
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from benchmarks.scan_public import fetch
from boundarygraph import analyze
from metadataproof import metadata_proofs

BASE=Path(__file__).parent
OUT=BASE.parent/"baseline-results"/"metadata"

def main():
    m=json.loads((BASE/"metadata_pairs.json").read_text(encoding="utf8"))
    OUT.mkdir(parents=True,exist_ok=True)
    result=[]
    for case in m["cases"]:
        with tempfile.TemporaryDirectory(prefix="metadataproof-") as tmp:
            root=Path(tmp)
            for entry in case["files"]:
                data=fetch(m["source"],case["commit"],entry)
                target=root/entry["path"]
                target.parent.mkdir(parents=True,exist_ok=True)
                target.write_bytes(data)
            old=analyze(root)
            new=metadata_proofs(root)
        record={"label":case["label"],"revision":case["commit"],
                "verified_files":len(case["files"]),
                "old_critical":sum(x["severity"]=="critical" for x in old["findings"]),
                "old_candidates":len(old["findings"])+len(old.get("unverified",[])),
                "metadata_witnesses":new["proofs"],
                "metadata_count":new["count"],
                "expected_count":case["expected_metadata_count"]}
        print(f"{case['label']} @ {case['commit'][:12]}: "
              f"prior_critical={record['old_critical']}, metadata_proofs={new['count']}, "
              f"expected={case['expected_metadata_count']}, files={len(case['files'])}")
        (OUT/(case["label"]+".json")).write_text(json.dumps(record,indent=2)+"\n","utf8")
        result.append(record)
    ok=all(r["metadata_count"]==r["expected_count"] for r in result)
    (OUT/"summary.json").write_text(json.dumps({
        "study":"historical disclosed metadata injection regression",
        "advisory":m["reference"],"passed":ok,"cases":result,
        "limitations":"one prior published case plus repair; not a prevalence or accuracy estimate"},indent=2)+"\n","utf8")
    return 0 if ok else 1

if __name__=="__main__":
    raise SystemExit(main())
