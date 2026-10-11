"""Run the official CodeQL Actions query pack on four pinned historical states.

This is *comparison*, not an attempt to prove superiority. The two advisory
pairs were chosen because their fixes are public. Their CodeQL alerts may be
non-equivalent to ProofCut's rule-specific evidence; preserve raw SARIF.
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from benchmarks.scan_public import fetch
from proofcut import inspect
from benchmarks.repairlab import patch_overlay, patch_metadata
import yaml

BASE=Path(__file__).resolve().parent
OUT=BASE.parent/"baseline-results"/"codeql"
BINARY=Path(os.environ.get("CODEQL_BIN","")).expanduser()
PACK="codeql/actions-queries:codeql-suites/actions-security-extended.qls"


def call(argv,label):
    result=subprocess.run(list(map(str,argv)),capture_output=True,text=True,timeout=300)
    if result.returncode:
        print(f"ERROR {label}: code {result.returncode}\n{result.stdout[-1500:]}\n{result.stderr[-3000:]}",file=sys.stderr)
        raise RuntimeError(label+" failed")
    return result


def main():
    if not BINARY.is_file():
        raise RuntimeError("CODEQL_BIN must point to the official verified CLI")
    OUT.mkdir(parents=True,exist_ok=True)
    version=call([BINARY,"version"],"version").stdout.strip().splitlines()[0]
    reports=[]
    for source_manifest in ("advisory_pairs.json","metadata_pairs.json"):
        data=json.loads((BASE/source_manifest).read_text("utf8"))
        for state in [*data["cases"],dict(data["cases"][0],label="candidate_patch")]:
            case_id=source_manifest.removesuffix(".json")+"__"+state["label"]
            with tempfile.TemporaryDirectory(prefix="codeql-actions-pair-") as tmp:
                root=Path(tmp)
                workspace=root/"source"
                for entry in state["files"]:
                    raw=fetch(data["source"],state["commit"],entry)
                    path=workspace/entry["path"]
                    path.parent.mkdir(parents=True,exist_ok=True)
                    path.write_bytes(raw)
                if state["label"]=="candidate_patch":
                    patcher=(patch_overlay if source_manifest=="advisory_pairs.json"
                             else patch_metadata)
                    target,patched,patch_info=patcher(workspace)
                    target.write_text(yaml.safe_dump(patched,sort_keys=False),encoding="utf8")
                result=inspect(workspace)
                db=root/"db"
                sarif=OUT/(case_id+".sarif")
                call([BINARY,"database","create",db,"--language=actions",
                      "--source-root="+str(workspace)],case_id+" create")
                call([BINARY,"database","analyze",db,PACK,
                      "--format=sarif-latest","--output="+str(sarif),
                      "--threads=2","--ram=4096"],case_id+" analyze")
                report=json.loads(sarif.read_text("utf8"))
            alerts=[r.get("ruleId","") for run in report.get("runs",[])
                    for r in run.get("results",[])]
            rules=sorted(set(alerts))
            row={"case":case_id,"repository":data["source"],
                 "revision":state["commit"],"label":state["label"],
                 "codeql_version":version,"query_pack":PACK,
                 "files_sha_verified":len(state["files"]),
                 "candidate_generated":state["label"]=="candidate_patch",
                 "proofcut_families":result["families"],
                 "codeql_total_alerts":len(alerts),
                 "codeql_artifact_poisoning_alerts":sum("artifact-poisoning" in a for a in alerts),
                 "codeql_rule_ids":rules,
                 "semantics_note":"Different rule families and path semantics; rule count is not a true/false label"}
            reports.append(row)
            print(json.dumps(row,ensure_ascii=False))
    (OUT/"summary.json").write_text(json.dumps({
        "version":version,"query_pack":PACK,"states":reports,
        "interpretation":"Four published historical versions and two generated draft-patch variants; labels are not a held-out data set; no runtime repair validation or precision/recall claim"},indent=2)+"\n")
    return 0

if __name__=="__main__":
    raise SystemExit(main())
