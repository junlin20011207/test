"""Complementarity experiment: CodeQL warnings vs broken business repair contracts.

Uses fixed, already-disclosed actions/attest workflows and a generated
repair candidate. Mutations are synthetic, never deployed or executed.
CodeQL is not intended to audit arbitrary business invariants; "zero alerts"
is NOT a false negative for non-security functional contract failures.
"""
import json
from pathlib import Path
import tempfile
import yaml
from benchmarks.codeql_comparison import BASE,BINARY,PACK,OUT,call
from benchmarks.repairlab import patch_metadata
from benchmarks.scan_public import fetch
from benchmarks.repair_invariants import load_from_workspace

DEST=BASE.parent/"baseline-results"/"contract-comparison"


def change(name,root):
    if name=="control":
        return
    p=root/".github/workflows/rebuild-dist.yml"
    c=root/".github/workflows/commit-dist.yml"
    prod=yaml.load(p.read_text("utf8"),Loader=yaml.BaseLoader)
    cons=yaml.load(c.read_text("utf8"),Loader=yaml.BaseLoader)
    producer_steps=prod["jobs"]["rebuild"]["steps"]
    consumer_steps=cons["jobs"]["commit"]["steps"]
    if name=="producer_renamed":
        upload=next(x for x in producer_steps if "actions/upload-artifact@" in str(x.get("uses","")))
        upload["with"]["name"]="different-artifact"
    elif name=="download_moved":
        download=next(x for x in consumer_steps if "actions/download-artifact@" in str(x.get("uses","")))
        download["with"]["path"]=download["with"]["path"].replace("/incoming/dist","/elsewhere")
    elif name=="readiness_always_true":
        step=next(x for x in consumer_steps if x.get("id")=="check")
        step["run"]='echo "present=true" >> "$GITHUB_OUTPUT"'
    elif name=="sha_only_logged":
        step=next(x for x in consumer_steps if "git rev-parse HEAD" in str(x.get("run","")))
        step["run"]='current=$(git rev-parse HEAD)\necho "observed: $current expected: $EXPECTED_SHA"'
    elif name=="actor_guard_bypass":
        cons["jobs"]["commit"]["if"]+=" || true"
    elif name=="push_failure_ignored":
        step=next(x for x in consumer_steps if "git push origin" in str(x.get("run","")))
        step["run"]+=" || true"
    else:
        raise ValueError(name)
    p.write_text(yaml.safe_dump(prod,sort_keys=False),encoding="utf8")
    c.write_text(yaml.safe_dump(cons,sort_keys=False),encoding="utf8")


def run():
    if not BINARY.is_file():
        raise RuntimeError("CODEQL_BIN not set to pinned official CLI")
    DEST.mkdir(parents=True,exist_ok=True)
    m=json.loads((BASE/"metadata_pairs.json").read_text("utf8"))
    pinned=next(x for x in m["cases"] if x["label"]=="vulnerable")
    variants=["control","producer_renamed","download_moved",
              "readiness_always_true","sha_only_logged",
              "actor_guard_bypass","push_failure_ignored"]
    output=[]
    for name in variants:
        with tempfile.TemporaryDirectory(prefix="contract-compare-") as tmp:
            root=Path(tmp)
            workspace=root/"src"
            for ent in pinned["files"]:
                data=fetch(m["source"],pinned["commit"],ent)
                dest=workspace/ent["path"]
                dest.parent.mkdir(parents=True,exist_ok=True)
                dest.write_bytes(data)
            target,patched,_=patch_metadata(workspace)
            target.write_text(yaml.safe_dump(patched,sort_keys=False),encoding="utf8")
            change(name,workspace)
            contract=load_from_workspace(workspace)
            database=root/"database"
            sarif=DEST/(name+".sarif")
            call([BINARY,"database","create",database,"--language=actions",
                  "--source-root="+str(workspace)],name+" create")
            call([BINARY,"database","analyze",database,PACK,
                  "--format=sarif-latest","--output="+str(sarif),
                  "--threads=2","--ram=4096"],name+" analyze")
            reports=json.loads(sarif.read_text("utf8"))
            alerts=[row.get("ruleId","") for entry in reports.get("runs",[])
                    for row in entry.get("results",[])]
        entry={
            "case":name,
            "contract_passed":contract["passed"],
            "failed_obligations":[key for key,value in contract["checks"].items() if not value],
            "codeql_total_alerts":len(alerts),
            "codeql_rules":sorted(set(alerts)),
            "provenance":"public GHSL-2026-225 vulnerable commit; repaired copy mutated only in temp",
            "limits":"zero CodeQL alerts for business drift is outside generic vulnerability detection semantics"
        }
        output.append(entry)
        print(json.dumps(entry,ensure_ascii=False))
    checks={
        "control_contract_passes":output[0]["contract_passed"],
        "all_mutants_contract_rejected":all(not row["contract_passed"] for row in output[1:]),
        "all_sarif_generated":all((DEST/(row["case"]+".sarif")).exists() for row in output),
    }
    report={"checks":checks,"passed":all(checks.values()),
            "cases":output,
            "interpretation":"Same fixed public input and CodeQL version; no general tool superiority claim"}
    (DEST/"comparison.json").write_text(json.dumps(report,indent=2,ensure_ascii=False)+"\n")
    if not report["passed"]:
        raise AssertionError("contract comparison self-check failure")
    return 0

if __name__=="__main__":
    raise SystemExit(run())
