"""Produce a non-deployed CAS-bound variant of the historical public repair.

The unmodified prior repair remains available as a compatible baseline.
The stronger candidate is opt-in research: explicit force-with-lease may be
blocked on protected branches and must never be auto-deployed.
"""
import argparse
import json
import tempfile
from pathlib import Path

import yaml
from benchmarks.repairlab import patch_metadata
from benchmarks.ref_update_contract import upgrade_push_to_expected_ref_cas
from benchmarks.repair_invariants import load_from_workspace
from benchmarks.scan_public import fetch

ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/"baseline-results"/"ref-cas-candidate"


def generate(codeql=False):
    manifest=json.loads((ROOT/"benchmarks"/"metadata_pairs.json").read_text("utf8"))
    selected=next(item for item in manifest["cases"] if item["label"]=="vulnerable")
    OUT.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="ref-cas-candidate-") as tmp:
        work=Path(tmp)
        for item in selected["files"]:
            destination=work/item["path"]
            destination.parent.mkdir(parents=True,exist_ok=True)
            destination.write_bytes(fetch(manifest["source"],selected["commit"],item))
        target,patched,_=patch_metadata(work)
        target.write_text(yaml.safe_dump(patched,sort_keys=False),encoding="utf8")
        base=load_from_workspace(work)
        assert base["passed"] and base["total_count"]==16
        assert not base["ref_update_assurance"]["stronger_pattern_passed"]
        weak_in_strict=load_from_workspace(work,require_ref_cas=True)
        assert not weak_in_strict["passed"] and not weak_in_strict["checks"]["remote_ref_expected_oid_cas"]
        stronger=upgrade_push_to_expected_ref_cas(patched)
        target.write_text(yaml.safe_dump(patched,sort_keys=False),encoding="utf8")
        improved=load_from_workspace(work,require_ref_cas=True)
        assert stronger["stronger_pattern_passed"]
        assert improved["passed"] and improved["total_count"]==17
        assert improved["checks"]["remote_ref_expected_oid_cas"],improved
        after_codeql=None
        if codeql:
            from benchmarks.codeql_comparison import BINARY,PACK,call
            if not BINARY.is_file():
                raise RuntimeError("pinned CodeQL executable not installed in runner")
            database=work.parent/"ref-cas-db"
            sarif=OUT/"ref-cas-candidate.sarif"
            call([BINARY,"database","create",database,
                  "--language=actions","--source-root="+str(work)],
                 "ref cas db create")
            call([BINARY,"database","analyze",database,PACK,
                  "--format=sarif-latest","--output="+str(sarif),
                  "--threads=2","--ram=4096"],"ref cas db analyze")
            codeql_results=json.loads(sarif.read_text("utf8"))
            rules=[r.get("ruleId","") for run in codeql_results.get("runs",[])
                   for r in run.get("results",[])]
            after_codeql={"alert_count":len(rules),"rules":sorted(set(rules))}
        (OUT/"consumer-candidate.yml").write_text(target.read_text("utf8"),encoding="utf8")
        summary={
            "source_repo":manifest["source"],"public_historical_commit":selected["commit"],
            "prior_repair":{"contract_passed":base["passed"],
                            "obligation_count":base["total_count"],
                            "remote_ref_cas":base["ref_update_assurance"]["tier"],
                            "strict_mode_rejected":not weak_in_strict["passed"]},
            "opt_in_cas_candidate":{"contract_passed":improved["passed"],
                                    "obligation_count":improved["total_count"],
                                    "remote_ref_cas":improved["ref_update_assurance"],
                                    "codeql":after_codeql},
            "not_deployed":True,
            "policy_caveat":"force-with-lease may be rejected by GitHub protected branches; local Git alone does not validate deployability",
        }
    (OUT/"comparison.json").write_text(json.dumps(summary,indent=2,ensure_ascii=False)+"\n","utf8")
    print(json.dumps(summary,ensure_ascii=False))
    return 0


if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--codeql",action="store_true")
    args=p.parse_args()
    raise SystemExit(generate(codeql=args.codeql))
