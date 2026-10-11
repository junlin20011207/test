"""Reproducible non-exploit proof certificate for two-stage contract falsification.

The certificate is a *restricted logical guarantee*, not a proof of complete
GitHub Actions semantics. Historical advisories are only read as data.
"""
import json
from pathlib import Path
import sys
import yaml

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"tests"))

from benchmarks.guard_semantics import parse,guaranteed_atoms
from benchmarks.repair_invariants import check_dist_contract
from test_repair_invariants import prepared
from test_contract_falsification import CASES

FAMILY="artifact_metadata_to_git_write"
SOURCE=ROOT/"baseline-results"/"repairlab"
OUTPUT=ROOT/"baseline-results"/"assurance"


def mutation_results():
    entries=[]
    for obligation,mutate in CASES:
        p,c=prepared()
        mutate(p,c)
        r=check_dist_contract(p,c)
        entries.append({"stage":"observed-first-wave", "obligation":obligation,
                        "blocked":not r["passed"],
                        "specific_check":r["checks"][obligation]})
    alternatives=[
        ("producer_event_permission_boundary","producer",
         "github.actor == 'emergency-maintainer'"),
        ("publisher_remains_guarded_by_diff","upload",
         "steps.diff.outputs.changed == 'force-upload'"),
        ("consumer_authorizes_same_repo_actor_and_branch","consumer",
         "github.event.workflow_run.head_branch == 'special-branch'"),
        ("consumer_authorizes_same_repo_actor_and_branch","consumer",
         "github.event.workflow_run.actor.login == 'trusted-service'"),
        ("consumer_authorizes_same_repo_actor_and_branch","consumer",
         "github.event.workflow_run.head_repository.full_name == 'other/repo'"),
    ]
    for obligation,kind,alternative in alternatives:
        p,c=prepared()
        if kind=="producer":
            p["jobs"]["rebuild"]["if"]+=" || "+alternative
        elif kind=="upload":
            p["jobs"]["rebuild"]["steps"][-1]["if"]+=" || "+alternative
        else:
            c["jobs"]["commit"]["if"]+=" || "+alternative
        r=check_dist_contract(p,c)
        entries.append({"stage":"observed-unseen-OR-wave",
                        "obligation":obligation,
                        "alternative":alternative,
                        "blocked":not r["passed"],
                        "specific_check":r["checks"][obligation]})
    return entries


def guard_certificate(expression):
    facts=guaranteed_atoms(parse(expression))
    return {"source_expression":expression,
            "must_hold_on_all_modeled_or_paths":[list(x) if isinstance(x,tuple)
                                                  else x for x in sorted(facts,key=repr)] if facts is not None else [],
            "model":"restricted compositional parser; sufficient predicate entailment"}


def main():
    output=OUTPUT
    output.mkdir(parents=True,exist_ok=True)
    baseline=prepared()
    synthetic=check_dist_contract(*baseline)
    if not synthetic["passed"]:
        raise AssertionError("positive valid fixture rejected")
    original=SOURCE/(FAMILY+"__rebuild-dist.yml")
    revised=SOURCE/(FAMILY+"__commit-dist.yml")
    if not original.exists() or not revised.exists():
        raise RuntimeError("repairlab output missing: run repairlab.py before certificate")
    producer=yaml.load(original.read_text("utf8"),Loader=yaml.BaseLoader)
    consumer=yaml.load(revised.read_text("utf8"),Loader=yaml.BaseLoader)
    real=check_dist_contract(producer,consumer)
    if not real["passed"]:
        raise AssertionError("repaired historical contract violated "+str(real["checks"]))
    producer_job=producer["jobs"]["rebuild"]
    consumer_job=consumer["jobs"]["commit"]
    upload=next(s for s in producer_job["steps"] if
                "actions/upload-artifact@" in str(s.get("uses","")))
    guards={
        "producer_actor":guard_certificate(producer_job["if"]),
        "publisher_changed":guard_certificate(upload["if"]),
        "consumer_approval":guard_certificate(consumer_job["if"]),
    }
    rejected=mutation_results()
    summary={
        "system":"ProofCut ContractLab",
        "validation_level":"limited structural guard proof + deterministic falsification",
        "git_advisory":"GHSL-2026-225 already disclosed",
        "historical_repair_contract":{"passed":real["passed"],
                                      "obligations":real["checks"]},
        "guard_certificates":guards,
        "adversarial_attempts":len(rejected),
        "adversarial_rejected":sum(x["blocked"] for x in rejected),
        "counterexamples":rejected,
        "limitations":[
            "supported operators only; no complete Actions interpreter",
            "OR-path facts are sufficient and may reject other valid guards",
            "test suite is self-designed; not population precision or recall",
            "no runtime GitHub branch authorization or external exploit tested",
        ],
    }
    (output/"certificate.json").write_text(
        json.dumps(summary,indent=2,ensure_ascii=False)+"\n",encoding="utf8")
    print("PROOFCUT ASSURANCE:",json.dumps({
        "obligations":len(real["checks"]),
        "passed":sum(real["checks"].values()),
        "adversarial_rejected":summary["adversarial_rejected"],
        "adversarial_attempts":len(rejected),
        "predicate_groups":list(guards),
    }))
    if summary["adversarial_rejected"]!=len(rejected):
        raise AssertionError("some known adversarial cases were accepted")
    return 0


if __name__=="__main__":
    raise SystemExit(main())
