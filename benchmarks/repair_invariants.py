"""Auditable cross-workflow producer/consumer repair contract.

A deliberately narrow *necessary-conditions* validator for a known dist
Artifact shape. This is independent of the ProofCut path detector. It does not
execute third-party workflows and does not certify runtime business behavior.
"""
from pathlib import Path
import json
import re
import yaml
from benchmarks.contract_semantics import harden
from benchmarks.temporal_semantics import temporal_contract

RUN="$"+"{{ github.event.workflow_run.id }}"
TOKEN="$"+"{{ github.token }}"
TMP="$"+"{{ runner.temp }}/incoming/dist"
TRUSTED_BRANCH="$"+"{{ github.event.workflow_run.head_branch }}"
BRANCH_SOURCE="$"+"{{ github.event.pull_request.head.ref }}"


def steps_for(workflow,job):
    value=workflow.get("jobs",{}).get(job,{})
    return value.get("steps",[]) if isinstance(value,dict) else []


def action_step(steps,action):
    return next((s for s in steps if isinstance(s,dict) and
                 re.fullmatch(r"actions/"+action+r"@[^\s]+",str(s.get("uses","")))),None)


def check_dist_contract(producer,consumer):
    """Return detailed Boolean obligations, never just a safe/unsafe verdict."""
    producer_steps=steps_for(producer,"rebuild")
    consumer_steps=steps_for(consumer,"commit")
    upload=action_step(producer_steps,"upload-artifact")
    download=action_step(consumer_steps,"download-artifact")
    checkout=action_step(consumer_steps,"checkout")
    producer_if=producer.get("jobs",{}).get("rebuild",{}).get("if","")
    consumer_if=consumer.get("jobs",{}).get("commit",{}).get("if","")
    consumer_perms=consumer.get("jobs",{}).get("commit",{}).get("permissions",{})
    p=(upload or {}).get("with") or {}
    d=(download or {}).get("with") or {}
    checkout_input=(checkout or {}).get("with") or {}
    source_runs=[str(s.get("run","")) for s in producer_steps if isinstance(s,dict)]
    consumer_runs=[str(s.get("run","")) for s in consumer_steps if isinstance(s,dict)]
    checker=next((s for s in consumer_steps if isinstance(s,dict)
                  and s.get("id")=="check"),{})
    checker_run=str(checker.get("run",""))
    push=next((s for s in consumer_steps if isinstance(s,dict)
               and re.search(r"(?m)^\s*git\s+push\s+origin",str(s.get("run","")))),{})
    verify=next((s for s in consumer_steps if isinstance(s,dict)
                 and "git rev-parse HEAD" in str(s.get("run",""))),{})
    apply_step=next((s for s in consumer_steps if isinstance(s,dict)
                     and "mv " in str(s.get("run","")) and " dist" in str(s.get("run",""))),{})
    output_presence=str(checker_run)
    obligations={
       "publisher_named_and_dist_only":p.get("name")=="rebuilt-dist" and
                    str(p.get("path","")).strip()=="dist/",
       "publisher_remains_guarded_by_diff":(
                    "steps.diff.outputs.changed" in str((upload or {}).get("if",""))),
       "producer_event_permission_boundary":(
                    "pull_request" in (producer.get("on") or {}) and
                    (producer.get("permissions") or {}).get("contents")=="read" and
                    "dependabot[bot]" in str(producer_if)),
       "no_pr_ref_interpolated_in_producer_shell":all(
                    BRANCH_SOURCE not in x for x in source_runs),
       "matching_download_identity":(
                    d.get("name")==p.get("name") and d.get("run-id")==RUN and
                    d.get("github-token")==TOKEN),
       "download_isolated_and_flat":d.get("path")==TMP,
       "consumer_explicit_write_only_in_job":(
                    (consumer.get("permissions") or {}).get("contents")=="read" and
                    consumer_perms.get("contents")=="write"),
       "consumer_checks_actual_dist_file":(
                    TMP+"/index.js" in output_presence and
                    'present=true' in output_presence and
                    'present=false' in output_presence and
                    "GITHUB_OUTPUT" in output_presence),
       "consumer_moves_exact_downloaded_tree":(
                    TMP in str(apply_step.get("run","")) and
                    re.search(r'(?m)^\s*mv\s+.*incoming/dist.*\s+dist\s*$',str(apply_step.get("run",""))) is not None),
       "checkout_target_from_event":checkout_input.get("ref")==TRUSTED_BRANCH,
       "write_target_environment_bound":(
                    (push.get("env") or {}).get("HEAD_BRANCH")==TRUSTED_BRANCH and
                    'git push origin "HEAD:refs/heads/$HEAD_BRANCH"' in str(push.get("run",""))),
       "sha_verification_environment_bound":(
                    (verify.get("env") or {}).get("EXPECTED_SHA")==
                    "$"+"{{ github.event.workflow_run.head_sha }}" and
                    "$EXPECTED_SHA" in str(verify.get("run",""))),
       "consumer_authorizes_same_repo_actor_and_branch":(
                    "head_repository.full_name == github.repository" in str(consumer_if) and
                    "dependabot[bot]" in str(consumer_if) and
                    "startsWith(github.event.workflow_run.head_branch" in str(consumer_if)),
    }
    obligations=harden(obligations,producer,consumer,producer_steps,consumer_steps)
    temporal=temporal_contract(consumer_steps,consumer.get("jobs",{}).get("commit",{}))
    obligations["temporal_order_and_dependencies"]=temporal["temporal_order_and_dependencies"]
    obligations["critical_step_failure_propagation"]=temporal["critical_step_failure_propagation"]
    obligations["critical_execution_context"]=temporal["critical_execution_context"]
    return {"status":"bounded_semantic_and_causal_contract_checks",
            "passed":all(obligations.values()),
            "passed_count":sum(obligations.values()),
            "total_count":len(obligations),
            "checks":obligations,
            "causal_evidence":temporal["explanation"],
            "limitations":"restricted expression parser and bounded negative scenarios; not exhaustive condition semantics or proof of business behavior"}


def load_from_workspace(root):
    d=Path(root)/".github"/"workflows"
    producer=yaml.load((d/"rebuild-dist.yml").read_text("utf8"),Loader=yaml.BaseLoader)
    consumer=yaml.load((d/"commit-dist.yml").read_text("utf8"),Loader=yaml.BaseLoader)
    return check_dist_contract(producer,consumer)


def main():
    import argparse
    p=argparse.ArgumentParser()
    p.add_argument("workspace")
    args=p.parse_args()
    result=load_from_workspace(args.workspace)
    print(json.dumps(result,indent=2))
    return 0 if result["passed"] else 2


if __name__=="__main__":
    raise SystemExit(main())
