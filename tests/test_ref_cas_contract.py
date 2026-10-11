"""Ref CAS acceptance has a separate proof tier from ordinary repair contract."""
import pytest
from test_repair_invariants import prepared
from benchmarks.ref_update_contract import (
    ANCESTRY,LEASE,PLAIN,inspect_push_step,upgrade_push_to_expected_ref_cas,
)


def make_upgraded():
    _,consumer=prepared()
    job=consumer["jobs"]["commit"]
    result=upgrade_push_to_expected_ref_cas(consumer)
    return job,job["steps"][-1],result


def test_plain_previously_accepted_push_does_not_prove_unchanged_remote_ref():
    _,consumer=prepared()
    job=consumer["jobs"]["commit"]
    outcome=inspect_push_step(job["steps"][-1],job)
    assert not outcome["stronger_pattern_passed"]
    assert outcome["tier"]=="ref_update_atomicity_unverified"


def test_upgraded_candidate_requires_expected_ref_and_ancestry():
    job,push,result=make_upgraded()
    assert result["stronger_pattern_passed"]
    assert all(result["checks"].values())
    assert push["run"].index(ANCESTRY)<push["run"].index(LEASE)


@pytest.mark.parametrize("fault",[
    "sha_unbound",
    "branch_unbound",
    "sha_wrong_expression",
    "lease_wrong_expected",
    "ancestry_after_push",
    "skip_ancestry",
    "ignored_push_failure",
    "job_ignores_failure",
    "shell_not_bash",
    "exit_errexit_disabled",
    "extra_plain_push",
])
def test_ref_cas_pattern_rejects_mutation(fault):
    job,push,_=make_upgraded()
    if fault=="sha_unbound":
        del push["env"]["EXPECTED_SHA"]
    elif fault=="branch_unbound":
        push["env"]["HEAD_BRANCH"]="release"
    elif fault=="sha_wrong_expression":
        push["env"]["EXPECTED_SHA"]="deadbeef"
    elif fault=="lease_wrong_expected":
        push["run"]=push["run"].replace(":$EXPECTED_SHA",":arbitrary")
    elif fault=="ancestry_after_push":
        push["run"]=push["run"].replace(ANCESTRY+"\n"+LEASE,LEASE+"\n"+ANCESTRY)
    elif fault=="skip_ancestry":
        push["run"]=push["run"].replace(ANCESTRY+"\n","")
    elif fault=="ignored_push_failure":
        push["continue-on-error"]=True
    elif fault=="job_ignores_failure":
        job["continue-on-error"]=True
    elif fault=="shell_not_bash":
        push["shell"]="python"
    elif fault=="exit_errexit_disabled":
        push["run"]="set +e\n"+push["run"]
    elif fault=="extra_plain_push":
        push["run"]+="\n"+PLAIN
    else:
        raise AssertionError("unknown fault")
    result=inspect_push_step(push,job)
    assert not result["stronger_pattern_passed"],(fault,result)
