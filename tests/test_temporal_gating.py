"""Data/control dependency DAG and GitHub-style recoverable download contract."""
import pytest
from benchmarks.repair_invariants import check_dist_contract
from test_repair_invariants import prepared


PRESENT="steps.check.outputs.present == 'true'"


def jobs():
    p,c=prepared()
    return p,c,c["jobs"]["commit"]["steps"]


def test_download_failure_tolerance_requires_all_mutating_steps_gated():
    p,c,steps=jobs()
    steps[0]["continue-on-error"]=True
    for i in (2,3,4,5):
        steps[i]["if"]=PRESENT
    result=check_dist_contract(p,c)
    assert result["passed"],result
    assert result["causal_evidence"]["downstream_gated_if_download_failure_ignored"]


@pytest.mark.parametrize("missing_gate",(2,3,4,5))
def test_tolerated_download_cannot_bypass_presence_gate(missing_gate):
    p,c,steps=jobs()
    steps[0]["continue-on-error"]=True
    for i in (2,3,4,5):steps[i]["if"]=PRESENT
    steps[missing_gate].pop("if")
    result=check_dist_contract(p,c)
    assert not result["passed"]
    assert not result["checks"]["critical_step_failure_propagation"]


def test_or_true_bypass_of_presence_is_rejected():
    p,c,steps=jobs()
    steps[0]["continue-on-error"]=True
    for i in (2,3,4,5):steps[i]["if"]=PRESENT
    steps[5]["if"]+=" || true"
    result=check_dist_contract(p,c)
    assert not result["passed"]


def test_gated_step_must_follow_its_output_producer():
    p,c,steps=jobs()
    steps[2]["if"]=PRESENT
    steps[1],steps[2]=steps[2],steps[1]
    result=check_dist_contract(p,c)
    assert not result["checks"]["temporal_order_and_dependencies"]


def test_unrecognized_continue_on_error_expression_rejected():
    p,c,steps=jobs()
    steps[3]["continue-on-error"]=chr(36)+"{{ matrix.allow_failure }}"
    result=check_dist_contract(p,c)
    assert not result["passed"]


def test_duplicated_sha_verification_step_fails_closed():
    p,c,steps=jobs()
    steps.insert(4,dict(steps[3]))
    result=check_dist_contract(p,c)
    assert not result["checks"]["temporal_order_and_dependencies"]


def test_unguarded_independent_checkout_before_download_allowed():
    p,c,steps=jobs()
    steps.insert(0,steps.pop(2))
    result=check_dist_contract(p,c)
    assert result["passed"],result
