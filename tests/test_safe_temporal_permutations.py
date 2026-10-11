"""Counterexamples to an unnecessarily rigid total-order repair contract.

A checkout with a trusted event ref and no presence-output dependency can run
before a separate isolated artifact download without invalidating the causal
file-consumption or SHA-before-write obligations.
"""
import pytest
from benchmarks.repair_invariants import check_dist_contract
from test_repair_invariants import prepared


@pytest.mark.parametrize("scenario",["checkout_first","checkout_before_readiness"])
def test_independent_checkout_can_be_reordered(scenario):
    producer,consumer=prepared()
    steps=consumer["jobs"]["commit"]["steps"]
    if scenario=="checkout_first":
        steps.insert(0,steps.pop(2))
    else:
        steps[1],steps[2]=steps[2],steps[1]
    result=check_dist_contract(producer,consumer)
    assert result["passed"],result
