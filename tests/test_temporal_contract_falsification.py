"""Falsify a static repair checker that ignores temporal order and skipped steps.

Fixture contains no untrusted payloads or credentials. Tests are intentionally
red on prior checker: a passed static contract cannot prove a post-write check
protects an earlier write.
"""
import pytest
from benchmarks.repair_invariants import check_dist_contract
from test_repair_invariants import prepared


def reorder(p,c,first,second):
    steps=c["jobs"]["commit"]["steps"]
    steps[first],steps[second]=steps[second],steps[first]


def move(p,c,from_i,to_i):
    steps=c["jobs"]["commit"]["steps"]
    steps.insert(to_i,steps.pop(from_i))


def disable(p,c,i):
    c["jobs"]["commit"]["steps"][i]["if"]="false"


def tolerate_failure(p,c,i):
    c["jobs"]["commit"]["steps"][i]["continue-on-error"]=True


CASES=[
    ("push_before_sha_verify",lambda p,c:move(p,c,5,3)),
    ("push_before_artifact_apply",lambda p,c:move(p,c,5,4)),
    ("sha_verify_after_artifact_apply",lambda p,c:reorder(p,c,3,4)),
    ("checkout_before_download",lambda p,c:reorder(p,c,0,2)),
    ("readiness_after_checkout",lambda p,c:reorder(p,c,1,2)),
    ("readiness_after_push",lambda p,c:move(p,c,1,5)),
    ("skipped_sha_verify",lambda p,c:disable(p,c,3)),
    ("skipped_artifact_apply",lambda p,c:disable(p,c,4)),
    ("ignored_sha_verify_failure",lambda p,c:tolerate_failure(p,c,3)),
    ("ignored_artifact_copy_failure",lambda p,c:tolerate_failure(p,c,4)),
    ("ignored_download_failure",lambda p,c:tolerate_failure(p,c,0)),
    ("conditional_push_skip",lambda p,c:disable(p,c,5)),
]

@pytest.mark.parametrize("label,mutation",CASES,ids=[x[0] for x in CASES])
def test_invalid_sequence_must_be_rejected(label,mutation):
    producer,consumer=prepared()
    original=check_dist_contract(producer,consumer)
    assert original["passed"],original
    mutation(producer,consumer)
    outcome=check_dist_contract(producer,consumer)
    assert not outcome["passed"],"false contract acceptance: "+label
