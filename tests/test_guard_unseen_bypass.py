"""Second-round tests intentionally out of the first bounded scenario set.

The contract should reject unauthorized OR alternatives even when the single
counterexample chosen in the initial test does not exercise that alternative.
"""
import pytest
from test_repair_invariants import prepared
from benchmarks.repair_invariants import check_dist_contract


@pytest.mark.parametrize(("field","bypass"),[
    ("producer_event_permission_boundary",
     ("rebuild","github.actor == 'emergency-maintainer'")),
    ("publisher_remains_guarded_by_diff",
     ("upload","steps.diff.outputs.changed == 'force-upload'")),
    ("consumer_authorizes_same_repo_actor_and_branch",
     ("commit","github.event.workflow_run.head_branch == 'special-branch'")),
    ("consumer_authorizes_same_repo_actor_and_branch",
     ("commit","github.event.workflow_run.actor.login == 'trusted-service'")),
    ("consumer_authorizes_same_repo_actor_and_branch",
     ("commit","github.event.workflow_run.head_repository.full_name == 'other/repo'")),
])
def test_unenumerated_unauthorized_or_branch_must_not_bypass(field,bypass):
    p,c=prepared()
    target,alternative=bypass
    if target=="rebuild":
        p["jobs"]["rebuild"]["if"]+=" || "+alternative
    elif target=="upload":
        p["jobs"]["rebuild"]["steps"][-1]["if"]+=" || "+alternative
    else:
        c["jobs"]["commit"]["if"]+=" || "+alternative
    r=check_dist_contract(p,c)
    assert r["checks"][field] is False,"unknown unauthorized alternative was accepted"
    assert r["passed"] is False
