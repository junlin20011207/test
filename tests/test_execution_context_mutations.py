"""Executable-context mutations for cross-workflow repair jobs.

Changing shell working directory redirects relative dist target; job-level
continue-on-error can also mask failures at a wider layer.
"""
import pytest
from benchmarks.repair_invariants import check_dist_contract
from test_repair_invariants import prepared


@pytest.mark.parametrize("case",[
    "job_ignores_failures",
    "job_changes_working_directory",
    "apply_runs_outside_workspace",
    "push_runs_outside_workspace",
    "verify_runs_outside_workspace",
])
def test_executable_context_must_not_silently_change(case):
    p,c=prepared()
    job=c["jobs"]["commit"]
    steps=job["steps"]
    if case=="job_ignores_failures":
        job["continue-on-error"]=True
    elif case=="job_changes_working_directory":
        job["defaults"]={"run":{"working-directory":"other"}}
    elif case=="apply_runs_outside_workspace":
        steps[4]["working-directory"]="other"
    elif case=="push_runs_outside_workspace":
        steps[5]["working-directory"]="other"
    elif case=="verify_runs_outside_workspace":
        steps[3]["working-directory"]="other"
    result=check_dist_contract(p,c)
    assert not result["passed"],"executable environment drift falsely accepted: "+case
