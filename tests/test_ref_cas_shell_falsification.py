"""Falsify line-presence-based proof without running untrusted shell code."""
import pytest
from test_repair_invariants import prepared
from benchmarks.ref_update_contract import (
    ANCESTRY,LEASE,inspect_push_step,upgrade_push_to_expected_ref_cas
)


@pytest.mark.parametrize("mutation",[
    "ancestry_in_dead_if",
    "push_in_dead_if",
    "ancestry_in_heredoc",
    "errexit_disabled_long_form",
])
def test_declarative_cas_proof_rejects_inert_shell_lines(mutation):
    _,workflow=prepared()
    upgrade_push_to_expected_ref_cas(workflow)
    job=workflow["jobs"]["commit"]
    push=job["steps"][-1]
    script=push["run"]
    if mutation=="ancestry_in_dead_if":
        script=script.replace(ANCESTRY,"if false; then\n"+ANCESTRY+"\nfi")
    elif mutation=="push_in_dead_if":
        script=script.replace(LEASE,"if false; then\n"+LEASE+"\nfi")
    elif mutation=="ancestry_in_heredoc":
        script=script.replace(ANCESTRY,"cat <<'IGNORED'\n"+ANCESTRY+"\nIGNORED")
    elif mutation=="errexit_disabled_long_form":
        script="set +o errexit\n"+script
    else:
        raise AssertionError(mutation)
    push["run"]=script
    result=inspect_push_step(push,job)
    assert not result["stronger_pattern_passed"],(mutation,result)
