"""Adversarial repair-contract falsification. Each mutation must be rejected.

The known original validator used substring matching, so this suite is a
red-team test of *evidence checking*, not an exploit or security exploit demo.
"""
import pytest
from benchmarks.repair_invariants import check_dist_contract
from test_repair_invariants import prepared


def producer_guard_bypass(p,c):
    p["jobs"]["rebuild"]["if"]+=" || true"


def consumer_guard_bypass(p,c):
    c["jobs"]["commit"]["if"]+=" || true"


def upload_guard_bypass(p,c):
    p["jobs"]["rebuild"]["steps"][-1]["if"]+=" || true"


def output_probe_only_in_comment(p,c):
    c["jobs"]["commit"]["steps"][1]["run"]=(
        "# if [ -f '${{ runner.temp }}/incoming/dist/index.js' ]; then\n"
        "# echo present=true >> $GITHUB_OUTPUT\n"
        "# echo present=false >> $GITHUB_OUTPUT\n"
        "echo 'present=true' >> $GITHUB_OUTPUT\n")


def sha_validation_is_only_printed(p,c):
    c["jobs"]["commit"]["steps"][3]["run"]=(
        "current=$(git rev-parse HEAD)\n"
        "echo \"expected: $EXPECTED_SHA; current: $current\"\n")


def swallowed_push_failure(p,c):
    c["jobs"]["commit"]["steps"][5]["run"]+=' || true'


def extra_untrusted_checkout(p,c):
    c["jobs"]["commit"]["steps"].insert(3,{
        "uses":"actions/checkout@v4",
        "with":{"ref":"${{ steps.check.outputs.head-ref }}"},
    })


def duplicate_untrusted_upload(p,c):
    p["jobs"]["rebuild"]["steps"].append({
        "uses":"actions/upload-artifact@v4",
        "with":{"name":"rebuilt-dist","path":"untrusted-other/"},
    })


CASES=[
    ("producer_event_permission_boundary",producer_guard_bypass),
    ("consumer_authorizes_same_repo_actor_and_branch",consumer_guard_bypass),
    ("publisher_remains_guarded_by_diff",upload_guard_bypass),
    ("consumer_checks_actual_dist_file",output_probe_only_in_comment),
    ("sha_verification_environment_bound",sha_validation_is_only_printed),
    ("write_target_environment_bound",swallowed_push_failure),
    ("checkout_target_from_event",extra_untrusted_checkout),
    ("publisher_named_and_dist_only",duplicate_untrusted_upload),
]


@pytest.mark.parametrize("obligation,mutation",CASES,ids=[x[0] for x in CASES])
def test_malformed_contract_must_not_pass(obligation,mutation):
    producer,consumer=prepared()
    assert check_dist_contract(producer,consumer)["passed"]
    mutation(producer,consumer)
    evaluated=check_dist_contract(producer,consumer)
    assert not evaluated["passed"],"unsound acceptance of "+obligation
    assert not evaluated["checks"][obligation],"specific false accept: "+obligation
