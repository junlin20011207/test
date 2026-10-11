"""Invariants must reject silent breakage of cross-workflow artifact contracts."""
import pytest
from benchmarks.repair_invariants import check_dist_contract

RUN="${{ github.event.workflow_run.id }}"
TOKEN="${{ github.token }}"
TMP="${{ runner.temp }}/incoming/dist"
HEAD="${{ github.event.workflow_run.head_branch }}"
SHA="${{ github.event.workflow_run.head_sha }}"


def prepared():
    upload={"uses":"actions/upload-artifact@v4",
            "if":"steps.diff.outputs.changed == 'true'",
            "with":{"name":"rebuilt-dist","path":"dist/"}}
    producer={"on":{"pull_request":{"branches":["main"]}},
              "permissions":{"contents":"read"},
              "jobs":{"rebuild":{"if":"github.actor == 'dependabot[bot]'",
                                 "steps":[{"run":"echo benign"},upload]}}}
    downloader={"uses":"actions/download-artifact@v4",
                "with":{"name":"rebuilt-dist","run-id":RUN,
                        "github-token":TOKEN,"path":TMP}}
    checker={"id":"check","run":(
        'if [ -f "'+TMP+'/index.js" ]; then\n'
        '  echo "present=true" >> "$GITHUB_OUTPUT"\n'
        'else\n'
        '  echo "present=false" >> "$GITHUB_OUTPUT"\nfi')}
    checkout={"uses":"actions/checkout@v4","with":{"ref":HEAD}}
    verify={"run":"current=$(git rev-parse HEAD)\ntest \"$current\" = \"$EXPECTED_SHA\"",
            "env":{"EXPECTED_SHA":SHA}}
    apply={"run":'mv "'+TMP+'" dist'}
    push={"run":'git push origin "HEAD:refs/heads/$HEAD_BRANCH"',
          "env":{"HEAD_BRANCH":HEAD}}
    consumer={"on":{"workflow_run":{"workflows":["Rebuild dist"]}},
              "permissions":{"contents":"read"},
              "jobs":{"commit":{"permissions":{"contents":"write"},
                                 "if":("github.event.workflow_run.conclusion == 'success' && "
                                       "github.event.workflow_run.event == 'pull_request' && "
                                       "github.event.workflow_run.head_repository.full_name == github.repository && "
                                       "github.event.workflow_run.actor.login == 'dependabot[bot]' && "
                                       "startsWith(github.event.workflow_run.head_branch, 'dependabot/')"),
                                 "steps":[downloader,checker,checkout,verify,apply,push]}}}
    return producer,consumer


def test_good_contract_all_obligations_hold():
    producer,consumer=prepared()
    result=check_dist_contract(producer,consumer)
    assert result["passed"] and result["passed_count"]==result["total_count"],[k for k,v in result["checks"].items() if not v]
    assert result["total_count"]>=12


@pytest.mark.parametrize("field,mutation",[
    ("publisher_named_and_dist_only",lambda p,c:p["jobs"]["rebuild"]["steps"][-1]["with"].update({"name":"other"})),
    ("publisher_remains_guarded_by_diff",lambda p,c:p["jobs"]["rebuild"]["steps"][-1].update({"if":"true"})),
    ("producer_event_permission_boundary",lambda p,c:p["permissions"].update({"contents":"write"})),
    ("no_pr_ref_interpolated_in_producer_shell",lambda p,c:p["jobs"]["rebuild"]["steps"][0].update({"run":"echo ${{ github.event.pull_request.head.ref }}"})),
    ("matching_download_identity",lambda p,c:c["jobs"]["commit"]["steps"][0]["with"].update({"run-id":"123"})),
    ("download_isolated_and_flat",lambda p,c:c["jobs"]["commit"]["steps"][0]["with"].update({"path":"incoming"})),
    ("consumer_explicit_write_only_in_job",lambda p,c:c["permissions"].update({"contents":"write"})),
    ("consumer_checks_actual_dist_file",lambda p,c:c["jobs"]["commit"]["steps"][1].update({"run":"echo present=true >> $GITHUB_OUTPUT"})),
    ("consumer_moves_exact_downloaded_tree",lambda p,c:c["jobs"]["commit"]["steps"][4].update({"run":"mv elsewhere dist"})),
    ("checkout_target_from_event",lambda p,c:c["jobs"]["commit"]["steps"][2]["with"].update({"ref":"${{ steps.check.outputs.head-ref }}"})),
    ("write_target_environment_bound",lambda p,c:c["jobs"]["commit"]["steps"][5].update({"run":"git push origin HEAD:main"})),
    ("sha_verification_environment_bound",lambda p,c:c["jobs"]["commit"]["steps"][3]["env"].update({"EXPECTED_SHA":"invalid"})),
    ("consumer_authorizes_same_repo_actor_and_branch",lambda p,c:c["jobs"]["commit"].update({"if":"github.event.workflow_run.conclusion == 'success'"})),
])
def test_each_invalid_change_is_detected(field,mutation):
    p,c=prepared()
    mutation(p,c)
    result=check_dist_contract(p,c)
    assert not result["passed"]
    assert result["checks"][field] is False
