"""Safety-focused metamorphic tests; fixture YAML is never installed as workflows."""
from pathlib import Path
import pytest
import yaml
from boundarygraph import analyze


RUN = "$" + "{{ github.event.workflow_run.id }}"


def analyze_fixture(tmp_path, command, *, consumer_step_guard=None,
                    consumer_job_guard=None, permission="write", producer_event="pull_request",
                    upstream=True, secret=False):
    d = tmp_path / ".github" / "workflows"
    d.mkdir(parents=True, exist_ok=True)
    producer = {"name": "Producer", "on": [producer_event], "jobs": {
        "build": {"runs-on": "ubuntu-latest", "steps": [{"run": "echo benign"}]}
    }}
    steps = [{"uses": "actions/download-artifact@v4",
              "with": {"run-id": RUN, "github-token": "synthetic-test-token", "path": "./incoming"}},
             {"run": command}]
    if consumer_step_guard is not None:
        steps[0]["if"] = consumer_step_guard
    job = {"runs-on": "ubuntu-latest", "steps": steps}
    if consumer_job_guard is not None:
        job["if"] = consumer_job_guard
    if secret:
        job["env"] = {"MARKER": "$" + "{{ secrets.SYNTHETIC_MARKER }}"}
    consumer = {"name": "Consumer",
                "on": {"workflow_run": {"workflows": ["Producer"], "types": ["completed"]}},
                "permissions": {"contents": permission},
                "jobs": {"use": job}}
    (d / "producer.yml").write_text(yaml.safe_dump(producer, sort_keys=False), encoding="utf-8")
    (d / "consumer.yml").write_text(yaml.safe_dump(consumer, sort_keys=False), encoding="utf-8")
    if not upstream:
        steps[0]["with"].pop("run-id")
        (d / "consumer.yml").write_text(yaml.safe_dump(consumer, sort_keys=False), encoding="utf-8")
    return analyze(tmp_path)


@pytest.mark.parametrize(("command", "severity"), [
    ("bash ./incoming/entry.sh", "critical"),
    ("sh ./incoming/entry.sh", "critical"),
    ("python3 ./incoming/check.py", "critical"),
    ("python3 -u ./incoming/check.py", "critical"),
    ("source ./incoming/env.sh", "critical"),
    (". ./incoming/env.sh", "critical"),
    ("./incoming/entry.sh", "critical"),
    ("echo inspect && bash ./incoming/entry.sh", "critical"),
    ("echo inspect\nbash ./incoming/entry.sh", "critical"),
    ("echo inspect | bash ./incoming/entry.sh", "critical"),
    ('echo "bash ./incoming/entry.sh"', "high"),
    ("echo bash ./incoming/entry.sh", "high"),
    ("echo harmless # bash ./incoming/entry.sh", "high"),
    ("bash ./incoming/../safe.sh", "high"),
    ("bash ./incoming-other/entry.sh", "high"),
    ("bash ./trusted/entry.sh", "high"),
    ("echo inspect\n# bash ./incoming/entry.sh", "high"),
    ("cat ./incoming/entry.sh", "high"),
])
def test_shell_command_mutations(tmp_path, command, severity):
    r = analyze_fixture(tmp_path, command)
    assert len(r["findings"]) == 1
    assert r["findings"][0]["severity"] == severity


@pytest.mark.parametrize(("guard", "is_cut"), [
    ("github.event.workflow_run.event == 'push'", True),
    ("$" + "{{ github.event.workflow_run.event == 'push' }}", True),
    ("github.event.workflow_run.event == 'push' || true", False),
    ("github.event.workflow_run.event == 'push' && false", False),
    ("github.event.workflow_run.conclusion == 'success'", False),
])
def test_download_guard_mutations(tmp_path, guard, is_cut):
    r = analyze_fixture(tmp_path, "bash ./incoming/entry.sh", consumer_step_guard=guard)
    assert bool(r["guarded"]) == is_cut
    assert bool(r["findings"]) != is_cut


def test_execution_step_guard_is_not_executable_under_untrusted_origin(tmp_path):
    d = tmp_path / ".github" / "workflows"
    d.mkdir(parents=True)
    source = {"name":"Producer","on":["pull_request"],
              "jobs":{"build":{"runs-on":"ubuntu-latest","steps":[{"run":"echo ok"}]}}}
    target = {"name":"Consumer","on":{"workflow_run":{"workflows":["Producer"]}},
              "permissions":{"contents":"write"},
              "jobs":{"use":{"runs-on":"ubuntu-latest","steps":[
                  {"uses":"actions/download-artifact@v4",
                   "with":{"github-token":"synthetic", "run-id":RUN, "path":"incoming"}},
                  {"if":"github.event.workflow_run.event == 'push'",
                   "run":"bash ./incoming/entry.sh"}]}}}
    (d/"a.yml").write_text(yaml.safe_dump(source),encoding="utf-8")
    (d/"b.yml").write_text(yaml.safe_dump(target),encoding="utf-8")
    findings=analyze(tmp_path)["findings"]
    assert len(findings)==1
    assert findings[0]["severity"]=="high"


@pytest.mark.parametrize(("event", "permission", "remote", "secrets", "risk"), [
    ("pull_request", "write", True, False, True),
    ("pull_request", "read", True, False, False),
    ("pull_request", "read", True, True, True),
    ("pull_request", "write", False, False, False),
    ("push", "write", True, False, False),
    ("issue_comment", "write", True, False, True),
    ("workflow_dispatch", "write", True, False, False),
])
def test_source_privilege_mutations(tmp_path, event, permission, remote, secrets, risk):
    r=analyze_fixture(tmp_path, "bash ./incoming/entry.sh",
                      permission=permission, producer_event=event,
                      upstream=remote, secret=secrets)
    assert bool(r["findings"]) is risk


def test_missing_scan_target_not_silent(tmp_path):
    missing=tmp_path/"missing-repo"
    result=analyze(missing)
    assert result["unknowns"] and not result["findings"]


def test_empty_workflow_directory_not_silent(tmp_path):
    (tmp_path/".github"/"workflows").mkdir(parents=True)
    result=analyze(tmp_path)
    assert any("no YAML workflows" in issue for issue in result["unknowns"])


def test_similarly_named_third_party_action_not_misidentified(tmp_path):
    analyze_fixture(tmp_path,"bash ./incoming/entry.sh")
    path=tmp_path/".github"/"workflows"/"consumer.yml"
    content=path.read_text(encoding="utf-8")
    assert "actions/download-artifact@v4" in content
    path.write_text(content.replace("actions/download-artifact@v4",
                                    "unrelated/actions/download-artifact@v4"),encoding="utf-8")
    result=analyze(tmp_path)
    assert not result["findings"]


@pytest.mark.parametrize(("run_id", "token", "recognized"), [
    ("${{ github.event.workflow_run.id }}", "token", True),
    ("${{github.event.workflow_run.id}}", "token", True),
    ("  ${{ github.event.workflow_run.id }}  ", "token", True),
    ("github.event.workflow_run.id", "token", False),
    ("prefix-${{ github.event.workflow_run.id }}", "token", False),
    ("${{ github.event.workflow_run.id }}-suffix", "token", False),
    ("${{ github.event.workflow_run.id || 1 }}", "token", False),
    ("${{ github.event.workflow_run.id }}", "", False),
    ("1234", "token", False),
])
def test_official_artifact_run_identity_exactness(tmp_path,run_id,token,recognized):
    analyze_fixture(tmp_path,"bash ./incoming/entry.sh")
    path=tmp_path/".github"/"workflows"/"consumer.yml"
    content=yaml.safe_load(path.read_text(encoding="utf-8"))
    step=content["jobs"]["use"]["steps"][0]
    step["with"]["run-id"]=run_id
    step["with"]["github-token"]=token
    path.write_text(yaml.safe_dump(content,sort_keys=False),encoding="utf-8")
    result=analyze(tmp_path)
    assert bool(result["findings"]) == recognized
    if not recognized:
        assert result["unknowns"]


@pytest.mark.parametrize(("command", "recognized"), [
    ("gh run download ${{ github.event.workflow_run.id }}", True),
    ('gh run download "${{ github.event.workflow_run.id }}"', True),
    ("echo ok && gh run download ${{ github.event.workflow_run.id }}", True),
    ("echo ok\ngh run download ${{ github.event.workflow_run.id }}", True),
    ('echo "gh run download ${{ github.event.workflow_run.id }}"', False),
    ('printf "echo done; gh run download ${{ github.event.workflow_run.id }}"', False),
    ("echo ok # gh run download ${{ github.event.workflow_run.id }}", False),
    ("gh run download 1234", False),
    ("gh run download -n build", False),
    ("gh run download ${{ github.event.workflow_run.id || 1 }}", False),
    ("gh run list", False),
])
def test_gh_cli_run_identity_not_substring(tmp_path,command,recognized):
    analyze_fixture(tmp_path,"echo harmless")
    path=tmp_path/".github"/"workflows"/"consumer.yml"
    content=yaml.safe_load(path.read_text(encoding="utf-8"))
    content["jobs"]["use"]["steps"]=[
        {"run":command},{"run":"echo benign"}
    ]
    path.write_text(yaml.safe_dump(content,sort_keys=False),encoding="utf-8")
    result=analyze(tmp_path)
    assert bool(result["findings"]) == recognized
    if "gh run download" in command and not recognized and command.startswith("gh "):
        assert result["unknowns"]


def test_pull_request_review_source_not_assumed_trusted(tmp_path):
    result=analyze_fixture(tmp_path,"echo harmless",producer_event="pull_request_review")
    assert len(result["findings"])==1
    assert "pull_request_review" in result["findings"][0]["witness"][0]


def test_benign_workflow_run_no_upstream_is_an_unknown_not_a_risk(tmp_path):
    result=analyze_fixture(tmp_path,"echo harmless",producer_event="push")
    assert not result["findings"]


def test_distinct_artifact_downloads_have_distinct_witnesses(tmp_path):
    analyze_fixture(tmp_path,"echo harmless")
    path=tmp_path/".github"/"workflows"/"consumer.yml"
    wf=yaml.safe_load(path.read_text(encoding="utf-8"))
    steps=wf["jobs"]["use"]["steps"]
    steps[0]["with"]["name"]="primary-report"
    steps.append({"uses":"actions/download-artifact@v4",
                  "with":{"run-id":RUN,"github-token":"synthetic-test-token",
                          "name":"secondary-report","path":"./secondary"}})
    path.write_text(yaml.safe_dump(wf,sort_keys=False),encoding="utf-8")
    findings=analyze(tmp_path)["findings"]
    assert len(findings)==2
    assert {item["download_step"] for item in findings}=={0,2}
    assert {item["artifact_name"] for item in findings}=={"primary-report","secondary-report"}
    assert all(item["download_action"]=="actions/download-artifact@v4" for item in findings)
