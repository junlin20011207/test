import pytest
from boundarygraph import analyze


def make(tmp_path, event="pull_request", guard="", permission="write", remote=True, execute=True):
    folder=tmp_path/".github"/"workflows"
    folder.mkdir(parents=True)
    (folder/"a.yml").write_text("name: Producer\non: ["+event+"]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo harmless\n")
    upstream=chr(36)+"{{ github.event.workflow_run.id }}"
    source=("        with:\n          github-token: test-token\n          run-id: "+upstream+"\n") if remote else ""
    gated=("    if: >-\n      "+guard+"\n") if guard else ""
    cmd="      - run: bash ./fixture.sh\n" if execute else ""
    (folder/"b.yml").write_text(
       "name: Consumer\non:\n  workflow_run:\n    workflows: [Producer]\n"+
       "permissions:\n  contents: "+permission+"\njobs:\n  deploy:\n    runs-on: ubuntu-latest\n"+
       gated+"    steps:\n      - uses: actions/download-artifact@v4\n"+source+cmd)
    return analyze(tmp_path)


@pytest.mark.parametrize("event",["pull_request","pull_request_target","issue_comment","discussion_comment"])
def test_untrusted_event(tmp_path,event):
    r=make(tmp_path,event=event)
    assert len(r["findings"])==1
    assert r["findings"][0]["severity"]=="critical"


@pytest.mark.parametrize("event",["push","schedule","workflow_dispatch"])
def test_trusted_event(tmp_path,event):
    assert not make(tmp_path,event=event)["findings"]


def test_push_guard_cuts_untrusted_path(tmp_path):
    r=make(tmp_path,guard="github.event.workflow_run.event == 'push'")
    assert not r["findings"] and r["guarded"]


def test_success_is_not_provenance(tmp_path):
    assert make(tmp_path,guard="github.event.workflow_run.conclusion == 'success'")["findings"]


def test_disjunction_not_trusted(tmp_path):
    assert make(tmp_path,guard="github.event.workflow_run.event == 'push' || true")["findings"]


def test_read_only_token(tmp_path):
    assert not make(tmp_path,permission="read")["findings"]


def test_current_run_artifact_not_cross_run(tmp_path):
    assert not make(tmp_path,remote=False)["findings"]


def test_no_exec_only_high_severity(tmp_path):
    assert make(tmp_path,execute=False)["findings"][0]["severity"]=="high"


def test_unknown_producer_not_silent(tmp_path):
    make(tmp_path)
    (tmp_path/".github/workflows/a.yml").unlink()
    r=analyze(tmp_path)
    assert not r["findings"] and r["unknowns"]


def test_invalid_yaml_not_silent(tmp_path):
    folder=tmp_path/".github/workflows";folder.mkdir(parents=True)
    (folder/"bad.yml").write_text("jobs: [")
    assert analyze(tmp_path)["unknowns"]
