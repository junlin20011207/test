import pytest
from boundarygraph import analyze


def make(tmp_path, event="pull_request", guard="", permission="write", remote=True, execute=True):
    folder=tmp_path/".github"/"workflows"
    folder.mkdir(parents=True)
    (folder/"a.yml").write_text("name: Producer\non: ["+event+"]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo harmless\n      - uses: actions/upload-artifact@v4\n        with: {path: fixture.txt}\n")
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
    assert r["findings"][0]["severity"]=="high"


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


def test_explicit_download_directory_script_execution(tmp_path):
    folder=tmp_path/".github"/"workflows"
    folder.mkdir(parents=True)
    (folder/"producer.yml").write_text(
        "name: Producer\non: [pull_request]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/upload-artifact@v4\n        with: {path: fixture.txt}\n")
    (folder/"consumer.yml").write_text(
        "name: Consumer\non:\n  workflow_run:\n    workflows: [Producer]\n"
        "permissions: {contents: write}\njobs:\n  deploy:\n"
        "    runs-on: ubuntu-latest\n    steps:\n"
        "      - uses: actions/download-artifact@v4\n"
        "        with:\n          github-token: token\n"
        "          run-id: ${{ github.event.workflow_run.id }}\n"
        "          path: ./incoming\n"
        "      - run: bash ./incoming/entry.sh\n")
    result=analyze(tmp_path)
    assert len(result["findings"])==1
    assert result["findings"][0]["severity"]=="critical"


def test_unrelated_script_not_attributed_to_artifact(tmp_path):
    result=make(tmp_path,execute=True)
    assert result["findings"][0]["severity"]=="high"
    assert "not established" in result["findings"][0]["witness"][-1]


@pytest.mark.parametrize("guard",[
    "github.event.workflow_run.event == 'push' == false",
    "contains('github.event.workflow_run.event == \\'push\\'', 'push')",
    "github.event.workflow_run.event == 'push' || true",
    "github.event.workflow_run.event == 'push' && false",
])
def test_ambiguous_guard_never_claims_protected(tmp_path,guard):
    assert make(tmp_path,guard=guard)["findings"]


def test_wrapped_exact_push_guard_is_protected(tmp_path):
    guard="${{ github.event.workflow_run.event == 'push' }}"
    result=make(tmp_path,guard=guard)
    assert not result["findings"] and result["guarded"]


def test_second_shell_command_under_download_path(tmp_path):
    folder=tmp_path/".github"/"workflows"
    folder.mkdir(parents=True)
    (folder/"a.yml").write_text(
        "name: Producer\non: [pull_request]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/upload-artifact@v4\n        with: {path: fixture.txt}\n")
    (folder/"b.yml").write_text(
        "name: Consumer\non:\n  workflow_run:\n    workflows: [Producer]\n"
        "permissions: {contents: write}\njobs:\n  deploy:\n"
        "    runs-on: ubuntu-latest\n    steps:\n"
        "      - uses: actions/download-artifact@v4\n"
        "        with:\n          github-token: token\n"
        "          run-id: ${{ github.event.workflow_run.id }}\n"
        "          path: ./incoming\n"
        "      - run: echo inspect && bash ./incoming/entry.sh\n")
    result=analyze(tmp_path)
    assert result["findings"][0]["severity"]=="critical"

def test_download_step_push_guard_cuts_transfer(tmp_path):
    folder=tmp_path/".github"/"workflows"
    folder.mkdir(parents=True)
    (folder/"a.yml").write_text(
        "name: Producer\non: [pull_request]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/upload-artifact@v4\n        with: {path: fixture.txt}\n")
    (folder/"b.yml").write_text(
        "name: Consumer\non:\n  workflow_run:\n    workflows: [Producer]\n"
        "permissions: {contents: write}\njobs:\n  deploy:\n"
        "    runs-on: ubuntu-latest\n    steps:\n"
        "      - uses: actions/download-artifact@v4\n"
        "        if: github.event.workflow_run.event == 'push'\n"
        "        with:\n          github-token: token\n"
        "          run-id: ${{ github.event.workflow_run.id }}\n"
        "          path: ./incoming\n"
        "      - run: bash ./incoming/entry.sh\n")
    result=analyze(tmp_path)
    assert not result["findings"]
    assert any(g.get("reason")=="artifact transfer gated to trusted push origin" for g in result["guarded"])


def test_download_step_ambiguous_guard_does_not_cut(tmp_path):
    folder=tmp_path/".github"/"workflows"
    folder.mkdir(parents=True)
    (folder/"a.yml").write_text(
        "name: Producer\non: [pull_request]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/upload-artifact@v4\n        with: {path: fixture.txt}\n")
    (folder/"b.yml").write_text(
        "name: Consumer\non:\n  workflow_run:\n    workflows: [Producer]\n"
        "permissions: {contents: write}\njobs:\n  deploy:\n"
        "    runs-on: ubuntu-latest\n    steps:\n"
        "      - uses: actions/download-artifact@v4\n"
        "        if: github.event.workflow_run.event == 'push' || true\n"
        "        with:\n          github-token: token\n"
        "          run-id: ${{ github.event.workflow_run.id }}\n"
        "          path: ./incoming\n"
        "      - run: bash ./incoming/entry.sh\n")
    result=analyze(tmp_path)
    assert result["findings"][0]["severity"]=="critical"
