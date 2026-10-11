"""Safe, non-executable fixtures that model a historical overwrite pattern."""
import pytest
import yaml
from sinkproof import sink_proofs

RUN="$"+"{{ github.event.workflow_run.id }}"
TMP="$"+"{{ runner.temp }}/reports"


def fixture(tmp_path, path=None, *, publisher=True, checkout=True, load=True,
            low_event="pull_request_review", permissions="write", guard=None):
    folder=tmp_path/".github"/"workflows"
    folder.mkdir(parents=True,exist_ok=True)
    producer={"name":"Producer","on":[low_event],"jobs":{"build":{
        "runs-on":"ubuntu-latest","steps":(
            [{"uses":"actions/upload-artifact@v4","with":{"name":"audit","path":"safe-report.txt"}}]
            if publisher else [{"run":"echo benign"}])}}}
    steps=[]
    if checkout:
        steps.append({"uses":"actions/checkout@v4","with":{"ref":"main"}})
    download={"uses":"actions/download-artifact@v4","with":{
        "name":"audit","run-id":RUN,"github-token":"fixture","path":path} }
    if path is None:
        del download["with"]["path"]
    steps.append(download)
    if load:
        steps.append({"uses":"actions/github-script@v8","with":{
            "script":"const a = require('./.github/workflows/scripts/helper.js'); a();"}})
    else:
        steps.append({"run":"echo no downstream dynamic import"})
    job={"runs-on":"ubuntu-latest","steps":steps}
    if guard:
        job["if"]=guard
    consumer={"name":"Consumer","on":{"workflow_run":{"workflows":["Producer"]}},
              "permissions":{"contents":permissions},"jobs":{"deploy":job}}
    (folder/"producer.yml").write_text(yaml.safe_dump(producer,sort_keys=False),encoding="utf8")
    (folder/"consumer.yml").write_text(yaml.safe_dump(consumer,sort_keys=False),encoding="utf8")
    return sink_proofs(tmp_path)


def test_workspace_import_produces_step_level_witness(tmp_path):
    result=fixture(tmp_path)
    assert result["count"]==1
    proof=result["proofs"][0]
    assert proof["checkout_step"]==0
    assert proof["download_step"]==1
    assert proof["load_step"]==2
    assert proof["loaded_path"]==".github/workflows/scripts/helper.js"


@pytest.mark.parametrize("path",[
    "incoming",
    "./incoming",
    TMP,
    "/tmp/reports",
])
def test_isolated_download_does_not_overlay_checked_out_module(tmp_path,path):
    result=fixture(tmp_path,path)
    assert result["count"]==0
    assert result["gaps"]


@pytest.mark.parametrize("options",[
    {"publisher":False},
    {"checkout":False},
    {"load":False},
    {"low_event":"push"},
    {"permissions":"read"},
    {"guard":"github.event.workflow_run.event == 'push'"},
])
def test_trust_boundary_negative_controls(tmp_path,options):
    assert fixture(tmp_path,**options)["count"]==0


def test_explicit_root_path_is_still_an_overlay_candidate(tmp_path):
    assert fixture(tmp_path,"./")["count"]==1


def test_unresolved_dynamic_path_not_false_overlay(tmp_path):
    dynamic="$"+"{{ matrix.destination }}"
    report=fixture(tmp_path,dynamic)
    assert not report["proofs"]


def test_proof_independent_of_late_data_validation(tmp_path):
    """Validating data after loading a workspace helper is too late."""
    report=fixture(tmp_path)
    assert report["count"]==1
