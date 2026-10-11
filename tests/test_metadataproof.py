"""Safe synthetic metadata-to-git-write pattern fixtures."""
import pytest
import yaml
from metadataproof import metadata_proofs

RUN="$"+"{{ github.event.workflow_run.id }}"
REF="$"+"{{ steps.check.outputs.head-ref }}"
EVENT_REF="$"+"{{ github.event.workflow_run.head_branch }}"
TMP="$"+"{{ runner.temp }}/incoming"


def fixture(tmp_path,*, upload=True, write=True, bridge=True,
            checkout_ref=REF, push_ref=REF):
    root=tmp_path/".github"/"workflows"
    root.mkdir(parents=True,exist_ok=True)
    producer={"name":"Rebuild dist","on":["pull_request"],"jobs":{"rebuild":{
        "runs-on":"ubuntu-latest","steps":(
            [{"uses":"actions/upload-artifact@v4","with":{"name":"rebuilt-dist","path":"dist/"}}]
            if upload else [{"run":"echo no artifact"}])}}}
    extraction={"uses":"actions/download-artifact@v4","with":{
        "name":"rebuilt-dist","run-id":RUN,"github-token":"fixture","path":TMP}}
    check={"id":"check","run":(
        'head_ref="$(head -n1 "$incoming/dist-meta/head-ref")"\n'
        'echo "head-ref=$head_ref" >> "$GITHUB_OUTPUT"' if bridge
        else 'echo "present=true" >> "$GITHUB_OUTPUT"')}
    steps=[extraction,check,
           {"uses":"actions/checkout@v4","with":{"ref":checkout_ref}},
           {"run":"git push origin HEAD:"+push_ref}]
    consumer={"name":"Commit dist","on":{"workflow_run":{"workflows":["Rebuild dist"]}},
              "permissions":{"contents":"read"},"jobs":{"commit":{
                  "runs-on":"ubuntu-latest",
                  "permissions":{"contents":"write" if write else "read"},
                  "steps":steps}}}
    (root/"p.yml").write_text(yaml.safe_dump(producer,sort_keys=False),encoding="utf8")
    (root/"c.yml").write_text(yaml.safe_dump(consumer,sort_keys=False),encoding="utf8")
    return metadata_proofs(tmp_path)


def test_artifact_driven_branch_write_complete_path(tmp_path):
    r=fixture(tmp_path)
    assert r["count"]==1
    p=r["proofs"][0]
    assert (p["download_step"],p["metadata_step"])==(0,1)
    assert p["checkout_steps"]==[2]
    assert p["push_steps"]==[3]


@pytest.mark.parametrize("kwargs",[
    {"upload":False},
    {"write":False},
    {"bridge":False},
    {"checkout_ref":EVENT_REF},
    {"push_ref":EVENT_REF},
    {"checkout_ref":"main"},
    {"push_ref":"HEAD:refs/heads/main"},
])
def test_metadata_control_paths_cut(tmp_path,kwargs):
    assert fixture(tmp_path,**kwargs)["count"]==0


def test_untrusted_ref_is_a_data_dependency_not_shell_injection_proof(tmp_path):
    p=fixture(tmp_path)["proofs"][0]
    assert "not verified exploitation" in p["impact"]


def test_issue_comment_alone_is_not_evidence_of_attacker_controlled_artifact(tmp_path):
    fixture(tmp_path)
    p=tmp_path/".github"/"workflows"/"p.yml"
    obj=yaml.load(p.read_text("utf8"),Loader=yaml.BaseLoader)
    obj["on"]=["issue_comment"]
    p.write_text(yaml.safe_dump(obj,sort_keys=False),encoding="utf8")
    r=metadata_proofs(tmp_path)
    assert r["count"]==0
    assert any("fork-modifiable" in x["reason"] for x in r["gaps"])
