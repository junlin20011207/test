"""Generalization tests across arbitrary workflows, permission policies and paths.

No historical project names or job IDs may be embedded in this inventory.
All candidates are metadata evidence; none is labeled an exploit.
"""
import yaml
from benchmarks.cross_project_contracts import examine,path_class


def workspace(tmp_path, linked=True, writer=True, destination="."):
    root=tmp_path/".github/workflows"
    root.mkdir(parents=True)
    producer={
        "name":"Arbitrary Packaging Project",
        "on":{"pull_request":{}},
        "permissions":{"contents":"read"},
        "jobs":{"assembly-of-libraries":{"steps":[{
            "uses":"actions/upload-artifact@v4",
            "with":{"name":"package-out","path":"dist/"}}]}}
    }
    consumer={
        "name":"Separate Publisher",
        "on":{"workflow_run":{"workflows":[
            "Arbitrary Packaging Project" if linked else "missing upstream"]}},
        "permissions":{"contents":"read"},
        "jobs":{"deploy-unrelated-name":{"permissions":{"contents":"write"} if writer else {"contents":"read"},
            "steps":[{"uses":"actions/download-artifact@v4","with":{
                "name":"package-out",
                "run-id":chr(36)+"{{ github.event.workflow_run.id }}",
                "github-token":chr(36)+"{{ github.token }}",
                "path":destination}}]}}}
    for name,data in (("produce.yaml",producer),("consume.yml",consumer)):
        (root/name).write_text(yaml.safe_dump(data,sort_keys=False),"utf8")
    return tmp_path


def test_generic_job_names_link_producer(tmp_path):
    report=examine(workspace(tmp_path))
    assert report["summary"]["total_workflows"]==2
    assert report["summary"]["explicit_upstream_transfers"]==1
    assert report["summary"]["linked_single_producer"]==1
    assert report["entries"][0]["producer_candidates"][0]["publication_status"]=="declared"
    assert report["entries"][0]["classification"]=="transfer_evidence_only"


def test_unmatched_producer_is_unknown_not_safe(tmp_path):
    out=examine(workspace(tmp_path,linked=False))
    assert out["summary"]["source_missing_or_ambiguous"]==1
    assert out["entries"][0]["producer_identity"]=="missing"
    assert out["entries"][0]["classification"]=="transfer_evidence_only"


def test_read_only_consumer_not_mislabeled_as_write(tmp_path):
    out=examine(workspace(tmp_path,writer=False))
    assert out["summary"]["read_only_jobs"]==1
    assert out["summary"]["explicit_write_jobs"]==0


def test_root_vs_runner_temp_transfer_scope(tmp_path):
    assert path_class({"with":{"path":"./"}})=="workspace_root_possible"
    assert path_class({"with":{"path":chr(36)+"{{ runner.temp }}/payload"}})=="runner_temp"
    assert path_class({"with":{"path":chr(36)+"{{ inputs.location }}"}})=="dynamic_unknown"
    assert path_class({"with":{"path":"assets/subdir"}})=="relative_subdirectory"


def test_missing_consumer_policy_explicit_unknown(tmp_path):
    root=workspace(tmp_path)
    target=root/".github/workflows/consume.yml"
    data=yaml.load(target.read_text("utf8"),Loader=yaml.BaseLoader)
    data.pop("permissions")
    data["jobs"]["deploy-unrelated-name"].pop("permissions")
    target.write_text(yaml.safe_dump(data,sort_keys=False),"utf8")
    out=examine(root)
    assert out["summary"]["permission_unknown"]==1
    assert out["summary"]["explicit_write_jobs"]==0
