"""Upstream Artifact declaration evidence tests; no workflow is executed."""
import pytest
import yaml
from boundarygraph import analyze


RUN = "$" + "{{ github.event.workflow_run.id }}"
DYNAMIC = "$" + "{{ matrix.artifact_name }}"


def fixture(tmp_path, *, uploads, requested="", pattern="", cli=False):
    directory=tmp_path / ".github" / "workflows"
    directory.mkdir(parents=True)
    producer={"name":"Producer","on":["pull_request"],"jobs":{
        "build":{"runs-on":"ubuntu-latest","steps":uploads}}}
    consumer_with={"run-id":RUN,"github-token":"fixture-token","path":"incoming"}
    if requested:
        consumer_with["name"]=requested
    if pattern:
        consumer_with["pattern"]=pattern
    download=({"run":"gh run download "+RUN} if cli else
              {"uses":"actions/download-artifact@v4","with":consumer_with})
    consumer={"name":"Consumer","on":{"workflow_run":{"workflows":["Producer"]}},
              "permissions":{"contents":"write"},"jobs":{
                  "use":{"runs-on":"ubuntu-latest","steps":[download,{"run":"echo safe"}]}}}
    (directory/"producer.yml").write_text(yaml.safe_dump(producer,sort_keys=False),encoding="utf8")
    (directory/"consumer.yml").write_text(yaml.safe_dump(consumer,sort_keys=False),encoding="utf8")
    return analyze(tmp_path)


def upload(name=None,*,guard=None):
    values={"path":"fixture.txt"}
    if name is not None:
        values["name"]=name
    result={"uses":"actions/upload-artifact@v4","with":values}
    if guard:
        result["if"]=guard
    return result


@pytest.mark.parametrize(("uploads","requested","pattern","status"),[
    ([upload()],"","","declared"),
    ([upload()],"artifact","","declared"),
    ([upload("audit")],"audit","","declared"),
    ([upload("audit")],"other","","unresolved"),
    ([upload("audit")],"","","declared"),
    ([upload("audit"),upload("evidence")],"","ev*","declared"),
    ([upload("audit")],"","reports-*","unresolved"),
    ([],"","","unresolved"),
    ([{"run":"echo benign"}],"","","unresolved"),
    ([upload(DYNAMIC)],"audit","","unresolved"),
    ([upload("audit",guard="github.event_name == 'push'")],"audit","","conditional"),
])
def test_declared_upload_matching(tmp_path,uploads,requested,pattern,status):
    result=fixture(tmp_path,uploads=uploads,requested=requested,pattern=pattern)
    if status=="declared":
        assert len(result["findings"])==1
        assert not result["unverified"]
        assert result["findings"][0]["publisher_status"]=="declared"
    else:
        assert not result["findings"]
        assert len(result["unverified"])==1
        assert result["unverified"][0]["publisher_status"]==status
        assert result["unknowns"]


def test_no_upstream_artifact_not_misrepresented_as_a_verified_path(tmp_path):
    result=fixture(tmp_path,uploads=[{"run":"echo work complete"}])
    assert not result["findings"]
    assert len(result["unverified"])==1
    assert "no upstream artifact" in result["unverified"][0]["publisher_reason"]


def test_matching_named_declaration_is_not_proof_of_upload_success(tmp_path):
    result=fixture(tmp_path,uploads=[upload("audit")],requested="audit")
    candidate=result["findings"][0]
    assert "runtime success not proven" in candidate["publisher_reason"]
    assert candidate["publisher_names"]==["audit"]


def test_cli_download_can_match_existing_declaration(tmp_path):
    result=fixture(tmp_path,uploads=[upload("artifact")],cli=True)
    assert len(result["findings"])==1
    assert result["findings"][0]["publisher_status"]=="declared"


def test_unknown_third_party_upload_stays_unverified(tmp_path):
    result=fixture(tmp_path,uploads=[
        {"uses":"example/upload-artifact@v2","with":{"name":"audit","path":"something"}}],
        requested="audit")
    assert not result["findings"]
    assert len(result["unverified"])==1
    assert "unmodeled" in result["unverified"][0]["publisher_reason"]


@pytest.mark.parametrize(("suffix","declared"),[
    ("-n artifact",True),
    ("--name artifact",True),
    ("--name=artifact",True),
    ("-D destination",True),
    ("-n other",False),
    ("--name other",False),
    ("-n artifact -n other",False),
    ("-n",False),
    ("--repo unrelated/project",False),
    ("-R unrelated/project",False),
])
def test_cli_artifact_name_selection(tmp_path,suffix,declared):
    fixture(tmp_path,uploads=[upload()],cli=True)
    path=tmp_path/".github"/"workflows"/"consumer.yml"
    consumer=yaml.safe_load(path.read_text(encoding="utf-8"))
    consumer["jobs"]["use"]["steps"][0]["run"]="gh run download "+RUN+" "+suffix
    path.write_text(yaml.safe_dump(consumer,sort_keys=False),encoding="utf-8")
    result=analyze(tmp_path)
    assert bool(result["findings"]) is declared
    if not declared:
        assert result["unverified"] and result["unknowns"]
