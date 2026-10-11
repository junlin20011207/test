"""Qualify artifact metadata source-to-sink witnesses with data dependency."""
import pytest
import yaml
from metadataproof import metadata_proofs
from test_metadataproof import fixture


def mutated(tmp_path,change):
    fixture(tmp_path)
    path=tmp_path/".github"/"workflows"/"c.yml"
    obj=yaml.load(path.read_text("utf8"),Loader=yaml.BaseLoader)
    change(obj["jobs"]["commit"]["steps"])
    path.write_text(yaml.safe_dump(obj,sort_keys=False),encoding="utf8")
    return metadata_proofs(tmp_path)


@pytest.mark.parametrize(("script","expected"),[
    ('head_ref="$(head -n1 "$incoming/dist-meta/head-ref")"\necho "head-ref=$head_ref" >> "$GITHUB_OUTPUT"',1),
    ('head_ref="$(head -n1 "$incoming/dist-meta/head-ref")"\necho "head-ref=main" >> "$GITHUB_OUTPUT"',0),
    ('head_ref="main"\necho "head-ref=$head_ref" >> "$GITHUB_OUTPUT"',0),
    ('# head_ref="$(head "$incoming/dist-meta/head-ref")"\necho "head-ref=$head_ref" >> "$GITHUB_OUTPUT"',0),
    ('head_ref="$(head -n1 "$incoming/dist-meta/head-ref")"\n# echo "head-ref=$head_ref" >> "$GITHUB_OUTPUT"',0),
    ('echo "example: head_ref=$(head dist-meta/head-ref)"\necho "head-ref=main" >> "$GITHUB_OUTPUT"',0),
])
def test_source_must_reach_output(tmp_path,script,expected):
    r=mutated(tmp_path,lambda steps:steps[1].update({"run":script}))
    assert r["count"]==expected


@pytest.mark.parametrize(("push","expected"),[
    ("git push origin HEAD:${{ steps.check.outputs.head-ref }}",1),
    ("echo 'git push origin HEAD:${{ steps.check.outputs.head-ref }}'",0),
    ("# git push origin HEAD:${{ steps.check.outputs.head-ref }}",0),
    ("printf 'git push origin HEAD:${{ steps.check.outputs.head-ref }}'",0),
    ("echo ok\ngit push origin HEAD:${{ steps.check.outputs.head-ref }}",1),
])
def test_write_sink_is_an_executed_command(tmp_path,push,expected):
    r=mutated(tmp_path,lambda steps:steps[3].update({"run":push}))
    assert r["count"]==expected
