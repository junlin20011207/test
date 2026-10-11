"""Metamorphic controls for semantic qualification of an overlay witness."""
import pytest
import yaml
from sinkproof import sink_proofs
from test_sinkproof import fixture

MODULE="./.github/workflows/scripts/helper.js"

def change(tmp_path,transform):
    fixture(tmp_path)
    p=tmp_path/".github"/"workflows"/"consumer.yml"
    data=yaml.load(p.read_text("utf8"),Loader=yaml.BaseLoader)
    transform(data["jobs"]["deploy"]["steps"])
    p.write_text(yaml.safe_dump(data,sort_keys=False),encoding="utf8")
    return sink_proofs(tmp_path)


@pytest.mark.parametrize(("checkout_path","sparse","expected"),[
    ("","",1),
    ("src","",0),
    ("other-root","",0),
    ("",".github/workflows/scripts",1),
    ("","docs",0),
    ("",".github/assets",0),
    ("",".github/workflows/scripts\nother",1),
])
def test_only_checked_out_paths_can_be_overwritten(tmp_path,checkout_path,sparse,expected):
    def mutate(steps):
        if checkout_path: steps[0]["with"]["path"]=checkout_path
        if sparse: steps[0]["with"]["sparse-checkout"]=sparse
    r=change(tmp_path,mutate)
    assert r["count"]==expected


@pytest.mark.parametrize(("script","expected"),[
    ("// require('./.github/workflows/scripts/helper.js')",0),
    ("/* require('./.github/workflows/scripts/helper.js') */",0),
    ("const text = \"require('./.github/workflows/scripts/helper.js')\";",0),
    ("const text = 'require(\"./.github/workflows/scripts/helper.js\")';",0),
    ("const text = "+chr(96)+"require('./.github/workflows/scripts/helper.js')"+chr(96)+";",0),
    ("const url='https://safe.example'; const x=require('./.github/workflows/scripts/helper.js');",1),
    ("/* no-op */ const x=require('./.github/workflows/scripts/helper.js');",1),
    ("const x=require('./.github/workflows/scripts/helper.js'); // allowed",1),
])
def test_script_code_is_not_comments_or_strings(tmp_path,script,expected):
    r=change(tmp_path,lambda steps:steps[2]["with"].update({"script":script}))
    assert r["count"]==expected


@pytest.mark.parametrize(("command","expected"),[
    ("echo 'bash ./.github/workflows/scripts/helper.js'",0),
    ("echo bash ./.github/workflows/scripts/helper.js",0),
    ("# bash ./.github/workflows/scripts/helper.js",0),
    ("bash ./.github/workflows/scripts/helper.js",1),
    ("echo starting && bash ./.github/workflows/scripts/helper.js",1),
])
def test_shell_commands_vs_echo_arguments(tmp_path,command,expected):
    def mutate(steps):
        steps[2]={"run":command}
    r=change(tmp_path,mutate)
    assert r["count"]==expected
