"""Controlled, non-executing counterfactual mutations of public past vulnerabilities.

Change one relevant workflow field and rerun the relevant proof model.
These are static path cuts, not simulated attacks or complete fix verification.
"""
import json
from pathlib import Path
import sys
import tempfile
import yaml
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from benchmarks.scan_public import fetch
from sinkproof import sink_proofs
from metadataproof import metadata_proofs

BASE=Path(__file__).parent
OUT=BASE.parent/"baseline-results"/"counterfactuals"


def snapshot(manifest_file,case_name="vulnerable"):
    m=json.loads((BASE/manifest_file).read_text("utf8"))
    case=next(x for x in m["cases"] if x["label"]==case_name)
    return m,case


def with_snapshot(manifest,case,mutate,scanner):
    with tempfile.TemporaryDirectory(prefix="boundarygraph-mut-") as tmp:
        root=Path(tmp)
        for entry in case["files"]:
            data=fetch(manifest["source"],case["commit"],entry)
            p=root/entry["path"]
            p.parent.mkdir(parents=True,exist_ok=True)
            p.write_bytes(data)
        mutate(root)
        return scanner(root)["count"]


def load_consumer(root,filename):
    path=root/".github"/"workflows"/filename
    data=yaml.load(path.read_text("utf8"),Loader=yaml.BaseLoader)
    return path,data


def save_consumer(path,data):
    path.write_text(yaml.safe_dump(data,sort_keys=False),encoding="utf8")


def overlay_mutation(which):
    def change(root):
        if which=="original":
            return
        path,data=load_consumer(root,"assign_reviewer_review_apply.yaml")
        steps=data["jobs"]["apply"]["steps"]
        if which=="placebo":
            steps[0]["name"]="Checkout (renamed only)"
        elif which=="isolate":
            next(s for s in steps if "download-artifact@" in str(s.get("uses","")))["with"]["path"]="$"+"{{ runner.temp }}/safe-data"
        elif which=="no_import":
            next(s for s in steps if "github-script@" in str(s.get("uses","")))["with"]["script"]="core.info('No local module is loaded')"
        else:
            raise ValueError(which)
        save_consumer(path,data)
    return change


def metadata_mutation(which):
    def change(root):
        if which=="original":
            return
        path,data=load_consumer(root,"commit-dist.yml")
        steps=data["jobs"]["commit"]["steps"]
        if which=="placebo":
            steps[0]["name"]="Artifact download (renamed only)"
        elif which=="trusted_checkout_ref":
            step=next(s for s in steps if "checkout@" in str(s.get("uses","")))
            step["with"]["ref"]="$"+"{{ github.event.workflow_run.head_branch }}"
        elif which=="trusted_push_ref":
            step=next(s for s in steps if "git push origin" in str(s.get("run","")))
            step["run"]=str(step["run"]).replace("steps.check.outputs.head-ref",
                                                    "github.event.workflow_run.head_branch")
        elif which=="stronger_text_filter":
            step=next(s for s in steps if "dist-meta/head-ref" in str(s.get("run","")))
            step["run"]=str(step["run"]).replace("[A-Za-z0-9._/-]+","[A-Za-z0-9._/-]{1,120}")
        else:
            raise ValueError(which)
        save_consumer(path,data)
    return change


def main():
    OUT.mkdir(parents=True,exist_ok=True)
    cases=[
        ("overlay","advisory_pairs.json",sink_proofs,overlay_mutation,
         [("original",1),("placebo",1),("isolate",0),("no_import",0)]),
        ("metadata","metadata_pairs.json",metadata_proofs,metadata_mutation,
         [("original",1),("placebo",1),("trusted_checkout_ref",0),
          ("trusted_push_ref",0),("stronger_text_filter",1)]),
    ]
    reports=[]
    for family,filename,scanner,mutator,variants in cases:
        m,case=snapshot(filename)
        for name,expected in variants:
            observed=with_snapshot(m,case,mutator(name),scanner)
            print(f"{family}/{name}: observed={observed}, expected={expected}")
            reports.append({"family":family,"variant":name,"expected":expected,
                            "observed":observed,"passed":observed==expected})
    passed=all(x["passed"] for x in reports)
    (OUT/"summary.json").write_text(json.dumps({
        "method":"controlled static mutation on two published historical vulnerable revisions",
        "passed":passed,"n":len(reports),"observations":reports,
        "limitations":"mutations are source-level counterfactuals, not executed exploit tests"}
        ,indent=2)+"\n","utf8")
    return 0 if passed else 1


if __name__=="__main__":
    raise SystemExit(main())
