"""MetadataProof: artifact-derived Git control target in a privileged workflow.

This is a narrow *static* path model: artifact file -> step output -> checkout
ref and git push target. It never runs workflows or interprets arbitrary shell.
"""
import argparse
import json
import re
from boundarygraph import analyze, read

STEP_OUTPUT=re.compile(r"steps\.([A-Za-z_][A-Za-z0-9_-]*)\.outputs\.([A-Za-z_][A-Za-z0-9_-]*)")
CHECKOUT=re.compile(r"actions/checkout@[^\s]+")


def contents_write(workflow,job):
    p=job.get("permissions",workflow.get("permissions"))
    return isinstance(p,dict) and p.get("contents")=="write"


def artifact_metadata_output(step):
    """Find a very specific untrusted head-ref metadata -> step output bridge."""
    run=str(step.get("run",""))
    if not step.get("id"):
        return None
    if not re.search(r"dist-meta/head-ref",run):
        return None
    if "GITHUB_OUTPUT" not in run or not re.search(r"head-ref\s*=",run):
        return None
    if not re.search(r"head_ref\s*=",run):
        return None
    return str(step["id"]),"head-ref"


def metadata_proofs(root="."):
    workflows,read_unknown=read(root)
    index={w["path"]:w for w in workflows}
    base=analyze(root)
    evidence=[]
    gaps=[]
    for candidate in base["findings"]+base.get("unverified",[]):
        if candidate.get("publisher_status") not in ("declared","conditional"):
            continue
        source=index.get(candidate["consumer"])
        if not source:
            continue
        job=source["raw"]["jobs"].get(candidate["job"],{})
        if not contents_write(source["raw"],job):
            gaps.append({"consumer":candidate["consumer"],"reason":"contents: write not explicit"})
            continue
        steps=job.get("steps",[])
        if not isinstance(steps,list):
            continue
        start=candidate["download_step"]
        for i in range(start+1,len(steps)):
            step=steps[i]
            if not isinstance(step,dict):
                continue
            mapping=artifact_metadata_output(step)
            if mapping is None:
                continue
            step_id,output_name=mapping
            checkout_steps=[]
            push_steps=[]
            for j in range(i+1,len(steps)):
                nxt=steps[j]
                if not isinstance(nxt,dict):
                    continue
                uses=str(nxt.get("uses","")).lower()
                params=nxt.get("with") or {}
                if re.fullmatch(CHECKOUT,uses) and isinstance(params,dict):
                    ref=str(params.get("ref",""))
                    if (step_id,output_name) in STEP_OUTPUT.findall(ref):
                        checkout_steps.append(j)
                command=str(nxt.get("run",""))
                if "git push" in command and (step_id,output_name) in STEP_OUTPUT.findall(command):
                    push_steps.append(j)
            if not checkout_steps or not push_steps:
                gaps.append({"consumer":candidate["consumer"],"job":candidate["job"],
                             "reason":"no observed downstream checkout + git push of artifact-derived ref"})
                continue
            evidence.append({
                "rule":"BG-META-001",
                "status":"potential_artifact_driven_write_target",
                "impact":"attacker-influenced Git target, not verified exploitation",
                "producer":candidate["producer"],"consumer":candidate["consumer"],
                "job":candidate["job"],"artifact_name":candidate.get("artifact_name",""),
                "publisher_status":candidate.get("publisher_status"),
                "download_step":start,"metadata_step":i,
                "checkout_steps":checkout_steps,"push_steps":push_steps,
                "output":step_id+"."+output_name,
                "witness":[
                    "potential low-trust upstream artifact is downloaded by privileged job",
                    "artifact dist-meta/head-ref is read into GitHub step output",
                    "artifact-derived ref drives a later checkout",
                    "same derived ref controls a git push destination"
                ],
                "repair":"authorize branch using workflow_run event and verify fork/actor provenance; never trust artifact metadata to select a writable ref"
            })
    return {"proofs":evidence,"count":len(evidence),"gaps":gaps,
            "baseline_candidates":len(base["findings"])+len(base.get("unverified",[])),
            "unknowns":sorted(set(read_unknown+base["unknowns"])),
            "scope":"specific metadata-to-checkout-and-push pattern only"}


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("path",nargs="?",default=".")
    parser.add_argument("--json",action="store_true")
    args=parser.parse_args()
    r=metadata_proofs(args.path)
    print(json.dumps(r,indent=2) if args.json else
          f"{r['count']} artifact-driven Git target candidates")
    return 0


if __name__=="__main__":
    raise SystemExit(main())
