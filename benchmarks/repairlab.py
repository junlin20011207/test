"""Experimental repair draft synthesis, never writing to upstream repositories.

Two narrowly supported, previously disclosed advisory patterns. A proof
disappearing after a draft is NOT evidence that the draft preserves behavior.
"""
import difflib
import json
from pathlib import Path
import re
import sys
import tempfile
import yaml
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from benchmarks.scan_public import fetch
from proofcut import inspect
from benchmarks.repair_invariants import load_from_workspace

ROOT=Path(__file__).parent
OUT=ROOT.parent/"baseline-results"/"repairlab"
TMP="$"+"{{ runner.temp }}/proofcut-artifact"


def read_yaml(path):
    return yaml.load(path.read_text("utf8"),Loader=yaml.BaseLoader)


def patch_overlay(workspace):
    path=workspace/".github/workflows/assign_reviewer_review_apply.yaml"
    wf=read_yaml(path)
    steps=wf["jobs"]["apply"]["steps"]
    download=next((s for s in steps if re.fullmatch(r"actions/download-artifact@[^\s]+",
                   str(s.get("uses","")))),None)
    js=next((s for s in steps if re.fullmatch(r"actions/github-script@[^\s]+",
             str(s.get("uses","")))),None)
    if not download or not js:
        raise ValueError("unsupported overlay workflow shape")
    params=download.get("with") or {}
    if str(params.get("path","")).strip() not in ("",".","./"):
        raise ValueError("download is not modeled at workspace root")
    script=str(js["with"].get("script",""))
    source="fs.readFileSync('review.json', 'utf8')"
    replacement=("fs.readFileSync(require('path').join(process.env.RUNNER_TEMP, "
                 "'proofcut-artifact', 'review.json'), 'utf8')")
    if script.count(source)!=1:
        raise ValueError("exactly one known data-file reader is required")
    download["with"]["path"]=TMP
    js["with"]["script"]=script.replace(source,replacement)
    return path,wf,{
        "target":"isolated runner temporary directory",
        "data_reader_relocated":True,
        "scope":"only one known review.json read rewritten",
    }


def patch_metadata(workspace):
    path=workspace/".github/workflows/commit-dist.yml"
    wf=read_yaml(path)
    job=wf["jobs"]["commit"]
    steps=job["steps"]
    old="$"+"{{ steps.check.outputs.head-ref }}"
    trusted="$"+"{{ github.event.workflow_run.head_branch }}"
    checkout=next((s for s in steps if re.fullmatch(r"actions/checkout@[^\s]+",
                   str(s.get("uses","")))),None)
    push=next((s for s in steps if re.search(r"(?m)^\s*git push origin",str(s.get("run","")))),None)
    if not checkout or not push:
        raise ValueError("unsupported metadata workflow shape")
    if checkout.get("with",{}).get("ref")!=old or old not in str(push["run"]):
        raise ValueError("artifact-derived metadata dependency not explicit")
    checkout["with"]["ref"]=trusted
    # GitHub expressions used directly inside Bash can create a distinct
    # code-injection path even when the chosen branch is authorized. Bind via
    # environment instead, quote the refspec, and use the event head SHA.
    push["env"]=dict(push.get("env") or {},HEAD_BRANCH=trusted)
    old_push="git push origin HEAD:"+old
    if old_push not in str(push["run"]):
        raise ValueError("known direct git push ref expression missing")
    push["run"]=str(push["run"]).replace(
        old_push,'git push origin "HEAD:refs/heads/$HEAD_BRANCH"')
    old_head_sha="$"+"{{ steps.check.outputs.head-sha }}"
    verify=next((s for s in steps if "git rev-parse HEAD" in str(s.get("run",""))),None)
    if verify is None or old_head_sha not in str(verify["run"]):
        raise ValueError("untrusted SHA interpolation cannot be safely localized")
    verify["env"]=dict(verify.get("env") or {},
                       EXPECTED_SHA="$"+"{{ github.event.workflow_run.head_sha }}")
    verify["run"]=str(verify["run"]).replace(old_head_sha,"$EXPECTED_SHA")
    # The producer still interpolates the pull-request branch directly into
    # an executable shell expression. The consumer no longer needs this
    # metadata: remove the producer metadata step and adjust artifact layout
    # and downstream presence check together as an explicit data contract.
    producer_path=workspace/".github/workflows/rebuild-dist.yml"
    producer=read_yaml(producer_path)
    original_producer_trigger=producer["on"]
    original_producer_permissions=producer.get("permissions")
    original_producer_jobs=list(producer["jobs"])
    builds=producer["jobs"]["rebuild"]["steps"]
    original_count=len(builds)
    builds[:]=[s for s in builds if s.get("name")!="Record PR context"]
    if len(builds)!=original_count-1:
        raise ValueError("producer has no unique metadata capture step")
    publisher=next((s for s in builds if re.fullmatch(
        r"actions/upload-artifact@[^\s]+",str(s.get("uses","")))),None)
    if not publisher:
        raise ValueError("producer uploader unknown")
    publisher["with"]["path"]="dist/"
    if (producer["on"]!=original_producer_trigger or
        producer.get("permissions")!=original_producer_permissions or
        list(producer["jobs"])!=original_producer_jobs):
        raise ValueError("unintended producer configuration changed")
    producer_path.write_text(yaml.safe_dump(producer,sort_keys=False),encoding="utf8")

    downloader=next((s for s in steps if re.fullmatch(
        r"actions/download-artifact@[^\s]+",str(s.get("uses","")))),None)
    checker=next((s for s in steps if s.get("id")=="check"),None)
    if not downloader or not checker:
        raise ValueError("consumer download/presence-check unknown")
    downloader["with"]["path"]="$"+"{{ runner.temp }}/incoming/dist"
    checker["run"]=(
        'if [ -f "'+"$"+"{{ runner.temp }}"+'/incoming/dist/index.js" ]; then\n'
        '  echo "present=true" >> "$GITHUB_OUTPUT"\n'
        'else\n'
        '  echo "present=false" >> "$GITHUB_OUTPUT"\n'
        'fi')
    old_if=str(job.get("if",""))
    if "github.event.workflow_run" not in old_if:
        raise ValueError("expected upstream-run guard missing")
    job["if"]=(
        "("+old_if+") && "
        "github.event.workflow_run.head_repository.full_name == github.repository && "
        "github.event.workflow_run.actor.login == 'dependabot[bot]' && "
        "startsWith(github.event.workflow_run.head_branch, 'dependabot/')")
    return path,wf,{
        "target":"trusted workflow_run branch context",
        "ref_and_push_migrated":True,
        "authorization_context_added":True,
        "branch_and_sha_passed_through_quoted_shell_environment":True,
        "producer_control_plane_metadata_removed":True,
        "artifact_layout_and_consumer_presence_check_reconciled":True,
        "caveat":"stronger origin guard may restrict legitimate use; runtime workflows not executed",
    }


def run_one(manifest_name,case_label,patcher,family):
    manifest=json.loads((ROOT/manifest_name).read_text("utf8"))
    selected=next(x for x in manifest["cases"] if x["label"]==case_label)
    with tempfile.TemporaryDirectory(prefix="repairlab-proof-") as tmp:
        workspace=Path(tmp)
        for entry in selected["files"]:
            content=fetch(manifest["source"],selected["commit"],entry)
            dest=workspace/entry["path"]
            dest.parent.mkdir(parents=True,exist_ok=True)
            dest.write_bytes(content)
        before=inspect(workspace)
        all_before={item["path"]:(workspace/item["path"]).read_text("utf8")
                    for item in selected["files"]}
        target,patched,desc=patcher(workspace)
        original=read_yaml(target)
        old_text=target.read_text("utf8")
        # Guard against accidentally changing event type, token scopes or job count.
        if original["on"] !=patched["on"]:
            raise AssertionError("trigger changed")
        if original.get("permissions")!=patched.get("permissions"):
            raise AssertionError("permissions changed")
        if list(original["jobs"])!=list(patched["jobs"]):
            raise AssertionError("job structure changed")
        target.write_text(yaml.safe_dump(patched,sort_keys=False),encoding="utf8")
        contract=(load_from_workspace(workspace) if family=="artifact_metadata_to_git_write"
                  else {"passed":None,"checks":{},"scope":"non-dist repair has separate transfer test"})
        if contract["passed"] is False:
            raise AssertionError("producer-consumer contract failed: "+
                                 str([k for k,v in contract["checks"].items() if not v]))
        after=inspect(workspace)
        diff="".join(difflib.unified_diff(
            old_text.splitlines(True),target.read_text("utf8").splitlines(True),
            fromfile="original/"+target.name,tofile="candidate/"+target.name))
        (OUT/(family+".diff")).write_text(diff,encoding="utf8")
        (OUT/(family+".yaml")).write_text(target.read_text("utf8"),encoding="utf8")
        for original_path,previous in all_before.items():
            next_text=(workspace/original_path).read_text("utf8")
            if previous!=next_text:
                basename=Path(original_path).name
                full_diff="".join(difflib.unified_diff(
                    previous.splitlines(True),next_text.splitlines(True),
                    fromfile="original/"+basename,tofile="candidate/"+basename))
                (OUT/(family+"__"+basename+".diff")).write_text(
                    full_diff,encoding="utf8")
                (OUT/(family+"__"+basename)).write_text(next_text,encoding="utf8")
    if before["families"].get(family,0)!=1 or after["families"].get(family,0)!=0:
        raise AssertionError("expected exact pre/post ProofCut path")
    return {
        "family":family,"repo":manifest["source"],"source_sha":selected["commit"],
        "original_model_witness":before["families"][family],
        "draft_model_witness":after["families"][family],
        "event_job_permissions_stable":True,
        "patch_details":desc,
        "machine_checked_producer_consumer_contract":contract,
        "limitation":"static candidate only; this does not prove runtime functionality or safe deploy",
    }


def main():
    OUT.mkdir(parents=True,exist_ok=True)
    reports=[
        run_one("advisory_pairs.json","vulnerable",patch_overlay,"workspace_overwrite_then_load"),
        run_one("metadata_pairs.json","vulnerable",patch_metadata,"artifact_metadata_to_git_write"),
    ]
    (OUT/"summary.json").write_text(json.dumps({
        "passed":True,"n":len(reports),"candidates":reports,
        "important":"do NOT automatically merge patches or claim security/functionality correctness"},
        ensure_ascii=False,indent=2)+"\n",encoding="utf8")
    for r in reports:
        contract=r["machine_checked_producer_consumer_contract"]
        score=(str(contract.get("passed_count"))+"/"+str(contract.get("total_count"))
               if contract["passed"] is not None else "not-applicable")
        print(r["family"],r["original_model_witness"],"->",r["draft_model_witness"],
              "source",r["source_sha"][:12],"repair_contract_checks",score)
    return 0


if __name__=="__main__":
    raise SystemExit(main())
