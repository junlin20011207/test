"""Pinned, read-only external GitHub Actions corpus exploration.

Only downloads publicly published YAML text, verifies Git blob IDs, runs the
local static analyzer, then saves the *unlabelled* output. Never executes YAML.
"""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import time
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from boundarygraph import analyze, read
from sinkproof import sink_proofs
from metadataproof import metadata_proofs

ROOT=Path(__file__).parent
MANIFEST=ROOT/"public_manifest.json"
OUT=ROOT.parent/"baseline-results"/"public"
MAX_BYTES=500_000


def fetch(repo, revision, entry):
    name=entry["path"]
    if not name.startswith(".github/workflows/") or ".." in Path(name).parts:
        raise ValueError("unsafe relative path")
    url="https://raw.githubusercontent.com/"+repo+"/"+revision+"/"+quote(name,safe="/")
    req=Request(url,headers={"User-Agent":"BoundaryGraph-ReadOnly-Corpus-Experiment"})
    for attempt in range(3):
        try:
            with urlopen(req,timeout=30) as response:
                raw=response.read(MAX_BYTES+1)
            break
        except (HTTPError,URLError,TimeoutError,OSError) as exc:
            retryable=(not isinstance(exc,HTTPError) or exc.code in
                       (408,429,500,502,503,504))
            if not retryable or attempt==2:
                raise
            time.sleep(0.5*(attempt+1))
    if len(raw)>MAX_BYTES:
        raise ValueError("file exceeds 500k byte ceiling")
    git_blob=hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\x00"+raw).hexdigest()
    if git_blob != entry["sha"]:
        raise ValueError("Git blob checksum mismatch")
    if len(raw)!=entry["size"]:
        raise ValueError("file size mismatch")
    raw.decode("utf-8")
    return raw


def main():
    manifest=json.loads(MANIFEST.read_text(encoding="utf-8"))
    OUT.mkdir(parents=True,exist_ok=True)
    reports=[]
    for source in manifest["repositories"]:
        repo=source["name"]
        revision=source["commit"]
        errors=[]
        with tempfile.TemporaryDirectory(prefix="boundarygraph-public-") as tmp:
            target=Path(tmp)
            downloaded=0
            for entry in source["files"]:
                try:
                    raw=fetch(repo,revision,entry)
                    dst=target/entry["path"]
                    dst.parent.mkdir(parents=True,exist_ok=True)
                    dst.write_bytes(raw)
                    downloaded+=1
                except (OSError,UnicodeError,ValueError) as exc:
                    errors.append({"path":entry["path"],"type":type(exc).__name__,"detail":str(exc)[:240]})
            result=analyze(target) if downloaded else {"findings":[],"unverified":[],"guarded":[],"unknowns":["no downloaded workflows"],"workflows":0}
            workflows=read(target)[0] if downloaded else []
            run_triggers=sum("workflow_run" in wf["events"] for wf in workflows)
            overlay_report=sink_proofs(target) if downloaded else {"count":0,"proofs":[]}
            metadata_report=metadata_proofs(target) if downloaded else {"count":0,"proofs":[]}
        report={"repository":repo,"commit":revision,"stratum":source.get("stratum","unspecified"),
                "expected_workflows":len(source["files"]),
                "downloaded":downloaded,"incomplete":bool(errors),
                "integrity_verified":downloaded,"workflow_run_triggers":run_triggers,"download_errors":errors,
                "sinkproof_overlay":overlay_report,"sinkproof_metadata":metadata_report,
                "static_scan":result,
                "human_labels":"none; do not compute precision or recall"}
        outfile=OUT/(repo.replace("/","__")+".json")
        outfile.write_text(json.dumps(report,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
        reports.append({"repo":repo,"commit":revision,"stratum":source.get("stratum","unspecified"),"expected":len(source["files"]),
                        "scanned":downloaded,"workflow_run_triggers":run_triggers,"findings":len(result["findings"]),
                        "unverified":len(result.get("unverified",[])),
                        "sinkproof_overlay":overlay_report["count"],"sinkproof_metadata":metadata_report["count"],
                        "unknowns":len(result["unknowns"]),"fetch_errors":len(errors)})
        for group,label in ((result["findings"],"DECLARED"),(result.get("unverified",[]),"UNVERIFIED")):
            for finding in group[:25]:
                producer=Path(finding["producer"]).name
                consumer=Path(finding["consumer"]).name
                print(f"  {label} static candidate: {producer} -> {consumer}, job={finding['job']}, "
                      f"step={finding.get('download_step')}, artifact={finding.get('artifact_name')}, "
                      f"publisher={finding.get('publisher_status')}; reason={finding.get('publisher_reason')}")
        print(f"{repo}@{revision[:12]} ({source.get('stratum','unspecified')}): {downloaded}/{len(source['files'])} verified, "
              f"workflow_run_triggers={run_triggers}, {len(result['findings'])} declared paths, "
              f"{len(result.get('unverified',[]))} unverified transfer candidates, "
              f"overlay_proofs={overlay_report['count']}, metadata_proofs={metadata_report['count']}, "
              f"{len(result['unknowns'])} unknowns, {len(errors)} fetch errors")
    summary={"study":"pinned-public-workflow-corpus","labelled":False,
             "repositories":reports,"complete":all(x["fetch_errors"]==0 for x in reports),
             "scope":"static reconnaissance only; paths are not confirmed vulnerabilities"}
    (OUT/"summary.json").write_text(json.dumps(summary,indent=2)+"\n",encoding="utf-8")
    if not summary["complete"]:
        print("ERROR: corpus download incomplete; no performance claim is justified",file=sys.stderr)
        return 2
    return 0


if __name__=="__main__":
    raise SystemExit(main())
