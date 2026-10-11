"""Pinned, read-only external GitHub Actions corpus exploration.

Only downloads publicly published YAML text, verifies Git blob IDs, runs the
local static analyzer, then saves the *unlabelled* output. Never executes YAML.
"""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
from urllib.parse import quote
from urllib.request import Request, urlopen

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from boundarygraph import analyze

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
    with urlopen(req,timeout=30) as response:
        raw=response.read(MAX_BYTES+1)
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
            result=analyze(target) if downloaded else {"findings":[],"guarded":[],"unknowns":["no downloaded workflows"],"workflows":0}
        report={"repository":repo,"commit":revision,"stratum":source.get("stratum","unspecified"),
                "expected_workflows":len(source["files"]),
                "downloaded":downloaded,"incomplete":bool(errors),
                "integrity_verified":downloaded,"download_errors":errors,
                "static_scan":result,
                "human_labels":"none; do not compute precision or recall"}
        outfile=OUT/(repo.replace("/","__")+".json")
        outfile.write_text(json.dumps(report,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
        reports.append({"repo":repo,"commit":revision,"stratum":source.get("stratum","unspecified"),"expected":len(source["files"]),
                        "scanned":downloaded,"findings":len(result["findings"]),
                        "unknowns":len(result["unknowns"]),"fetch_errors":len(errors)})
        for finding in result["findings"][:25]:
            producer=Path(finding["producer"]).name
            consumer=Path(finding["consumer"]).name
            print(f"  UNLABELLED {finding['severity']}: {producer} -> {consumer}, job={finding['job']}; "
                  f"witness={finding['witness'][-2:]}")
        print(f"{repo}@{revision[:12]} ({source.get('stratum','unspecified')}): {downloaded}/{len(source['files'])} verified, "
              f"{len(result['findings'])} unlabelled path candidates, "
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
