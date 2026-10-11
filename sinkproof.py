"""Defensive source-to-workspace-overwrite-to-import evidence checker.

Only reasons about selected GitHub Actions patterns. Never executes downloaded
files and does not establish exploitability or overall workflow safety.
"""
import argparse
import json
import posixpath
import re
from boundarygraph import analyze, read, shell_commands

JS_IMPORT=re.compile(r"""(?:require\s*\(\s*|from\s+|import\s*\(\s*)["'](\./[^"']+)["']""")
SHELL_EXEC=re.compile(r"""(?:^|[;&|\n]\s*)(?:bash|sh|python(?:3(?:\.\d+)?)?|node|source)\s+(\./[\w./-]+)""")


def download_area(step):
    params=step.get("with") or {}
    if not isinstance(params,dict):
        return "unknown"
    path=str(params.get("path","")).strip()
    if not path or path in (".","./","./."):
        return "workspace_root"
    if chr(36)+"{{" in path:
        if re.fullmatch(r"\$\{\{\s*runner\.temp\s*\}\}/[^$]+",path):
            return "isolated_temp"
        return "unknown_dynamic"
    norm=posixpath.normpath(path)
    if norm==".":
        return "workspace_root"
    if norm==".." or norm.startswith("../"):
        return "unknown_traversal"
    return "isolated_directory"


def trusted_checkout(step):
    action=str(step.get("uses","")).lower()
    if not re.fullmatch(r"actions/checkout@[^\s]+",action):
        return False
    params=step.get("with") or {}
    if not isinstance(params,dict):
        return False
    ref=str(params.get("ref","")).strip()
    return chr(36)+"{{" not in ref and not any(
        phrase in ref for phrase in ("pull_request.head","workflow_run.head_sha","github.head_ref"))


def checkout_covers(step, executable):
    """Three-valued coverage of an executable by a checkout."""
    if not trusted_checkout(step):
        return "unknown"
    params=step.get("with") or {}
    raw_path=str(params.get("path","")).strip()
    if chr(36)+"{{" in raw_path:
        return "unknown"
    if posixpath.normpath(raw_path or ".")!=".":
        return "excluded"
    sparse=str(params.get("sparse-checkout","")).strip()
    if not sparse:
        return "covered"
    if chr(36)+"{{" in sparse:
        return "unknown"
    targets=[posixpath.normpath(line.strip().removeprefix("./"))
             for line in sparse.splitlines()
             if line.strip() and not line.lstrip().startswith("#")]
    target=executable.removeprefix("./")
    return "covered" if any(t=="." or target==t or target.startswith(t+"/")
                            for t in targets) else "excluded"


def js_code_positions(script):
    """Lex strings and comments; this is not a JavaScript parser."""
    clean=list(script)
    active=set()
    mode="code"
    i=0
    while i<len(script):
        ch=script[i]
        nxt=script[i+1] if i+1<len(script) else ""
        if mode=="code":
            if ch=="/" and nxt in ("/","*"):
                mode="line" if nxt=="/" else "block"
                clean[i]=clean[i+1]=" "
                i+=2
                continue
            if ch in ("'",'"',chr(96)):
                mode=ch
            else:
                active.add(i)
            i+=1
            continue
        if mode in ("'",'"',chr(96)):
            if ch==chr(92):
                i+=2
                continue
            if ch==mode:
                mode="code"
            i+=1
            continue
        if mode=="line":
            if ch=="\n":
                mode="code"
            else:
                clean[i]=" "
            i+=1
            continue
        if mode=="block":
            if ch=="*" and nxt=="/":
                clean[i]=clean[i+1]=" "
                i+=2
                mode="code"
            else:
                if ch!="\n":clean[i]=" "
                i+=1
    return "".join(clean),active


def referenced_executables(step):
    targets=[]
    action=str(step.get("uses","")).lower()
    params=step.get("with") or {}
    if re.fullmatch(r"actions/github-script@[^\s]+",action) and isinstance(params,dict):
        clean,code=js_code_positions(str(params.get("script","")))
        targets.extend(m.group(1) for m in JS_IMPORT.finditer(clean)
                       if m.start() in code)
    commands=shell_commands(str(step.get("run","")))
    if commands:
        for cmd in commands:
            if not cmd:
                continue
            if cmd[0] in ("bash","sh","source",".","node","python","python3"):
                args=[a for a in cmd[1:] if not a.startswith("-")]
                if args and args[0].startswith("./"):
                    targets.append(args[0])
            elif cmd[0].startswith("./"):
                targets.append(cmd[0])
    return sorted(set(posixpath.normpath(f) for f in targets if f.startswith("./")))

def sink_proofs(root="."):
    workflows,read_errors=read(root)
    by_path={w["path"]:w for w in workflows}
    baseline=analyze(root)
    proofs=[]
    gaps=[]
    for entry in baseline["findings"]+baseline.get("unverified",[]):
        producer=by_path.get(entry["producer"])
        if producer is None or not producer["events"].intersection(
            {"pull_request","pull_request_review"}):
            gaps.append({"consumer":entry["consumer"],
                         "reason":"producer fork-modifiable workflow origin not established"})
            continue
        if entry.get("publisher_status")!="declared":
            gaps.append({"consumer":entry["consumer"],"job":entry["job"],
                         "reason":"publisher not unconditionally declared"})
            continue
        workflow=by_path.get(entry["consumer"])
        if not workflow:
            continue
        job=workflow["raw"]["jobs"].get(entry["job"],{})
        steps=job.get("steps",[])
        i=entry.get("download_step")
        if not isinstance(steps,list) or not isinstance(i,int) or i>=len(steps):
            gaps.append({"consumer":entry["consumer"],"reason":"steps unresolved"})
            continue
        area=download_area(steps[i])
        if area!="workspace_root":
            gaps.append({"consumer":entry["consumer"],"job":entry["job"],
                         "reason":"no modeled root-overwrite evidence: "+area})
            continue
        checkouts=[j for j in range(i) if isinstance(steps[j],dict)
                   and trusted_checkout(steps[j])]
        if not checkouts:
            gaps.append({"consumer":entry["consumer"],"job":entry["job"],
                         "reason":"no earlier trusted checkout"})
            continue
        for j in range(i+1,len(steps)):
            step=steps[j]
            if not isinstance(step,dict) or str(step.get("if","")).strip() in (
                "false",chr(36)+"{{ false }}"):
                continue
            for target in referenced_executables(step):
                coverage=[k for k in checkouts
                          if checkout_covers(steps[k],target)=="covered"]
                if not coverage:
                    gaps.append({"consumer":entry["consumer"],"job":entry["job"],
                                 "reason":"no checkout proven to contain loaded path "+target})
                    continue
                proofs.append({
                    "rule":"BG-OVERLAY-001",
                    "status":"potential_overwrite_then_load",
                    "impact":"potential privileged execution, not verified",
                    "producer":entry["producer"],"consumer":entry["consumer"],
                    "job":entry["job"],"artifact_name":entry.get("artifact_name",""),
                    "checkout_step":coverage[-1],"download_step":i,"load_step":j,
                    "loaded_path":target,
                    "publisher_status":entry["publisher_status"],
                    "witness":[
                        "untrusted upstream event and matching producer publication",
                        "privileged downstream selects triggering upstream run",
                        "covered checkout at step "+str(coverage[-1])+" precedes artifact download",
                        "download at step "+str(i)+" extracts at workspace root",
                        "relative executable "+target+" imported/executed at step "+str(j),
                    ],
                    "repair":"extract into an isolated directory; validate expected data and never execute it"
                })
    return {"proofs":proofs,"count":len(proofs),"gaps":gaps,
            "baseline_candidates":len(baseline["findings"])+len(baseline.get("unverified",[])),
            "unknowns":sorted(set(read_errors+baseline["unknowns"])),
            "scope":"narrow static overwrite-and-load pattern; no general safety certification"}


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("path",nargs="?",default=".")
    parser.add_argument("--json",action="store_true")
    parser.add_argument("--strict",action="store_true")
    args=parser.parse_args()
    report=sink_proofs(args.path)
    if args.json:
        print(json.dumps(report,ensure_ascii=False,indent=2))
    else:
        print(f"{report['count']} overlay/load candidates, {len(report['gaps'])} gaps")
    return int(bool(report["proofs"] or report["unknowns"]) if args.strict else False)


if __name__=="__main__":
    raise SystemExit(main())
