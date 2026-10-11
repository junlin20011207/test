"""BoundaryGraph: defensive GitHub Actions event-conditioned artifact trust-path analysis."""
from pathlib import Path
import argparse, json, re, shlex, posixpath
import yaml

UNTRUSTED={"pull_request","pull_request_target","issue_comment","discussion_comment","pull_request_review_comment","issues"}
PUSH_GUARD=re.compile(r"""github\.event\.workflow_run\.event\s*==\s*['"]push['"]|['"]push['"]\s*==\s*github\.event\.workflow_run\.event""")
EXEC=re.compile(r"(?:^|[\s;&|])(?:bash|sh|python\d*|node|source|eval|\.\/|chmod\s+\+x|npm\s+run)",re.I)
SECRET=re.compile(r"secrets\.(?!GITHUB_TOKEN\b)[A-Z_]\w*",re.I)

def read(root):
    root=Path(root)
    if not root.exists():
        return [],[str(root)+": path does not exist"]
    files=sorted(root.glob(".github/workflows/*.y*ml")) if root.is_dir() else [root]

    if root.is_dir() and not files:files=sorted(root.glob("*.y*ml"))
    if not files:return [],[str(root)+": no YAML workflows found"]
    w=[];unknown=[]
    for p in files:
        try:
            d=yaml.load(p.read_text(encoding="utf8"),Loader=yaml.BaseLoader)
            if not isinstance(d,dict) or not isinstance(d.get("jobs"),dict):
                unknown.append(str(p)+": invalid workflow");continue
            ev=d.get("on",{})
            events={ev} if isinstance(ev,str) else set(ev) if isinstance(ev,(list,dict)) else set()
            w.append({"path":str(p),"name":str(d.get("name") or p.stem),"events":events,"raw":d})
        except (OSError,yaml.YAMLError,UnicodeError):
            unknown.append(str(p)+": unreadable YAML")
    return w,unknown

def protected(condition):
    """Conservatively recognize only a complete push-origin guard."""
    c=str(condition or "").strip()
    if c.startswith("${{") and c.endswith("}}"):
        c=c[3:-2].strip()
    c=re.sub(r"\s+"," ",c)
    return bool(PUSH_GUARD.fullmatch(c))

def privilege(w,j):
    p=j.get("permissions",w.get("permissions"))
    if p is None:return True,"unknown token policy"
    if isinstance(p,dict):
        scopes=[str(k) for k,v in p.items() if v=="write"]
        return bool(scopes),"write scopes="+",".join(scopes)
    return p not in ("read-all","none"),"permissions="+str(p)

def transfers(steps):
    ids=[];unknown=[]
    for i,s in enumerate(steps):
        if not isinstance(s,dict):continue
        action=str(s.get("uses","")).lower()
        params=s.get("with") or {}
        if not isinstance(params,dict):params={}
        command=str(s.get("run",""))
        if re.fullmatch(r"actions/download-artifact@[^\s]+",action):
            run_id=str(params.get("run-id",""))
            token=str(params.get("github-token",""))
            # The official action defaults to CURRENT run, not the upstream run.
            if "github.event.workflow_run.id" in run_id and token:ids.append(i)
            elif run_id or token:unknown.append("download run identity unresolved")
        elif re.fullmatch(r"dawidd6/action-download-artifact@[^\s]+",action):
            if "github.event.workflow_run.id" in str(params.get("run_id","")):ids.append(i)
            else:unknown.append("third-party artifact origin unresolved")
        elif "gh run download" in command:
            if "github.event.workflow_run.id" in command:ids.append(i)
            else:unknown.append("CLI artifact origin unresolved")
    return ids,unknown

def artifact_execution_evidence(steps, download_index):
    """Conservative script-execution candidate correlated to the artifact directory.

    Tokenize visible shell commands so comments, echo arguments and quoted strings
    aren't mistaken for executed commands. This is not a full shell interpreter.
    """
    download=steps[download_index]
    params=download.get("with") or {}
    if not isinstance(params,dict):return False
    path=str(params.get("path","")).strip().rstrip("/")
    if not path or chr(36)+"{{" in path:return False
    directory=posixpath.normpath(path)
    if directory in (".","/") or directory.startswith("../") or posixpath.isabs(directory):
        return False
    separators={"\n",";","&&","||","|","&","(",")"}
    for step in steps[download_index+1:]:
        if not isinstance(step,dict) or protected(step.get("if","")):
            continue
        command=str(step.get("run",""))
        if not command:continue
        try:
            lex=shlex.shlex(command,posix=True,punctuation_chars=";&|()")
            lex.whitespace=" \t\r"
            lex.whitespace_split=False
            lex.commenters="#"
            tokens=list(lex)
        except ValueError:
            # An unparseable shell command does not justify critical severity.
            continue
        current=[]
        for token in [*tokens,"\n"]:
            if token not in separators:
                current.append(token)
                continue
            if not current:
                continue
            executable=current[0]
            candidate=None
            if executable in ("bash","sh","source",".","node") or re.fullmatch(r"python(?:\d+(?:\.\d+)?)?",executable):
                args=current[1:]
                # A short option flag is not a file. No attempt to decode -c.
                candidate=next((arg for arg in args if not arg.startswith("-")),None)
            elif executable.startswith("./"):
                candidate=executable
            if candidate and chr(36)+"{{" not in candidate:
                resolved=posixpath.normpath(candidate)
                if resolved.startswith(directory+"/"):
                    return True
            current=[]
    return False

def analyze(root="."):
    workflows,unknown=read(root)
    named={}
    for w in workflows:named.setdefault(w["name"],[]).append(w)
    findings=[];guarded=[]
    for consumer in workflows:
        if "workflow_run" not in consumer["events"]:continue
        conf=consumer["raw"]["on"].get("workflow_run",{})
        names=conf.get("workflows",[]) if isinstance(conf,dict) else []
        if isinstance(names,str):names=[names]
        if not isinstance(names,list):names=[]
        if not names:unknown.append(consumer["path"]+": no upstream reference")
        for name in names:
            if name not in named:unknown.append(consumer["path"]+": unknown upstream "+str(name))
            for producer in named.get(name,[]):
                bad=sorted(producer["events"] & UNTRUSTED)
                if not bad:continue
                for jobname,job in consumer["raw"]["jobs"].items():
                    if not isinstance(job,dict):continue
                    if protected(job.get("if","")):
                        guarded.append({"consumer":consumer["path"],"job":str(jobname),"producer":producer["path"]});continue
                    steps=job.get("steps",[])
                    if not isinstance(steps,list):
                        unknown.append(consumer["path"]+": unmodeled steps");continue
                    downloads,unknown_sources=transfers(steps)
                    unknown.extend(consumer["path"]+": "+u for u in unknown_sources)
                    privileged,permission=privilege(consumer["raw"],job)
                    secrets=bool(SECRET.search(str(job)+str(consumer["raw"].get("env",{}))))
                    if not privileged and not secrets:continue
                    for i in downloads:
                        if protected(steps[i].get("if","")):
                            guarded.append({"consumer":consumer["path"],"job":str(jobname),"producer":producer["path"],"step":i,"reason":"artifact transfer gated to trusted push origin"})
                            continue
                        possible_exec=artifact_execution_evidence(steps,i)
                        findings.append({
                          "rule":"BG-CROSS-001","severity":"critical" if possible_exec else "high",
                          "producer":producer["path"],"consumer":consumer["path"],"job":str(jobname),
                          "witness":["untrusted events "+",".join(bad),"workflow_run "+str(name),
                                    "explicit upstream artifact transfer",permission+" secret_refs="+str(secrets),
                                    "downloaded content execution: "+("path-correlated candidate" if possible_exec else "not established")],
                          "repair":["require trusted upstream event for privileged job",
                                    "isolate untrusted artifacts in read-only validation",
                                    "avoid code execution of untrusted artifact; reduce token rights"],
                          "boundary":"Potential influence path, not proof of exploitation."})
    return {"workflows":len(workflows),"findings":findings,"guarded":guarded,
            "unknowns":sorted(set(unknown)),
            "scope":"limited static proof obligations; no findings does not mean safe"}

def main(argv=None):
    a=argparse.ArgumentParser()
    a.add_argument("path",nargs="?",default=".")
    a.add_argument("--strict",action="store_true")
    a.add_argument("--json",action="store_true")
    args=a.parse_args(argv)
    r=analyze(args.path)
    print(json.dumps(r,ensure_ascii=False,indent=2) if args.json else
          f'{r["workflows"]} workflows, {len(r["findings"])} findings, {len(r["unknowns"])} unknowns')
    return int(bool(r["findings"]) or (args.strict and bool(r["unknowns"])))

if __name__=="__main__":raise SystemExit(main())
