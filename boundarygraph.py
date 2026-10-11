"""BoundaryGraph: defensive GitHub Actions event-conditioned artifact trust-path analysis."""
from pathlib import Path
import argparse, json, re, shlex, posixpath
import yaml

UNTRUSTED={"pull_request","pull_request_target","pull_request_review","issue_comment","discussion_comment","pull_request_review_comment","issues"}
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

UPSTREAM_RUN_ID=re.compile(r"\s*\$\{\{\s*github\.event\.workflow_run\.id\s*\}\}\s*\Z")


def shell_commands(command):
    """Split a small, auditable subset of visible shell syntax.

    Lexing is only used to recognize explicit top-level commands; it is not a
    security proof of full Bash semantics. Unparseable input stays unknown.
    """
    try:
        lex=shlex.shlex(str(command),posix=True,punctuation_chars=";&|()")
        lex.whitespace=" \t\r"
        lex.whitespace_split=False
        lex.commenters="#"
        tokens=list(lex)
    except ValueError:
        return None
    separators={"\n",";","&&","||","|","&","(",")"}
    commands=[]
    current=[]
    for token in [*tokens,"\n"]:
        if token in separators:
            if current:commands.append(current)
            current=[]
        else:
            current.append(token)
    return commands


def gh_download_source(tokens):
    """Recognize only gh run download with an explicit upstream run argument.

    Unmodeled flags/variables are unknown, never evidence of exact provenance.
    """
    if tokens[:3] != ["gh","run","download"]:
        return None
    rest=tokens[3:]
    if not rest:
        return False
    if UPSTREAM_RUN_ID.fullmatch(rest[0]):
        return True
    if rest[:6] == ["$","{","{","github.event.workflow_run.id","}","}"]:
        return True
    return False


def transfers(steps):
    ids=[];unknown=[]
    for i,s in enumerate(steps):
        if not isinstance(s,dict):continue
        action=str(s.get("uses","")).lower().strip()
        params=s.get("with") or {}
        if not isinstance(params,dict):params={}
        if re.fullmatch(r"actions/download-artifact@[^\s]+",action):
            run_id=str(params.get("run-id",""))
            token=str(params.get("github-token","")).strip()
            if UPSTREAM_RUN_ID.fullmatch(run_id) and token:
                ids.append(i)
            elif run_id or token:
                unknown.append("official artifact run identity not proven")
        elif re.fullmatch(r"dawidd6/action-download-artifact@[^\s]+",action):
            run_id=str(params.get("run_id",""))
            if UPSTREAM_RUN_ID.fullmatch(run_id):
                ids.append(i)
            else:
                unknown.append("third-party artifact origin unresolved")
        else:
            command=str(s.get("run",""))
            commands=shell_commands(command)
            if commands is None:
                if "gh run download" in command:
                    unknown.append("CLI download command could not be parsed")
                continue
            for tokens in commands:
                source=gh_download_source(tokens)
                if source is True:
                    ids.append(i)
                elif source is False:
                    unknown.append("CLI artifact run identity unresolved")
    return sorted(set(ids)),unknown


def artifact_publications(producer):
    """Statically declared names are not proof an artifact upload ran."""
    named={}
    uncertain=[]
    jobs=producer["raw"].get("jobs",{})
    for job_name,job in jobs.items():
        if not isinstance(job,dict):
            continue
        if job.get("uses"):
            uncertain.append("reusable job may publish artifacts")
        steps=job.get("steps",[])
        if not isinstance(steps,list):
            uncertain.append("unmodeled publisher steps")
            continue
        for i,step in enumerate(steps):
            if not isinstance(step,dict):
                continue
            action=str(step.get("uses","")).strip().lower()
            if re.fullmatch(r"actions/upload-artifact@[^\s]+",action):
                params=step.get("with") or {}
                if not isinstance(params,dict) or not params.get("path"):
                    uncertain.append("upload has missing path")
                    continue
                if str(params.get("archive","true")).lower()=="false":
                    uncertain.append("unarchived artifact name follows source file")
                    continue
                name=str(params.get("name") or "artifact").strip()
                if not name or chr(36)+"{{" in name:
                    uncertain.append("dynamic artifact name")
                    continue
                named.setdefault(name,[]).append({
                    "job":str(job_name),"step":i,
                    "conditional":bool(step.get("if") or job.get("if"))})
            elif ("upload-artifact" in action or
                  ("upload" in str(step.get("run","")).lower() and
                   "artifact" in str(step.get("run","")).lower())):
                uncertain.append("unmodeled artifact publisher")
    return named,sorted(set(uncertain))


def gh_requested_artifact_names(tokens):
    """Parse CLI artifact selectors for a confirmed upstream run-id.

    None means unsupported selector syntax, not an unrestricted artifact name.
    """
    rest=tokens[3:]
    if not rest:
        return None
    if UPSTREAM_RUN_ID.fullmatch(rest[0]):
        remaining=rest[1:]
    elif rest[:6] == ["$","{","{","github.event.workflow_run.id","}","}"]:
        remaining=rest[6:]
    else:
        return None
    names=[]
    idx=0
    while idx<len(remaining):
        part=remaining[idx]
        if part in ("-n","--name"):
            if idx+1>=len(remaining):
                return None
            value=remaining[idx+1]
            if not value or chr(36)+"{{" in value:
                return None
            names.append(value)
            idx+=2
        elif part.startswith("--name="):
            value=part.partition("=")[2]
            if not value or chr(36)+"{{" in value:
                return None
            names.append(value)
            idx+=1
        elif part in ("-D","--dir"):
            if idx+1>=len(remaining):
                return None
            idx+=2
        else:
            # Other flags and additional positional arguments are not modeled.
            return None
    return names


def publication_match(producer, download_step):
    """Return declared/conditional/unresolved, never runtime proof."""
    named,unknown=artifact_publications(producer)
    params=download_step.get("with") or {}
    if not isinstance(params,dict):
        params={}
    requested=str(params.get("name","")).strip()
    pattern=str(params.get("pattern","")).strip()
    action=str(download_step.get("uses","shell")).lower()
    if action=="shell":
        commands=shell_commands(download_step.get("run",""))
        match=[tokens for tokens in (commands or []) if gh_download_source(tokens) is True]
        if len(match)!=1:
            return "unresolved",[],"CLI artifact source is absent or ambiguous"
        requested_names=gh_requested_artifact_names(match[0])
        if requested_names is None:
            return "unresolved",[],"CLI artifact name selector not modeled"
        names_to_match=requested_names or sorted(named)
        matches=[name for name in names_to_match if name in named]
        if matches and len(matches)==len(names_to_match):
            conditional=any(item["conditional"] for n in matches for item in named[n])
            return ("conditional" if conditional else "declared"),sorted(set(matches)),(
                "upstream upload declared; runtime success not proven")
        return "unresolved",[],"CLI artifact name not established in upstream upload declarations"
    if not re.fullmatch(r"actions/download-artifact@[^\s]+",action):
        return "unresolved",[],"download selector semantics not modeled"
    if (chr(36)+"{{" in requested or chr(36)+"{{" in pattern or
        (requested and pattern)):
        return "unresolved",[],"dynamic or conflicting artifact selector"
    if pattern:
        import fnmatch
        matches=[n for n in named if fnmatch.fnmatchcase(n,pattern)]
    elif requested:
        matches=[requested] if requested in named else []
    else:
        matches=sorted(named)
    if matches:
        conditional=any(x["conditional"] for n in matches for x in named[n])
        return ("conditional" if conditional else "declared"),matches,(
            "upload has conditions" if conditional else
            "upstream upload declared; runtime success not proven")
    if unknown:
        return "unresolved",[],"; ".join(unknown)
    if named:
        return "unresolved",[],("no declared upstream artifact matches selector; known: "
                               +", ".join(sorted(named)))
    return "unresolved",[],"no upstream artifact publication observed"


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
        commands=shell_commands(command)
        if commands is None:
            continue
        for current in commands:
            executable=current[0]
            candidate=None
            if executable in ("bash","sh","source",".","node") or re.fullmatch(r"python(?:\d+(?:\.\d+)?)?",executable):
                args=current[1:]
                candidate=next((arg for arg in args if not arg.startswith("-")),None)
            elif executable.startswith("./"):
                candidate=executable
            if candidate and chr(36)+"{{" not in candidate:
                resolved=posixpath.normpath(candidate)
                if resolved.startswith(directory+"/"):
                    return True
    return False

def analyze(root="."):
    workflows,unknown=read(root)
    named={}
    for w in workflows:named.setdefault(w["name"],[]).append(w)
    findings=[];guarded=[];unverified=[]
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
                        status,published_names,publisher_reason=publication_match(producer,steps[i])
                        possible_exec=artifact_execution_evidence(steps,i)
                        candidate={
                          "rule":"BG-CROSS-001","severity":"critical" if possible_exec else "high",
                          "producer":producer["path"],"consumer":consumer["path"],"job":str(jobname),
                          "download_step":i,
                          "download_action":str(steps[i].get("uses","shell")),
                          "artifact_name":str((steps[i].get("with") or {}).get("name","")) if isinstance(steps[i].get("with") or {},dict) else "",
                          "publisher_status":status,
                          "publisher_names":published_names,
                          "publisher_reason":publisher_reason,
                          "witness":["untrusted events "+",".join(bad),"workflow_run "+str(name),
                                    "explicit upstream artifact transfer",permission+" secret_refs="+str(secrets),
                                    "downloaded content execution: "+("path-correlated candidate" if possible_exec else "not established")],
                          "repair":["require trusted upstream event for privileged job",
                                    "isolate untrusted artifacts in read-only validation",
                                    "avoid code execution of untrusted artifact; reduce token rights"],
                          "boundary":"Potential influence path, not proof of exploitation."}
                        if status=="declared":
                            findings.append(candidate)
                        else:
                            unverified.append(candidate)
                            unknown.append(consumer["path"]+": upstream artifact publication "+status+
                                           " for "+str(name)+": "+publisher_reason)
    return {"workflows":len(workflows),"findings":findings,"unverified":unverified,"guarded":guarded,
            "unknowns":sorted(set(unknown)),
            "scope":"explicit upstream upload declarations required for findings; no proof of runtime upload"}

def main(argv=None):
    a=argparse.ArgumentParser()
    a.add_argument("path",nargs="?",default=".")
    a.add_argument("--strict",action="store_true")
    a.add_argument("--json",action="store_true")
    args=a.parse_args(argv)
    r=analyze(args.path)
    print(json.dumps(r,ensure_ascii=False,indent=2) if args.json else
          f'{r["workflows"]} workflows, {len(r["findings"])} declared paths, {len(r["unverified"])} unverified, {len(r["unknowns"])} unknowns')
    return int(bool(r["findings"]) or (args.strict and bool(r["unknowns"])))

if __name__=="__main__":raise SystemExit(main())
