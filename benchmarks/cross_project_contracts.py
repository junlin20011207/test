"""Workflow-independent upstream artifact contract evidence inventory.

Reports observable source/path/privilege facts and unknowns; not exploitability.
"""
from pathlib import Path
import json
from boundarygraph import read,transfers,publication_match,privilege

DOLLAR=chr(36)+"{{"
UNTRUSTED={"pull_request","pull_request_target","pull_request_review","issue_comment","issues"}


def path_class(step):
    params=step.get("with") or {}
    path=str(params.get("path","")).strip() if isinstance(params,dict) else ""
    if not path or path in (".","./",DOLLAR+" github.workspace }}"):
        return "workspace_root_possible"
    if path.startswith(DOLLAR+" runner.temp }}"):
        return "runner_temp"
    if DOLLAR in path:
        return "dynamic_unknown"
    if path.startswith("/") or path.startswith("../") or path=="..":
        return "external_or_parent_path"
    return "relative_subdirectory"


def examine(root):
    files,parse_unknown=read(root)
    by_name={}
    for wf in files:
        by_name.setdefault(wf["name"],[]).append(wf)
    entries=[]
    count={"total_workflows":len(files),"workflow_run_consumers":0,
           "consumer_jobs":0,"explicit_upstream_transfers":0,
           "linked_single_producer":0,"source_missing_or_ambiguous":0,
           "untrusted_event_producer_candidates":0,
           "potential_workspace_root":0,"runner_temp":0,
           "other_paths":0,"explicit_write_jobs":0,
           "read_only_jobs":0,"permission_unknown":0}
    for wf in files:
        if "workflow_run" not in wf["events"]:
            continue
        count["workflow_run_consumers"]+=1
        wr=wf["raw"].get("on") or {}
        cfg=wr.get("workflow_run",{}) if isinstance(wr,dict) else {}
        names=cfg.get("workflows",[]) if isinstance(cfg,dict) else []
        names=[names] if isinstance(names,str) else names if isinstance(names,list) else []
        possible=[p for name in names for p in by_name.get(str(name),[])]
        for job_name,job in wf["raw"]["jobs"].items():
            if not isinstance(job,dict) or not isinstance(job.get("steps"),list):
                continue
            count["consumer_jobs"]+=1
            indices,_=transfers(job["steps"])
            for idx in indices:
                step=job["steps"][idx]
                source=[]
                for p in possible:
                    kind,matching,reason=publication_match(p,step)
                    source.append({"file":Path(p["path"]).name,
                                   "event_types":sorted(p["events"]),
                                   "untrusted_event_possible":bool(p["events"] & UNTRUSTED),
                                   "publication_status":kind,"artifact_names":matching,
                                   "limits":reason})
                identity="unique" if len(source)==1 else "missing" if not source else "ambiguous"
                route=path_class(step)
                permission=job.get("permissions",wf["raw"].get("permissions"))
                write,reason=privilege(wf["raw"],job)
                policy="unknown" if permission is None else "write" if write else "read_only"
                count["explicit_upstream_transfers"]+=1
                count["linked_single_producer"]+=int(identity=="unique")
                count["source_missing_or_ambiguous"]+=int(identity!="unique")
                count["untrusted_event_producer_candidates"]+=int(any(p["untrusted_event_possible"] for p in source))
                count["potential_workspace_root"]+=int(route=="workspace_root_possible")
                count["runner_temp"]+=int(route=="runner_temp")
                count["other_paths"]+=int(route not in ("workspace_root_possible","runner_temp"))
                count[{"unknown":"permission_unknown","write":"explicit_write_jobs","read_only":"read_only_jobs"}[policy]]+=1
                entries.append({
                    "consumer_file":Path(wf["path"]).name,
                    "consumer_job":str(job_name),"download_step":idx,
                    "download_action":str(step.get("uses","shell")),
                    "path_class":route,"permission_status":policy,
                    "permission_reason":reason,"producer_identity":identity,
                    "producer_candidates":source,
                    "classification":"transfer_evidence_only",
                    "unknowns":[
                        "actual producer job execution and artifact bytes unverified",
                        "business parsing, sanitization and authorized effect unverified",
                        "indirect and reusable workflow flows not modeled",
                    ]
                })
    return {"schema_version":1,"summary":count,"entries":entries,
            "parse_unknowns":parse_unknown,
            "limits":"not a vulnerability or correctness label; unknown is explicit"}


if __name__=="__main__":
    import argparse
    parser=argparse.ArgumentParser()
    parser.add_argument("workspace")
    parser.add_argument("--output")
    a=parser.parse_args()
    result=examine(a.workspace)
    if a.output:
        file=Path(a.output)
        file.parent.mkdir(parents=True,exist_ok=True)
        file.write_text(json.dumps(result,indent=2)+"\n")
    print(json.dumps(result["summary"],sort_keys=True))
