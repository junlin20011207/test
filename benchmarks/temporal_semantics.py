"""Conservative causal-chain validation for a known dist artifact repair.

Models necessary ordering and step outcome propagation, not arbitrary Bash
semantics. Unknown conditions are explicitly rejected as unverified.
"""
import re
from benchmarks.guard_semantics import parse, evaluate, require_on_every_branch


def _matches(steps,name):
    if name=="download":
        return [i for i,s in enumerate(steps) if isinstance(s,dict) and
                re.fullmatch(r"actions/download-artifact@[^\s]+",str(s.get("uses","")))]
    if name=="checkout":
        return [i for i,s in enumerate(steps) if isinstance(s,dict) and
                re.fullmatch(r"actions/checkout@[^\s]+",str(s.get("uses","")))]
    if name=="check":
        return [i for i,s in enumerate(steps) if isinstance(s,dict) and s.get("id")=="check"]
    if name=="verify":
        return [i for i,s in enumerate(steps) if isinstance(s,dict) and
                "git rev-parse HEAD" in str(s.get("run",""))]
    if name=="apply":
        return [i for i,s in enumerate(steps) if isinstance(s,dict) and
                re.search(r"(?m)^\s*mv\s+.*incoming/dist.*\s+dist\s*$",str(s.get("run","")))]
    if name=="push":
        return [i for i,s in enumerate(steps) if isinstance(s,dict) and
                re.search(r"(?m)^\s*git\s+push\s+origin\b",str(s.get("run","")))]
    raise ValueError("unknown step kind")


def _tolerance(value):
    explicit_false=chr(36)+"{{ false }}"
    explicit_true=chr(36)+"{{ true }}"
    if value is None or value is False or value in ("false",explicit_false):
        return "no"
    if value is True or value in ("true",explicit_true):
        return "yes"
    return "unknown"


def _if_guard(value):
    if value is None or str(value).strip()=="":
        return "unconditional"
    try:
        tree=parse(value)
        if require_on_every_branch(value,{("eq","steps.check.outputs.present","true")}):
            return "presence_guard"
        evaluated=evaluate(tree,{})
        if evaluated is True:
            return "unconditional"
        return "unverified_or_false"
    except (ValueError,TypeError,KeyError,IndexError):
        return "unverified_or_false"


def temporal_contract(steps):
    labels=("download","check","checkout","verify","apply","push")
    indices={name:_matches(steps,name) for name in labels}
    unique=all(len(values)==1 for values in indices.values())
    decisions=[_if_guard(steps[indices[name][0]].get("if")) if unique else "unverified"
               for name in labels]
    # Only prove actual data and control dependencies. A trusted event-based,
    # unconditional checkout is independent of an isolated artifact download.
    # Its location relative to download/check is not itself a safety defect.
    causal_edges=[
        ("download","check"),
        ("download","apply"),
        ("check","apply"),
        ("checkout","verify"),
        ("verify","apply"),
        ("apply","push"),
    ]
    if unique:
        for name,decision in zip(labels,decisions):
            if name not in ("check","download") and decision=="presence_guard":
                causal_edges.append(("check",name))
    ordered=unique and all(
        indices[before][0]<indices[after][0]
        for before,after in causal_edges)

    no_skipped=unique and all(x in ("unconditional","presence_guard") for x in decisions)
    download_tolerance=(
        _tolerance(steps[indices["download"][0]].get("continue-on-error"))
        if unique else "unknown")
    critical_not_tolerated=unique and all(
        _tolerance(steps[indices[name][0]].get("continue-on-error"))=="no"
        for name in labels if name!="download")
    # Tolerating absent upstream artifacts is legitimate only when all
    # downstream mutating operations require check.present=true.
    gated=unique and all(
        _if_guard(steps[indices[name][0]].get("if"))=="presence_guard"
        for name in ("checkout","verify","apply","push"))
    download_safe=download_tolerance=="no" or (
        download_tolerance=="yes" and gated)
    return {
        "temporal_order_and_dependencies":bool(ordered),
        "critical_step_failure_propagation":bool(
            no_skipped and critical_not_tolerated and download_safe),
        "explanation":{
            "unique_steps":bool(unique),
            "mandatory_precedence_edges":causal_edges,
            "indices":{name:(values[0] if len(values)==1 else None)
                       for name,values in indices.items()},
            "step_conditions":dict(zip(labels,decisions)),
            "download_continue_on_error":download_tolerance,
            "downstream_gated_if_download_failure_ignored":bool(gated),
            "supported_scope":"six-step known dist workflow; unsupported conditions fail closed",
        }
    }
