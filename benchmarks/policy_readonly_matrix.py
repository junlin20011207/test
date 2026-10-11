"""Public protected-branch read-only observations; no remote writes.

Pre-registered repositories supply contrasting real GitHub policy states.
A protected flag is enough to BLOCK our CAS deployment workflow; reading
all effective rules still requires privileges we may not possess.
"""
import json
from pathlib import Path
from urllib.error import HTTPError,URLError
from benchmarks.policy_preflight import github_get,assess

CASES=[("github/docs","main"),
       ("microsoft/vscode","main"),
       ("sigstore/cosign","main"),
       ("cloudflare/kumo","main")]


def main():
    observations=[]
    for repo,branch in CASES:
        error=None
        try:
            result=github_get(repo,"branches/"+branch,"")
            protected=result.get("protected")
        except (HTTPError,URLError,ValueError,OSError) as exc:
            protected=None
            error=type(exc).__name__
        decision=assess(repo,branch,{"protected":protected} if protected is not None else None,None,error)
        item={"repository":repo,"branch":branch,
              "protected":protected,
              "deployment_authorized":decision["production_deployment_authorized"],
              "policy_verdict":decision["status"],
              "error":error}
        observations.append(item)
        print(json.dumps(item,sort_keys=True))
    report={"study":"read-only remote protected-branch policy matrix",
            "observations":observations,
            "observed_protected":sum(x["protected"] is True for x in observations),
            "unknown_protection":sum(x["protected"] is None for x in observations),
            "wrongly_approved":sum(x["deployment_authorized"] for x in observations),
            "no_repos_modified":True}
    target=Path("baseline-results/policy-preflight/public-protected.json")
    target.parent.mkdir(parents=True,exist_ok=True)
    target.write_text(json.dumps(report,indent=2)+"\n")
    assert report["wrongly_approved"]==0
    # This is an empirical observation, not a universal claim. All four refs
    # are expected protected at sampling time, and unknowns fail closed.
    return 0


if __name__=="__main__":
    raise SystemExit(main())
