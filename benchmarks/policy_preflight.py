"""Read-only GitHub pre-deployment policy assessment for a disposable lab branch.

Never pushes or mutates anything. A successful LAB_ONLY result is not
authorization for production deployment, even if branch.protected is false.
"""
import argparse
import json
import os
import re
from pathlib import Path
from urllib.request import Request,urlopen
from urllib.error import HTTPError,URLError
from urllib.parse import quote

SAFE_LAB_PREFIX="research/ref-cas-remote-"


def assess(repo,branch,branch_record,rulesets,error=None):
    """Fail closed on absent policy, prohibited branch or unknown repository."""
    branches_ok=(
        repo=="junlin20011207/test" and
        re.fullmatch(
            r"research/ref-cas-remote-(?:plain|strict|positive)-20261011",
            branch) is not None
    )
    is_protected=(branch_record.get("protected")
                  if isinstance(branch_record,dict) else None)
    matching_unknown=(rulesets is None or error is not None)
    no_rules=isinstance(rulesets,list) and len(rulesets)==0
    laboratory_only=bool(branches_ok and is_protected is False
                         and no_rules and not matching_unknown)
    return {
        "repository":repo,"branch":branch,
        "protected_flag":is_protected,
        "ruleset_count":len(rulesets) if isinstance(rulesets,list) else None,
        "safe_lab_name":branches_ok,
        "status":"LAB_READ_ONLY_PRECHECK_PASSED" if laboratory_only
                 else "DEPLOYMENT_NOT_VERIFIED",
        "production_deployment_authorized":False,
        "limitations":[
            "only evaluates repository-reported protected flag and visible rulesets",
            "read authorization does not prove write token scope or successful push",
            "explicit lease may be incompatible with undisclosed branch enforcement",
            "even success permits no action beyond preflight of isolated lab branches",
        ],
        "error":str(error)[:220] if error else None,
    }


def github_get(repo,path,token):
    url="https://api.github.com/repos/"+repo+"/"+path
    headers={
        "Accept":"application/vnd.github+json",
        "User-Agent":"ProofCutReadOnlyPolicyResearch",
        "X-GitHub-Api-Version":"2022-11-28",
    }
    if token:
        headers["Authorization"]="Bearer "+token
    with urlopen(Request(url,headers=headers),timeout=25) as response:
        return json.load(response)


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--repo",default=os.getenv("GITHUB_REPOSITORY",""))
    parser.add_argument("--branch",default="research/ref-cas-remote-positive-20261011")
    parser.add_argument("--output",default="baseline-results/policy-preflight/result.json")
    args=parser.parse_args()
    token=os.getenv("GH_TOKEN","")
    error=None
    record=None
    rulesets=None
    try:
        record=github_get(args.repo,"branches/"+quote(args.branch,safe="/"),token)
        rulesets=github_get(args.repo,"rulesets",token)
    except (HTTPError,URLError,ValueError,TimeoutError,OSError) as exc:
        error=type(exc).__name__+": "+str(exc)
    result=assess(args.repo,args.branch,record,rulesets,error=error)
    output=Path(args.output)
    output.parent.mkdir(parents=True,exist_ok=True)
    output.write_text(json.dumps(result,indent=2)+"\n")
    print(json.dumps(result,sort_keys=True))
    # Only the expected own lab branch may pass. A failed policy response is
    # unverified, not a reason to retry with more powerful credentials.
    assert result["status"]=="LAB_READ_ONLY_PRECHECK_PASSED",result
    return 0

if __name__=="__main__":
    raise SystemExit(main())
