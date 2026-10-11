"""Scoped expected-commit reference update contract.

This is a narrow, auditable pattern recognizer for a known GitHub workflow
shape, not a general proof of arbitrary Bash scripts or remote branch policy.
"""
import re

EXPECTED_REF=chr(36)+"{{ github.event.workflow_run.head_branch }}"
EXPECTED_SHA=chr(36)+"{{ github.event.workflow_run.head_sha }}"
PLAIN='git push origin "HEAD:refs/heads/$HEAD_BRANCH"'
ANCESTRY='git merge-base --is-ancestor "$EXPECTED_SHA" HEAD'
LEASE='git push --force-with-lease="refs/heads/$HEAD_BRANCH:$EXPECTED_SHA" origin "HEAD:refs/heads/$HEAD_BRANCH"'


def _exec_lines(script):
    return [line.strip() for line in str(script).splitlines()
            if line.strip() and not line.lstrip().startswith("#")]


def inspect_push_step(step,job=None):
    """Explain whether this step proves expected-source ref-bound atomicity."""
    job=job or {}
    script=str(step.get("run",""))
    statements=_exec_lines(script)
    env=step.get("env") or {}
    defaults=(job.get("defaults") or {}).get("run") or {}
    declared_shell=step.get("shell",defaults.get("shell","bash"))
    checks={
        "trusted_branch_bound":env.get("HEAD_BRANCH")==EXPECTED_REF,
        "source_sha_bound":env.get("EXPECTED_SHA")==EXPECTED_SHA,
        "known_failure_propagation":(
            str(step.get("continue-on-error",False)).lower()=="false"
            and str(job.get("continue-on-error",False)).lower()=="false"
            and declared_shell in ("bash",)
            and not any(re.search(r"\bset\s+\+e\b|(?:\|\|\s*true)|\bgit\s+push\s+--force(?:\s|$)",l)
                        for l in statements)),
        "ancestor_precondition_before_push":(
            ANCESTRY in statements and LEASE in statements
            and statements.index(ANCESTRY)<statements.index(LEASE)),
        "explicit_expected_ref_lease":(
            statements.count(LEASE)==1
            and statements.count(PLAIN)==0
            and sum(bool(re.match(r"^git\s+push\b",l)) for l in statements)==1),
    }
    # A separate contract must also ensure checkout and the SHA check are
    # valid, and real GitHub branch/ruleset policies may reject force-with-lease.
    return {
        "tier":"expected_ref_cas_pattern" if all(checks.values())
               else "ref_update_atomicity_unverified",
        "stronger_pattern_passed":all(checks.values()),
        "checks":checks,
        "limits":"no arbitrary Bash proof; no GitHub protected-branch compatibility guarantee",
    }


def upgrade_push_to_expected_ref_cas(workflow):
    """Modify a copy of one already validated historical repair candidate."""
    job=workflow["jobs"]["commit"]
    steps=job["steps"]
    pushes=[s for s in steps if isinstance(s,dict) and PLAIN in str(s.get("run",""))]
    if len(pushes)!=1:
        raise ValueError("expected exactly one known plain push in candidate")
    step=pushes[0]
    if str(step["run"]).count(PLAIN)!=1:
        raise ValueError("ambiguous push sequence")
    if step.get("shell") not in (None,"bash"):
        raise ValueError("unsupported shell")
    step["env"]=dict(step.get("env") or {},EXPECTED_SHA=EXPECTED_SHA)
    step["run"]=step["run"].replace(
        PLAIN,
        ANCESTRY+"\n"+LEASE)
    result=inspect_push_step(step,job)
    if not result["stronger_pattern_passed"]:
        raise AssertionError(result)
    return result
