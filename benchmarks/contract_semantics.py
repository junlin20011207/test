"""Independent semantic hardening of a narrow cross-workflow repair contract.

Supported guards are interpreted by a strict parser and evaluated on known
authorized and forbidden scenarios. This is bounded counterexample checking,
NOT a complete GitHub expression-language verification or safety proof.
"""
import re
from benchmarks.guard_semantics import guard_samples, require_on_every_branch
from benchmarks.ref_update_contract import inspect_push_step

TMP=chr(36)+"{{ runner.temp }}/incoming/dist"
TRUSTED_BRANCH=chr(36)+"{{ github.event.workflow_run.head_branch }}"


def unique_action(steps,short_name):
    hits=[s for s in steps if isinstance(s,dict) and re.fullmatch(
        r"actions/"+re.escape(short_name)+r"@[^\s]+",str(s.get("uses","")))]
    return len(hits)==1


def output_check_is_executed(script):
    """Only a visibly executed if-file / echo true/else/echo false structure."""
    code="\n".join(line.strip() for line in str(script).splitlines()
                   if line.strip() and not line.lstrip().startswith("#"))
    path=re.escape(TMP+"/index.js")
    has_probe=bool(re.search(r'(?m)^if\s+\[\s+-f\s+["\x27]?'+path+
                             r'["\x27]?\s+\];\s*then\s*$',code))
    has_true=bool(re.search(r'(?m)^echo\s+["\x27]present=true["\x27]\s*>>\s*["\x27]?\$GITHUB_OUTPUT["\x27]?\s*$',code))
    has_false=bool(re.search(r'(?m)^echo\s+["\x27]present=false["\x27]\s*>>\s*["\x27]?\$GITHUB_OUTPUT["\x27]?\s*$',code))
    return (has_probe and has_true and has_false and
            bool(re.search(r'(?m)^else\s*$',code)) and
            bool(re.search(r'(?m)^fi\s*$',code)))


def sha_is_actually_compared(step):
    script=str(step.get("run",""))
    if step.get("continue-on-error") in (True,"true"):
        return False
    code="\n".join(line.strip() for line in script.splitlines()
                   if line.strip() and not line.lstrip().startswith("#"))
    if "|| true" in code or "git rev-parse HEAD" not in code:
        return False
    test_equal=bool(re.search(
        r'(?m)^test\s+["\x27]?\$current["\x27]?\s+=\s+["\x27]?\$EXPECTED_SHA["\x27]?\s*$',code))
    if_guard=bool(re.search(
        r'if\s+\[\s+["\x27]?\$current["\x27]?\s+!=\s+["\x27]?\$EXPECTED_SHA["\x27]?\s+\];\s*then',
        code)) and bool(re.search(r'(?m)^\s*exit\s+1\s*$',code))
    return test_equal or if_guard


def push_failure_is_not_swallowed(step,job=None):
    code="\n".join(line.strip() for line in str(step.get("run","")).splitlines()
                   if line.strip() and not line.lstrip().startswith("#"))
    expected='git push origin "HEAD:refs/heads/$HEAD_BRANCH"'
    legacy=bool(re.search(r'(?m)^'+re.escape(expected)+r'\s*$',code))
    if "--force-with-lease" in code:
        return inspect_push_step(step,job)["stronger_pattern_passed"]
    return legacy and (
        "|| true" not in code and
        step.get("continue-on-error") not in (True,"true") and
        str(step.get("if","")).strip() not in ("false",chr(36)+"{{ false }}"))

def producer_actor_is_guarded(expr):
    ok={"github.actor":"dependabot[bot]"}
    return (guard_samples(expr,ok,[{"github.actor":"arbitrary-contributor"},
                                   {"github.actor":"dependabot-other[bot]"}]) and
            require_on_every_branch(expr,{
                ("eq","github.actor","dependabot[bot]")}))


def artifact_change_is_guarded(expr):
    good={"steps.diff.outputs.changed":"true"}
    bad={"steps.diff.outputs.changed":"false"}
    return (guard_samples(expr,good,[bad]) and
            require_on_every_branch(expr,{
                ("eq","steps.diff.outputs.changed","true")}))


def consumer_auth_is_guarded(expr):
    good={
        "github.repository":"org/repo",
        "github.event.workflow_run.head_repository.full_name":"org/repo",
        "github.event.workflow_run.actor.login":"dependabot[bot]",
        "github.event.workflow_run.head_branch":"dependabot/npm/pkg-1",
        "github.event.workflow_run.conclusion":"success",
        "github.event.workflow_run.event":"pull_request"
    }
    deny=[]
    for k,bad_value in {
       "github.event.workflow_run.head_repository.full_name":"external/fork",
       "github.event.workflow_run.actor.login":"untrusted-author",
       "github.event.workflow_run.head_branch":"release",
       "github.event.workflow_run.conclusion":"failure",
       "github.event.workflow_run.event":"push",
    }.items():
        alt=dict(good)
        alt[k]=bad_value
        deny.append(alt)
    required={
        ("same",tuple(sorted(("github.event.workflow_run.head_repository.full_name",
                              "github.repository")))),
        ("eq","github.event.workflow_run.actor.login","dependabot[bot]"),
        ("prefix","github.event.workflow_run.head_branch","dependabot/"),
        ("eq","github.event.workflow_run.conclusion","success"),
        ("eq","github.event.workflow_run.event","pull_request"),
    }
    return guard_samples(expr,good,deny) and require_on_every_branch(expr,required)


def harden(existing,producer,consumer,producer_steps,consumer_steps):
    checks=dict(existing)
    producer_job=producer.get("jobs",{}).get("rebuild",{})
    consumer_job=consumer.get("jobs",{}).get("commit",{})
    uploader=next((s for s in producer_steps if isinstance(s,dict) and
                  re.fullmatch(r"actions/upload-artifact@[^\s]+",str(s.get("uses","")))),{})
    checker=next((s for s in consumer_steps if isinstance(s,dict) and s.get("id")=="check"),{})
    verification=next((s for s in consumer_steps if isinstance(s,dict) and
                       "git rev-parse HEAD" in str(s.get("run",""))),{})
    pusher=next((s for s in consumer_steps if isinstance(s,dict) and
                 re.search(r"(?m)^\s*git\s+push\s+(?:--force-with-lease=\S+\s+)?origin\b",str(s.get("run","")))),{})
    checks["publisher_named_and_dist_only"]=(
        checks["publisher_named_and_dist_only"] and
        unique_action(producer_steps,"upload-artifact"))
    checks["publisher_remains_guarded_by_diff"]=(
        checks["publisher_remains_guarded_by_diff"] and
        artifact_change_is_guarded(uploader.get("if","")))
    checks["producer_event_permission_boundary"]=(
        checks["producer_event_permission_boundary"] and
        producer_actor_is_guarded(producer_job.get("if","")))
    checks["consumer_authorizes_same_repo_actor_and_branch"]=(
        checks["consumer_authorizes_same_repo_actor_and_branch"] and
        consumer_auth_is_guarded(consumer_job.get("if","")))
    checks["consumer_checks_actual_dist_file"]=(
        checks["consumer_checks_actual_dist_file"] and
        output_check_is_executed(checker.get("run","")))
    checks["sha_verification_environment_bound"]=(
        checks["sha_verification_environment_bound"] and
        sha_is_actually_compared(verification))
    checks["write_target_environment_bound"]=(
        checks["write_target_environment_bound"] and
        push_failure_is_not_swallowed(pusher,consumer_job))
    checks["checkout_target_from_event"]=(
        checks["checkout_target_from_event"] and
        unique_action(consumer_steps,"checkout"))
    checks["matching_download_identity"]=(
        checks["matching_download_identity"] and
        unique_action(consumer_steps,"download-artifact"))
    return checks
