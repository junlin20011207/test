"""Real Git compare-and-swap oracle, using only self-owned ephemeral bare repos.

At build A, write candidate C. A separate writer may advance, diverge, or
roll back the remote ref before the consumer pushes. No GitHub token or
external repo write, no untrusted payload execution.
"""
import json
import subprocess
import tempfile
from pathlib import Path


def git(*args,cwd=None,check=True):
    p=subprocess.run(["git",*map(str,args)],cwd=cwd,capture_output=True,text=True)
    if check and p.returncode:
        raise RuntimeError(f"git {args!r}: {p.stderr[-700:]}")
    return p


def one(scenario,mode):
    with tempfile.TemporaryDirectory(prefix="proofcut-ref-cas-") as base:
        root=Path(base)
        bare=root/"origin.git"
        work=root/"work"
        git("init","--bare",bare)
        git("clone",bare,work)
        git("config","user.name","ContractLab",cwd=work)
        git("config","user.email","test@invalid.example",cwd=work)
        branch="refs/heads/dependabot/fixture"
        git("checkout","-b","dependabot/fixture",cwd=work)
        file=work/"data.txt"
        file.write_text("root\n")
        git("add","data.txt",cwd=work)
        git("commit","-m","root",cwd=work)
        root_oid=git("rev-parse","HEAD",cwd=work).stdout.strip()
        file.write_text("build-input-A\n")
        git("commit","-am","A source",cwd=work)
        source_oid=git("rev-parse","HEAD",cwd=work).stdout.strip()
        git("push","origin","HEAD:"+branch,cwd=work)
        file.write_text("benign-generated-C\n")
        git("commit","-am","C consumer",cwd=work)
        candidate_oid=git("rev-parse","HEAD",cwd=work).stdout.strip()

        if scenario in ("forward","diverged"):
            git("checkout",source_oid,cwd=work)
            file.write_text("concurrent B\n" if scenario=="forward" else "diverging D\n")
            git("commit","-am","concurrent writer",cwd=work)
            git("push","origin","HEAD:"+branch,cwd=work)
        elif scenario=="rollback":
            # Authorized second writer rewrites A to its ancestor root.
            # Plain non-FF protection does not prevent C being reintroduced.
            git("push","--force","origin",root_oid+":"+branch,cwd=work)

        previous=git("--git-dir="+str(bare),"rev-parse",branch).stdout.strip()
        # Ancestry precondition ensures lease cannot force any history unrelated
        # to the original source commit from this consumer.
        ancestry_ok=git("merge-base","--is-ancestor",source_oid,candidate_oid,
                        cwd=work,check=False).returncode==0
        assert ancestry_ok
        if mode=="plain":
            outcome=git("push","origin",candidate_oid+":"+branch,
                        cwd=work,check=False)
        elif mode=="explicit-lease":
            outcome=git("push","--force-with-lease="+branch+":"+source_oid,
                        "origin",candidate_oid+":"+branch,cwd=work,check=False)
        else:
            raise ValueError(mode)
        after=git("--git-dir="+str(bare),"rev-parse",branch).stdout.strip()
        return {
            "scenario":scenario,
            "mode":mode,
            "remote_was_still_expected_source":previous==source_oid,
            "push_accepted":outcome.returncode==0,
            "remote_changed_by_consumer":previous!=after,
            "candidate_descends_from_expected_source":ancestry_ok,
        }


def main():
    observations=[one(s,m) for s in ("unchanged","forward","rollback","diverged")
                  for m in ("plain","explicit-lease")]
    by={(r["scenario"],r["mode"]):r for r in observations}
    assertions={
        "both_allow_intended_update":all(by[("unchanged",m)]["push_accepted"]
                                         for m in ("plain","explicit-lease")),
        "both_reject_divergent_forward":all(
            not by[(s,m)]["push_accepted"]
            for s in ("forward","diverged") for m in ("plain","explicit-lease")),
        "plain_push_accepts_rollback_stale_write":
            by[("rollback","plain")]["push_accepted"] and
            by[("rollback","plain")]["remote_changed_by_consumer"],
        "explicit_sha_lease_rejects_rollback_stale_write":
            not by[("rollback","explicit-lease")]["push_accepted"] and
            not by[("rollback","explicit-lease")]["remote_changed_by_consumer"],
        "lease_never_writes_after_other_writer_moves_ref":
            all(not by[(s,"explicit-lease")]["remote_changed_by_consumer"]
                for s in ("forward","rollback","diverged")),
    }
    report={
        "source":"real Git push to disposable local bare repositories",
        "cases":observations,"assertions":assertions,
        "passed":all(assertions.values()),
        "limits":[
            "local Git, not GitHub branch protection/rulesets",
            "force-with-lease may be refused by protected GitHub branches",
            "controlled authorized concurrent ref modifications, not exploitation",
            "must check ancestor relation before enabling a lease-mediated push",
        ],
    }
    target=Path("baseline-results/ref-cas")
    target.mkdir(parents=True,exist_ok=True)
    (target/"comparison.json").write_text(
        json.dumps(report,indent=2,ensure_ascii=False)+"\n")
    print(json.dumps(report,sort_keys=True))
    assert report["passed"],report
    return 0


if __name__=="__main__":
    raise SystemExit(main())
