"""Non-executable local Git race illustration of why verify-before-push matters.

No network, no GitHub token, no untrusted file execution, no external writes.
Each scenario creates a fresh isolated bare repository and commits inert text.
"""
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile


def git(*args,cwd=None):
    p=subprocess.run(["git",*map(str,args)],cwd=cwd,capture_output=True,text=True)
    if p.returncode!=0:
        raise RuntimeError(f"git {args}: {p.stderr[-650:]}")
    return p.stdout.strip()


def experiment(parent,verify_first):
    bare=parent/"origin.git"
    work=parent/"work"
    git("init","--bare",bare)
    git("clone",bare,work)
    git("config","user.name","ContractLab Test",cwd=work)
    git("config","user.email","contract-test@invalid.example",cwd=work)
    git("checkout","-b","dependabot/contract-fixture",cwd=work)
    (work/"dist").mkdir()
    (work/"dist"/"index.js").write_text("// harmless initial\n","utf8")
    (work/"README").write_text("initial\n","utf8")
    git("add",".",cwd=work)
    git("commit","-m","initial",cwd=work)
    git("push","origin","HEAD:refs/heads/dependabot/contract-fixture",cwd=work)
    artifact_source_sha=git("rev-parse","HEAD",cwd=work)
    # Simulate branch moving after an upstream builder already observed SHA.
    (work/"README").write_text("later branch state\n","utf8")
    git("add","README",cwd=work)
    git("commit","-m","branch advanced",cwd=work)
    git("push","origin","HEAD:refs/heads/dependabot/contract-fixture",cwd=work)
    advanced_sha=git("rev-parse","HEAD",cwd=work)
    remote_ref="refs/heads/dependabot/contract-fixture"
    before=git("--git-dir="+str(bare),"rev-parse",remote_ref)
    assert before==advanced_sha and advanced_sha!=artifact_source_sha
    mismatch=before!=artifact_source_sha
    if not verify_first:
        # Deliberately wrong order. Commit stale inert artifact before checking.
        (work/"dist"/"index.js").write_text("// inert stale artifact bytes\n","utf8")
        git("add","dist/",cwd=work)
        git("commit","-m","unsafe stale data before SHA validation",cwd=work)
        git("push","origin","HEAD:"+remote_ref,cwd=work)
    else:
        # Correct: refuse write when branch has advanced since builder run.
        if not mismatch:
            raise AssertionError("fixture must demonstrate stale artifact")
    after=git("--git-dir="+str(bare),"rev-parse",remote_ref)
    return {
        "variant":"verify_before_write" if verify_first else "write_before_verify",
        "artifact_source_sha":artifact_source_sha,
        "branch_advanced_sha":advanced_sha,
        "sha_mismatch_detected":mismatch,
        "branch_write_happened":before!=after,
        "branch_remained_unchanged_after_mismatch":before==after,
        "scope":"inert local bare Git; does not exercise GitHub branch protection"
    }


def main():
    with tempfile.TemporaryDirectory(prefix="proofcut-temporal-git-") as tmp:
        root=Path(tmp)
        safe=root/"safe"
        unsafe=root/"unsafe"
        safe.mkdir();unsafe.mkdir()
        observations=[experiment(safe,True),experiment(unsafe,False)]
    assert observations[0]["sha_mismatch_detected"]
    assert observations[0]["branch_remained_unchanged_after_mismatch"]
    assert observations[1]["sha_mismatch_detected"]
    assert observations[1]["branch_write_happened"]
    destination=Path("baseline-results/temporal-contract")
    destination.mkdir(parents=True,exist_ok=True)
    report={"passed":True,"observations":observations,
            "conclusion":"checking stale SHA after local Git push cannot undo the already performed write",
            "limits":"local synthetic schedule only; no actual GitHub privileged run"}
    (destination/"git-race.json").write_text(json.dumps(report,indent=2)+"\n")
    print(json.dumps(report,indent=2))
    return 0


if __name__=="__main__":
    raise SystemExit(main())
