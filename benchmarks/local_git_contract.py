"""Exercise a repair's dist-copy + git-branch-update *data* contract locally.

Never pushes to GitHub. Creates an isolated bare Git repository inside a
temporary directory. Does not execute artifact JavaScript or use credentials.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile


def git(*args,cwd=None):
    command=["git",*map(str,args)]
    completed=subprocess.run(command,cwd=cwd,text=True,capture_output=True)
    if completed.returncode:
        raise RuntimeError("git command failed: "+repr(command)+"; "+completed.stderr[-800:])
    return completed.stdout.strip()


def main():
    p=argparse.ArgumentParser()
    p.add_argument("--dist",required=True)
    args=p.parse_args()
    source=Path(args.dist).resolve()
    source_file=source/"index.js"
    assert source_file.read_bytes()==b"// inert dist fixture\n"
    digest=hashlib.sha256(source_file.read_bytes()).hexdigest()
    branch="dependabot/benign-source-fixture"
    with tempfile.TemporaryDirectory(prefix="proofcut-local-git-") as folder:
        base=Path(folder)
        bare=base/"bare.git"
        work=base/"worktree"
        git("init","--bare",bare)
        git("clone",bare,work)
        git("config","user.name","ProofCut Fixture",cwd=work)
        git("config","user.email","fixture@invalid.example",cwd=work)
        git("checkout","-b",branch,cwd=work)
        (work/"dist").mkdir()
        (work/"dist"/"index.js").write_bytes(b"// prior inert dist\n")
        git("add","dist/",cwd=work)
        git("commit","-m","initial inert fixture",cwd=work)
        git("push","origin","HEAD:refs/heads/"+branch,cwd=work)
        expected_old_sha=git("rev-parse","HEAD",cwd=work)
        # This is the repaired consumer's workflow-run SHA guard.
        assert git("rev-parse","HEAD",cwd=work)==expected_old_sha
        shutil.rmtree(work/"dist")
        shutil.copytree(source,work/"dist")
        git("add","dist/",cwd=work)
        git("commit","-m","rebuild benign dist fixture",cwd=work)
        # This refspec is equivalent to a shell-quoted HEAD_BRANCH value.
        git("push","origin","HEAD:refs/heads/"+branch,cwd=work)
        expected_new_sha=git("rev-parse","HEAD",cwd=work)
        actual=git("--git-dir="+str(bare),"rev-parse","refs/heads/"+branch)
        no_main=(subprocess.run(["git","--git-dir="+str(bare),"show-ref","--verify","refs/heads/main"],
                                stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode!=0)
        checks={
            "local_branch_push_updates_only_expected_ref":actual==expected_new_sha,
            "different_commit_created_for_changed_business_data":expected_old_sha!=expected_new_sha,
            "dist_file_digest_preserved":hashlib.sha256((work/"dist"/"index.js").read_bytes()).hexdigest()==digest,
            "unrelated_default_branch_never_pushed":no_main,
        }
    result={"scenario":"local_bare_git_no_credentials",
            "checks":checks,"all_passed":all(checks.values()),
            "limitations":"isolated local Git object updates only; not GitHub branch permissions, Dependabot policy or workflow_run security"}
    print(json.dumps(result,sort_keys=True))
    assert result["all_passed"]
    return 0


if __name__=="__main__":
    raise SystemExit(main())
