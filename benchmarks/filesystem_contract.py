"""Inert filesystem-overlay experiment, not an exploit or execution of scripts.

Uses Python zipfile extraction into a temporary sandbox to validate that the
chosen extraction directory changes which paths can be overwritten while
preserving the availability of the intended review.json payload.
This is NOT a faithful implementation of every GitHub download-artifact mode.
"""
import hashlib
import io
import json
from pathlib import Path
import tempfile
from zipfile import ZipFile

TRUSTED=b"/* trusted non-executable module fixture */\n"
UNTRUSTED=b"/* different but deliberately non-executable fixture bytes */\n"
PAYLOAD={"pr_number":123,"review_state":"approved","submitter":"sample-user"}
MODULE=".github/workflows/scripts/assign_reviewer_lib.js"


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def run_layout(folder, isolated):
    worktree=folder/"worktree"
    worktree.mkdir()
    module=worktree/MODULE
    module.parent.mkdir(parents=True)
    module.write_bytes(TRUSTED)
    archive=io.BytesIO()
    with ZipFile(archive,"w") as z:
        z.writestr(MODULE,UNTRUSTED)
        z.writestr("review.json",json.dumps(PAYLOAD))
    archive.seek(0)
    extraction=(folder/"runner-temp"/"proofcut-artifact") if isolated else worktree
    extraction.mkdir(parents=True,exist_ok=True)
    with ZipFile(archive) as z:
        z.extractall(extraction)
    actual_payload=json.loads((extraction/"review.json").read_text("utf8"))
    return {"trusted_module_unchanged":digest(module.read_bytes())==digest(TRUSTED),
            "intended_json_preserved":actual_payload==PAYLOAD,
            "sha256_of_remaining_module":digest(module.read_bytes())}


def main():
    with tempfile.TemporaryDirectory(prefix="proofcut-filesystem-") as tmp:
        old=run_layout(Path(tmp)/"default",False) if False else None
        one=Path(tmp)/"before"
        two=Path(tmp)/"isolated"
        one.mkdir()
        two.mkdir()
        before=run_layout(one,False)
        after=run_layout(two,True)
    assert not before["trusted_module_unchanged"]
    assert after["trusted_module_unchanged"]
    assert before["intended_json_preserved"] and after["intended_json_preserved"]
    print(json.dumps({
        "scope":"offline inert Python zip extraction, not GitHub action execution",
        "root_extraction":before,"isolated_extraction":after,
        "passed":True,
        "limitation":"no branch permissions, symlink/zip-slip, GitHub runtime, or exploit claim"},
        indent=2))
    return 0


if __name__=="__main__":
    raise SystemExit(main())
