"""Small, benign contract assertions for *real* actions/upload/download-artifact@v4.

Only fixture data, no downloaded scripts are executed. Each scenario is tested
in a read-only-permission GitHub-hosted runner, separate from external repos.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path

TRUSTED=b"trusted-fixture-nonexecutable\n"
UNTRUSTED=b"artifact-fixture-nonexecutable\n"
EXPECTED={"unit":"artifact-contract","number":42,"kind":"benign"}

def sha(data):
    return hashlib.sha256(data).hexdigest()

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("scenario",choices=["root","isolated","dist","negative"])
    parser.add_argument("--workspace",required=True)
    parser.add_argument("--temp",required=True)
    args=parser.parse_args()
    root=Path(args.workspace).resolve()
    tmp=Path(args.temp).resolve()
    checks={}
    if args.scenario=="root":
        current=(root/"trusted-marker.txt").read_bytes()
        checks["workspace_marker_overwritten_by_artifact"]=current==UNTRUSTED
        data=json.loads((root/"review.json").read_text("utf8"))
        checks["business_json_preserved"]=data==EXPECTED
    elif args.scenario=="isolated":
        original=(root/"trusted-marker.txt").read_bytes()
        payload=(tmp/"proofcut-artifact"/"trusted-marker.txt").read_bytes()
        data=json.loads((tmp/"proofcut-artifact"/"review.json").read_text("utf8"))
        checks["workspace_marker_unchanged"]=original==TRUSTED
        checks["payload_separated"]=payload==UNTRUSTED
        checks["business_json_preserved"]=data==EXPECTED
    elif args.scenario=="dist":
        check=(tmp/"incoming"/"dist"/"index.js")
        checks["v4_named_directory_flattens_source_root"]=check.is_file()
        if check.is_file():
            checks["file_content_preserved"]=check.read_bytes()==b"// inert dist fixture\n"
        # The original producer only uploaded dist/, not its parent.
        checks["no_nested_dist_subdir"]=not (tmp/"incoming"/"dist"/"dist"/"index.js").exists()
    else:
        # This deliberately tests the previously hypothesized but unsupported
        # extra dist/ folder from upload-artifact's path handling.
        checks["nested_path_not_expected"]=not (tmp/"incoming"/"dist"/"dist"/"index.js").exists()
    result={"scenario":args.scenario,"runner":os.getenv("RUNNER_OS"),
            "checks":checks,"all_passed":all(checks.values()),
            "scope":"GitHub-hosted isolated fixture transport, not cross-run or exploit execution"}
    folder=root/"baseline-results"/"runtime-contract"
    folder.mkdir(parents=True,exist_ok=True)
    (folder/(args.scenario+".json")).write_text(json.dumps(result,indent=2)+"\n","utf8")
    print(json.dumps(result,sort_keys=True))
    assert result["all_passed"],result
if __name__=="__main__":
    main()
