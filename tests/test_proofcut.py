"""Stable machine-readable orchestration checks."""
import json
from proofcut import inspect


def test_empty_scan_is_unknown_not_clean(tmp_path):
    result=inspect(tmp_path)
    assert result["proof_candidates"]==0
    assert result["unknowns"]
    assert result["families"]=={
        "workspace_overwrite_then_load":0,
        "artifact_metadata_to_git_write":0,
    }
    assert json.loads(json.dumps(result))["schema_version"]==1
