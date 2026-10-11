"""Immutable evidence check of live, self-owned remote GitHub CAS lab branches.

Only GETs repository commit refs and a harmless fixture file. The original
write responses are documented separately; this validates their final state.
"""
import json
from pathlib import Path
from urllib.parse import quote
from benchmarks.policy_preflight import github_get

REPO="junlin20011207/test"
BASE="660213216cf3d36dd3dbc6e87079d0609eefbf6b"
SOURCE="ae29213a1e50e946b4a57a70f7a5d0257d4f5407"
CANDIDATE="b0fdf26829aaddd1feb3a61cc7f8b4b3c8425dab"
EXPECTED={
    "research/ref-cas-remote-plain-20261011":CANDIDATE,
    "research/ref-cas-remote-strict-20261011":BASE,
    "research/ref-cas-remote-positive-20261011":CANDIDATE,
}


def run():
    results=[]
    for ref,expected in EXPECTED.items():
        obj=github_get(REPO,"branches/"+quote(ref,safe="/"),token="")
        seen=obj["commit"]["sha"]
        row={"ref":ref,"observed_sha":seen,"expected_sha":expected,
             "matches":seen==expected,"protected":obj.get("protected")}
        results.append(row)
    source_commit=github_get(REPO,"git/commits/"+SOURCE,token="")
    candidate_commit=github_get(REPO,"git/commits/"+CANDIDATE,token="")
    ancestry={
        "source_parent_base":source_commit["parents"][0]["sha"]==BASE,
        "candidate_parent_source":candidate_commit["parents"][0]["sha"]==SOURCE,
    }
    data=github_get(REPO,"contents/lab/expected-head-test.txt?ref="+quote(
        "research/deploy-lab-20261011",safe=""),token="")
    blob={"sha":data["sha"],"expected_sha":"24814607fa536e6d9dfb4ffa0d4bcd8abce64158",
          "matches":data["sha"]=="24814607fa536e6d9dfb4ffa0d4bcd8abce64158"}
    result={
        "scope":"public read-only final-state verification of self-owned lab branches",
        "refs":results,"ancestry_checks":ancestry,"file_blob":blob,
        "passed":all(x["matches"] for x in results) and all(ancestry.values()) and blob["matches"],
        "evidence_limitation":"GET confirms final states; write rejection error type and real atomicity require separate transaction evidence",
        "remote_writes_performed_here":0,
    }
    destination=Path("baseline-results/policy-preflight/ref-evidence.json")
    destination.parent.mkdir(parents=True,exist_ok=True)
    destination.write_text(json.dumps(result,indent=2)+"\n")
    print(json.dumps(result,sort_keys=True))
    assert result["passed"],result
    return 0


if __name__=="__main__":
    raise SystemExit(run())
