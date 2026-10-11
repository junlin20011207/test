"""ProofCut: combined conservative trust-boundary evidence and repair-cut report."""
import argparse
import json
from boundarygraph import analyze
from sinkproof import sink_proofs
from metadataproof import metadata_proofs


def inspect(root="."):
    base=analyze(root)
    overlay=sink_proofs(root)
    metadata=metadata_proofs(root)
    paths=overlay["proofs"]+metadata["proofs"]
    return {
        "tool":"BoundaryGraph ProofCut research prototype",
        "schema_version":1,
        "workflows":base["workflows"],
        "candidate_artifact_transfers":len(base["findings"])+len(base.get("unverified",[])),
        "unconditionally_declared_transfers":len(base["findings"]),
        "conditional_or_unresolved_transfers":len(base.get("unverified",[])),
        "proof_candidates":len(paths),
        "families":{
            "workspace_overwrite_then_load":overlay["count"],
            "artifact_metadata_to_git_write":metadata["count"],
        },
        "evidence":paths,
        "unknowns":sorted(set(base["unknowns"]+overlay["unknowns"]+metadata["unknowns"])),
        "scope":"static proof candidates are neither established exploits nor complete security audits",
    }


def main():
    p=argparse.ArgumentParser()
    p.add_argument("path",nargs="?",default=".")
    p.add_argument("--json",action="store_true")
    p.add_argument("--strict",action="store_true")
    args=p.parse_args()
    result=inspect(args.path)
    if args.json:
        print(json.dumps(result,indent=2,ensure_ascii=False))
    else:
        print(f"ProofCut: {result['workflows']} workflows; "
              f"{result['candidate_artifact_transfers']} potential transfer paths; "
              f"{result['proof_candidates']} sink-level witnesses; "
              f"{len(result['unknowns'])} unknowns")
    return int(args.strict and bool(result["evidence"] or result["unknowns"]))


if __name__=="__main__":
    raise SystemExit(main())
