"""Real runner oracle: continue-on-error changes conclusion, not outcome.

Nonprivileged, intentionally failing harmless step. Produces machine-readable
evidence that final step status need not mean a successful operation.
"""
import json
import os
from pathlib import Path


def main():
    observed={
        "outcome_before_continue_on_error":os.environ.get("STEP_OUTCOME"),
        "conclusion_after_continue_on_error":os.environ.get("STEP_CONCLUSION"),
    }
    expected={"outcome_before_continue_on_error":"failure",
              "conclusion_after_continue_on_error":"success"}
    report={
        "source":"actual GitHub Actions steps.fail.outcome and steps.fail.conclusion",
        "checks":observed,
        "expected":expected,
        "passed":observed==expected,
        "scope":"read-only workflow with an intentionally failing benign command",
    }
    path=Path("baseline-results/temporal-contract")
    path.mkdir(parents=True,exist_ok=True)
    (path/"runner-status.json").write_text(json.dumps(report,indent=2)+"\n")
    print(json.dumps(report,indent=2))
    assert report["passed"]
if __name__=="__main__":
    main()
