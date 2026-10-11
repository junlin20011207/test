"""Compare official GitHub Actions interpolation results to local interpreter.

These are literal, harmless expressions. GitHub computes env GH_* in the
workflow engine, Python compares values on the hosted runner.
"""
import json
import os
from pathlib import Path
from benchmarks.guard_semantics import evaluate,parse

SAMPLES=[
    ("EQ","'MAIN' == 'main'"),
    ("NE","'MAIN' != 'main'"),
    ("START","startsWith('Dependabot/npm', 'dependabot/')"),
    ("QUOTED","'It''s safe' == 'it''s SAFE'"),
    ("FALSE","startsWith('Release', 'dependabot/')"),
    ("COMBINED","'main' == 'MAIN' && !startsWith('RELEASE','dependabot/')"),
]


def main():
    rows=[]
    for name,source in SAMPLES:
        real=os.environ.get("GH_"+name)
        if real not in ("true","false"):
            raise AssertionError("GitHub did not provide a Boolean: "+name+":"+repr(real))
        predicted=bool(evaluate(parse(source),{}))
        expected=(real=="true")
        rows.append({"name":name,"expression":source,
                     "github_engine":expected,
                     "contract_interpreter":predicted,
                     "matches":expected==predicted})
    root=Path("baseline-results/expression-oracle")
    root.mkdir(parents=True,exist_ok=True)
    (root/"results.json").write_text(json.dumps({
        "oracle":"actual GitHub workflow expression interpolation",
        "observations":rows,
        "matched":sum(item["matches"] for item in rows),
        "total":len(rows),
        "result":"success" if all(x["matches"] for x in rows) else "mismatch",
    },indent=2)+"\n")
    for r in rows:print(json.dumps(r))
    assert all(x["matches"] for x in rows),"actual hosted GitHub Actions evaluator disagrees"
if __name__=="__main__":
    main()
