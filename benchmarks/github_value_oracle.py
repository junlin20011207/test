"""Literal operand-valued expression comparisons against GitHub's runner engine."""
import json
import os
from pathlib import Path
from benchmarks.guard_semantics import evaluate,parse

EXAMPLES=[
 ("AND","'hit' && 'value'"),
 ("OR","'' || 'fallback'"),
 ("OR_KEEP","'already' || 'fallback'"),
 ("FALSE_OR","false || 'lowercase'"),
 ("TRUE_AND","true && 'kept'"),
 ("FALSE_AND","false && 'unreachable'"),
 ("NESTED","startsWith('x' && 'Dependabot/pkg','dependabot/')"),
]

def main():
    rows=[]
    for name,source in EXAMPLES:
        actual=os.environ.get("GH_"+name)
        if actual is None:raise ValueError("missing actual GitHub environment value "+name)
        local=evaluate(parse(source),{})
        normalized=("true" if local is True else "false" if local is False else str(local))
        rows.append({"id":name,"expression":source,"github":actual,"local":normalized,
                     "matches":actual==normalized})
        print(json.dumps(rows[-1]))
    d=Path("baseline-results/expression-oracle")
    d.mkdir(parents=True,exist_ok=True)
    (d/"values.json").write_text(json.dumps(rows,indent=2)+"\n")
    assert all(row["matches"] for row in rows),"operand-valued GitHub operator mismatch"
if __name__=="__main__":
    main()
