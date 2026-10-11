"""Produce descriptive, not automatically comparable, scanner summaries."""
from pathlib import Path
import json
import sys

root=Path(sys.argv[1])
tools=sys.argv[2:]
cases=("risk","guarded","same_run","read_only")
for tool in tools:
    print(f"## {tool} baseline")
    for case in cases:
        path=root/f"{case}.{tool}.json"
        err=root/f"{case}.{tool}.err"
        if not path.exists():
            print(f"{case}: NOT RUN (no output file)")
            continue
        raw=path.read_text(encoding="utf-8",errors="replace")
        stderr=err.read_text(encoding="utf-8",errors="replace") if err.exists() else ""
        try:
            data=json.loads(raw)
            if tool=="boundarygraph":
                print(f'{case}: paths={len(data.get("findings",[]))}, unknown={len(data.get("unknowns",[]))}')
            elif tool=="zizmor":
                findings=data if isinstance(data,list) else [data]
                names=[str(x.get("ident","unknown")) for x in findings if isinstance(x,dict)]
                print(f"{case}: {len(names)} total findings; ident={','.join(sorted(set(names))[:25])}")
            elif tool=="poutine":
                findings=data.get("findings",[]) if isinstance(data,dict) else []
                rules=sorted(set(str(x.get("rule_id","unknown")) for x in findings if isinstance(x,dict)))
                print(f"{case}: total_findings={len(findings)}, rule_ids={','.join(rules)}")
            else:
                print(f"{case}: json_top_type={type(data).__name__}")
        except (ValueError,TypeError) as error:
            print(f"{case}: MALFORMED/EMPTY json ({type(error).__name__}), preview={raw[:250]}")
        if stderr:
            print("    stderr="+stderr[-450:].replace("\n"," "))
