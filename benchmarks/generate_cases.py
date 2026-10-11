"""Offline benign static-analysis fixtures: never installed as runnable GitHub Actions."""
from pathlib import Path
from shutil import rmtree
import json

ROOT=Path(__file__).parent/"cases"
CASES={
  "risk": {"event":"pull_request","guard":"","rights":"write","remote":True},
  "guarded": {"event":"pull_request","guard":"github.event.workflow_run.event == 'push'","rights":"write","remote":True},
  "same_run": {"event":"pull_request","guard":"","rights":"write","remote":False},
  "read_only": {"event":"pull_request","guard":"","rights":"read","remote":True},
}
TOKEN="$"+"{{ secrets.GITHUB_TOKEN }}"
RUNID="$"+"{{ github.event.workflow_run.id }}"

def generate():
    for name,config in CASES.items():
        dest=ROOT/name/".github"/"workflows"
        dest.mkdir(parents=True,exist_ok=True)
        upstream=(
          "name: Producer\non: [pull_request]\npermissions: {contents: read}\n"+
          "jobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n"+
          "      - run: echo 'static fixture only'\n"
        )
        guard=("    if: >-\n      "+config["guard"]+"\n") if config["guard"] else ""
        wiring=("        with:\n"+
                "          run-id: "+RUNID+"\n"+
                "          github-token: "+TOKEN+"\n") if config["remote"] else ""
        downstream=(
          "name: Consumer\non:\n  workflow_run:\n"+
          "    workflows: [Producer]\n    types: [completed]\n"+
          "permissions: {contents: "+config["rights"]+"}\n"+
          "jobs:\n  use:\n    runs-on: ubuntu-latest\n"+
          guard+
          "    steps:\n"+
          "      - uses: actions/download-artifact@v4\n"+wiring+
          "      - name: Symbolic only; fixture never executed\n"+
          "        run: bash ./downloaded-fixture.sh\n"
        )
        (dest/"producer.yml").write_text(upstream,encoding="utf-8")
        (dest/"consumer.yml").write_text(downstream,encoding="utf-8")
    (ROOT/"labels.json").write_text(json.dumps({
        "risk":1,"guarded":0,"same_run":0,"read_only":0
    },indent=2),encoding="utf-8")
    print("Generated "+str(len(CASES))+" isolated non-executable fixture repositories")

if __name__=="__main__":generate()
