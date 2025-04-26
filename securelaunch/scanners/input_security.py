"""
Runs Semgrep managed-rule set p/ci and returns quick findings.
"""
import json, subprocess, tempfile
from pathlib import Path
from typing import List

def scan_inputs(repo: Path) -> List[str]:
    with tempfile.TemporaryDirectory() as tmp:
        cmd = ["semgrep", "scan", "--config", "p/ci", "--json", str(repo)]
        run = subprocess.run(cmd, capture_output=True, text=True, check=False)
        results = json.loads(run.stdout or "{}").get("results", [])
        return [f'{r["path"]}:{r["start"]["line"]} – {r["check_id"]}' for r in results]