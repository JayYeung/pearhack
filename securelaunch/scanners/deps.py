"""
Uses pip-audit to flag vulnerable Python dependencies.
"""
import json, subprocess
from pathlib import Path
from typing import List

def scan_dependencies(repo: Path) -> List[str]:
    req = next(repo.glob("**/requirements*.txt"), None)
    if not req:
        return ["No requirements.txt found"]
    run = subprocess.run(
        ["pip-audit", "-r", str(req), "-f", "json"],
        capture_output=True, text=True, check=False
    )
    data = json.loads(run.stdout or "[]")
    return [f'{d["name"]} {d["version"]} – {d["id"]} (fix: {",".join(d["fix_versions"]) or "none"})'
            for d in data]