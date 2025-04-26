"""
Light-weight wrapper around TruffleHog for secret-leak detection.
"""
import json, subprocess, tempfile
from pathlib import Path
from typing import List

def scan_api_keys(repo: Path) -> List[str]:
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "results.json"
        subprocess.run(
            ["trufflehog", "filesystem", str(repo), "--json", "--output", out],
            check=False, capture_output=True
        )
        if not out.exists():
            return []
        findings = json.loads(out.read_text())
        return [f'{f["DetectorName"]}: {f["Raw"][:60]}…' for f in findings]