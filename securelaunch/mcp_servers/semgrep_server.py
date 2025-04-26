"""
FastMCP server exposing `run_semgrep_scan`.
"""
import json, subprocess
from pathlib import Path
from typing import Annotated
from fastmcp import FastMCP

mcp = FastMCP("SemgrepServer")

@mcp.tool()
def run_semgrep_scan(
    repo_path: Annotated[str, "Path from clone_repository"],
    config: Annotated[str, "Semgrep config id"] = "auto"
) -> str:
    """Run semgrep and return raw JSON results."""
    if not Path(repo_path).is_dir():
        return json.dumps({"error": "repo_path not found"})
    cmd = ["semgrep", "scan", "--json", "--config", config, repo_path]
    run = subprocess.run(cmd, capture_output=True, text=True, check=False)
    return run.stdout or json.dumps({"error": run.stderr.strip()})

if __name__ == "__main__":
    mcp.run()