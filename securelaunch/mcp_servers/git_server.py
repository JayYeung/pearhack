"""
FastMCP server exposing `clone_repository`.
"""
from pathlib import Path
from typing import Annotated
from fastmcp import FastMCP
from securelaunch.scanners.git_utils import clone_repo

mcp = FastMCP("GitServer")

@mcp.tool()
def clone_repository(url: Annotated[str, "Git URL to clone"]) -> str:
    """Clone repo and return filesystem path."""
    return str(clone_repo(url))

if __name__ == "__main__":
    mcp.run()