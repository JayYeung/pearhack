"""
Shallow-clone a public Git repo using GitPython.
"""
import tempfile
from pathlib import Path
from git import Repo   # pip install gitpython

def clone_repo(url: str) -> Path:
    dst = Path(tempfile.mkdtemp(prefix="securelaunch_"))
    Repo.clone_from(url, dst, depth=1, single_branch=True)
    return dst