# securelaunch/auditor_server.py
"""
Autonomous Codebase Security Auditor – MCP Server
================================================
Upgraded **secret‑scanning** phase: now a *single* Claude‑powered agent that
actually *reads* the content of each text file (up to a size / count limit)
and flags hard‑coded credentials. No regex heuristics are used.

Pipeline:
clone_repo → summarize → git_secrets → ai_secrets → deps → static → aggregate

Glossary:
* **git_secrets** – TruffleHog scan through history.
* **ai_secrets** – Claude reviews file content and returns lines that look like
  API keys / tokens / passwords.
"""

from __future__ import annotations

import os
import textwrap
from collections import Counter
from pathlib import Path
from typing import Dict, List, Optional

from fastmcp import FastMCP
from langgraph.graph import END, StateGraph
from pydantic import BaseModel, Field
from langchain.prompts import PromptTemplate

# ─── LLM setup ───────────────────────────────────────────────────────────────
ANTHROPIC_MODEL = os.getenv("ANTHROPIC_MODEL", "claude-3-opus-20240229")
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY")
print(f"Using Anthropic model: {ANTHROPIC_MODEL}")
print(f"Using Anthropic API key: {bool(ANTHROPIC_API_KEY)}")

if ANTHROPIC_API_KEY:
    from langchain_anthropic import ChatAnthropic
    _llm = ChatAnthropic(model_name=ANTHROPIC_MODEL, temperature=0)
else:
    _llm = None  # type: ignore

###############################################################################
# Local scanner imports                                                       #
###############################################################################
from securelaunch.scanners.git_utils import clone_repo
from securelaunch.scanners.api_keys import scan_api_keys      # TruffleHog
from securelaunch.scanners.deps import scan_dependencies
from securelaunch.scanners.input_security import scan_inputs

###############################################################################
# Constants                                                                   #
###############################################################################
_TEXT_EXTS = {
    ".py", ".js", ".ts", ".java", ".go", ".rb", ".php", ".c", ".cpp", ".cs",
    ".json", ".yml", ".yaml", ".env", ".txt", ".sh", ".md",
}
_MAX_FILE_SIZE = 60_000      # read up to 60 KB per file
_MAX_FILES_FOR_AI = 120      # to keep token cost sane

###############################################################################
# AI secret‑scan prompt                                                       #
###############################################################################

_AI_FILE_PROMPT = textwrap.dedent(
    """
    You are a senior security engineer. Below is the full text of a project file
    from a repository. Identify any hard‑coded credentials such as API keys,
    OAuth tokens, JWTs, passwords, or long random strings that look like
    secrets. Output a bullet list where each bullet is:
        <path>:<lineno> – <short description of the secret>
    If you find nothing risky in the file, output nothing.

    <FILE {path}>
    {content}
    </FILE>
    """
)

###############################################################################
# State model                                                                 #
###############################################################################

class AuditState(BaseModel):
    repo_url: str
    repo_path: Optional[str] = None

    summary: Optional[str] = None
    git_secret_findings: List[str] = Field(default_factory=list)   # TruffleHog
    ai_secret_findings: List[str] = Field(default_factory=list)    # Claude
    dependency_findings: List[str] = Field(default_factory=list)
    static_findings: List[str] = Field(default_factory=list)

    report: Optional[str] = None

###############################################################################
# Helpers                                                                     #
###############################################################################

def _simple_summary(repo_path: str) -> str:
    exts = [p.suffix.lower() for p in Path(repo_path).rglob("*") if p.is_file()]
    counts = Counter(exts)
    top = ", ".join(f"{e or '[noext]'} ×{n}" for e, n in counts.most_common(5))
    return f"Repo has {len(exts)} files. Top types: {top}."

_SUM_PROMPT = PromptTemplate(
    template="Provide a concise (5‑7 sentence) overview of the repository at {repo_path}.",
    input_variables=["repo_path"],
)

###############################################################################
# Nodes                                                                       #
###############################################################################

def node_clone_repo(state: AuditState) -> AuditState:
    state.repo_path = str(clone_repo(state.repo_url))
    return state


def node_summarize(state: AuditState) -> AuditState:
    if _llm is None:
        state.summary = _simple_summary(state.repo_path)
        return state
    file_list = [str(p.relative_to(state.repo_path)) for p in Path(state.repo_path).rglob("*") if p.is_file()][:200]
    prompt = "File list:\n" + "\n".join(file_list) + "\n\n" + _SUM_PROMPT.format(repo_path=state.repo_path)
    state.summary = _llm.invoke(prompt).content.strip()
    return state

# ─── secrets: TruffleHog history scan ────────────────────────────────────────

def node_git_secrets(state: AuditState) -> AuditState:
    state.git_secret_findings = scan_api_keys(Path(state.repo_path))
    return state

# ─── AI full file review ─────────────────────────────────────────────────────

def node_ai_secrets(state: AuditState) -> AuditState:
    if _llm is None:
        state.ai_secret_findings = []
        return state

    findings: List[str] = []
    files_scanned = 0
    for file in Path(state.repo_path).rglob("*"):
        if files_scanned >= _MAX_FILES_FOR_AI:
            break
        if not file.is_file():
            continue
        if file.suffix not in _TEXT_EXTS:
            continue
        if file.stat().st_size > _MAX_FILE_SIZE:
            continue
        try:
            content = file.read_text(errors="ignore")
        except Exception:
            continue
        files_scanned += 1
        prompt = _AI_FILE_PROMPT.format(path=str(file.relative_to(state.repo_path)), content=content)
        bullets = _llm.invoke(prompt).content.strip().splitlines()
        for b in bullets:
            b = b.lstrip("*- •\t ").strip()
            if b:
                findings.append(b)
    state.ai_secret_findings = findings
    return state

# ─── dependency / static analysis ────────────────────────────────────────────

def node_scan_dependencies(state: AuditState) -> AuditState:
    state.dependency_findings = scan_dependencies(Path(state.repo_path))
    return state


def node_static_analysis(state: AuditState) -> AuditState:
    state.static_findings = scan_inputs(Path(state.repo_path))
    return state

###############################################################################
# Aggregation                                                                 #
###############################################################################

if _llm is not None:
    _AGG_PROMPT = PromptTemplate(
        template=textwrap.dedent(
            """
            You are an application‑security analyst. Produce a structured markdown report.
            <SUMMARY>{summary}</SUMMARY>
            <GIT>{gitsec}</GIT>
            <AI>{aifind}</AI>
            <DEPENDENCIES>{deps}</DEPENDENCIES>
            <STATIC>{static}</STATIC>
            """
        ),
        input_variables=["summary", "gitsec", "aifind", "deps", "static"],
    )


def _fallback_report(state: AuditState) -> str:
    lines = ["# Security Audit Report", ""]
    if state.summary:
        lines.extend(["## Codebase overview", state.summary, ""])
    sections = [
        ("Secrets – TruffleHog", state.git_secret_findings),
        ("Secrets – AI review", state.ai_secret_findings),
        ("Dependency vulnerabilities", state.dependency_findings),
        ("Static analysis findings", state.static_findings),
    ]
    for title, finds in sections:
        lines.append(f"## {title}")
        lines.extend(f"* {f}" for f in finds) if finds else lines.append("No issues found.")
        lines.append("")
    return "\n".join(lines).strip()


def node_aggregate(state: AuditState) -> AuditState:
    if _llm is None:
        state.report = _fallback_report(state)
        return state
    state.report = _llm.invoke(
        _AGG_PROMPT.format(
            summary=state.summary or "(no summary)",
            gitsec="\n".join(state.git_secret_findings) or "(none)",
            aifind="\n".join(state.ai_secret_findings) or "(none)",
            deps="\n".join(state.dependency_findings) or "(none)",
            static="\n".join(state.static_findings) or "(none)",
        )
    ).content.strip()
    return state

###############################################################################
# Workflow                                                                    #
###############################################################################

def build_workflow():
    sg = StateGraph(AuditState)

    sg.add_node("clone_repo", node_clone_repo)
    sg.add_node("summarize", node_summarize)
    sg.add_node("git_secrets", node_git_secrets)
    sg.add_node("ai_secrets", node_ai_secrets)
    sg.add_node("deps", node_scan_dependencies)
    sg.add_node("static", node_static_analysis)
    sg.add_node("aggregate", node_aggregate)

    sg.set_entry_point("clone_repo")
    sg.add_edge("clone_repo", "summarize")
    sg.add_edge("summarize", "git_secrets")
    sg.add_edge("git_secrets", "ai_secrets")
    sg.add_edge("ai_secrets", "deps")
    sg.add_edge("deps", "static")
    sg.add_edge("static", "aggregate")
    sg.add_edge("aggregate", END)

    return sg.compile()

_WORKFLOW = build_workflow()

###############################################################################
# FastMCP exposure                                                            #
###############################################################################

mcp = FastMCP("SecureLaunchAuditor")

@mcp.tool()
def audit_repository(github_url: str) -> Dict[str, object]:
    """Run full audit and return JSON results."""
    final_state = _WORKFLOW.invoke({"repo_url": github_url})

    def g(attr: str):
        return getattr(final_state, attr) if hasattr(final_state, attr) else final_state.get(attr)  # type: ignore

    return {
        "summary": g("summary"),
        "report": g("report"),
        "secrets_git": g("git_secret_findings"),
        "secrets_ai": g("ai_secret_findings"),
        "dependencies": g("dependency_findings"),
        "static": g("static_findings"),
    }

###############################################################################
# Entrypoint                                                                  #
###############################################################################

if __name__ == "__main__":
    try:
        mcp.run()
    except AttributeError:
        import uvicorn
        uvicorn.run(mcp.app, host="0.0.0.0", port=4001)
