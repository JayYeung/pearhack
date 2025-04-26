"""
LangGraph orchestrator that:
1. clones the repo,
2. runs semgrep,
3. returns a markdown summary.
"""
import os, asyncio, json, logging
from typing import TypedDict, Sequence

from langchain_core.messages import BaseMessage, HumanMessage
from langgraph.graph import StateGraph, END
from langgraph.prebuilt import ToolNode
from langchain_anthropic import ChatAnthropic
from langchain_mcp_adapters.client import MultiServerMCPClient

logger = logging.getLogger("securelaunch.pipeline")
logging.basicConfig(level=logging.INFO)

class AuditState(TypedDict):
    messages: Sequence[BaseMessage]
    repo_url: str | None
    error: str | None

async def _build_app() -> StateGraph:
    root = os.path.dirname(os.path.dirname(__file__))
    servers = {
        "git": {
            "command": "python",
            "args": [os.path.join(root, "mcp_servers", "git_server.py")],
            "transport": "stdio",
        },
        "semgrep": {
            "command": "python",
            "args": [os.path.join(root, "mcp_servers", "semgrep_server.py")],
            "transport": "stdio",
        },
    }

    client = await MultiServerMCPClient.from_config(servers)
    tools = client.get_tools()
    tool_node = ToolNode(tools)

    llm = ChatAnthropic(model="claude-3-sonnet-20240229", temperature=0).bind_tools(tools)

    def call_llm(state: AuditState):
        resp = llm.invoke(state["messages"])
        return {"messages": [resp]}

    def should_continue(state: AuditState):
        if state.get("error"):
            return END
        last = state["messages"][-1]
        return "tools" if getattr(last, "tool_calls", None) else END

    g = StateGraph(AuditState)
    g.add_node("agent", call_llm)
    g.add_node("tools", tool_node)
    g.set_entry_point("agent")
    g.add_conditional_edges("agent", should_continue, {"tools": "tools", END: END})
    g.add_edge("tools", "agent")
    return g.compile()

async def run_audit(repo_url: str) -> str:
    app = await _build_app()
    init = {"messages": [HumanMessage(
        content=(f"Clone `{repo_url}` with clone_repository, "
                 f"then run run_semgrep_scan on the cloned path. "
                 f"Return a markdown summary of findings."))],
            "repo_url": repo_url}

    state: AuditState | None = None
    async for update in app.astream(init):
        state = update[next(iter(update))]  # grab last state fragment

    if not state:
        return "Pipeline returned no state."

    return state["messages"][-1].content