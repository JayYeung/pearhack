import os
from fastmcp import FastMCP
from typing import Dict
ANTHROPIC_MODEL = os.getenv("ANTHROPIC_MODEL", "claude-3-opus-20240229")
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY")
print(f"Using Anthropic model: {ANTHROPIC_MODEL}")
print(f"Using Anthropic API key: {bool(ANTHROPIC_API_KEY)}")

if ANTHROPIC_API_KEY:
    from langchain_anthropic import ChatAnthropic
    _llm = ChatAnthropic(model_name=ANTHROPIC_MODEL, temperature=0)
else:
    _llm = None  # type: ignore

try:
    # Try relative import first
    try:
        from .multi_agent_auditor import app as multi_agent_workflow_app
        print("Successfully imported multi-agent workflow via relative import.")
    except ImportError:
        # Try absolute import as fallback
        import sys
        sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        from securelaunch.multi_agent_auditor import app as multi_agent_workflow_app
        print("Successfully imported multi-agent workflow via absolute import.")
except ImportError as e:
    print(f"Error importing multi-agent workflow: {e}")
    print("Please ensure 'multi_agent_auditor.py' has been moved to 'securelaunch/multi_agent_auditor.py'")
    multi_agent_workflow_app = None

mcp = FastMCP("SecureLaunchAuditor")

@mcp.tool()
def audit_repository(github_url: str) -> Dict[str, object]:
    """Run full audit using the multi-agent workflow and return results."""
    if not multi_agent_workflow_app:
        return {"error": "Multi-agent workflow not loaded."}

    print(f"Starting multi-agent audit for: {github_url}")
    try:
        inputs = {"repo_url": github_url}
        config = {"recursion_limit": 100}

        final_state = multi_agent_workflow_app.invoke(inputs, config=config)
        print("Multi-agent audit workflow finished.")

        report = final_state.get('final_report', 'Report generation failed.')
        error = final_state.get('error', None)

        results = {
            "report": report,
            "error": error,
            "static_analysis_results": final_state.get('static_analysis_results'),
            "secret_findings": final_state.get('secret_findings'),
            "dependency_vulns": final_state.get('dependency_vulns'),
            "holistic_analysis_results": final_state.get('holistic_analysis_results'),
        }
        return {k: v for k, v in results.items() if v is not None}

    except Exception as e:
        import traceback
        print(f"Error during multi-agent workflow execution: {e}")
        traceback.print_exc()
        return {"error": f"Workflow execution failed: {e}"}

if __name__ == "__main__":
    try:
        mcp.run()
    except AttributeError:
        import uvicorn
        uvicorn.run(mcp.app, host="0.0.0.0", port=4001)
