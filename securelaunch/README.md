# SecureLaunch Multi-Agent Auditor - MCP Server

This project implements a multi-agent system using LangGraph to perform security audits on GitHub repositories. It is designed to be run as a FastMCP server, allowing integration with tools like the Claude CLI.

## Features

*   Clones a target GitHub repository.
*   Runs multiple parallel security analysis tasks:
    *   **Static Analysis:** Uses Semgrep to identify potential code vulnerabilities.
    *   **Secret Detection:** Employs Gitleaks and LLM-based analysis to find exposed secrets.
    *   **Dependency Check:** Uses `pip-audit` (or similar for other languages if extended) to find known vulnerabilities in dependencies.
    *   **Holistic Code Review:** Uses an LLM to review code for broader security issues.
*   Synthesizes findings into a comprehensive security report using an LLM.
*   Exposes the auditing functionality via a FastMCP server endpoint.

## Prerequisites

*   **Python:** Version 3.11 or higher recommended.
*   **Git:** Required for cloning repositories.
*   **Semgrep:** Must be installed separately. Follow instructions at [semgrep.dev](https://semgrep.dev/docs/getting-started/).
*   **Gitleaks:** Must be installed separately. Follow instructions at [github.com/gitleaks/gitleaks](https://github.com/gitleaks/gitleaks#installing).
*   **Anthropic API Key:** Required for the LLM components.

## Setup

1.  **Clone the Repository (if you haven't already):**
    ```bash
    git clone <repository_url>
    cd pearhack # Or your project's root directory
    ```

2.  **Create and Activate a Virtual Environment:**
    ```bash
    python3 -m venv venv
    source venv/bin/activate
    # On Windows use `venv\Scripts\activate`
    ```

3.  **Install Dependencies:**
    Navigate to the `securelaunch` directory and install the required Python packages:
    ```bash
    cd securelaunch
    pip install -r requirements.txt
    cd .. # Return to project root
    ```

4.  **Set Up Environment Variables:**
    Create a `.env` file in the *project root* directory (`/Users/seantai/Desktop/pearhack`) and add your Anthropic API key:
    ```dotenv
    # .env
    ANTHROPIC_API_KEY="sk-ant-api03-..."
    ```
    The server will load this automatically.

## Running the Server

You must run the server as a Python module from the *project root* directory (`/Users/seantai/Desktop/pearhack`) to ensure imports work correctly:

```bash
python -m securelaunch.auditor_server
```

You should see output indicating the server has started, using your Anthropic API key.

## Using with FastMCP / Claude CLI

Once the server is running, you can interact with it using FastMCP tools or the Claude CLI.

1.  **Adding to Claude CLI (Optional):**
    If you use the Claude CLI, you can add this server for easy access (ensure the server is running first):
    ```bash
    # Make sure you are in the project root directory
    claude mcp add securelaunch python securelaunch/auditor_server.py
    ```
    *Note: The exact command might vary based on your FastMCP/Claude CLI setup.*

2.  **Calling the Auditor:**
    You can trigger an audit via the exposed `audit_repository` tool.

    *   **Example using Claude CLI (if added):**
        ```
        /mcp securelaunch:audit_repository github_url="https://github.com/someuser/somerepo"
        ```
    *   **Example using `curl` (if server running on default port 4001):**
        ```bash
        curl -X POST http://localhost:4001/call/audit_repository \
             -H "Content-Type: application/json" \
             -d '{"github_url": "https://github.com/someuser/somerepo"}'
        ```

## How it Works

The core logic resides in `securelaunch/multi_agent_auditor.py`, which defines a LangGraph state machine. `securelaunch/auditor_server.py` wraps this graph in a FastMCP server, handling the API key setup and exposing the `audit_repository` endpoint.
