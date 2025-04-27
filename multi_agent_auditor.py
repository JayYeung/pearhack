import os
import json
import subprocess
import tempfile
import shutil
from typing import TypedDict, List, Dict, Optional
from dotenv import load_dotenv
from git import Repo, GitCommandError
from langgraph.graph import StateGraph, END
from langgraph.checkpoint.memory import MemorySaver # For potential state saving

# --- Environment & LLM Setup --- #
load_dotenv() # Load environment variables from .env file

# --- LLM Client Setup ---
# Define the placeholder class first, so the name is always available
class PlaceholderLLM:
    def invoke(self, prompt):
        # Simulate an LLM call for debugging/testing without API usage
        print("\n--- LLM Invoke (Placeholder) ---")
        # Limit printed prompt length if needed
        # print(f"Prompt: {prompt[:300]}...")
        # Simulate a successful response structure
        return type('obj', (object,), {'content': "(LLM validation placeholder)"})()

# Check for Anthropic API key
api_key = os.getenv("ANTHROPIC_API_KEY")
if not api_key:
    print("Warning: ANTHROPIC_API_KEY environment variable not set.")
    llm = None # Will use placeholder later
else:
    try:
        # Import Anthropic client
        from langchain_anthropic import ChatAnthropic
        # Initialize the Anthropic LLM client (using Haiku for speed/cost)
        llm = ChatAnthropic(model="claude-3-7-sonnet-latest", temperature=0)
        print("ChatAnthropic LLM Client Initialized (Model: claude-3-7-sonnet-latest).")
    except ImportError:
        print("Error: langchain-anthropic package not found. Please install it (`pip install langchain-anthropic`)")
        llm = None
    except Exception as e:
        print(f"Error initializing Anthropic LLM: {e}")
        llm = None

# If LLM initialization failed or key was missing, assign the placeholder instance
if llm is None:
    print("Using LLM Placeholder.")
    llm = PlaceholderLLM()

# --- Helper Functions ---
def _extract_code_snippet(file_path: str, start_line: int, end_line: int) -> str:
    """Extracts a code snippet from a file given start and end lines."""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
        # Adjust line numbers to be 0-indexed and inclusive
        start_index = max(0, start_line - 1)
        end_index = min(len(lines), end_line)
        snippet_lines = lines[start_index:end_index]
        # Add some context around the snippet if possible
        context_before = max(0, start_index - 2)
        context_after = min(len(lines), end_index + 2)
        context_lines = lines[context_before:start_index] + snippet_lines + lines[end_index:context_after]

        # Indicate the actual finding lines
        formatted_snippet = ""
        for i, line in enumerate(context_lines, start=context_before + 1):
            prefix = ">> " if start_line <= i <= end_line else "   "
            formatted_snippet += f"{prefix}{i:4d} | {line.rstrip()}\n"

        return formatted_snippet.strip()
    except FileNotFoundError:
        return f"Error: File not found: {file_path}"
    except Exception as e:
        return f"Error extracting snippet from {file_path}: {e}"

# --- State Definition ---
class AgentState(TypedDict):
    repo_url: str
    local_path: Optional[str]
    static_analysis_results: Optional[List[Dict]]
    secret_findings: Optional[List[Dict]]
    dependency_vulns: Optional[List[Dict]]
    holistic_analysis_results: Optional[str]
    final_report: Optional[str]
    error: Optional[str] # To capture any errors during the process

# --- Agent Nodes ---

def clone_repo_node(state: AgentState) -> AgentState:
    """Clones the repository from the given URL into a temporary directory."""
    repo_url = state['repo_url']
    repo_dir = None
    try:
        repo_dir = tempfile.mkdtemp()
        print(f"Cloning {repo_url} into {repo_dir}...")
        Repo.clone_from(repo_url, repo_dir)
        print("Cloning successful.")
        state['local_path'] = repo_dir
        state['error'] = None # Reset error on success
    except GitCommandError as e:
        print(f"Error cloning repository: {e}")
        state['local_path'] = None
        state['error'] = f"Failed to clone repository: {str(e)}. Check URL and permissions."
        if repo_dir and os.path.exists(repo_dir):
            shutil.rmtree(repo_dir) # Clean up temp dir on clone failure
    except Exception as e:
        print(f"An unexpected error occurred during cloning: {e}")
        state['local_path'] = None
        state['error'] = f"An unexpected error occurred during cloning: {str(e)}"
        if repo_dir and os.path.exists(repo_dir):
            shutil.rmtree(repo_dir) # Clean up temp dir on error
    return state

# --- Placeholder functions for other nodes (to be implemented) ---
def static_analysis_node(state: AgentState) -> AgentState:
    """Runs Semgrep for static analysis and refines findings with LLM."""
    print("Running Static Analysis Node...")
    repo_path = state.get('local_path')
    if not repo_path or state.get('error'):
        print("Skipping static analysis due to previous error or missing path.")
        state['static_analysis_results'] = [] # Ensure it's an empty list
        return {"static_analysis_results": state.get('static_analysis_results', [])}

    results_file = 'semgrep_results.json'
    refined_results = []

    try:
        print(f"Running Semgrep on {repo_path}...")
        # Use 'semgrep ci' which combines scanning popular rulesets
        # Timeout added for safety against very large repos
        semgrep_cmd = ['semgrep', 'scan', '--config', 'auto', '--json', '-o', results_file, repo_path]

        # Setting cwd might be necessary depending on semgrep version/installation
        process = subprocess.run(semgrep_cmd, check=False, capture_output=True, text=True, timeout=600) # 10 min timeout

        if process.returncode != 0:
            # Semgrep returns specific exit codes, 0=no findings, 1=findings, >1=error
            if process.returncode > 1:
                print(f"Semgrep execution error (Exit Code {process.returncode}):")
                print(f"Stderr: {process.stderr}")
                raise subprocess.CalledProcessError(process.returncode, semgrep_cmd, output=process.stdout, stderr=process.stderr)
            else:
                print(f"Semgrep finished with exit code {process.returncode} (might indicate findings or no findings).")

        # Check if the results file was created
        if not os.path.exists(results_file):
             print(f"Semgrep ran but the output file '{results_file}' was not found. Stdout: {process.stdout}")
             state['static_analysis_results'] = [{'error': 'Semgrep ran but produced no output file.'}]
             return {"static_analysis_results": state.get('static_analysis_results', [])}

        with open(results_file, 'r') as f:
            semgrep_output = json.load(f)

        findings = semgrep_output.get('results', [])
        print(f"Semgrep raw analysis complete. Found {len(findings)} potential issues.")

        semgrep_results = findings
        print(f"Semgrep found {len(semgrep_results)} potential issues.")

        refined_results = []
        # Limit LLM calls for now to avoid excessive cost/time during testing
        findings_to_refine = semgrep_results[:3] # Refine first 3 findings
        print(f"Attempting LLM refinement for {len(findings_to_refine)} findings...")

        for finding in findings_to_refine:
            file_path = finding['path']
            start_line = finding['start']['line']
            end_line = finding['end']['line']
            rule_id = finding['check_id']
            message = finding['extra']['message']
            severity = finding['extra']['severity']
            code_snippet = _extract_code_snippet(os.path.join(repo_path, file_path), start_line, end_line)

            # Prepare finding data for state and LLM
            finding_data = {
                'file': file_path,
                'line_start': start_line,
                'line_end': end_line,
                'rule_id': rule_id,
                'message': message,
                'severity': severity,
                'code_snippet': code_snippet,
                'llm_validation': 'Pending'
            }

            # --- LLM Refinement --- 
            prompt = f"""Analyze the following Semgrep finding:

Rule ID: {rule_id}
Severity: {severity}
Message: {message}
File: {file_path}
Line: {start_line}
Code Snippet:
```
{code_snippet}
```

Briefly assess this finding:
1. Is it likely a true positive or potential false positive?
2. What is the potential security impact?
3. Provide a concise (1-2 sentence) summary for a report.

Assessment:
"""
            try:
                print(f"  - Refining finding: {rule_id} in {file_path}:{start_line}...")
                llm_response = llm.invoke(prompt)
                finding_data['llm_validation'] = llm_response.content.strip()
                print(f"  - LLM assessment received.")
            except Exception as llm_e:
                print(f"  - LLM refinement failed for {rule_id}: {llm_e}")
                finding_data['llm_validation'] = f"LLM Error: {str(llm_e)}"
            
            refined_results.append(finding_data)
        
        # Add remaining findings without LLM refinement (if any)
        for finding in semgrep_results[3:]:
             file_path = finding['path']
             start_line = finding['start']['line']
             end_line = finding['end']['line']
             rule_id = finding['check_id']
             message = finding['extra']['message']
             severity = finding['extra']['severity']
             code_snippet = _extract_code_snippet(os.path.join(repo_path, file_path), start_line, end_line)
             refined_results.append({
                'file': file_path,
                'line_start': start_line,
                'line_end': end_line,
                'rule_id': rule_id,
                'message': message,
                'severity': severity,
                'code_snippet': code_snippet,
                'llm_validation': 'Not Processed'
            })

        state['static_analysis_results'] = refined_results

    except subprocess.CalledProcessError as e:
        error_detail = e.stderr.strip() if e.stderr else str(e)
        state['static_analysis_results'] = [{'error': f'Semgrep execution failed: {error_detail}'}]
    except json.JSONDecodeError:
        print(f"Error: Failed to parse Semgrep JSON output from {results_file}.")
        state['static_analysis_results'] = [{'error': 'Failed to parse Semgrep JSON output.'}]
    except Exception as e:
        print(f"An unexpected error occurred during static analysis: {e}")
        state['static_analysis_results'] = [{'error': f'Unexpected static analysis error: {str(e)}'}]
    finally:
        # Clean up the results file
        if os.path.exists(results_file):
            os.remove(results_file)
            print(f"Cleaned up {results_file}.")
            
        # Return only the updated part of the state
        return {"static_analysis_results": state.get('static_analysis_results', [])}


def secret_detection_node(state: AgentState) -> AgentState:
    print("Running Secret Detection Node...")
    local_path = state.get('local_path')
    if not local_path or state.get('error'):
        print("Skipping secret detection due to previous error or missing path.")
        state['secret_findings'] = []
        return {"secret_findings": state.get('secret_findings', [])}

    results_file = 'gitleaks_results.json'
    refined_findings = []

    try:
        print(f"Running GitLeaks on {local_path}...")
        # Command: gitleaks detect --source <path> -f json -r <output_file>
        # Note: The --no-git flag is used to scan the directory content, not just git history
        gitleaks_cmd = [
            'gitleaks',
            'detect',
            '--source', local_path,
            '-f', 'json',
            '-r', results_file,
            '--no-git', # Scan the directory content, not just git history for this example
            '--verbose'
        ]

        process = subprocess.run(gitleaks_cmd, check=False, capture_output=True, text=True, timeout=300) # 5 min timeout

        # GitLeaks exit codes: 0 = no leaks, 1 = leaks found, 2 = error
        if process.returncode == 2:
            print(f"GitLeaks execution error (Exit Code {process.returncode}):")
            print(f"Stderr: {process.stderr}")
            raise subprocess.CalledProcessError(process.returncode, gitleaks_cmd, output=process.stdout, stderr=process.stderr)
        else:
            print(f"GitLeaks finished with exit code {process.returncode} (0=no leaks, 1=leaks found).")

        # Check if the results file exists, even if leaks were found (code 1)
        if not os.path.exists(results_file):
             # If exit code was 0 (no leaks), file might not be created. This is okay.
            if process.returncode == 0:
                print("GitLeaks found no secrets.")
                state['secret_findings'] = []
                return {"secret_findings": state.get('secret_findings', [])}
            else:
                # If leaks were expected (code 1) but no file, it's an issue.
                print(f"GitLeaks exited with code {process.returncode} but the output file '{results_file}' was not found. Stdout: {process.stdout}, Stderr: {process.stderr}")
                state['secret_findings'] = [{'error': f'GitLeaks ran (exit code {process.returncode}) but produced no output file.'}]
                return {"secret_findings": state.get('secret_findings', [])}

        # Load findings if the file exists
        with open(results_file, 'r') as f:
            # GitLeaks JSON output is a list of findings, potentially empty
            gitleaks_findings = json.load(f)

        print(f"GitLeaks raw analysis complete. Found {len(gitleaks_findings)} potential secrets.")

        # --- LLM Enhancement --- 
        refined_secrets = []
        secrets_to_refine = gitleaks_findings[:3] # Refine first 3 findings
        print(f"Attempting LLM refinement for {len(secrets_to_refine)} potential secrets...")

        for finding in secrets_to_refine:
            finding_data = {
                'description': finding.get('Description', 'N/A'),
                'file': finding.get('File', 'N/A'),
                'commit': finding.get('Commit', 'N/A'),
                'rule_id': finding.get('RuleID', 'N/A'),
                'secret': finding.get('Secret', 'N/A'), # Be cautious logging/storing this
                'line_number': finding.get('StartLine', 'N/A'),
                'llm_assessment': 'Pending'
            }

            # Prepare LLM prompt
            prompt = f"""Analyze the following potential secret found by GitLeaks:

Rule ID: {finding_data['rule_id']}
Description: {finding_data['description']}
File: {finding_data['file']}
Line: {finding_data['line_number']}
Commit: {finding_data['commit']}
Secret Snippet (Masked): {finding_data['secret'][:2]}...{finding_data['secret'][-2:] if len(finding_data['secret']) > 4 else ''}

Briefly assess this finding:
1. How likely is this a real, sensitive secret exposed in the codebase/history?
2. What is the potential impact if it is real?
3. Provide a concise (1-2 sentence) summary for a report (DO NOT include the secret itself).

Assessment:
"""
            try:
                print(f"  - Refining secret finding: {finding_data['rule_id']} in {finding_data['file']}...")
                llm_response = llm.invoke(prompt)
                finding_data['llm_assessment'] = llm_response.content.strip()
                print(f"  - LLM assessment received.")
            except Exception as llm_e:
                print(f"  - LLM refinement failed for {finding_data['rule_id']}: {llm_e}")
                finding_data['llm_assessment'] = f"LLM Error: {str(llm_e)}"

            # Important: Remove or further mask the actual secret before storing long-term if needed
            finding_data.pop('secret', None) # Remove the raw secret from the final stored data
            refined_secrets.append(finding_data)

        # Add remaining findings without LLM refinement
        for finding in gitleaks_findings[3:]:
             refined_secrets.append({
                'description': finding.get('Description', 'N/A'),
                'file': finding.get('File', 'N/A'),
                'commit': finding.get('Commit', 'N/A'),
                'rule_id': finding.get('RuleID', 'N/A'),
                # 'secret': finding.get('Secret', 'N/A'), # Exclude raw secret
                'line_number': finding.get('StartLine', 'N/A'),
                'llm_assessment': 'Not Processed'
            })

        state['secret_findings'] = refined_secrets
    except subprocess.CalledProcessError as e:
        # GitLeaks uses exit code 1 to indicate leaks were found, not necessarily an execution error.
        error_detail = e.stderr.strip() if e.stderr else str(e)
        state['secret_findings'] = [{'error': f'GitLeaks execution failed: {error_detail}'}]
    except FileNotFoundError:
        print("Error: 'gitleaks' command not found. Is GitLeaks installed and in the system PATH?")
        state['secret_findings'] = [{'error': 'GitLeaks command not found.'}]
    except subprocess.TimeoutExpired:
        print("Error: GitLeaks execution timed out.")
        state['secret_findings'] = [{'error': 'GitLeaks execution timed out.'}]
    except json.JSONDecodeError:
        print(f"Error: Failed to parse GitLeaks JSON output from {results_file}.")
        state['secret_findings'] = [{'error': 'Failed to parse GitLeaks JSON output.'}]
    except Exception as e:
        print(f"An unexpected error occurred during secret detection: {e}")
        state['secret_findings'] = [{'error': f'Unexpected secret detection error: {str(e)}'}]
    finally:
        # Clean up the results file
        if os.path.exists(results_file):
            os.remove(results_file)
            print(f"Cleaned up {results_file}.")
        # Return only the updated part of the state
        return {"secret_findings": state.get('secret_findings', [])}


def dependency_check_node(state: AgentState) -> AgentState:
    print("Running Dependency Check Node...")
    local_path = state.get('local_path')
    if not local_path or state.get('error'):
        print("Skipping dependency check due to previous error or missing path.")
        state['dependency_vulns'] = []
        return {"dependency_vulns": state.get('dependency_vulns', [])}

    refined_vulns = []
    tool_used = None
    results_file = None
    command = []

    try:
        # --- Detect Dependency File and Choose Tool ---
        req_file = os.path.join(local_path, 'requirements.txt')
        pkg_file = os.path.join(local_path, 'package.json')

        if os.path.exists(req_file):
            tool_used = 'pip-audit'
            results_file = 'pip_audit_results.json'
            print(f"Found {req_file}, preparing to run {tool_used}...")
            # Command: pip-audit -r <req_file> --json -o <output_file> --progress-spinner=off
            # Adding --ignore-vuln PPY-000 to ignore potential self-scan issues if pip-audit is in reqs
            command = [
                'pip-audit',
                '-r', req_file,
                '--json',
                '-o', results_file,
                '--progress-spinner=off', # Cleaner output for automation
                '--ignore-vuln', 'PYSEC-2023-119', # Example ignore, adjust as needed
                # '--fix' # Optionally try to auto-fix, but requires careful handling
            ]
            # Pip-audit should generally be run from anywhere, specifying the req file
            cwd = None # Run from the current script's directory is usually fine
            check = False # pip-audit exits non-zero if vulns are found
            expected_exit_codes = {0, 1} # 0=no vulns, 1=vulns found

        elif os.path.exists(pkg_file):
            tool_used = 'npm audit'
            results_file = 'npm_audit_results.json'
            print(f"Found {pkg_file}, preparing to run {tool_used}...")
            # Command: npm audit --json > <output_file>
            # Note: npm audit needs to be run in the directory containing package.json
            # We redirect stdout to a file as npm audit --json outputs to stdout
            command = f"npm audit --json > {results_file}" # Use shell=True for redirection
            cwd = local_path # MUST run in the repo directory
            check = False # npm audit also exits non-zero for vulns
            expected_exit_codes = {0, 1} # 0=no vulns, 1=vulns found
            # Handle cases where package-lock.json might be missing (npm audit requires it)
            lock_file = os.path.join(local_path, 'package-lock.json')
            if not os.path.exists(lock_file):
                print(f"Warning: {pkg_file} found, but {lock_file} is missing.")
                print("Running 'npm install' first to generate lock file (this may take time)...")
                try:
                    install_cmd = ['npm', 'install', '--package-lock-only', '--ignore-scripts']
                    install_proc = subprocess.run(install_cmd, cwd=local_path, check=True, capture_output=True, text=True, timeout=300)
                    print("'npm install' completed successfully.")
                except Exception as install_e:
                    print(f"Failed to run 'npm install' to generate lock file: {install_e}")
                    state['dependency_vulns'] = [{'error': f"npm install failed: {install_e}"}]
                    return {"dependency_vulns": state.get('dependency_vulns', [])}
        else:
            print("No supported dependency file (requirements.txt or package.json) found.")
            state['dependency_vulns'] = []
            return {"dependency_vulns": state.get('dependency_vulns', [])}

        # --- Run the Selected Tool ---
        print(f"Executing: {' '.join(command) if isinstance(command, list) else command}")
        process = subprocess.run(command, cwd=cwd, check=check, capture_output=True, text=True, shell=isinstance(command, str), timeout=600)

        if process.returncode not in expected_exit_codes:
             # Treat unexpected non-zero exit codes as errors
            print(f"{tool_used} execution error (Exit Code {process.returncode}):")
            print(f"Stderr: {process.stderr}")
            raise subprocess.CalledProcessError(process.returncode, command, output=process.stdout, stderr=process.stderr)
        else:
            print(f"{tool_used} finished with exit code {process.returncode}.")

        # --- Parse Results --- (Handle tool-specific JSON structures)
        if not os.path.exists(results_file):
            print(f"Warning: {tool_used} ran but the output file '{results_file}' was not found.")
            # Check if stdout might contain the JSON (less ideal)
            if process.stdout and tool_used == 'npm audit': # npm might output JSON here if redirection failed
                 print("Attempting to parse JSON from stdout...")
                 try:
                     audit_output = json.loads(process.stdout)
                 except json.JSONDecodeError:
                     print("Failed to parse JSON from stdout.")
                     audit_output = None
            else:
                 audit_output = None
        else:
            with open(results_file, 'r') as f:
                audit_output = json.load(f)

        if not audit_output:
            print(f"No valid output found from {tool_used}.")
            state['dependency_vulns'] = []
            return {"dependency_vulns": state.get('dependency_vulns', [])}

        findings = []
        if tool_used == 'pip-audit':
            # Expected format: List of {'name', 'version', 'vulns': [{'id', 'fix_versions', 'description'}]}
            findings = audit_output
        elif tool_used == 'npm audit':
             # Expected format: {'vulnerabilities': { 'package_name': {'name', 'severity', 'via': [{'source', 'name', 'dependency', 'title', 'url', 'severity', 'range'}]}}} - complex!
            # Simplified extraction:
            raw_vulns = audit_output.get('vulnerabilities', {})
            for pkg_name, vuln_data in raw_vulns.items():
                for via_item in vuln_data.get('via', []):
                    if isinstance(via_item, dict): # Sometimes 'via' can be just a string ID
                         findings.append({
                            'id': via_item.get('source', 'N/A'), # Using source ID as CVE placeholder
                            'package_name': via_item.get('name', pkg_name),
                            'vulnerable_versions': via_item.get('range', 'N/A'),
                            'fix_versions': [], # npm audit v2 JSON doesn't always provide this easily
                            'description': via_item.get('title', 'N/A'),
                            'severity': via_item.get('severity', 'N/A'),
                            'url': via_item.get('url', 'N/A')
                         })

        print(f"{tool_used} raw analysis complete. Found {len(findings)} potential vulnerabilities.")

        # --- LLM Enhancement --- 
        refined_vulns = []
        vulns_to_refine = findings[:3] # Refine first 3 vulnerabilities
        print(f"Attempting LLM refinement for {len(vulns_to_refine)} vulnerabilities...")

        for vuln in vulns_to_refine:
            vuln_data = vuln.copy() # Start with existing data
            vuln_data['llm_assessment'] = 'Pending'

            # Create a generic prompt adaptable to both pip-audit and npm audit fields
            prompt = f"""Analyze the following dependency vulnerability:

Package: {vuln_data.get('package', 'N/A')}
Version: {vuln_data.get('version', 'N/A')}
Vulnerability ID: {vuln_data.get('vulnerability_id', 'N/A')}
Severity: {vuln_data.get('severity', 'N/A')}
Description: {vuln_data.get('description', 'N/A')}
Fix Available/Versions: {vuln_data.get('fix_available', vuln_data.get('fix_versions', 'N/A'))}
Introduced Via (if applicable): {vuln_data.get('via', 'N/A')}

Briefly assess this vulnerability:
1. What is the potential impact of this vulnerability on the application?
2. How urgent is the fix (consider severity and fix availability)?
3. Provide a concise (1-2 sentence) summary for a report.

Assessment:
"""
            try:
                print(f"  - Refining vulnerability: {vuln_data.get('vulnerability_id', 'N/A')} in {vuln_data.get('package', 'N/A')}...")
                llm_response = llm.invoke(prompt)
                vuln_data['llm_assessment'] = llm_response.content.strip()
                print(f"  - LLM assessment received.")
            except Exception as llm_e:
                print(f"  - LLM refinement failed for {vuln_data.get('vulnerability_id', 'N/A')}: {llm_e}")
                vuln_data['llm_assessment'] = f"LLM Error: {str(llm_e)}"
            
            refined_vulns.append(vuln_data)

        # Add remaining findings without LLM refinement
        for vuln in findings[3:]:
            vuln_data = vuln.copy()
            vuln_data['llm_assessment'] = 'Not Processed'
            refined_vulns.append(vuln_data)

        state['dependency_vulns'] = refined_vulns

    except FileNotFoundError as e:
        # Check if it's the audit tool command itself
        if tool_used and tool_used in str(e):
            print(f"Error: '{tool_used}' command not found. Is it installed and in the system PATH?")
            state['dependency_vulns'] = [{'error': f'{tool_used} command not found.'}]
        else:
            print(f"An unexpected FileNotFoundError occurred: {e}")
            state['dependency_vulns'] = [{'error': f'Dependency check file error: {str(e)}'}]
    except subprocess.TimeoutExpired:
        print(f"Error: {tool_used or 'Dependency check'} execution timed out.")
        state['dependency_vulns'] = [{'error': f"{tool_used or 'Dependency check'} execution timed out."}]
    except subprocess.CalledProcessError as e:
        print(f"Error during {tool_used or 'dependency check'} execution: {e}")
        # Include stderr if available and potentially stdout for npm
        error_detail = e.stderr.strip() if e.stderr else (e.stdout.strip() if e.stdout else str(e))
        state['dependency_vulns'] = [{'error': f"{tool_used or 'Dependency check'} execution failed: {error_detail}"}]
    except json.JSONDecodeError:
        print(f"Error: Failed to parse {tool_used or 'dependency check'} JSON output from {results_file}.")
        state['dependency_vulns'] = [{'error': f'Failed to parse {tool_used} JSON output.'}]
    except Exception as e:
        print(f"An unexpected error occurred during dependency check: {e}")
        state['dependency_vulns'] = [{'error': f'Unexpected dependency check error: {str(e)}'}]
    finally:
        # Clean up the results file
        if results_file and os.path.exists(results_file):
            os.remove(results_file)
            print(f"Cleaned up {results_file}.")
        # Return only the updated part of the state
        return {"dependency_vulns": state.get('dependency_vulns', [])}


def holistic_code_analysis_node(state: AgentState) -> Dict:
    """Performs LLM-based secret scanning on a concatenated subset of smaller code/config files."""
    print("Running Holistic Code Content Scanning Node...")
    local_path = state.get('local_path')
    repo_url = state.get('repo_url')
    if not local_path or not os.path.exists(local_path):
        print("Error: Local path not available for holistic analysis.")
        return {"holistic_analysis_results": "Error: Could not access repository code."}

    if not llm or isinstance(llm, PlaceholderLLM):
        print("Skipping holistic LLM content scan as LLM is not configured.")
        return {"holistic_analysis_results": "(Holistic content scan skipped - LLM not configured)"}

    # --- Configuration --- #
    # Max file size to read content from (bytes). Avoids huge files.
    max_file_size_bytes = 50000 
    # Target token limit for concatenated content (leave buffer for prompt & response)
    # Estimate: ~100k tokens for gpt-4o's 128k context. Adjust if needed.
    max_content_tokens = 100000 
    # Rough estimate: 1 token ~= 4 characters (adjust based on model/language)
    chars_per_token_estimate = 4 
    max_content_chars = max_content_tokens * chars_per_token_estimate
    
    ignored_dirs = {'.git', '__pycache__', 'node_modules', '.venv', 'dist', 'build', 'target', 'vendor'}
    # Focus on file types likely to contain code or secrets
    relevant_extensions = {'.py', '.js', '.ts', '.java', '.go', '.rb', '.php', '.sh', 
                           '.json', '.yaml', '.yml', '.toml', '.ini', '.cfg', '.env', '.conf', 
                           '.tf', '.hcl', '.xml', '.properties'}
    # Specific filenames also relevant
    relevant_filenames = {'config', 'settings', 'credentials', 'secrets', 'key', 'token', 
                          'dockerfile', 'docker-compose.yml', 'kustomization.yaml'}

    print(f"Scanning files up to {max_file_size_bytes} bytes, concatenating content up to ~{max_content_tokens} tokens...")
    concatenated_content = ""
    total_chars_added = 0
    files_scanned_count = 0
    files_skipped_large = 0
    files_skipped_limit = 0

    try:
        for root, dirs, files in os.walk(local_path, topdown=True):
            dirs[:] = [d for d in dirs if d not in ignored_dirs]

            for file in files:
                if total_chars_added >= max_content_chars:
                    files_skipped_limit += 1
                    continue # Stop adding content if limit reached

                file_lower = file.lower()
                file_ext = os.path.splitext(file_lower)[1]
                
                # Check if file is relevant by extension or name
                is_relevant = (file_ext in relevant_extensions or 
                               any(fn in file_lower for fn in relevant_filenames))

                if is_relevant:
                    full_path = os.path.join(root, file)
                    try:
                        file_size = os.path.getsize(full_path)
                        if file_size > max_file_size_bytes:
                            files_skipped_large += 1
                            continue # Skip files that are too large

                        # Try reading the file content
                        with open(full_path, 'r', encoding='utf-8', errors='ignore') as f_content:
                            content = f_content.read()
                            
                        content_chars = len(content)
                        # Check if adding this file exceeds the limit
                        if total_chars_added + content_chars > max_content_chars:
                           files_skipped_limit += 1
                           continue 

                        # Add file content with separator/header
                        relative_path = os.path.relpath(full_path, local_path)
                        concatenated_content += f"\n--- File: {relative_path} ---\n"
                        concatenated_content += content
                        total_chars_added += content_chars + len(relative_path) + 20 # Approx header size
                        files_scanned_count += 1
                        
                    except FileNotFoundError:
                        pass # Should not happen with os.walk, but safety first
                    except OSError as e:
                        print(f"Warning: Could not read file {full_path}: {e}")
                    except Exception as e:
                         print(f"Warning: Error processing file {full_path}: {e}")
        
        if not concatenated_content:
             return {"holistic_analysis_results": "No relevant small files found to scan content."}

        print(f"Prepared concatenated content from {files_scanned_count} files ({total_chars_added} chars). Skipped {files_skipped_large} large files, {files_skipped_limit} due to token limit.")

        # Construct the prompt for secret scanning
        prompt = f"""You are a security auditor. Scan the following concatenated code snippets from the repository '{repo_url}' for potential hardcoded secrets like API keys, tokens, passwords, private keys, or sensitive configuration values. 
        List any potential secrets found, specifying the file path and the potential secret itself. Be precise.
        If no potential secrets are found, state that clearly.

        BEGIN CONCATENATED CODE
        {concatenated_content}
        END CONCATENATED CODE

        Potential Secrets Found:
        """

        print(f"Invoking LLM for holistic content scan...")
        response = llm.invoke(prompt)
        holistic_findings = response.content
        print("Holistic LLM content scan complete.")
        return {"holistic_analysis_results": holistic_findings}

    except Exception as e:
        print(f"Error during holistic code content scan: {e}")
        import traceback
        traceback.print_exc()
        return {"holistic_analysis_results": f"Error during holistic content scan: {e}"}


def synthesis_node(state: AgentState) -> Dict:
    """Aggregates findings and uses LLM to generate the final report."""
    print("Running Synthesis Node...")
    print("Aggregating findings for final report...")

    repo_url = state.get('repo_url', 'N/A')
    static_results = state.get('static_analysis_results', [])
    secret_results = state.get('secret_findings', [])
    dependency_results = state.get('dependency_vulns', [])
    holistic_results = state.get('holistic_analysis_results', "(Not performed or failed)") # Get holistic results

    # Helper to format findings for the prompt, limiting length
    def format_findings(findings, category_name, max_items=5):
        if not findings:
            return f"**{category_name}:** No significant findings.\n"
        output = f"**{category_name}:** (Top {min(len(findings), max_items)} findings)\n"
        # Handle potential error dictionaries
        if isinstance(findings[0], dict) and 'error' in findings[0]:
            return f"**{category_name}:** Error during analysis: {findings[0]['error']}\n"
            
        for i, finding in enumerate(findings[:max_items]):
            details = []
            if 'rule_id' in finding: details.append(f"Rule: {finding['rule_id']}")
            if 'description' in finding: details.append(f"Desc: {finding['description'][:100]}...") # Truncate
            if 'package' in finding: details.append(f"Package: {finding['package']}")
            if 'severity' in finding: details.append(f"Severity: {finding['severity']}")
            if 'file' in finding: details.append(f"File: {finding['file']}")
            if 'line_start' in finding: details.append(f"Line: {finding['line_start']}")
            if 'llm_assessment' in finding: details.append(f"Initial LLM Assess: {finding['llm_assessment'][:150]}...") # Truncate
            elif 'llm_validation' in finding: details.append(f"Initial LLM Assess: {finding['llm_validation'][:150]}...") # Truncate
            output += f"- Finding {i+1}: {'; '.join(details)}\n"
        if len(findings) > max_items:
            output += f"(... and {len(findings) - max_items} more)\n"
        return output + "\n"

    # --- Construct the Synthesis Prompt --- 
    prompt_content = f"""## Security Audit Synthesis Request

**Repository:** {repo_url}

**Objective:** Generate a concise and actionable security audit report based on the findings from automated tools (Semgrep, GitLeaks, pip-audit/npm audit) and their initial LLM assessments.

**Input Findings:**

{format_findings(static_results, 'Static Analysis (Semgrep)')}
{format_findings(secret_results, 'Secret Detection (GitLeaks)')}
{format_findings(dependency_results, 'Dependency Vulnerabilities (pip-audit/npm audit)')}
**Holistic LLM Scan (Partial Code Content):**
{holistic_results}

**Instructions:**

1.  **Overall Summary:** Write a brief (2-3 sentence) executive summary of the security posture based *only* on the provided findings (including static, secrets found by tools, dependencies, and potential secrets found by LLM scan of partial code content). Mention the main areas of concern.
2.  **Key Findings:** For each category (Static Analysis, Secret Detection, Dependencies, **Holistic LLM Scan**), list the 1-3 *most critical* findings or observations identified in the input. Briefly explain the risk for each. For secrets (from GitLeaks or LLM Scan), clearly state the file involved.
3.  **Actionable Recommendations:** Provide a short, prioritized list of 2-5 concrete actions the development team should take based on *all* findings.
4.  **Format:** Use clear Markdown formatting with headings for Summary, Key Findings (with subheadings for categories), and Recommendations.

**Generate the Security Audit Report:**
"""

    print("Prompt prepared for LLM-based report generation...")
    # print(f"Synthesis Prompt Snippet:\n{prompt_content[:500]}...") # Uncomment for debugging

    try:
        # --- Invoke the LLM --- 
        if llm:
            print("Invoking LLM for final report synthesis...")
            llm_response = llm.invoke(prompt_content)
            final_report_content = llm_response.content.strip()
            print("LLM synthesis complete.")
        else:
            print("LLM client not available, using placeholder report.")
            # Fallback placeholder if LLM init failed earlier
            final_report_content = f"## Security Audit Report for {repo_url} (Placeholder - LLM Error)\n\nLLM client was not initialized successfully. Unable to generate report."

    except Exception as e:
        print(f"Error during LLM synthesis: {e}")
        final_report_content = f"## Security Audit Report for {repo_url} (Placeholder - Synthesis Error)\n\nAn error occurred during LLM report generation: {str(e)}"

    state['final_report'] = final_report_content
    print(f"Report synthesis complete (using {'LLM' if llm and not isinstance(llm, PlaceholderLLM) else 'placeholder text'}).")
    # Optional: Print a snippet for confirmation
    # print(f"Generated Report Snippet:\n{final_report_content[:200]}...")

    # Return only the updated part of the state
    return {"final_report": state.get('final_report')}


def cleanup_node(state: AgentState) -> AgentState:
    print("Cleanup Node")
    local_path = state.get('local_path')
    if local_path and os.path.exists(local_path):
        print(f"Cleaning up temporary directory: {local_path}")
        try:
            shutil.rmtree(local_path)
            print("Cleanup successful.")
        except Exception as e:
            print(f"Error during cleanup: {e}")
            # Optionally update state with cleanup error, though it's the last step
    return state

# --- Dummy Node for branching ---
def start_analysis_tasks_node(state: AgentState) -> AgentState:
    """Dummy node to act as a fork point for parallel analysis tasks."""
    print("Forking to parallel analysis nodes...")
    return state

# --- Graph Definition ---
print("Defining the LangGraph workflow...")

workflow = StateGraph(AgentState)

# Add nodes
workflow.add_node("clone_repo", clone_repo_node)
workflow.add_node("start_analysis_tasks", start_analysis_tasks_node) # Add the new fork node
workflow.add_node("static_analysis", static_analysis_node)
workflow.add_node("secret_detection", secret_detection_node)
workflow.add_node("dependency_check", dependency_check_node)
workflow.add_node("holistic_code_analysis", holistic_code_analysis_node) # Add new node
workflow.add_node("synthesize_report", synthesis_node)
workflow.add_node("cleanup", cleanup_node)

# Define edges
workflow.set_entry_point("clone_repo")

# Conditional edge after cloning
def check_clone_status(state: AgentState):
    """Checks if cloning resulted in an error."""
    if state.get('error'):
        print("Conditional Check: Clone failed, routing to synthesis.")
        return 'error'
    else:
        print("Conditional Check: Clone succeeded, proceeding via standard edges.")
        return 'success'

workflow.add_conditional_edges(
    "clone_repo",
    check_clone_status,
    # Map outcomes to the next logical step
    {
        "error": "synthesize_report",
        "success": "start_analysis_tasks" # Route success to the new fork node
    }
)

# Edges from the fork node to start parallel tasks
workflow.add_edge("start_analysis_tasks", "static_analysis")
workflow.add_edge("start_analysis_tasks", "secret_detection")
workflow.add_edge("start_analysis_tasks", "dependency_check")
workflow.add_edge("start_analysis_tasks", "holistic_code_analysis") # Add edge for holistic analysis

# Define how the parallel branches join before synthesis
workflow.add_edge("static_analysis", "synthesize_report")
workflow.add_edge("secret_detection", "synthesize_report")
workflow.add_edge("dependency_check", "synthesize_report")
workflow.add_edge("holistic_code_analysis", "synthesize_report") # Add edge for holistic analysis

# Edge from synthesis to cleanup
workflow.add_edge("synthesize_report", "cleanup")

# Final edge after cleanup
workflow.add_edge("cleanup", END)


# Compile the graph
# memory = MemorySaver() # Optional: In-memory checkpointing
app = workflow.compile()
# app = workflow.compile(checkpointer=memory) # With checkpointing

print("Workflow compiled successfully.")

# --- Main Execution --- 
if __name__ == "__main__":
    print("\n--- Starting Security Audit Workflow ---")

    # --- Configuration ---
    # *** Replace with the target repository URL ***
    # repo_to_audit = "https://github.com/knqyf263/trivy" # Example: Trivy (Go project, might not have py/js deps)
    repo_to_audit = "https://github.com/JayYeung/all-my-old-discord-bots" # Example: Flask (Python)
    # repo_to_audit = "https://github.com/langchain-ai/langgraph" # Example: LangGraph (Python)
    # repo_to_audit = "https://github.com/facebook/react" # Example: React (JavaScript)
    # repo_to_audit = "invalid-url" # Example: Test error handling

    print(f"Target Repository: {repo_to_audit}")
    inputs = {"repo_url": repo_to_audit}

    # Optional: Configuration for execution, like recursion limit for complex graphs
    config = {"recursion_limit": 100}

    try:
        # --- Invoke the Workflow ---
        # Use .stream() to see state changes or .invoke() for final state
        # final_state = app.invoke(inputs, config=config)

        # Streaming output for better visibility during execution
        print("\n--- Workflow Execution Log ---")
        final_state = None
        for event in app.stream(inputs, config=config):
            for node, output in event.items():
                print(f"Finished node: {node}")
                # print(f"Output: {output}") # Can be very verbose, print selectively
                if node == "clone_repo":
                    print(f" -> Cloned Path: {output.get('local_path')}, Error: {output.get('error')}")
                if node == "static_analysis":
                    count = len(output.get('static_analysis_results', []))
                    error = next((item.get('error') for item in output.get('static_analysis_results', []) if 'error' in item), None)
                    print(f" -> Static Analysis Findings: {count}, Error: {error}")
                if node == "secret_detection":
                    count = len(output.get('secret_findings', []))
                    error = next((item.get('error') for item in output.get('secret_findings', []) if 'error' in item), None)
                    print(f" -> Secret Findings: {count}, Error: {error}")
                if node == "dependency_check":
                    count = len(output.get('dependency_vulns', []))
                    error = next((item.get('error') for item in output.get('dependency_vulns', []) if 'error' in item), None)
                    print(f" -> Dependency Vulns: {count}, Error: {error}")
                if node == "holistic_code_analysis":
                    print(f" -> Holistic Analysis: {'Completed' if output.get('holistic_analysis_results') and 'Error' not in output.get('holistic_analysis_results', '') else 'Skipped/Error'}")
                if node == "synthesize_report":
                    print(f" -> Report generated (first 100 chars): {output.get('final_report', '')[:100]}...")
                if node == "cleanup":
                    print(f" -> Cleanup finished.")

            # Keep track of the last state
            # The stream yields events like {'node_name': state_after_node}
            # The actual final state might be accessed differently depending on stream format
            # Often the last event contains the full final state or just the output of END
            # Let's assume the last 'output' in the stream is the final state dictionary
            if END in event:
                 print("Workflow finished.")
                 # The event for END might not contain the full state.
                 # It's safer to capture state from the synthesis node if needed before cleanup
                 pass # final_state should be available from the synthesis node's output event
            else:
                # Update final_state with the latest complete state dictionary from the event
                # Assuming the event dictionary values are AgentState objects
                last_state_update = list(event.values())[0] # Get the state dict from the first node in the event
                if isinstance(last_state_update, dict):
                     final_state = last_state_update # Update our final_state tracker


        # --- Print Final Report --- 
        print("\n" + "="*40)
        print("--- Final Security Audit Report ---")
        print("="*40)
        if final_state and 'final_report' in final_state:
            print(final_state['final_report'])
        elif final_state and 'error' in final_state:
             print(f"Workflow completed with an error reported in the final state: {final_state['error']}")
             if 'final_report' in final_state: # Print report even if error exists
                 print("\n--- Report (may be partial due to error) ---")
                 print(final_state['final_report'])
        else:
            print("Workflow finished, but no final report was found in the state.")
            # You might want to inspect the last few events from the stream if this happens

    except Exception as e:
        print(f"\n--- Workflow Execution Failed --- ")
        print(f"An unexpected error occurred during graph execution: {e}")
        import traceback
        traceback.print_exc()

    print("\n--- Workflow Complete ---")
