"""
Shieldbot MCP Server

Exposes security scanning tools via the Model Context Protocol so any
MCP-compatible client (Claude Code, Claude Desktop, etc.) can invoke them.
"""

from __future__ import annotations

import asyncio
import json
import shutil
import sys
from pathlib import Path

# Allow running from the package root
_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))

from mcp.server.fastmcp import FastMCP

from shieldbot.run_scan import detect_project_type, run_scan
from shieldbot.reporters.json_reporter import write_json_report

mcp = FastMCP(
    "shieldbot",
    instructions=(
        "Shieldbot is a security code review agent. Use scan_repository to scan a "
        "local repository for vulnerabilities, hardcoded secrets, and CVEs using "
        "CodeQL (deep dataflow SAST), Semgrep (5,000+ rules), bandit, ruff, "
        "detect-secrets, osv-scanner/dependabot (OSV/GHSA advisory database), "
        "pip-audit, npm-audit, and Trivy (Docker image CVEs/misconfigs/secrets) — "
        "all running in parallel. "
        "Use check_scanner_tools first if you are unsure which tools are installed."
    ),
)


@mcp.tool()
async def scan_repository(
    repo_path: str,
    skip_scanners: list[str] | None = None,
    scan_git_history: bool = False,
    min_severity: str = "info",
) -> str:
    """
    Run a full security scan on a repository.

    Executes the following scanners in parallel:
    - CodeQL (deep dataflow / taint-analysis SAST, open-source CLI)
    - Semgrep (5,000+ OWASP/CWE rules)
    - bandit (Python-specific security linter)
    - ruff (Python quality + security patterns)
    - detect-secrets / gitleaks (hardcoded secrets)
    - osv-scanner / dependabot (dependency CVEs via OSV/GHSA advisory DB)
    - pip-audit (Python CVEs)
    - npm-audit (Node.js CVEs)
    - trivy (Docker image CVEs, misconfigurations, and baked-in secrets — runs when a Dockerfile is found)

    Returns a JSON report with deduplicated, severity-ranked findings.

    Args:
        repo_path: Absolute or relative path to the repository to scan.
        skip_scanners: Optional list of scanner names to skip.
                       Valid values: codeql, semgrep, bandit, ruff,
                       detect-secrets, dependabot, pip-audit, npm-audit, trivy
        scan_git_history: If True, scan git history for leaked secrets
                          (requires gitleaks to be installed).
        min_severity: Minimum severity to include in output.
                      One of: critical, high, medium, low, info

    Returns:
        JSON string containing the full SecurityReport with all findings,
        per-scanner metadata, severity counts, and scan duration.
    """
    path = str(Path(repo_path).resolve())
    if not Path(path).is_dir():
        return json.dumps({"error": f"Not a directory: {repo_path}"})

    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    min_order = sev_order.get(min_severity, 4)

    report = await run_scan(
        repo_path=path,
        skip_scanners=set(skip_scanners or []),
        scan_git_history=scan_git_history,
    )

    # Apply severity filter
    report.all_findings = [
        f for f in report.all_findings
        if sev_order.get(f.severity.value, 9) <= min_order
    ]

    return write_json_report(report)


@mcp.tool()
def check_scanner_tools() -> str:
    """
    Check which security scanner tools are installed and available.

    Returns a JSON object mapping each tool name to its availability
    status and install path (or install instructions if missing).
    """
    tools = {
        "codeql": (
            "codeql",
            "Auto-installed by shieldbot on first scan  "
            "or manually: shieldbot-install --codeql  "
            "(macOS/Linux x86_64+arm64, no sudo required)",
        ),
        "osv-scanner": (
            "osv-scanner",
            "Auto-installed by shieldbot on first scan  "
            "or manually: shieldbot-install --osv  "
            "(macOS/Linux x86_64+arm64, no sudo required)",
        ),
        "dependabot": (
            "dependabot",
            "Auto-installed by shieldbot on first scan  "
            "or manually: shieldbot-install --dependabot  "
            "(source: https://github.com/dependabot/cli — requires Docker at runtime)",
        ),
        "semgrep": ("semgrep", "pip install semgrep"),
        "bandit": ("bandit", "pip install bandit"),
        "ruff": ("ruff", "pip install ruff"),
        "detect-secrets": ("detect-secrets", "pip install detect-secrets"),
        "gitleaks": ("gitleaks", "brew install gitleaks"),
        "pip-audit": ("pip-audit", "pip install pip-audit"),
        "npm": ("npm", "Install Node.js from https://nodejs.org"),
        "trivy": (
            "trivy",
            "Auto-installed by shieldbot on first scan (when a Dockerfile is found)  "
            "or manually: shieldbot-install --trivy  "
            "(macOS/Linux x86_64+arm64, no sudo required — requires Docker at runtime)",
        ),
        "docker": ("docker", "Install Docker from https://docs.docker.com/get-docker/"),
    }
    result = {}
    for name, (binary, install_hint) in tools.items():
        path = shutil.which(binary)
        result[name] = {
            "available": bool(path),
            "path": path or None,
            "install": None if path else install_hint,
        }
    return json.dumps(result, indent=2)


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
