# Shieldbot — Security Code Review Plugin

AI-powered security code review for Claude Code. Combines **5,000+ static analysis rules** with Claude's security expertise to detect vulnerabilities, hardcoded secrets, and CVEs — then delivers a prioritized, actionable report.

## What it scans

| Scanner | What it finds |
|---------|--------------|
| **Semgrep** (5,000+ rules) | OWASP Top 10, CWE Top 25, injection, XSS, SSRF, taint analysis |
| **bandit** | Python-specific security issues |
| **ruff** | Python code quality and security-adjacent patterns |
| **detect-secrets** | Hardcoded API keys, passwords, tokens, credentials |
| **pip-audit** | Python dependency CVEs (PyPI Advisory Database) |
| **npm audit** | Node.js dependency CVEs |

All scanners run **in parallel**. Findings are deduplicated across scanners (same vulnerability reported by multiple tools appears once).

## Installation

```
/plugin marketplace add BalaSriharsha/shieldbot
/plugin install shieldbot
/reload-plugins
```

Requires `uvx` (comes with `uv`):
```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

The MCP server (`shieldbot-mcp`) installs automatically on first use via `uvx`.

## Usage

### Slash command
```
/shieldbot .
/shieldbot /path/to/repo
/shieldbot . --skip ruff --skip bandit
/shieldbot . --git-history
```

### Natural language
Just ask Claude:
- *"scan this repo for security issues"*
- *"check for hardcoded secrets"*
- *"audit my dependencies for CVEs"*
- *"run a security review on /path/to/project"*

The `shieldbot` agent activates automatically.

## Report structure

Every scan produces:

- **Risk score** and **executive summary** (Claude's synthesis)
- **Critical & High findings** with CWE, OWASP category, code snippet, and specific fix
- **Medium findings** table
- **Dependency CVEs** table with fix versions
- **Attack narrative** — how findings chain into a real compromise
- **Top 5 remediation priorities** ordered by impact × effort
- **False positive flags** — findings Claude identifies as likely benign

## Exit codes (when run via Bash)

| Code | Meaning |
|------|---------|
| 0 | No findings (or info-only) |
| 1 | Medium+ findings present |
| 2 | High+ findings present |
| 3 | Critical findings present |

Useful for CI/CD: `shieldbot-mcp scan . || exit $?`

## Prerequisites

The following tools must be on your `PATH`:

| Tool | Install |
|------|---------|
| semgrep | `pip install semgrep` |
| bandit | `pip install bandit` |
| ruff | `pip install ruff` |
| detect-secrets | `pip install detect-secrets` |
| pip-audit | `pip install pip-audit` |
| gitleaks *(optional)* | `brew install gitleaks` |
| npm *(optional)* | Install [Node.js](https://nodejs.org) |

Run `/shieldbot check-tools` to see which are installed.

## Languages supported

Python · JavaScript · TypeScript · Java · Go · Ruby · PHP · Rust · C/C++ · Kotlin · Scala · C#

## Privacy

All scanning runs **locally** on your machine. No code is sent to external services. The MCP server communicates only with Claude Code via stdio.

## Source

[github.com/BalaSriharsha/shieldbot](https://github.com/BalaSriharsha/shieldbot)
