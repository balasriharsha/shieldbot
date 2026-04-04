---
name: shieldbot
description: Run a full security scan on a repository. Invokes the shieldbot agent to detect vulnerabilities, hardcoded secrets, and CVEs using Semgrep (5,000+ rules), bandit, detect-secrets, pip-audit, and npm-audit.
argument-hint: <repo_path> [--skip <scanner>] [--min-severity critical|high|medium|low|info] [--git-history]
allowed-tools: [Bash, Read, Grep, Glob]
---

# Shieldbot Security Scan

The user invoked `/shieldbot-scan` with arguments: $ARGUMENTS

## Instructions

Parse the arguments:
- First positional argument: `repo_path` (default: current directory `.`)
- `--skip <scanner>`: skip a specific scanner (may appear multiple times)
- `--min-severity <level>`: only show findings at or above this level (default: `high`)
- `--git-history`: also scan git commit history for leaked secrets

Then spawn the `shieldbot` agent with the resolved parameters to perform the full security scan and deliver a report.

## Examples

```
/shieldbot-scan .
/shieldbot-scan /path/to/myproject
/shieldbot-scan . --min-severity critical
/shieldbot-scan /path/to/repo --skip ruff --skip bandit
/shieldbot-scan . --git-history
```
