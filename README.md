# Shieldbot — AI Security Code Review for Claude Code

[![PyPI](https://img.shields.io/pypi/v/shieldbot-mcp)](https://pypi.org/project/shieldbot-mcp/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/)
[![MCP Compatible](https://img.shields.io/badge/MCP-compatible-green.svg)](https://modelcontextprotocol.io/)

**Shieldbot** is an AI-powered security scanner that runs directly inside [Claude Code](https://claude.ai/code). It combines deep dataflow analysis, 5,000+ static analysis rules, and advisory-database lookups with Claude's reasoning to detect vulnerabilities, hardcoded secrets, and CVE-affected dependencies — then synthesizes findings into a prioritized, actionable report.

> One command. Full security audit. Zero context switching.

---

## What It Scans

| Scanner | What It Catches | Auto-installed |
|---------|----------------|:--------------:|
| **CodeQL** | Deep dataflow / taint-analysis SAST — SQL injection, XSS, path traversal, RCE, authentication flaws across 8+ languages | ✓ |
| **Semgrep** (5,000+ rules) | OWASP Top 10, CWE Top 25, SQL injection, XSS, SSRF, command injection | |
| **Bandit** | Python-specific security flaws (hardcoded passwords, weak crypto, shell injection) | |
| **Ruff** | Python code quality and security anti-patterns | |
| **detect-secrets** | API keys, tokens, passwords, private keys in source code | |
| **Dependabot CLI** | Ecosystem-specific security updates via GitHub's Dependabot engine (security-updates-only mode, requires Docker at runtime) | ✓ |
| **osv-scanner** | Dependency CVEs from the OSV / GitHub Advisory Database — works offline, no token required | ✓ |
| **pip-audit** | Python dependency CVEs (PyPI Advisory Database) | |
| **npm audit** | Node.js dependency CVEs | |

All scanners run **in parallel**. Findings are deduplicated, ranked by exploitability, and explained in plain English.

> **Auto-installed tools** (CodeQL, osv-scanner, Dependabot CLI) are downloaded automatically on first scan — no package manager or sudo required. Supports macOS and Linux on x86\_64 and arm64.

---

## Install as a Claude Code Plugin (Recommended)

**Step 1 — Add the Shieldbot marketplace:**
```
/plugin marketplace add BalaSriharsha/shieldbot
```

**Step 2 — Install the plugin:**
```
/plugin install shieldbot
```

**Step 3 — Reload plugins:**
```
/reload-plugins
```

**Step 4 — Run a scan:**
```
/shieldbot .
/shieldbot /path/to/repo
/shieldbot . --min-severity critical
/shieldbot . --git-history
```

Or just ask Claude naturally:
- *"scan this repo for security vulnerabilities"*
- *"check my code for hardcoded secrets"*
- *"audit my Python dependencies for CVEs"*

---

## Install as a Standalone MCP Server

Add to your MCP client config (`.mcp.json` or `claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "shieldbot": {
      "command": "uvx",
      "args": ["shieldbot-mcp"]
    }
  }
}
```

Or install via pip:
```bash
pip install shieldbot-mcp
```

---

## Pre-install Scanner Tools

CodeQL, osv-scanner, and Dependabot CLI are downloaded automatically on first scan, but you can pre-install them with the bundled CLI:

```bash
shieldbot-install              # install all three
shieldbot-install --codeql     # CodeQL only
shieldbot-install --osv        # osv-scanner only
shieldbot-install --dependabot # Dependabot CLI only
shieldbot-install --force      # reinstall / upgrade to latest
```

Binaries are placed in `~/.local/bin`. Add it to your shell profile if needed:
```bash
export PATH="$HOME/.local/bin:$PATH"
```

All three tools are fully open-source and installed from their official GitHub releases — no package manager, no sudo, no API keys:

| Tool | Source | License |
|------|--------|---------|
| CodeQL CLI | [github/codeql-cli-binaries](https://github.com/github/codeql-cli-binaries) | MIT |
| osv-scanner | [google/osv-scanner](https://github.com/google/osv-scanner) | Apache-2.0 |
| Dependabot CLI | [dependabot/cli](https://github.com/dependabot/cli) | MIT |

---

## MCP Tools

| Tool | Description |
|------|-------------|
| `scan_repository` | Run a full parallel security scan and return a structured JSON report |
| `check_scanner_tools` | Check which scanners are installed and available |

### `scan_repository` parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `repo_path` | string | required | Absolute path to the repository |
| `skip_scanners` | list | `[]` | Scanners to skip — valid values: `codeql`, `semgrep`, `bandit`, `ruff`, `detect-secrets`, `dependabot`, `pip-audit`, `npm-audit` |
| `scan_git_history` | bool | `false` | Also scan git commit history for leaked secrets |
| `min_severity` | string | `"info"` | Minimum severity to include (`critical`, `high`, `medium`, `low`, `info`) |

---

## GitHub Actions Integration

Add Shieldbot to any repository in 3 lines. Findings appear in the **Security > Code Scanning** tab via SARIF upload.

```yaml
# .github/workflows/shieldbot.yml
name: Shieldbot Security Scan
on:
  push:
    branches: [main, master]
  pull_request:
    branches: [main, master]
  schedule:
    - cron: '0 8 * * 1'  # Weekly scan

permissions:
  contents: read
  security-events: write  # Required for Code Scanning upload

jobs:
  shieldbot:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: BalaSriharsha/shieldbot@main
```

**All available inputs:**

| Input | Default | Description |
|-------|---------|-------------|
| `path` | `.` | Directory to scan |
| `min-severity` | `high` | Minimum severity to report |
| `fail-on` | `high` | Fail build if findings at or above this level |
| `skip-scanners` | `` | Comma-separated scanners to skip |
| `scan-git-history` | `false` | Scan git history for leaked secrets |
| `upload-sarif` | `true` | Upload to GitHub Code Scanning |
| `sarif-file` | `shieldbot-results.sarif` | SARIF output path |

**Outputs:** `total-findings`, `risk-score`, `sarif-file`

See [`.github/workflows/shieldbot-example.yml`](.github/workflows/shieldbot-example.yml) for the full annotated example.

---

## Exit Codes (CI/CD Integration)

| Code | Meaning |
|------|---------|
| `0` | Clean — no findings above threshold |
| `1` | Medium+ findings detected |
| `2` | High+ findings detected |
| `3` | Critical findings detected |

Use exit codes to gate deployments in GitHub Actions, GitLab CI, or any pipeline.

---

## How It Works

1. **Detect** — Shieldbot profiles the repository (languages, package managers, git history)
2. **Auto-install** — Any missing scanner tools (CodeQL, osv-scanner, Dependabot CLI) are downloaded from GitHub releases for the current OS and architecture
3. **Scan** — All applicable scanners run in parallel via `asyncio.gather()`
4. **Deduplicate** — Findings are deduplicated by exact hash and proximity (±3 lines), with scanner priority: CodeQL → Semgrep → Bandit → detect-secrets → Dependabot/osv-scanner → pip-audit/npm-audit
5. **Analyze** — Claude synthesizes raw scanner output into prioritized findings with context
6. **Report** — Structured output with executive summary, risk score, and remediation steps

---

## Requirements

- Python 3.11+
- [Claude Code](https://claude.ai/code) (for plugin mode)
- Docker (optional — only needed at runtime for Dependabot CLI's ecosystem updaters)

---

## Contributing

Issues and pull requests welcome at [github.com/BalaSriharsha/shieldbot](https://github.com/BalaSriharsha/shieldbot).

---

## License

MIT — see [LICENSE](LICENSE)
