"""
Dependency vulnerability scanner using Dependabot CLI + osv-scanner.

Both tools are installed automatically on first use (no sudo, no package
manager required) via shieldbot's built-in installer.

How it works
~~~~~~~~~~~~
1. **osv-scanner** (https://github.com/google/osv-scanner) scans lock files
   in the local repository against the OSV / GitHub Advisory Database (GHSA).
   Works entirely offline (after the first internet-connected run) and needs
   no Docker, no GitHub token.

2. **Dependabot CLI** (https://github.com/dependabot/cli) runs ecosystem-
   specific Dependabot update jobs. When the repository has a GitHub remote,
   the CLI is run in *security-updates-only* mode using a generated job YAML.
   If Docker is unavailable or the repo has no GitHub remote, this step is
   skipped gracefully and only osv-scanner results are returned.

Both sets of findings are merged and deduplicated by (package, version, cve).

Install
~~~~~~~
Both tools are auto-installed on first scan. To pre-install manually:
    shieldbot-install --dependabot --osv

Or individually:
    shieldbot-install --osv        # osv-scanner (offline, always works)
    shieldbot-install --dependabot # Dependabot CLI (needs Docker at runtime)
"""

from __future__ import annotations

import json
import os
import re
import shutil
import tempfile
from pathlib import Path
from typing import Any

from shieldbot.models import Finding, FindingCategory, Severity, ScanResult
from shieldbot.scanners.base import BaseScanner


# ---------------------------------------------------------------------------
# Ecosystem maps
# ---------------------------------------------------------------------------

# shieldbot language → Dependabot CLI package-manager name
_DEPENDABOT_ECOSYSTEM: dict[str, str] = {
    "python":     "pip",
    "javascript": "npm_and_yarn",
    "typescript": "npm_and_yarn",
    "go":         "go_modules",
    "ruby":       "bundler",
    "java":       "maven",
    "kotlin":     "gradle",
    "csharp":     "nuget",
    "rust":       "cargo",
    "php":        "composer",
}

# Human-readable ecosystem labels (for finding titles)
_ECOSYSTEM_LABEL: dict[str, str] = {
    "PyPI":       "Python",
    "npm":        "Node.js",
    "Go":         "Go",
    "Maven":      "Java (Maven)",
    "RubyGems":   "Ruby",
    "crates.io":  "Rust",
    "NuGet":      ".NET",
    "Packagist":  "PHP",
    "Pub":        "Dart/Flutter",
    "Cargo":      "Rust",
}


# ---------------------------------------------------------------------------
# Severity helpers
# ---------------------------------------------------------------------------

def _cvss_to_severity(score_str: str) -> Severity:
    try:
        score = float(score_str)
    except (ValueError, TypeError):
        return Severity.MEDIUM
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    return Severity.LOW


# ---------------------------------------------------------------------------
# Git remote helper
# ---------------------------------------------------------------------------

async def _get_github_repo_slug(repo_path: str) -> str | None:
    """
    Try to extract an owner/repo slug from the git remote URL.

    Handles formats:
      https://github.com/owner/repo.git
      git@github.com:owner/repo.git
    Returns None if not a GitHub remote or git is unavailable.
    """
    if not shutil.which("git"):
        return None
    try:
        proc = __import__("asyncio").create_subprocess_exec
        p = await proc(
            "git", "remote", "get-url", "origin",
            stdout=__import__("asyncio").subprocess.PIPE,
            stderr=__import__("asyncio").subprocess.PIPE,
            cwd=repo_path,
        )
        stdout, _ = await p.communicate()
        remote_url = stdout.decode().strip()
    except Exception:  # noqa: BLE001
        return None

    if "github.com" not in remote_url:
        return None

    match = re.search(
        r"github\.com[:/]([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+?)(?:\.git)?$",
        remote_url,
    )
    return match.group(1) if match else None


# ---------------------------------------------------------------------------
# Main scanner class
# ---------------------------------------------------------------------------

class DependabotScanner(BaseScanner):
    """
    Dependency vulnerability scanner combining Dependabot CLI and osv-scanner.

    Both tools are auto-installed on first run via shieldbot-install.
    """

    name = "dependabot"

    def is_available(self) -> bool:
        return (
            shutil.which("dependabot") is not None
            or shutil.which("osv-scanner") is not None
        )

    async def run(self, repo_path: str, **kwargs) -> ScanResult:
        # ------------------------------------------------------------------ #
        # Auto-install both tools if neither is available                     #
        # ------------------------------------------------------------------ #
        if not self.is_available():
            from shieldbot.tools.installer import (
                ensure_dependabot_cli,
                ensure_osv_scanner,
            )
            _, _ = await __import__("asyncio").gather(
                ensure_dependabot_cli(),
                ensure_osv_scanner(),
            )
            # Refresh availability check after install attempt
            if not self.is_available():
                return self._make_error_result(
                    "Auto-install failed for both dependabot and osv-scanner. "
                    "Run: shieldbot-install --dependabot --osv"
                )

        languages: list[str] = kwargs.get("languages", [])

        # Run both scanners concurrently; each returns [] on failure
        osv_task        = self._run_osv_scanner(repo_path)
        dependabot_task = self._run_dependabot_cli(repo_path, languages)

        osv_findings, dependabot_findings = await __import__("asyncio").gather(
            osv_task, dependabot_task
        )

        merged = _merge_findings(osv_findings + dependabot_findings)

        return ScanResult(
            scanner=self.name,
            success=True,
            findings=merged,
            raw_output={
                "osv_count":        len(osv_findings),
                "dependabot_count": len(dependabot_findings),
            },
        )

    # ------------------------------------------------------------------ #
    # osv-scanner backend                                                  #
    # ------------------------------------------------------------------ #

    async def _run_osv_scanner(self, repo_path: str) -> list[Finding]:
        """
        Run osv-scanner against the local repo and return findings.
        Tries the v2 CLI syntax first, falls back to v1.
        """
        if not shutil.which("osv-scanner"):
            from shieldbot.tools.installer import ensure_osv_scanner
            osv_bin = await ensure_osv_scanner()
            if osv_bin is None:
                return []

        stdout = ""
        for cmd in (
            ["osv-scanner", "scan", "dir", repo_path, "--json"],
            ["osv-scanner", "--json", "-r", repo_path],
        ):
            out, _err, _rc = await self._run_subprocess(cmd, timeout=120)
            if out.strip():
                stdout = out
                break

        if not stdout.strip():
            return []

        try:
            data = json.loads(stdout)
        except json.JSONDecodeError:
            return []

        return self._normalize_osv(data, repo_path)

    def _normalize_osv(
        self, data: dict[str, Any], repo_path: str
    ) -> list[Finding]:
        findings: list[Finding] = []
        prefix = repo_path.rstrip("/") + "/"

        for source_block in data.get("results", []):
            source_path: str = source_block.get("source", {}).get("path", "")
            rel_source = (
                source_path[len(prefix):]
                if source_path.startswith(prefix)
                else source_path
            )

            for pkg_entry in source_block.get("packages", []):
                pkg     = pkg_entry.get("package", {})
                name    = pkg.get("name", "unknown")
                version = pkg.get("version", "unknown")

                # max_severity keyed by advisory id (from groups)
                max_sev_by_id: dict[str, str] = {}
                for grp in pkg_entry.get("groups", []):
                    sev = grp.get("max_severity", "")
                    for vid in grp.get("ids", []) + grp.get("aliases", []):
                        max_sev_by_id[vid] = sev

                for vuln in pkg_entry.get("vulnerabilities", []):
                    vuln_id: str  = vuln.get("id", "unknown")
                    summary: str  = vuln.get("summary", "")
                    details: str  = vuln.get("details", summary)
                    aliases: list = vuln.get("aliases", [])

                    cve_id = next(
                        (a for a in aliases if a.startswith("CVE-")), None
                    )

                    # Severity: prefer group max_severity, then CVSS
                    sev_str = max_sev_by_id.get(vuln_id, "")
                    if not sev_str:
                        for a in aliases:
                            if a in max_sev_by_id:
                                sev_str = max_sev_by_id[a]
                                break
                    severity = (
                        _cvss_to_severity(sev_str)
                        if sev_str
                        else self._parse_vuln_severity(vuln)
                    )

                    refs = [
                        r.get("url", "")
                        for r in vuln.get("references", [])
                        if r.get("url")
                    ]

                    fix_ver = self._extract_fix_versions(vuln, name)
                    remediation = (
                        f"Upgrade {name} from {version} to {fix_ver}."
                        if fix_ver
                        else f"Upgrade {name} from {version} to a patched version."
                    )

                    findings.append(Finding(
                        scanner="osv-scanner",
                        rule_id=f"dependabot/osv/{vuln_id}",
                        title=f"{name} {version} — {vuln_id}: {summary}"[:200],
                        description=details or summary,
                        severity=severity,
                        category=FindingCategory.DEPENDENCY_CVE,
                        file_path=rel_source or "dependency manifest",
                        line_start=0,
                        cve_id=cve_id,
                        remediation=remediation,
                        references=refs,
                        confidence="high",
                    ))

        return findings

    @staticmethod
    def _parse_vuln_severity(vuln: dict[str, Any]) -> Severity:
        for sev_entry in vuln.get("severity", []):
            score = sev_entry.get("score", "")
            if score and not score.startswith("CVSS:"):
                return _cvss_to_severity(score)
        return Severity.MEDIUM

    @staticmethod
    def _extract_fix_versions(vuln: dict[str, Any], pkg_name: str) -> str:
        fixes: set[str] = set()
        for affected in vuln.get("affected", []):
            if affected.get("package", {}).get("name", "").lower() != pkg_name.lower():
                continue
            for rng in affected.get("ranges", []):
                for ev in rng.get("events", []):
                    fixed = ev.get("fixed")
                    if fixed:
                        fixes.add(str(fixed))
        return ", ".join(sorted(fixes)) if fixes else ""

    # ------------------------------------------------------------------ #
    # Dependabot CLI backend                                               #
    # ------------------------------------------------------------------ #

    async def _run_dependabot_cli(
        self, repo_path: str, languages: list[str]
    ) -> list[Finding]:
        """
        Run the Dependabot CLI in security-updates-only mode using a
        generated job YAML file.

        Requires:
          - `dependabot` binary on PATH (auto-installed if missing)
          - Docker running (for the ecosystem-specific updater containers)
          - The repository to have a GitHub remote (owner/repo is extracted
            from `git remote get-url origin`; if absent, skipped gracefully)

        Returns an empty list if any precondition is unmet.
        """
        if not shutil.which("dependabot"):
            from shieldbot.tools.installer import ensure_dependabot_cli
            dep_bin = await ensure_dependabot_cli()
            if dep_bin is None:
                return []

        # Dependabot CLI requires a GitHub repo slug
        github_repo = await _get_github_repo_slug(repo_path)
        if not github_repo:
            return []

        # Determine which ecosystems to check
        ecosystems = list({
            _DEPENDABOT_ECOSYSTEM[lang]
            for lang in languages
            if lang in _DEPENDABOT_ECOSYSTEM
        })
        if not ecosystems:
            # Probe common ones
            ecosystems = []
            if (Path(repo_path) / "requirements.txt").exists() or (Path(repo_path) / "pyproject.toml").exists():
                ecosystems.append("pip")
            if (Path(repo_path) / "package.json").exists():
                ecosystems.append("npm_and_yarn")
            if (Path(repo_path) / "go.mod").exists():
                ecosystems.append("go_modules")
            if not ecosystems:
                return []

        all_findings: list[Finding] = []

        with tempfile.TemporaryDirectory(prefix="shieldbot_dependabot_") as tmp:
            for ecosystem in ecosystems:
                findings = await self._run_dependabot_ecosystem(
                    ecosystem, github_repo, repo_path, tmp
                )
                all_findings.extend(findings)

        return all_findings

    async def _run_dependabot_ecosystem(
        self,
        ecosystem: str,
        github_repo: str,
        repo_path: str,
        tmp_dir: str,
    ) -> list[Finding]:
        """
        Write a security-focused job YAML for one ecosystem and run the
        Dependabot CLI against the GitHub repository.
        """
        job_file   = os.path.join(tmp_dir, f"job_{ecosystem}.yaml")
        out_file   = os.path.join(tmp_dir, f"output_{ecosystem}.json")

        job_yaml = (
            "job:\n"
            f"  package-manager: {ecosystem}\n"
            "  allowed-updates:\n"
            "    - update-type: security\n"
            "  security-updates-only: true\n"
            "  source:\n"
            "    provider: github\n"
            f"    repo: {github_repo}\n"
            "    directory: /\n"
        )
        with open(job_file, "w") as fh:
            fh.write(job_yaml)

        cmd = [
            "dependabot", "update",
            "--file",   job_file,
            "--output", out_file,
        ]
        stdout, stderr, rc = await self._run_subprocess(cmd, timeout=300)

        # Parse output file first (structured JSON/YAML), then stdout
        findings = []
        if Path(out_file).exists():
            findings = self._parse_dependabot_output_file(out_file, ecosystem)
        if not findings and stdout.strip():
            findings = self._parse_dependabot_stdout(stdout, ecosystem)

        return findings

    def _parse_dependabot_output_file(
        self, out_file: str, ecosystem: str
    ) -> list[Finding]:
        """Parse the dependabot --output JSON/YAML file."""
        raw = Path(out_file).read_text(encoding="utf-8", errors="replace").strip()
        if not raw:
            return []
        # Try JSON
        try:
            data = json.loads(raw)
            return self._extract_dependabot_updates(data, ecosystem)
        except json.JSONDecodeError:
            pass
        # Try YAML (without adding PyYAML as a dep — parse simple key: value)
        return self._parse_dependabot_simple_yaml(raw, ecosystem)

    def _extract_dependabot_updates(
        self, data: Any, ecosystem: str
    ) -> list[Finding]:
        """Extract security updates from parsed JSON dependabot output."""
        findings: list[Finding] = []

        updates = (
            data.get("dependency_updates", [])
            if isinstance(data, dict)
            else (data if isinstance(data, list) else [])
        )

        for upd in updates:
            if not isinstance(upd, dict):
                continue

            advisories = upd.get("security-advisories", [])
            is_security = bool(advisories) or upd.get("security", False)
            if not is_security:
                continue

            dep_name    = upd.get("dependency-name") or upd.get("dependency_name", "unknown")
            new_ver     = upd.get("dependency-version") or upd.get("dependency_version", "?")
            prev_ver    = upd.get("previous-version") or upd.get("previous_version", "?")
            ghsa_id     = next(
                (str(a) for a in advisories if "GHSA" in str(a)), ""
            )
            cve_id      = next(
                (str(a) for a in advisories if str(a).startswith("CVE-")), None
            )

            findings.append(Finding(
                scanner=self.name,
                rule_id=f"dependabot/{ghsa_id or dep_name}",
                title=(
                    f"{dep_name} {prev_ver} has a known vulnerability "
                    f"(upgrade to {new_ver})"
                )[:200],
                description=(
                    f"Dependabot security update for {dep_name} "
                    f"({ecosystem} ecosystem). "
                    f"Current version: {prev_ver} → fixed in {new_ver}. "
                    f"Advisories: {', '.join(str(a) for a in advisories) or 'see advisory'}."
                ),
                severity=Severity.HIGH,
                category=FindingCategory.DEPENDENCY_CVE,
                file_path="dependency manifest",
                line_start=0,
                cve_id=cve_id,
                remediation=f"Upgrade {dep_name} from {prev_ver} to {new_ver}.",
                references=[
                    f"https://github.com/advisories/{ghsa_id}" if ghsa_id else ""
                ],
                confidence="high",
            ))

        return findings

    def _parse_dependabot_stdout(
        self, stdout: str, ecosystem: str
    ) -> list[Finding]:
        """
        Parse the human-readable table that dependabot prints to stdout:

          | created | requests ( from 2.27.0 to 2.31.0 ) |

        We include ALL updates from stdout when run in security-updates-only
        mode, because every update in that mode is a security fix.
        """
        findings: list[Finding] = []

        # Match lines like: | created | pkg ( from OLD to NEW ) |
        row_re = re.compile(
            r"\|\s*(?:created|updated)\s*\|\s*"
            r"(?P<pkg>[^\s(]+)\s*\(\s*from\s+(?P<old>[^\s]+)\s+to\s+(?P<new>[^\s)]+)\s*\)"
        )
        for match in row_re.finditer(stdout):
            pkg, old_ver, new_ver = (
                match.group("pkg"),
                match.group("old"),
                match.group("new"),
            )
            findings.append(Finding(
                scanner=self.name,
                rule_id=f"dependabot/{pkg}",
                title=(
                    f"{pkg} {old_ver} has a security vulnerability "
                    f"(upgrade to {new_ver})"
                )[:200],
                description=(
                    f"Dependabot identified a security update for {pkg} "
                    f"({ecosystem} ecosystem). "
                    f"Upgrade from {old_ver} to {new_ver}."
                ),
                severity=Severity.HIGH,
                category=FindingCategory.DEPENDENCY_CVE,
                file_path="dependency manifest",
                line_start=0,
                remediation=f"Upgrade {pkg} from {old_ver} to {new_ver}.",
                references=[],
                confidence="high",
            ))

        return findings

    @staticmethod
    def _parse_dependabot_simple_yaml(raw: str, ecosystem: str) -> list[Finding]:
        """
        Minimal YAML parser for dependabot output — handles only the fields
        we care about without requiring PyYAML.
        Looks for dependency_updates blocks and extracts key fields.
        """
        findings: list[Finding] = []
        current: dict[str, str] = {}

        for line in raw.splitlines():
            stripped = line.strip()
            if stripped.startswith("- dependency-name:"):
                if current:
                    findings.extend(
                        DependabotScanner._yaml_block_to_finding(current, ecosystem)
                    )
                current = {"dependency-name": stripped.split(":", 1)[1].strip()}
            elif ":" in stripped and current:
                k, _, v = stripped.partition(":")
                current[k.strip()] = v.strip()

        if current:
            findings.extend(
                DependabotScanner._yaml_block_to_finding(current, ecosystem)
            )

        return findings

    @staticmethod
    def _yaml_block_to_finding(
        block: dict[str, str], ecosystem: str
    ) -> list[Finding]:
        name     = block.get("dependency-name", "unknown")
        new_ver  = block.get("dependency-version", "?")
        prev_ver = block.get("previous-version", "?")

        if prev_ver == "?":
            return []

        return [Finding(
            scanner="dependabot",
            rule_id=f"dependabot/{name}",
            title=f"{name} {prev_ver} security update → {new_ver}"[:200],
            description=(
                f"Dependabot security update for {name} ({ecosystem}). "
                f"Upgrade from {prev_ver} to {new_ver}."
            ),
            severity=Severity.HIGH,
            category=FindingCategory.DEPENDENCY_CVE,
            file_path="dependency manifest",
            line_start=0,
            remediation=f"Upgrade {name} from {prev_ver} to {new_ver}.",
            references=[],
            confidence="medium",
        )]


# ---------------------------------------------------------------------------
# Merge / deduplicate findings from both tools
# ---------------------------------------------------------------------------

def _merge_findings(findings: list[Finding]) -> list[Finding]:
    """
    Deduplicate findings by (lower(package_name), cve_id OR rule_id).
    When two findings describe the same vulnerability, prefer the one from
    osv-scanner (more complete advisory data) over dependabot CLI stdout.
    """
    seen: dict[str, Finding] = {}

    # Process osv-scanner findings first (higher data quality)
    for f in sorted(findings, key=lambda x: 0 if x.scanner == "osv-scanner" else 1):
        # Dedup key: normalise package name from title + CVE/advisory ID
        pkg_part = f.title.split("—")[0].strip().lower() if "—" in f.title else f.rule_id.lower()
        cve_part = f.cve_id or f.rule_id
        key = f"{pkg_part}:{cve_part}"

        if key not in seen:
            seen[key] = f

    return list(seen.values())
