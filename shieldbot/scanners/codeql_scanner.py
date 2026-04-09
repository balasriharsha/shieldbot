"""CodeQL SAST scanner — uses the official open-source CodeQL CLI.

Install:
    brew install codeql                                # macOS via Homebrew
    gh extension install github/gh-codeql            # via GitHub CLI
    # or download from https://github.com/github/codeql-cli-binaries/releases

CodeQL is fully open-source (https://github.com/github/codeql).
No API keys, no license required for open-source codebases.
Query packs are bundled with the CLI binary.
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
from pathlib import Path
from typing import Any

from shieldbot.models import Finding, FindingCategory, Severity, ScanResult
from shieldbot.scanners.base import BaseScanner, infer_category_from_rule_id


# Map shieldbot-detected languages → CodeQL language identifiers
_CODEQL_LANGUAGE_MAP: dict[str, str] = {
    "python":     "python",
    "javascript": "javascript",
    "typescript": "javascript",   # CodeQL uses the JS extractor for TS
    "java":       "java",
    "kotlin":     "java",         # CodeQL Java extractor covers Kotlin
    "go":         "go",
    "csharp":     "csharp",
    "cpp":        "cpp",
    "c":          "cpp",          # CodeQL cpp extractor covers C and C++
    "ruby":       "ruby",
    "swift":      "swift",
}

# Query suites bundled with the CodeQL CLI distribution
_CODEQL_QUERY_SUITES: dict[str, str] = {
    "python":     "python-security-and-quality.qls",
    "javascript": "javascript-security-and-quality.qls",
    "java":       "java-security-and-quality.qls",
    "go":         "go-security-and-quality.qls",
    "csharp":     "csharp-security-and-quality.qls",
    "cpp":        "cpp-security-and-quality.qls",
    "ruby":       "ruby-security-and-quality.qls",
    "swift":      "swift-security-and-quality.qls",
}

# Languages that don't need a build step for CodeQL extraction
_BUILDLESS_LANGUAGES = frozenset({"python", "javascript", "ruby", "swift"})

_SARIF_LEVEL_TO_SEVERITY: dict[str, Severity] = {
    "error":   Severity.HIGH,
    "warning": Severity.MEDIUM,
    "note":    Severity.LOW,
    "none":    Severity.INFO,
}


def _cvss_to_severity(score: float) -> Severity:
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    return Severity.LOW


class CodeQLScanner(BaseScanner):
    """
    Static analysis via the CodeQL CLI.

    For each detected language the scanner:
      1. Creates a CodeQL database  (`codeql database create`)
      2. Runs the security-and-quality query suite (`codeql database analyze`)
      3. Parses the SARIF 2.1.0 output into normalized Finding objects

    Build strategy
    ~~~~~~~~~~~~~~
    - Interpreted languages (Python, JS/TS, Ruby): ``--build-mode=none``
      (fast, no build system required)
    - Compiled languages (Java, Go, C/C++, C#):  ``--build-mode=autobuild``
      (CodeQL detects and invokes the project's build tool)
    """

    name = "codeql"

    def is_available(self) -> bool:
        return shutil.which("codeql") is not None

    async def run(self, repo_path: str, **kwargs) -> ScanResult:
        if not self.is_available():
            # Auto-install from GitHub releases (works on macOS and Linux,
            # x86_64 and arm64, no sudo required)
            from shieldbot.tools.installer import ensure_codeql
            codeql_bin = await ensure_codeql()
            if codeql_bin is None:
                return self._make_error_result(
                    "codeql not found and auto-install failed. "
                    "Manual install: "
                    "brew install codeql  "
                    "or download from https://github.com/github/codeql-cli-binaries/releases"
                )

        detected: list[str] = kwargs.get("languages", [])
        codeql_langs = self._resolve_languages(repo_path, detected)

        if not codeql_langs:
            return ScanResult(scanner=self.name, success=True, findings=[])

        all_findings: list[Finding] = []
        files_scanned = 0

        with tempfile.TemporaryDirectory(prefix="shieldbot_codeql_") as tmpdir:
            for lang in codeql_langs:
                db_path    = os.path.join(tmpdir, f"db_{lang}")
                sarif_path = os.path.join(tmpdir, f"results_{lang}.sarif")

                ok = await self._create_database(repo_path, db_path, lang)
                if not ok:
                    continue

                sarif = await self._analyze_database(db_path, sarif_path, lang)
                if sarif is None:
                    continue

                findings = self._parse_sarif(sarif, repo_path)
                all_findings.extend(findings)
                files_scanned += len({f.file_path for f in findings})

        return ScanResult(
            scanner=self.name,
            success=True,
            findings=all_findings,
            files_scanned=files_scanned,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _resolve_languages(
        self, repo_path: str, detected: list[str]
    ) -> list[str]:
        """Return deduplicated CodeQL language IDs for the detected languages."""
        seen: set[str] = set()
        result: list[str] = []
        for lang in detected:
            cl = _CODEQL_LANGUAGE_MAP.get(lang)
            if cl and cl not in seen and cl in _CODEQL_QUERY_SUITES:
                seen.add(cl)
                result.append(cl)
        # Fallback: if nothing matched, probe for the two most common
        if not result:
            for cl in ("python", "javascript"):
                if cl not in seen:
                    result.append(cl)
                    seen.add(cl)
        return result

    async def _create_database(
        self, repo_path: str, db_path: str, lang: str
    ) -> bool:
        """
        Create a CodeQL database.

        Uses --build-mode=none for interpreted languages (faster, no build
        required) and --build-mode=autobuild for compiled languages.
        Returns True on success.
        """
        build_mode = "none" if lang in _BUILDLESS_LANGUAGES else "autobuild"

        cmd = [
            "codeql", "database", "create",
            db_path,
            f"--language={lang}",
            f"--source-root={repo_path}",
            f"--build-mode={build_mode}",
            "--overwrite",
        ]
        stdout, stderr, rc = await self._run_subprocess(cmd, timeout=300)

        if rc == 0:
            return True
        # Some CodeQL versions (< 2.13) don't support --build-mode; retry
        # with the legacy --no-tracing flag for buildless extraction.
        if "build-mode" in stderr and build_mode == "none":
            cmd_legacy = [
                "codeql", "database", "create",
                db_path,
                f"--language={lang}",
                f"--source-root={repo_path}",
                "--no-tracing",
                "--overwrite",
            ]
            _, _, rc2 = await self._run_subprocess(cmd_legacy, timeout=300)
            return rc2 == 0 or Path(db_path).is_dir()

        return Path(db_path).is_dir()  # partial success if DB dir was created

    async def _analyze_database(
        self, db_path: str, sarif_path: str, lang: str
    ) -> dict[str, Any] | None:
        """Run CodeQL analysis and return parsed SARIF data, or None on failure."""
        query_suite = _CODEQL_QUERY_SUITES.get(lang, f"{lang}-security-and-quality.qls")

        cmd = [
            "codeql", "database", "analyze",
            db_path,
            query_suite,
            "--format=sarif-latest",
            f"--output={sarif_path}",
            "--no-print-diff-informed-queries",
        ]
        await self._run_subprocess(cmd, timeout=600)

        if not Path(sarif_path).exists():
            return None
        try:
            with open(sarif_path, encoding="utf-8") as fh:
                return json.load(fh)
        except (json.JSONDecodeError, OSError):
            return None

    def _parse_sarif(
        self, sarif_data: dict[str, Any], repo_path: str
    ) -> list[Finding]:
        """Convert SARIF 2.1.0 output from CodeQL into normalized Finding objects."""
        findings: list[Finding] = []
        prefix = repo_path.rstrip("/") + "/"

        for run in sarif_data.get("runs", []):
            driver = run.get("tool", {}).get("driver", {})
            rules_by_id: dict[str, dict] = {
                r.get("id", ""): r for r in driver.get("rules", [])
            }

            for result in run.get("results", []):
                rule_id: str = result.get("ruleId") or "unknown"
                rule    = rules_by_id.get(rule_id, {})

                # ---- Location ----
                locs = result.get("locations", [])
                if not locs:
                    continue
                phys = locs[0].get("physicalLocation", {})
                uri: str = phys.get("artifactLocation", {}).get("uri", "")
                region = phys.get("region", {})
                line_start: int = region.get("startLine", 0)
                line_end: int | None = region.get("endLine")

                # Normalise to a relative path
                file_path = uri
                if file_path.startswith("file://"):
                    file_path = file_path[7:]
                if file_path.startswith(prefix):
                    file_path = file_path[len(prefix):]

                # ---- Severity ----
                level = result.get("level", "warning")
                severity = _SARIF_LEVEL_TO_SEVERITY.get(level, Severity.MEDIUM)

                # Upgrade severity using CodeQL's security-severity CVSS score
                props = rule.get("properties", {})
                sec_sev = props.get("security-severity", "")
                if sec_sev:
                    try:
                        severity = _cvss_to_severity(float(sec_sev))
                    except (ValueError, TypeError):
                        pass

                # ---- CWE tag ----
                tags: list[str] = props.get("tags", [])
                cwe_id = next(
                    (t for t in tags if t.upper().startswith("CWE")), None
                )

                # ---- Texts ----
                message_text = (result.get("message") or {}).get("text", rule_id)
                short_desc   = (rule.get("shortDescription") or {}).get("text", "")
                full_desc    = (rule.get("fullDescription") or {}).get("text", "")
                title        = (short_desc or message_text)[:200]
                description  = full_desc or message_text

                # ---- Help / references ----
                help_uri = rule.get("helpUri") or ""
                refs = [help_uri] if help_uri else []

                # ---- Remediation ----
                help_block = rule.get("help") or {}
                remediation: str | None = (
                    help_block.get("markdown")
                    or help_block.get("text")
                    or None
                )

                findings.append(Finding(
                    scanner=self.name,
                    rule_id=f"codeql/{rule_id}",
                    title=title,
                    description=description,
                    severity=severity,
                    category=infer_category_from_rule_id(rule_id),
                    file_path=file_path,
                    line_start=line_start,
                    line_end=line_end,
                    cwe_id=cwe_id,
                    references=refs,
                    remediation=remediation,
                    confidence="high",
                ))

        return findings
