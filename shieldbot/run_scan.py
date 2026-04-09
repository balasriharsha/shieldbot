#!/usr/bin/env python3
"""
Standalone scanner runner for shieldbot.

Runs all applicable security scanners in parallel, deduplicates findings,
and writes a structured JSON report. No Claude API required — this is the
data-gathering layer; the Claude Code agent provides the AI analysis.

Usage:
    python shieldbot/run_scan.py /path/to/repo
    python shieldbot/run_scan.py /path/to/repo --output-file /tmp/report.json
    python shieldbot/run_scan.py /path/to/repo --skip bandit --min-severity high
    python shieldbot/run_scan.py /path/to/repo --scan-git-history
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path

# Ensure the shieldbot package is importable when run from any directory
_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))

from shieldbot.config import (
    EXIT_CODE_CRITICAL,
    EXIT_CODE_HIGH,
    EXIT_CODE_MEDIUM,
    SEMGREP_ALWAYS_RULESETS,
    SEMGREP_LANGUAGE_RULESETS,
)
from shieldbot.models import SecurityReport, Severity
from shieldbot.scanners import (
    BanditScanner,
    CodeQLScanner,
    DependabotScanner,
    NpmAuditScanner,
    PipAuditScanner,
    RuffScanner,
    SecretsScanner,
    SemgrepScanner,
    TrivyScanner,
)
from shieldbot.scanners.base import deduplicate, run_all_parallel
from shieldbot.reporters.json_reporter import write_json_report
from shieldbot.reporters.sarif_reporter import write_sarif_report


# ---------------------------------------------------------------------------
# Project type detection
# ---------------------------------------------------------------------------


def detect_project_type(repo_path: str) -> dict:
    root = Path(repo_path)
    languages: set[str] = set()
    ext_lang = {
        ".py": "python", ".js": "javascript", ".ts": "typescript",
        ".jsx": "javascript", ".tsx": "typescript", ".java": "java",
        ".go": "go", ".rb": "ruby", ".php": "php", ".rs": "rust",
        ".cs": "csharp", ".cpp": "cpp", ".c": "c", ".kt": "kotlin",
    }
    SKIP_DIRS = {"node_modules", ".git", "__pycache__", ".venv", "venv", ".tox", "dist", "build"}

    for path in root.rglob("*"):
        if any(skip in path.parts for skip in SKIP_DIRS):
            continue
        if path.is_file():
            lang = ext_lang.get(path.suffix.lower())
            if lang:
                languages.add(lang)

    has_requirements = bool(
        list(root.glob("requirements*.txt"))
        or list(root.glob("requirements/*.txt"))
    )
    has_pyproject = (root / "pyproject.toml").exists()
    has_setup = (root / "setup.py").exists() or (root / "setup.cfg").exists()
    has_package_json = (root / "package.json").exists()
    has_go_mod = (root / "go.mod").exists()
    _docker_skip = {"node_modules", ".git", "__pycache__", ".venv", "venv", ".tox",
                    "dist", "build", "vendor", ".cache"}
    has_dockerfile = any(
        df for df in root.rglob("Dockerfile*")
        if not any(p.startswith(".") or p in _docker_skip for p in df.relative_to(root).parts)
    )
    if has_go_mod:
        languages.add("go")
    if has_pyproject or has_requirements or has_setup:
        languages.add("python")

    return {
        "languages": sorted(languages),
        "has_requirements_txt": has_requirements,
        "has_pyproject_toml": has_pyproject,
        "has_package_json": has_package_json,
        "has_go_mod": has_go_mod,
        "has_dockerfile": has_dockerfile,
    }


# ---------------------------------------------------------------------------
# Main scan pipeline
# ---------------------------------------------------------------------------


async def run_scan(
    repo_path: str,
    skip_scanners: set[str],
    scan_git_history: bool,
    extra_images: list[str] | None = None,
) -> SecurityReport:
    start = time.monotonic()
    report_id = hashlib.sha256(f"{repo_path}{start}".encode()).hexdigest()[:12]

    profile = detect_project_type(repo_path)
    languages = profile["languages"]
    is_python = "python" in languages
    has_py_deps = profile["has_requirements_txt"] or profile["has_pyproject_toml"]
    has_pkg_json = profile["has_package_json"]
    has_dockerfile = profile["has_dockerfile"]

    # Select Semgrep rulesets
    rulesets = list(SEMGREP_ALWAYS_RULESETS)
    seen = set(rulesets)
    for lang in languages:
        for rs in SEMGREP_LANGUAGE_RULESETS.get(lang.lower(), []):
            if rs not in seen:
                rulesets.append(rs)
                seen.add(rs)

    # Build scanner list
    scanners = []
    # --- SAST scanners ---
    if "codeql" not in skip_scanners:
        scanners.append(CodeQLScanner())
    if "semgrep" not in skip_scanners:
        scanners.append(SemgrepScanner(rulesets=rulesets))
    if is_python and "bandit" not in skip_scanners:
        scanners.append(BanditScanner())
    if is_python and "ruff" not in skip_scanners:
        scanners.append(RuffScanner())
    if "detect-secrets" not in skip_scanners:
        scanners.append(SecretsScanner())
    # --- Dependency / CVE scanners ---
    if "dependabot" not in skip_scanners:
        scanners.append(DependabotScanner())
    if has_py_deps and "pip-audit" not in skip_scanners:
        scanners.append(PipAuditScanner())
    if has_pkg_json and "npm-audit" not in skip_scanners:
        scanners.append(NpmAuditScanner())
    # Trivy runs if there's a Dockerfile OR explicit image names were passed
    if (has_dockerfile or extra_images) and "trivy" not in skip_scanners:
        scanners.append(TrivyScanner())

    # Run all scanners in parallel
    scan_results = await run_all_parallel(
        scanners, repo_path,
        languages=languages,
        scan_git_history=scan_git_history,
        extra_images=extra_images or [],
    )

    # Aggregate and deduplicate
    all_findings = []
    scanners_run = []
    for result in scan_results:
        scanners_run.append(result.scanner)
        all_findings.extend(result.findings)

    deduped = deduplicate(all_findings)
    canonical = [f for f in deduped if not f.duplicate_of]

    by_severity = {s.value: 0 for s in Severity}
    by_category: dict[str, int] = {}
    for f in canonical:
        by_severity[f.severity.value] += 1
        by_category[f.category.value] = by_category.get(f.category.value, 0) + 1

    return SecurityReport(
        report_id=report_id,
        repo_path=repo_path,
        scan_timestamp=datetime.utcnow(),
        scan_duration_seconds=round(time.monotonic() - start, 2),
        languages_detected=languages,
        scanners_run=scanners_run,
        total_findings=len(canonical),
        findings_by_severity=by_severity,
        findings_by_category=by_category,
        all_findings=deduped,
        scan_results=scan_results,
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser(
        description="Shieldbot scanner runner — outputs JSON for the Claude Code agent to analyze."
    )
    parser.add_argument("repo_path", help="Path to the repository to scan")
    parser.add_argument(
        "--output-file", "-o", default=None,
        help="Write JSON report to this file (default: print to stdout)",
    )
    parser.add_argument(
        "--output-sarif", default=None, metavar="FILE",
        help="Also write a SARIF 2.1.0 report to this file (for GitHub Code Scanning)",
    )
    parser.add_argument(
        "--skip", action="append", default=[],
        choices=[
            "codeql", "semgrep", "bandit", "ruff",
            "detect-secrets", "dependabot", "pip-audit", "npm-audit", "trivy",
        ],
        help="Skip a scanner (repeatable)",
    )
    parser.add_argument(
        "--scan-git-history", action="store_true", default=False,
        help="Scan git commit history for leaked secrets (requires gitleaks)",
    )
    parser.add_argument(
        "--image", action="append", default=[], dest="extra_images",
        metavar="IMAGE",
        help=(
            "Pre-built Docker image name/tag to scan directly with Trivy "
            "(repeatable). Use when docker build fails in a restricted environment. "
            "Example: --image mcr.microsoft.com/playwright:v1.50-noble"
        ),
    )
    parser.add_argument(
        "--min-severity",
        choices=["critical", "high", "medium", "low", "info"],
        default="info",
        help="Only include findings at or above this severity in the output",
    )
    args = parser.parse_args()

    repo_path = str(Path(args.repo_path).resolve())
    if not Path(repo_path).is_dir():
        print(f"Error: {repo_path} is not a directory", file=sys.stderr)
        sys.exit(1)

    print(f"[shieldbot] Scanning {repo_path} ...", file=sys.stderr)

    report = asyncio.run(
        run_scan(
            repo_path=repo_path,
            skip_scanners=set(args.skip),
            scan_git_history=args.scan_git_history,
            extra_images=args.extra_images or [],
        )
    )

    # Filter by min severity if requested
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    min_order = sev_order[args.min_severity]
    report.all_findings = [
        f for f in report.all_findings
        if sev_order.get(f.severity.value, 9) <= min_order
    ]

    # Write output
    json_text = write_json_report(report, output_file=args.output_file)
    if not args.output_file:
        print(json_text)
    else:
        print(f"[shieldbot] Report written to {args.output_file}", file=sys.stderr)

    if args.output_sarif:
        write_sarif_report(report, args.output_sarif)
        print(f"[shieldbot] SARIF report written to {args.output_sarif}", file=sys.stderr)

    print(
        f"[shieldbot] {report.total_findings} findings: "
        f"critical={report.findings_by_severity.get('critical', 0)} "
        f"high={report.findings_by_severity.get('high', 0)} "
        f"medium={report.findings_by_severity.get('medium', 0)} "
        f"low={report.findings_by_severity.get('low', 0)}",
        file=sys.stderr,
    )

    # Exit code based on severity
    crit = report.findings_by_severity.get("critical", 0)
    high = report.findings_by_severity.get("high", 0)
    med = report.findings_by_severity.get("medium", 0)
    if crit:
        sys.exit(EXIT_CODE_CRITICAL)
    if high:
        sys.exit(EXIT_CODE_HIGH)
    if med:
        sys.exit(EXIT_CODE_MEDIUM)


if __name__ == "__main__":
    main()
