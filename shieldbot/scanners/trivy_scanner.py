"""
Trivy Docker image scanner.

Detects Dockerfile(s) in the repository, builds each Docker image, then
scans it with Trivy for OS/library CVEs, misconfigurations, and secrets.

Trivy is auto-installed from https://github.com/aquasecurity/trivy (Apache-2.0).
Docker must be present at runtime for the image build step.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import List

from shieldbot.models import Finding, FindingCategory, ScanResult, Severity
from shieldbot.scanners.base import BaseScanner


_SEVERITY_MAP: dict[str, Severity] = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "UNKNOWN": Severity.INFO,
}

_SKIP_DIRS = {"node_modules", ".git", "__pycache__", ".venv", "venv", ".tox",
              "dist", "build", "vendor", ".cache"}


class TrivyScanner(BaseScanner):
    """
    Container image scanner using Trivy.

    For each Dockerfile found in the repository:
      1. Builds the image with `docker build`
      2. Scans with `trivy image --scanners vuln,secret,misconfig --format json`
      3. Parses CVEs, misconfigurations, and baked-in secrets into Finding objects
      4. Removes the built image after scanning

    Trivy is auto-installed on first run if not found on PATH.
    Docker is required at runtime (build + Trivy image scan).
    """

    name = "trivy"

    def is_available(self) -> bool:
        return bool(shutil.which("trivy") and shutil.which("docker"))

    async def run(self, repo_path: str, **kwargs) -> ScanResult:
        from shieldbot.tools.installer import ensure_trivy

        # Ensure Trivy is available
        trivy_bin = shutil.which("trivy")
        if not trivy_bin:
            path = await ensure_trivy()
            trivy_bin = str(path) if path else None

        if not trivy_bin:
            return self._make_error_result(
                "trivy not found and auto-install failed. "
                "Install manually: https://aquasecurity.github.io/trivy/latest/getting-started/installation/"
            )

        if not shutil.which("docker"):
            return self._make_error_result(
                "Docker is required to build images for Trivy scanning. "
                "Install Docker from https://docs.docker.com/get-docker/"
            )

        # Discover Dockerfiles, skip hidden/vendor dirs
        repo = Path(repo_path)
        dockerfiles: list[Path] = []
        for pattern in ("**/Dockerfile", "**/Dockerfile.*"):
            for df in repo.glob(pattern):
                parts = df.relative_to(repo).parts
                if not any(p.startswith(".") or p in _SKIP_DIRS for p in parts):
                    dockerfiles.append(df)

        if not dockerfiles:
            return ScanResult(
                scanner=self.name,
                success=True,
                findings=[],
                raw_output={"info": "No Dockerfile found in repository — Trivy skipped"},
            )

        all_findings: list[Finding] = []
        raw_outputs: dict = {}

        for dockerfile in dockerfiles:
            rel_path = str(dockerfile.relative_to(repo))
            context_dir = str(dockerfile.parent)
            # Produce a safe, lowercase image tag
            safe_name = dockerfile.parent.name.lower().replace(" ", "-") or "root"
            image_tag = f"shieldbot-scan-{safe_name}:latest"

            # Step 1: Build the Docker image
            _, build_stderr, build_rc = await self._run_subprocess(
                ["docker", "build", "-f", str(dockerfile), "-t", image_tag, context_dir],
                timeout=300,
            )
            if build_rc != 0:
                raw_outputs[rel_path] = {"build_error": build_stderr[:500]}
                all_findings.append(Finding(
                    scanner=self.name,
                    rule_id="trivy:docker-build-failed",
                    title=f"Docker build failed: {rel_path}",
                    description=(
                        f"Could not build image from {rel_path}. "
                        f"Error: {build_stderr[:200]}"
                    ),
                    severity=Severity.INFO,
                    category=FindingCategory.MISCONFIGURATION,
                    file_path=rel_path,
                    line_start=1,
                ))
                continue

            # Step 2: Scan the built image
            stdout, stderr, _ = await self._run_subprocess(
                [
                    trivy_bin, "image",
                    "--format", "json",
                    "--scanners", "vuln,secret,misconfig",
                    "--quiet",
                    image_tag,
                ],
                timeout=300,
            )

            # Step 3: Clean up the image regardless of scan outcome
            await self._run_subprocess(
                ["docker", "rmi", "-f", image_tag],
                timeout=30,
            )

            if not stdout.strip():
                raw_outputs[rel_path] = {"error": stderr[:300]}
                continue

            try:
                data = json.loads(stdout)
            except json.JSONDecodeError:
                raw_outputs[rel_path] = {"parse_error": stdout[:200]}
                continue

            raw_outputs[rel_path] = {"Results": len(data.get("Results", []))}
            findings = self._parse_trivy_json(data, rel_path)
            all_findings.extend(findings)

        return ScanResult(
            scanner=self.name,
            success=True,
            findings=all_findings,
            raw_output=raw_outputs,
        )

    # ------------------------------------------------------------------
    # Parsing helpers
    # ------------------------------------------------------------------

    def _parse_trivy_json(self, data: dict, dockerfile_path: str) -> List[Finding]:
        findings: List[Finding] = []

        for result in data.get("Results") or []:
            target = result.get("Target", dockerfile_path)

            # --- CVE vulnerabilities ---
            for vuln in result.get("Vulnerabilities") or []:
                vuln_id = vuln.get("VulnerabilityID", "UNKNOWN")
                pkg = vuln.get("PkgName", "unknown")
                installed_ver = vuln.get("InstalledVersion", "?")
                fixed_ver = vuln.get("FixedVersion", "")
                title = vuln.get("Title") or f"{pkg}: {vuln_id}"
                description = vuln.get("Description") or title
                severity = _SEVERITY_MAP.get(
                    (vuln.get("Severity") or "UNKNOWN").upper(), Severity.INFO
                )
                references = (vuln.get("References") or [])[:5]
                fix_text = (
                    f"Upgrade {pkg} from {installed_ver} to {fixed_ver}"
                    if fixed_ver
                    else f"No upstream fix available for {pkg} {installed_ver} — consider replacing or pinning a patched base image"
                )

                findings.append(Finding(
                    scanner=self.name,
                    rule_id=f"trivy:{vuln_id}",
                    title=title,
                    description=description,
                    severity=severity,
                    category=FindingCategory.DEPENDENCY_CVE,
                    file_path=dockerfile_path,
                    line_start=1,
                    cve_id=vuln_id if vuln_id.startswith("CVE-") else None,
                    remediation=fix_text,
                    references=references,
                    confidence="high",
                ))

            # --- Misconfigurations ---
            for mis in result.get("Misconfigurations") or []:
                mis_id = mis.get("ID", "UNKNOWN")
                title = mis.get("Title", mis_id)
                description = mis.get("Description", title)
                severity = _SEVERITY_MAP.get(
                    (mis.get("Severity") or "UNKNOWN").upper(), Severity.INFO
                )
                resolution = mis.get("Resolution", "")
                refs: list[str] = []
                for ref in mis.get("References") or []:
                    if isinstance(ref, str):
                        refs.append(ref)
                    elif isinstance(ref, dict) and ref.get("URL"):
                        refs.append(ref["URL"])
                cause = mis.get("CauseMetadata") or {}

                findings.append(Finding(
                    scanner=self.name,
                    rule_id=f"trivy:misconfig:{mis_id}",
                    title=title,
                    description=description,
                    severity=severity,
                    category=FindingCategory.MISCONFIGURATION,
                    file_path=dockerfile_path,
                    line_start=cause.get("StartLine", 1),
                    line_end=cause.get("EndLine"),
                    remediation=resolution,
                    references=refs[:5],
                    confidence="high",
                ))

            # --- Secrets baked into image layers ---
            for secret in result.get("Secrets") or []:
                rule_id = secret.get("RuleID", "UNKNOWN")
                category = secret.get("Category", "Secret")
                match_preview = (secret.get("Match") or "")[:100]
                start_line = secret.get("StartLine", 1)

                findings.append(Finding(
                    scanner=self.name,
                    rule_id=f"trivy:secret:{rule_id}",
                    title=f"Secret in Docker image layer: {category}",
                    description=(
                        f"{category} detected in image layer '{target}'. "
                        f"Match preview: {match_preview}"
                    ),
                    severity=Severity.HIGH,
                    category=FindingCategory.SECRETS,
                    file_path=f"{dockerfile_path} → layer: {target}",
                    line_start=start_line,
                    remediation=(
                        "Remove the secret from the Docker image. "
                        "Rebuild from scratch (do not just delete the layer — git history retains it). "
                        "Rotate the exposed credential immediately. "
                        "Use Docker build secrets (--secret) or runtime environment variables instead."
                    ),
                    confidence="high",
                ))

        return findings
