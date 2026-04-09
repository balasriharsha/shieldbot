"""
Trivy Docker image scanner.

Scanning strategy (in order, most to least complete):
  1. docker build → trivy image <built_tag>   (full image — all layers visible)
  2. docker pull  → trivy image <base_image>  (base image — OS-level packages)
  3. trivy fs <repo>                           (filesystem only — no apt/apk packages)

When docker build fails (e.g. network restricted sandbox):
  - Emits a prominent HIGH "SCAN GAP" warning so the user knows OS packages were missed
  - Falls back to base-image scan (parse FROM line, docker pull, trivy image)
  - Falls back further to filesystem scan if pull also fails
  - Reports explicit coverage status for each scan path attempted

Trivy is auto-installed from https://github.com/aquasecurity/trivy (Apache-2.0).
Docker must be present at runtime for image build/pull steps.
"""

from __future__ import annotations

import json
import re
import shutil
from pathlib import Path
from typing import List, Optional

from shieldbot.models import Finding, FindingCategory, ScanResult, Severity
from shieldbot.scanners.base import BaseScanner


_SEVERITY_MAP: dict[str, Severity] = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "UNKNOWN": Severity.INFO,
}

_SKIP_DIRS = {
    "node_modules", ".git", "__pycache__", ".venv", "venv",
    ".tox", "dist", "build", "vendor", ".cache",
}


def _parse_from_images(dockerfile_path: Path) -> list[str]:
    """
    Extract all base image references from a Dockerfile's FROM instructions.
    Handles multi-stage builds (returns all FROM targets).
    Skips `FROM scratch` (not pullable).
    """
    images: list[str] = []
    try:
        text = dockerfile_path.read_text(errors="replace")
    except OSError:
        return images
    for line in text.splitlines():
        line = line.strip()
        m = re.match(r"^FROM\s+([^\s]+)", line, re.IGNORECASE)
        if m:
            img = m.group(1).strip()
            # Skip ARG-based references we can't resolve and scratch
            if img.lower() == "scratch" or img.startswith("$"):
                continue
            # Strip AS alias
            img = re.sub(r"\s+AS\s+.*$", "", img, flags=re.IGNORECASE).strip()
            if img and img not in images:
                images.append(img)
    return images


class TrivyScanner(BaseScanner):
    """
    Container image scanner using Trivy.

    For each Dockerfile found in the repository:

    Primary path (build succeeds):
      docker build → trivy image <tag> → docker rmi

    Fallback path (build fails — network restricted sandbox, missing context, etc.):
      1. Parse FROM → docker pull <base_image> → trivy image <base_image>
      2. trivy fs <repo>  (filesystem scan — catches npm/pip CVEs but NOT apt/apk packages)
      3. Emit a prominent SCAN GAP warning listing what was NOT covered

    Additional: always scan the base image separately to catch OS-level CVEs
    regardless of whether the full build succeeded.

    Accepts extra_images=[...] kwarg from run_scan to scan pre-built images directly.
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

        docker_available = bool(shutil.which("docker"))

        # Pre-built image names passed explicitly (e.g. --image flag from CLI)
        extra_images: list[str] = kwargs.get("extra_images") or []

        # Discover Dockerfiles, skip hidden/vendor dirs
        repo = Path(repo_path)
        dockerfiles: list[Path] = []
        for pattern in ("**/Dockerfile", "**/Dockerfile.*"):
            for df in repo.glob(pattern):
                parts = df.relative_to(repo).parts
                if not any(p.startswith(".") or p in _SKIP_DIRS for p in parts):
                    dockerfiles.append(df)

        all_findings: list[Finding] = []
        raw_outputs: dict = {}
        coverage_notes: list[str] = []

        # ----------------------------------------------------------------
        # Scan any explicitly passed pre-built images first
        # ----------------------------------------------------------------
        for image_ref in extra_images:
            if not docker_available:
                coverage_notes.append(
                    f"SKIP (no Docker): pre-built image {image_ref}"
                )
                continue
            findings, note = await self._scan_image(
                trivy_bin, image_ref, image_ref, cleanup=False
            )
            all_findings.extend(findings)
            raw_outputs[f"image:{image_ref}"] = note
            coverage_notes.append(f"SCANNED (pre-built): {image_ref}")

        # ----------------------------------------------------------------
        # No Dockerfiles and no extra images
        # ----------------------------------------------------------------
        if not dockerfiles and not extra_images:
            return ScanResult(
                scanner=self.name,
                success=True,
                findings=[],
                raw_output={"info": "No Dockerfile found in repository — Trivy skipped"},
            )

        # ----------------------------------------------------------------
        # Process each Dockerfile
        # ----------------------------------------------------------------
        for dockerfile in dockerfiles:
            rel_path = str(dockerfile.relative_to(repo))
            context_dir = str(dockerfile.parent)
            safe_name = (dockerfile.parent.name.lower().replace(" ", "-") or "root")
            image_tag = f"shieldbot-scan-{safe_name}:latest"

            base_images = _parse_from_images(dockerfile)
            build_succeeded = False

            # ---- Attempt 1: full docker build ----
            if docker_available:
                _, build_stderr, build_rc = await self._run_subprocess(
                    ["docker", "build", "-f", str(dockerfile), "-t", image_tag, context_dir],
                    timeout=300,
                )

                if build_rc == 0:
                    build_succeeded = True
                    findings, note = await self._scan_image(
                        trivy_bin, image_tag, rel_path, cleanup=True
                    )
                    all_findings.extend(findings)
                    raw_outputs[rel_path] = note
                    coverage_notes.append(
                        f"SCANNED (full build): {rel_path} → {image_tag}"
                    )
                else:
                    raw_outputs[f"{rel_path}:build_error"] = build_stderr[:500]
                    # Emit a prominent SCAN GAP warning — not just info
                    all_findings.append(
                        Finding(
                            scanner=self.name,
                            rule_id="trivy:scan-gap:build-failed",
                            title=f"SCAN GAP — Docker build failed, OS packages NOT scanned: {rel_path}",
                            description=(
                                f"docker build failed for {rel_path} "
                                f"(likely network restriction or missing build context in this environment). "
                                f"Error: {build_stderr[:300]}\n\n"
                                "IMPACT: All OS-level packages installed via apt/apk/yum "
                                "(e.g. ffmpeg, libsoup, gstreamer, zbar, libav) are INVISIBLE to "
                                "filesystem-mode scanning. Critical/high CVEs in these packages "
                                "will NOT appear in this report unless the base image scan below succeeds."
                            ),
                            severity=Severity.HIGH,
                            category=FindingCategory.MISCONFIGURATION,
                            file_path=rel_path,
                            line_start=1,
                            remediation=(
                                "To get full coverage:\n"
                                "1. Run shieldbot in an environment with Docker network access\n"
                                "2. Or pre-build the image and pass it via --image <tag>\n"
                                "3. Or run: docker build ... && trivy image <tag> locally"
                            ),
                        )
                    )
                    coverage_notes.append(
                        f"SCAN GAP (build failed): {rel_path} — OS packages NOT scanned"
                    )

            else:
                all_findings.append(
                    Finding(
                        scanner=self.name,
                        rule_id="trivy:scan-gap:no-docker",
                        title=f"SCAN GAP — Docker not available, OS packages NOT scanned: {rel_path}",
                        description=(
                            "Docker is not installed or not on PATH. "
                            "OS-level packages (apt/apk/yum) baked into this image cannot be scanned. "
                            "Only filesystem-level dependencies (npm, pip, go.sum) are visible."
                        ),
                        severity=Severity.HIGH,
                        category=FindingCategory.MISCONFIGURATION,
                        file_path=rel_path,
                        line_start=1,
                        remediation="Install Docker and re-run, or pass a pre-built image with --image <tag>.",
                    )
                )
                coverage_notes.append(
                    f"SCAN GAP (no Docker): {rel_path} — OS packages NOT scanned"
                )

            # ---- Attempt 2: scan base image(s) separately ----
            # Do this regardless of build outcome — base image is where most OS CVEs live.
            if docker_available and base_images:
                for base_img in base_images:
                    # Try to pull the base image
                    _, pull_stderr, pull_rc = await self._run_subprocess(
                        ["docker", "pull", base_img],
                        timeout=180,
                    )
                    if pull_rc == 0:
                        findings, note = await self._scan_image(
                            trivy_bin, base_img,
                            f"{rel_path} (base: {base_img})",
                            cleanup=False,   # don't rmi pulled base images (may be reused)
                        )
                        all_findings.extend(findings)
                        raw_outputs[f"{rel_path}:base:{base_img}"] = note
                        coverage_notes.append(
                            f"SCANNED (base image): {base_img} for {rel_path}"
                        )
                    else:
                        # Pull failed — emit a scan gap note
                        if not build_succeeded:
                            # Only add another gap finding if the build also failed
                            # (if build succeeded, full scan already covers base)
                            all_findings.append(
                                Finding(
                                    scanner=self.name,
                                    rule_id="trivy:scan-gap:base-pull-failed",
                                    title=f"SCAN GAP — Could not pull base image: {base_img}",
                                    description=(
                                        f"docker pull {base_img} failed "
                                        f"(network restricted or image not public). "
                                        f"OS-level packages in this base image are NOT scanned.\n"
                                        f"Pull error: {pull_stderr[:200]}"
                                    ),
                                    severity=Severity.MEDIUM,
                                    category=FindingCategory.MISCONFIGURATION,
                                    file_path=rel_path,
                                    line_start=1,
                                    remediation=(
                                        f"Pull and scan manually:\n"
                                        f"  docker pull {base_img}\n"
                                        f"  trivy image --scanners vuln,secret,misconfig {base_img}"
                                    ),
                                )
                            )
                        coverage_notes.append(
                            f"SCAN GAP (pull failed): base image {base_img} for {rel_path}"
                        )

            # ---- Attempt 3: filesystem fallback scan ----
            # Always run — catches npm/pip/go CVEs even without Docker.
            # Note: does NOT catch apt/apk packages.
            fs_stdout, fs_stderr, fs_rc = await self._run_subprocess(
                [
                    trivy_bin, "fs",
                    "--format", "json",
                    "--scanners", "vuln,secret",
                    "--quiet",
                    repo_path,
                ],
                timeout=180,
            )
            if fs_stdout.strip():
                try:
                    fs_data = json.loads(fs_stdout)
                    fs_findings = self._parse_trivy_json(
                        fs_data, f"{rel_path} (filesystem scan)"
                    )
                    all_findings.extend(fs_findings)
                    raw_outputs[f"{rel_path}:fs"] = {
                        "Results": len(fs_data.get("Results", []))
                    }
                    coverage_notes.append(
                        f"SCANNED (filesystem): {repo_path} — npm/pip/go deps only, NOT apt/apk"
                    )
                except json.JSONDecodeError:
                    pass

        # Attach coverage summary to raw output
        raw_outputs["_coverage"] = coverage_notes

        return ScanResult(
            scanner=self.name,
            success=True,
            findings=all_findings,
            raw_output=raw_outputs,
        )

    # ------------------------------------------------------------------
    # Scan a single image tag and return (findings, info_dict)
    # ------------------------------------------------------------------

    async def _scan_image(
        self,
        trivy_bin: str,
        image_ref: str,
        report_path: str,
        cleanup: bool,
    ) -> tuple[List[Finding], dict]:
        stdout, stderr, _ = await self._run_subprocess(
            [
                trivy_bin, "image",
                "--format", "json",
                "--scanners", "vuln,secret,misconfig",
                "--quiet",
                image_ref,
            ],
            timeout=300,
        )

        if cleanup:
            await self._run_subprocess(["docker", "rmi", "-f", image_ref], timeout=30)

        if not stdout.strip():
            return [], {"error": stderr[:300]}

        try:
            data = json.loads(stdout)
        except json.JSONDecodeError:
            return [], {"parse_error": stdout[:200]}

        findings = self._parse_trivy_json(data, report_path)
        return findings, {"Results": len(data.get("Results", []))}

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
                    else (
                        f"No upstream fix available for {pkg} {installed_ver} — "
                        "consider switching to a newer base image or distroless variant"
                    )
                )

                findings.append(Finding(
                    scanner=self.name,
                    rule_id=f"trivy:{vuln_id}:{pkg}",
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
                        "Rebuild from scratch (layer deletion does not remove from git history). "
                        "Rotate the exposed credential immediately. "
                        "Use Docker build secrets (--secret) or runtime environment variables instead."
                    ),
                    confidence="high",
                ))

        return findings
