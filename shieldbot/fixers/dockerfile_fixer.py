"""
Dockerfile and docker-compose security fixer.

Provides:
  - Parsing: extract FROM stages, RUN install commands, docker-compose image refs
  - Analysis: map Trivy CVE/misconfig findings to specific fixable lines
  - Fixing: apply targeted edits to Dockerfiles and compose files
  - Base image lookup: try Docker Hub to find a patched tag

Can be used as a library by the shieldbot agent, or run directly:

  python -m shieldbot.fixers.dockerfile_fixer analyze <dockerfile> [trivy_json]
  python -m shieldbot.fixers.dockerfile_fixer list-stages <dockerfile>
  python -m shieldbot.fixers.dockerfile_fixer list-compose-images <compose_file>
  python -m shieldbot.fixers.dockerfile_fixer suggest-base-upgrade <image_ref>
"""

from __future__ import annotations

import json
import re
import sys
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

@dataclass
class DockerStage:
    """One FROM … AS … stage in a Dockerfile."""
    base_image: str          # e.g. "ubuntu:22.04"
    alias: Optional[str]     # AS name, or None
    from_line_no: int        # 1-based line number
    pkg_manager: str         # "apt" | "apk" | "yum" | "dnf" | "unknown"


@dataclass
class RunInstall:
    """A RUN command that installs packages."""
    line_no: int             # 1-based line number of the RUN instruction
    raw_line: str            # Full RUN line (may span multiple lines via \)
    pkg_manager: str         # "apt" | "apk" | "yum" | "dnf" | "pip" | "npm"
    packages: list[str]      # Parsed package names (without version pins)


@dataclass
class ComposeImageRef:
    """An image: reference in a docker-compose file."""
    service: str
    image: str               # e.g. "redis:7.2"
    line_no: int
    compose_path: str


@dataclass
class FixSuggestion:
    """A specific, automatable fix for a Trivy finding."""
    fix_type: str            # "add_upgrade_step" | "pin_package" | "upgrade_from" | "add_user" | "add_healthcheck" | "compose_image_update"
    file: str                # Absolute or relative file path
    line_no: int             # Line to modify or insert after
    old_text: str            # Current text (empty for insertions)
    new_text: str            # Replacement / insertion text
    cve_ids: list[str]       # CVEs this fix addresses
    severity: str            # "CRITICAL" | "HIGH" | etc.
    description: str         # Human-readable description of the change
    confidence: str          # "high" | "medium" | "low"


# ---------------------------------------------------------------------------
# Package manager detection
# ---------------------------------------------------------------------------

_APT_IMAGES = re.compile(
    r"ubuntu|debian|mint|kali|raspbian", re.IGNORECASE
)
_APK_IMAGES = re.compile(
    r"alpine|alpinelinux", re.IGNORECASE
)
_YUM_IMAGES = re.compile(
    r"centos|rhel|redhat|fedora|ubi\d*|amazonlinux|rockylinux|almalinux",
    re.IGNORECASE,
)

_RUN_APT     = re.compile(r"apt-get\s+install|apt\s+install", re.IGNORECASE)
_RUN_APK     = re.compile(r"apk\s+add", re.IGNORECASE)
_RUN_YUM     = re.compile(r"yum\s+install|dnf\s+install", re.IGNORECASE)
_RUN_PIP     = re.compile(r"pip\s+install|pip3\s+install", re.IGNORECASE)
_RUN_NPM     = re.compile(r"npm\s+install|npm\s+ci", re.IGNORECASE)


def _infer_pkg_manager_from_image(image: str) -> str:
    if _APT_IMAGES.search(image):
        return "apt"
    if _APK_IMAGES.search(image):
        return "apk"
    if _YUM_IMAGES.search(image):
        return "yum"
    # Well-known official images with known base OS
    img_lower = image.lower().split(":")[0].split("/")[-1]
    _APT_DEFAULTS = {"node", "python", "ruby", "php", "java", "openjdk",
                     "gradle", "maven", "golang", "rust", "nginx", "httpd",
                     "postgres", "mysql", "mariadb"}
    _APK_DEFAULTS = {"node-alpine", "python-alpine", "ruby-alpine"}
    if "alpine" in image.lower():
        return "apk"
    if img_lower in _APT_DEFAULTS:
        return "apt"
    return "unknown"


# ---------------------------------------------------------------------------
# Dockerfile parser
# ---------------------------------------------------------------------------

def _join_continuation_lines(lines: list[str]) -> list[tuple[int, str]]:
    """
    Collapse backslash-continuation lines into logical lines.
    Returns list of (start_line_no_1based, logical_line).
    """
    result: list[tuple[int, str]] = []
    current_start: Optional[int] = None
    current_parts: list[str] = []

    for i, raw in enumerate(lines, start=1):
        stripped = raw.rstrip("\n")
        if current_start is None:
            current_start = i
        if stripped.endswith("\\"):
            current_parts.append(stripped[:-1])
        else:
            current_parts.append(stripped)
            result.append((current_start, " ".join(current_parts).strip()))
            current_start = None
            current_parts = []

    if current_parts and current_start is not None:
        result.append((current_start, " ".join(current_parts).strip()))

    return result


def parse_stages(dockerfile_path: str | Path) -> list[DockerStage]:
    """
    Parse all FROM … AS … stages from a Dockerfile.
    Returns stages in order. Skips `FROM scratch` (not pullable).
    """
    path = Path(dockerfile_path)
    try:
        raw_lines = path.read_text(errors="replace").splitlines(keepends=True)
    except OSError:
        return []

    stages: list[DockerStage] = []
    for line_no, logical in _join_continuation_lines(raw_lines):
        m = re.match(
            r"^FROM\s+([^\s]+)(?:\s+AS\s+([^\s]+))?",
            logical, re.IGNORECASE,
        )
        if not m:
            continue
        img = m.group(1).strip()
        alias = m.group(2).strip() if m.group(2) else None
        if img.lower() == "scratch" or img.startswith("$"):
            continue
        pkg_mgr = _infer_pkg_manager_from_image(img)
        stages.append(DockerStage(
            base_image=img,
            alias=alias,
            from_line_no=line_no,
            pkg_manager=pkg_mgr,
        ))

    return stages


def parse_run_installs(dockerfile_path: str | Path) -> list[RunInstall]:
    """
    Parse all RUN commands that install packages (apt/apk/yum/pip/npm).
    Returns list of RunInstall objects.
    """
    path = Path(dockerfile_path)
    try:
        raw_lines = path.read_text(errors="replace").splitlines(keepends=True)
    except OSError:
        return []

    installs: list[RunInstall] = []
    for line_no, logical in _join_continuation_lines(raw_lines):
        if not re.match(r"^RUN\b", logical, re.IGNORECASE):
            continue

        pkg_mgr: Optional[str] = None
        pkgs: list[str] = []

        if _RUN_APT.search(logical):
            pkg_mgr = "apt"
            pkgs = _extract_apt_packages(logical)
        elif _RUN_APK.search(logical):
            pkg_mgr = "apk"
            pkgs = _extract_apk_packages(logical)
        elif _RUN_YUM.search(logical):
            pkg_mgr = "yum"
            pkgs = _extract_yum_packages(logical)
        elif _RUN_PIP.search(logical):
            pkg_mgr = "pip"
            pkgs = _extract_pip_packages(logical)
        elif _RUN_NPM.search(logical):
            pkg_mgr = "npm"

        if pkg_mgr:
            installs.append(RunInstall(
                line_no=line_no,
                raw_line=logical,
                pkg_manager=pkg_mgr,
                packages=pkgs,
            ))

    return installs


def _extract_apt_packages(run_line: str) -> list[str]:
    """Extract package names from apt-get install ... lines."""
    # Remove flags like -y, --no-install-recommends, versions
    # Package list comes after install/install-recommends
    m = re.search(r"(?:apt-get|apt)\s+install[^\s]*\s+(.*)", run_line, re.IGNORECASE)
    if not m:
        return []
    raw = m.group(1)
    # Strip shell conditionals and redirects
    raw = re.sub(r"&&.*", "", raw).strip()
    tokens = raw.split()
    pkgs = [
        re.sub(r"[=<>:].+$", "", t)   # strip version specs
        for t in tokens
        if not t.startswith("-") and not t.startswith("$")
    ]
    return [p for p in pkgs if p and not p.startswith("#")]


def _extract_apk_packages(run_line: str) -> list[str]:
    """Extract package names from apk add ... lines."""
    m = re.search(r"apk\s+add[^\s]*\s+(.*)", run_line, re.IGNORECASE)
    if not m:
        return []
    raw = re.sub(r"&&.*", "", m.group(1)).strip()
    tokens = raw.split()
    pkgs = [
        re.sub(r"[=<>~].+$", "", t)
        for t in tokens
        if not t.startswith("-") and not t.startswith("$")
    ]
    return [p for p in pkgs if p]


def _extract_yum_packages(run_line: str) -> list[str]:
    """Extract package names from yum/dnf install ... lines."""
    m = re.search(r"(?:yum|dnf)\s+install[^\s]*\s+(.*)", run_line, re.IGNORECASE)
    if not m:
        return []
    raw = re.sub(r"&&.*", "", m.group(1)).strip()
    tokens = raw.split()
    pkgs = [
        re.sub(r"[=\-][0-9].+$", "", t)
        for t in tokens
        if not t.startswith("-") and not t.startswith("$")
    ]
    return [p for p in pkgs if p]


def _extract_pip_packages(run_line: str) -> list[str]:
    """Extract package names from pip install ... lines."""
    m = re.search(r"pip[0-9]?\s+install[^\s]*\s+(.*)", run_line, re.IGNORECASE)
    if not m:
        return []
    raw = re.sub(r"&&.*", "", m.group(1)).strip()
    tokens = raw.split()
    pkgs = [
        re.sub(r"[=<>!~].+$", "", t)
        for t in tokens
        if not t.startswith("-") and not t.startswith("$") and not t.startswith("-r")
    ]
    return [p for p in pkgs if p]


# ---------------------------------------------------------------------------
# docker-compose parser
# ---------------------------------------------------------------------------

def parse_compose_images(compose_path: str | Path) -> list[ComposeImageRef]:
    """
    Extract all image: references from a docker-compose file.
    Uses regex — no PyYAML dependency.
    """
    path = Path(compose_path)
    try:
        lines = path.read_text(errors="replace").splitlines()
    except OSError:
        return []

    refs: list[ComposeImageRef] = []
    current_service: Optional[str] = None

    for i, line in enumerate(lines, start=1):
        # Top-level service names (2-space indent, alphanumeric key)
        svc_m = re.match(r"^  ([a-zA-Z0-9_][a-zA-Z0-9_\-.]*):\s*$", line)
        if svc_m:
            current_service = svc_m.group(1)
            continue
        # image: field (4-space indent)
        img_m = re.match(r"^\s{3,}image:\s*['\"]?([^\s'\"\n#]+)['\"]?", line)
        if img_m and current_service:
            refs.append(ComposeImageRef(
                service=current_service,
                image=img_m.group(1).strip(),
                line_no=i,
                compose_path=str(path),
            ))

    return refs


def find_compose_files(repo_path: str | Path) -> list[Path]:
    """Find all docker-compose YAML files in the repo."""
    repo = Path(repo_path)
    found: list[Path] = []
    for pattern in (
        "**/docker-compose.yml",
        "**/docker-compose.yaml",
        "**/compose.yml",
        "**/compose.yaml",
    ):
        for f in repo.glob(pattern):
            parts = f.relative_to(repo).parts
            if not any(p.startswith(".") or p in {"node_modules", "vendor"} for p in parts):
                found.append(f)
    return found


# ---------------------------------------------------------------------------
# Docker Hub tag lookup (optional, graceful fallback)
# ---------------------------------------------------------------------------

def _parse_image_ref(image_ref: str) -> tuple[str, str]:
    """
    Split image_ref into (repository, tag).
    e.g. "ubuntu:20.04" → ("ubuntu", "20.04")
         "node:18-alpine" → ("node", "18-alpine")
         "mcr.microsoft.com/playwright:v1.50" → ("mcr.microsoft.com/playwright", "v1.50")
    """
    if ":" in image_ref.split("/")[-1]:
        repo, tag = image_ref.rsplit(":", 1)
    else:
        repo, tag = image_ref, "latest"
    return repo, tag


def suggest_base_upgrade(image_ref: str, timeout: int = 10) -> Optional[str]:
    """
    Try to find a patched/newer tag for a base image via Docker Hub API.
    Returns a suggested newer image ref, or None if lookup fails or no better
    tag is found.

    Only works for Docker Hub images (library/* and user/* namespaces).
    Private registries (mcr.microsoft.com, gcr.io, etc.) return None gracefully.
    """
    repo, current_tag = _parse_image_ref(image_ref)

    # Only attempt Docker Hub (public registry)
    if "/" not in repo:
        namespace, name = "library", repo
    elif repo.count("/") == 1 and "." not in repo.split("/")[0]:
        namespace, name = repo.split("/", 1)
    else:
        return None   # Private registry — skip

    try:
        url = (
            f"https://hub.docker.com/v2/repositories/{namespace}/{name}"
            f"/tags?page_size=25&ordering=last_updated"
        )
        req = urllib.request.Request(
            url, headers={"User-Agent": "shieldbot-fixer/1.0"}
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read())
    except (urllib.error.URLError, json.JSONDecodeError, OSError):
        return None

    tags: list[str] = [t["name"] for t in data.get("results", [])]
    if not tags:
        return None

    # Heuristic: if current tag is a specific version, suggest the latest
    # patch release in the same minor series
    # e.g. "3.17.2" → look for "3.17.X" where X is highest
    ver_m = re.match(r"^(\d+\.\d+)\.(\d+)(.*)", current_tag)
    if ver_m:
        prefix = ver_m.group(1)
        suffix = ver_m.group(3)
        candidates = [
            t for t in tags
            if re.match(rf"^{re.escape(prefix)}\.\d+{re.escape(suffix)}$", t)
        ]
        if candidates:
            # Pick the one with the highest patch number
            def _patch(t: str) -> int:
                m = re.match(rf"^{re.escape(prefix)}\.(\d+)", t)
                return int(m.group(1)) if m else 0
            best = max(candidates, key=_patch)
            if best != current_tag:
                return f"{repo}:{best}"

    # If current tag is a major/minor (e.g., "3.17" or "18-alpine"), suggest latest
    if "latest" in tags and current_tag != "latest":
        return None  # "latest" is usually too imprecise to recommend

    return None


# ---------------------------------------------------------------------------
# Fix plan generator
# ---------------------------------------------------------------------------

def generate_fix_plan(
    dockerfile_path: str | Path,
    trivy_findings: list[dict],
) -> list[FixSuggestion]:
    """
    Given a Dockerfile path and a list of Trivy Finding dicts (from scan JSON),
    produce a list of FixSuggestion objects.

    trivy_findings: list of Finding dicts from shieldbot scan JSON where
                    scanner == "trivy"
    """
    df_path = Path(dockerfile_path)
    if not df_path.exists():
        return []

    stages = parse_stages(df_path)
    run_installs = parse_run_installs(df_path)
    suggestions: list[FixSuggestion] = []
    seen_upgrade_stages: set[int] = set()

    # Index: package_name → (stage, run_install) for packages explicitly installed
    installed_pkg_index: dict[str, RunInstall] = {}
    for ri in run_installs:
        for pkg in ri.packages:
            installed_pkg_index[pkg.lower()] = ri

    for finding in trivy_findings:
        rule_id = finding.get("rule_id", "")
        severity = finding.get("severity", "info").upper()
        cve_ids = [finding.get("cve_id")] if finding.get("cve_id") else []
        title = finding.get("title", "")
        remediation = finding.get("remediation", "")

        # ---- CVE in a dependency package ----
        if rule_id.startswith("trivy:CVE-") or rule_id.startswith("trivy:GHSA-"):
            # Extract package name from rule_id: "trivy:CVE-2023-1234:libssl"
            parts = rule_id.split(":")
            pkg_name = parts[2].lower() if len(parts) >= 3 else ""

            # Extract fixed version from remediation text
            fixed_ver = ""
            m = re.search(r"Upgrade \S+ from \S+ to ([^\s\n]+)", remediation)
            if m:
                fixed_ver = m.group(1)

            # Is this package explicitly installed by a RUN command?
            if pkg_name and pkg_name in installed_pkg_index:
                ri = installed_pkg_index[pkg_name]
                if fixed_ver and ri.pkg_manager in ("apt", "apk", "yum"):
                    # Suggest pinning to fixed version in the RUN line
                    old_pkg = pkg_name
                    if ri.pkg_manager == "apt":
                        new_pkg_spec = f"{pkg_name}={fixed_ver}"
                        suggestions.append(FixSuggestion(
                            fix_type="pin_package",
                            file=str(df_path),
                            line_no=ri.line_no,
                            old_text=old_pkg,
                            new_text=new_pkg_spec,
                            cve_ids=cve_ids,
                            severity=severity,
                            description=(
                                f"Pin {pkg_name} to {fixed_ver} in apt-get install "
                                f"to fix {', '.join(cve_ids) or title}"
                            ),
                            confidence="high",
                        ))
                    elif ri.pkg_manager == "apk":
                        new_pkg_spec = f"{pkg_name}={fixed_ver}"
                        suggestions.append(FixSuggestion(
                            fix_type="pin_package",
                            file=str(df_path),
                            line_no=ri.line_no,
                            old_text=old_pkg,
                            new_text=new_pkg_spec,
                            cve_ids=cve_ids,
                            severity=severity,
                            description=(
                                f"Pin {pkg_name} to {fixed_ver} in apk add "
                                f"to fix {', '.join(cve_ids) or title}"
                            ),
                            confidence="high",
                        ))
            else:
                # Package came from base image — suggest upgrade step for the stage
                # Find the relevant stage (use first stage for simplicity)
                if stages and stages[0].from_line_no not in seen_upgrade_stages:
                    stage = stages[0]
                    pkg_mgr = stage.pkg_manager
                    if pkg_mgr in ("apt", "apk", "yum", "unknown"):
                        upgrade_cmd = _upgrade_command(pkg_mgr)
                        suggestions.append(FixSuggestion(
                            fix_type="add_upgrade_step",
                            file=str(df_path),
                            line_no=stage.from_line_no,
                            old_text="",
                            new_text=upgrade_cmd,
                            cve_ids=cve_ids,
                            severity=severity,
                            description=(
                                f"Add security upgrade step after FROM {stage.base_image} "
                                f"to patch OS packages with known CVEs"
                            ),
                            confidence="high",
                        ))
                        seen_upgrade_stages.add(stage.from_line_no)

        # ---- Misconfigurations ----
        elif rule_id.startswith("trivy:misconfig:"):
            mis_id = rule_id.split("trivy:misconfig:")[-1]
            fix = _misconfig_fix(mis_id, df_path, stages, title, remediation)
            if fix:
                suggestions.append(fix)

    return suggestions


def _upgrade_command(pkg_manager: str) -> str:
    if pkg_manager == "apt":
        return (
            "RUN apt-get update \\\n"
            "    && apt-get upgrade -y --no-install-recommends \\\n"
            "    && rm -rf /var/lib/apt/lists/*"
        )
    if pkg_manager == "apk":
        return "RUN apk upgrade --no-cache"
    if pkg_manager in ("yum", "dnf"):
        return "RUN yum update -y && yum clean all"
    # unknown — try apt first, fall back to apk
    return (
        "RUN (apt-get update && apt-get upgrade -y --no-install-recommends "
        "&& rm -rf /var/lib/apt/lists/*) || apk upgrade --no-cache || true"
    )


def _misconfig_fix(
    mis_id: str,
    df_path: Path,
    stages: list[DockerStage],
    title: str,
    remediation: str,
) -> Optional[FixSuggestion]:
    """Return a FixSuggestion for a known Trivy misconfiguration ID."""
    mid = mis_id.upper()

    # DS002 / AVD-DS-0002: Root user
    if "DS002" in mid or "AVD-DS-0002" in mid or "root" in title.lower():
        return FixSuggestion(
            fix_type="add_user",
            file=str(df_path),
            line_no=_last_stage_from_line(stages),
            old_text="",
            new_text="RUN addgroup --system appgroup && adduser --system --ingroup appgroup appuser\nUSER appuser",
            cve_ids=[],
            severity="HIGH",
            description="Add non-root USER directive to avoid running container as root",
            confidence="medium",
        )

    # DS026 / no HEALTHCHECK
    if "DS026" in mid or "HEALTHCHECK" in title.upper():
        return FixSuggestion(
            fix_type="add_healthcheck",
            file=str(df_path),
            line_no=_last_stage_from_line(stages),
            old_text="",
            new_text='HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \\\n  CMD wget -qO- http://localhost/ || exit 1',
            cve_ids=[],
            severity="LOW",
            description="Add HEALTHCHECK directive (update the CMD to match your application's health endpoint)",
            confidence="low",
        )

    # DS005 / ADD instead of COPY
    if "DS005" in mid or ("ADD" in title.upper() and "COPY" in title.upper()):
        return FixSuggestion(
            fix_type="replace_add_with_copy",
            file=str(df_path),
            line_no=0,  # Agent should search for ADD instructions
            old_text="ADD",
            new_text="COPY",
            cve_ids=[],
            severity="LOW",
            description="Replace ADD with COPY where remote URLs or archives are not needed",
            confidence="medium",
        )

    # DS013 / RUN cd instead of WORKDIR
    if "DS013" in mid:
        return FixSuggestion(
            fix_type="informational",
            file=str(df_path),
            line_no=0,
            old_text="",
            new_text="",
            cve_ids=[],
            severity="LOW",
            description="Replace `RUN cd ...` patterns with WORKDIR instruction",
            confidence="low",
        )

    return None


def _last_stage_from_line(stages: list[DockerStage]) -> int:
    return stages[-1].from_line_no if stages else 1


# ---------------------------------------------------------------------------
# File editors
# ---------------------------------------------------------------------------

def apply_upgrade_step(dockerfile_path: str | Path, after_line_no: int, pkg_manager: str) -> bool:
    """
    Insert a security upgrade RUN step immediately after the given line number.
    Returns True on success.
    """
    path = Path(dockerfile_path)
    try:
        lines = path.read_text(errors="replace").splitlines(keepends=True)
    except OSError:
        return False

    upgrade_cmd = _upgrade_command(pkg_manager)
    insert_pos = min(after_line_no, len(lines))  # after_line_no is 1-based
    lines.insert(insert_pos, f"\n{upgrade_cmd}\n")

    path.write_text("".join(lines))
    return True


def pin_package_in_run(
    dockerfile_path: str | Path,
    run_line_no: int,
    package_name: str,
    fixed_version: str,
    pkg_manager: str,
) -> bool:
    """
    In the RUN command at run_line_no, replace a bare package name with
    a version-pinned form.  Returns True on success.
    """
    path = Path(dockerfile_path)
    try:
        content = path.read_text(errors="replace")
        lines = content.splitlines(keepends=True)
    except OSError:
        return False

    if run_line_no < 1 or run_line_no > len(lines):
        return False

    # Locate the logical RUN block (may span multiple lines with \)
    # Simple replacement: find bare package name and add version pin
    if pkg_manager in ("apt",):
        sep = "="
    elif pkg_manager == "apk":
        sep = "="
    else:
        sep = "-"   # yum: package-version

    new_spec = f"{package_name}{sep}{fixed_version}"
    # Replace word-boundary match of package_name in lines starting at run_line_no
    target_idx = run_line_no - 1
    original = lines[target_idx]
    replaced = re.sub(
        rf"\b{re.escape(package_name)}\b(?![=<>~])",
        new_spec,
        original,
    )
    if replaced == original:
        return False  # Nothing was changed

    lines[target_idx] = replaced
    path.write_text("".join(lines))
    return True


def upgrade_from_line(
    dockerfile_path: str | Path,
    old_image: str,
    new_image: str,
) -> bool:
    """
    Replace the base image in all matching FROM lines.
    Returns True if at least one replacement was made.
    """
    path = Path(dockerfile_path)
    try:
        content = path.read_text(errors="replace")
    except OSError:
        return False

    new_content, count = re.subn(
        rf"(^FROM\s+){re.escape(old_image)}(\s|$)",
        rf"\g<1>{new_image}\2",
        content,
        flags=re.IGNORECASE | re.MULTILINE,
    )
    if count == 0:
        return False

    path.write_text(new_content)
    return True


def update_compose_image(
    compose_path: str | Path,
    old_image: str,
    new_image: str,
) -> bool:
    """
    Replace an image reference in a docker-compose file.
    Returns True if replacement was made.
    """
    path = Path(compose_path)
    try:
        content = path.read_text(errors="replace")
    except OSError:
        return False

    new_content, count = re.subn(
        rf"(image:\s*['\"]?){re.escape(old_image)}(['\"]?\s*(?:#.*)?$)",
        rf"\g<1>{new_image}\g<2>",
        content,
        flags=re.MULTILINE,
    )
    if count == 0:
        return False

    path.write_text(new_content)
    return True


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def _cmd_list_stages(args: list[str]) -> None:
    if not args:
        print("Usage: list-stages <dockerfile>", file=sys.stderr)
        sys.exit(1)
    stages = parse_stages(args[0])
    for s in stages:
        alias_txt = f" AS {s.alias}" if s.alias else ""
        print(f"line {s.from_line_no:4d}: FROM {s.base_image}{alias_txt}  [{s.pkg_manager}]")


def _cmd_list_run_installs(args: list[str]) -> None:
    if not args:
        print("Usage: list-installs <dockerfile>", file=sys.stderr)
        sys.exit(1)
    installs = parse_run_installs(args[0])
    for ri in installs:
        print(f"line {ri.line_no:4d}: [{ri.pkg_manager}] {' '.join(ri.packages)}")


def _cmd_list_compose_images(args: list[str]) -> None:
    if not args:
        print("Usage: list-compose-images <compose_file>", file=sys.stderr)
        sys.exit(1)
    refs = parse_compose_images(args[0])
    for r in refs:
        print(f"line {r.line_no:4d}: service={r.service}  image={r.image}")


def _cmd_suggest_base_upgrade(args: list[str]) -> None:
    if not args:
        print("Usage: suggest-base-upgrade <image_ref>", file=sys.stderr)
        sys.exit(1)
    result = suggest_base_upgrade(args[0])
    if result:
        print(f"Suggested upgrade: {args[0]} → {result}")
    else:
        print(f"No newer tag found for {args[0]} (may be up to date or private registry)")


def _cmd_analyze(args: list[str]) -> None:
    if not args:
        print("Usage: analyze <dockerfile> [trivy_scan_json]", file=sys.stderr)
        sys.exit(1)

    df = args[0]
    findings: list[dict] = []
    if len(args) >= 2:
        try:
            scan_data = json.loads(Path(args[1]).read_text())
            findings = [
                f for f in scan_data.get("all_findings", [])
                if f.get("scanner") == "trivy"
            ]
        except (OSError, json.JSONDecodeError) as e:
            print(f"Warning: could not load trivy JSON: {e}", file=sys.stderr)

    stages = parse_stages(df)
    installs = parse_run_installs(df)
    print(f"\n=== Stages ({len(stages)}) ===")
    for s in stages:
        alias_txt = f" AS {s.alias}" if s.alias else ""
        print(f"  line {s.from_line_no}: FROM {s.base_image}{alias_txt}  [{s.pkg_manager}]")
        upgrade = suggest_base_upgrade(s.base_image)
        if upgrade:
            print(f"    → Suggested upgrade: {upgrade}")

    print(f"\n=== RUN Installs ({len(installs)}) ===")
    for ri in installs:
        print(f"  line {ri.line_no}: [{ri.pkg_manager}] {' '.join(ri.packages) or '(no packages parsed)'}")

    if findings:
        suggestions = generate_fix_plan(df, findings)
        print(f"\n=== Fix Suggestions ({len(suggestions)}) ===")
        print(json.dumps(
            [s.__dict__ for s in suggestions],
            indent=2, default=str,
        ))


def main() -> None:
    args = sys.argv[1:]
    if not args:
        print(
            "Usage: python -m shieldbot.fixers.dockerfile_fixer <command> [args]\n"
            "Commands:\n"
            "  analyze <dockerfile> [trivy_json]    — show stages, installs, fix plan\n"
            "  list-stages <dockerfile>             — list FROM stages\n"
            "  list-installs <dockerfile>           — list RUN install commands\n"
            "  list-compose-images <compose_file>   — list image: refs in compose\n"
            "  suggest-base-upgrade <image_ref>     — look up newer Docker Hub tag\n",
            file=sys.stderr,
        )
        sys.exit(1)

    cmd, rest = args[0], args[1:]
    dispatch = {
        "analyze": _cmd_analyze,
        "list-stages": _cmd_list_stages,
        "list-installs": _cmd_list_run_installs,
        "list-compose-images": _cmd_list_compose_images,
        "suggest-base-upgrade": _cmd_suggest_base_upgrade,
    }
    fn = dispatch.get(cmd)
    if not fn:
        print(f"Unknown command: {cmd}", file=sys.stderr)
        sys.exit(1)
    fn(rest)


if __name__ == "__main__":
    main()
