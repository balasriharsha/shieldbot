"""
Cross-platform auto-installer for CodeQL CLI, osv-scanner, and Dependabot CLI.

Supports:
  - macOS  x86_64 (Intel)
  - macOS  arm64  (Apple Silicon)
  - Linux  x86_64
  - Linux  arm64 / aarch64

Install location (no sudo required):
  ~/.local/share/shieldbot/  — extracted archives (CodeQL)
  ~/.local/bin/              — binaries / symlinks (added to current PATH)

All tools are fully open-source:
  CodeQL:        https://github.com/github/codeql-cli-binaries  (MIT)
  osv-scanner:   https://github.com/google/osv-scanner          (Apache-2.0)
  Dependabot CLI: https://github.com/dependabot/cli             (MIT)
"""

from __future__ import annotations

import asyncio
import json
import os
import platform
import re
import shutil
import stat
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path
from typing import Optional
import urllib.request
import urllib.error


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

SHIELDBOT_HOME = Path.home() / ".local" / "share" / "shieldbot"
BIN_DIR        = Path.home() / ".local" / "bin"

# GitHub repositories
_CODEQL_REPO       = "github/codeql-cli-binaries"
_OSVSCANNER_REPO   = "google/osv-scanner"
_DEPENDABOT_REPO   = "dependabot/cli"


# ---------------------------------------------------------------------------
# OS / arch detection
# ---------------------------------------------------------------------------

def _detect_platform() -> tuple[str, str]:
    """
    Return (os_name, arch) where:
      os_name: "linux" | "macos"
      arch:    "x86_64" | "arm64"
    """
    system  = platform.system().lower()
    machine = platform.machine().lower()

    if system == "darwin":
        os_name = "macos"
    elif system == "linux":
        os_name = "linux"
    else:
        raise RuntimeError(
            f"Unsupported operating system: {platform.system()}. "
            "shieldbot auto-install supports macOS and Linux."
        )

    if machine in ("arm64", "aarch64"):
        arch = "arm64"
    elif machine in ("x86_64", "amd64", "i386", "i686"):
        arch = "x86_64"
    else:
        raise RuntimeError(
            f"Unsupported CPU architecture: {platform.machine()}. "
            "shieldbot auto-install supports x86_64 and arm64."
        )

    return os_name, arch


# ---------------------------------------------------------------------------
# PATH management
# ---------------------------------------------------------------------------

def _ensure_bin_dir_on_path() -> None:
    """Ensure BIN_DIR exists and is prepended to the current process PATH."""
    BIN_DIR.mkdir(parents=True, exist_ok=True)
    current = os.environ.get("PATH", "")
    if str(BIN_DIR) not in current.split(":"):
        os.environ["PATH"] = str(BIN_DIR) + ":" + current


def _print(msg: str) -> None:
    print(f"[shieldbot-install] {msg}", file=sys.stderr, flush=True)


# ---------------------------------------------------------------------------
# GitHub releases helpers (no token required, public API)
# ---------------------------------------------------------------------------

def _github_latest_release(repo: str) -> dict:
    """Fetch the latest release JSON for a GitHub repo via the public API."""
    url = f"https://api.github.com/repos/{repo}/releases/latest"
    req = urllib.request.Request(
        url,
        headers={
            "Accept":     "application/vnd.github+json",
            "User-Agent": "shieldbot-installer/1.0",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())
    except (urllib.error.URLError, json.JSONDecodeError) as exc:
        raise RuntimeError(
            f"Could not fetch latest release for {repo}: {exc}"
        ) from exc


def _github_latest_tag(repo: str) -> str:
    return _github_latest_release(repo)["tag_name"]


def _github_asset_url(repo: str, tag: str, asset_name: str) -> str:
    return f"https://github.com/{repo}/releases/download/{tag}/{asset_name}"


# ---------------------------------------------------------------------------
# Download helper  (curl → wget → urllib)
# ---------------------------------------------------------------------------

async def _download_file(url: str, dest: Path, label: str) -> None:
    """Download *url* to *dest*, preferring curl/wget for progress display."""
    _print(f"Downloading {label} ...")
    _print(f"  {url}")
    dest.parent.mkdir(parents=True, exist_ok=True)

    if shutil.which("curl"):
        cmd = ["curl", "-fsSL", "--progress-bar", "-o", str(dest), url]
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=sys.stderr, stderr=sys.stderr
        )
        if (await proc.wait()) == 0 and dest.exists() and dest.stat().st_size > 0:
            return

    if shutil.which("wget"):
        cmd = ["wget", "-q", "--show-progress", "-O", str(dest), url]
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=sys.stderr, stderr=sys.stderr
        )
        if (await proc.wait()) == 0 and dest.exists() and dest.stat().st_size > 0:
            return

    # Python urllib fallback — always available
    _print("  (using Python urllib fallback — no progress bar)")

    def _urllib_dl() -> None:
        req = urllib.request.Request(
            url, headers={"User-Agent": "shieldbot-installer/1.0"}
        )
        with urllib.request.urlopen(req, timeout=300) as resp, open(dest, "wb") as fh:
            while chunk := resp.read(65536):
                fh.write(chunk)

    await asyncio.get_event_loop().run_in_executor(None, _urllib_dl)

    if not dest.exists() or dest.stat().st_size == 0:
        raise RuntimeError(f"Download failed: {url}")
    _print(f"  {dest.stat().st_size // 1024:,} KB")


# ---------------------------------------------------------------------------
# CodeQL installer
# ---------------------------------------------------------------------------

def _codeql_asset_name(os_name: str, arch: str) -> str:
    """
    Asset names at github/codeql-cli-binaries:
      codeql-linux64.zip       — Linux x86_64
      codeql-linux-arm64.zip   — Linux arm64
      codeql-osx64.zip         — macOS (universal binary)
    """
    if os_name == "linux" and arch == "arm64":
        return "codeql-linux-arm64.zip"
    if os_name == "linux":
        return "codeql-linux64.zip"
    return "codeql-osx64.zip"   # macOS universal


async def install_codeql(force: bool = False) -> Path:
    """
    Install the CodeQL CLI to ~/.local/share/shieldbot/codeql/.
    Returns the path to the `codeql` binary.
    Skips if already installed (pass force=True to reinstall).
    """
    _ensure_bin_dir_on_path()
    install_root = SHIELDBOT_HOME / "codeql"
    binary_path  = install_root / "codeql"
    symlink_path = BIN_DIR / "codeql"

    if not force and binary_path.exists():
        if not symlink_path.exists():
            symlink_path.symlink_to(binary_path)
        _print(f"CodeQL already installed at {binary_path}")
        return binary_path

    os_name, arch = _detect_platform()
    tag        = _github_latest_tag(_CODEQL_REPO)
    asset_name = _codeql_asset_name(os_name, arch)
    url        = _github_asset_url(_CODEQL_REPO, tag, asset_name)

    _print(f"Installing CodeQL {tag} for {os_name}/{arch}")

    with tempfile.TemporaryDirectory(prefix="shieldbot_codeql_dl_") as tmp:
        zip_path = Path(tmp) / asset_name
        await _download_file(url, zip_path, f"CodeQL {tag}")

        _print("Extracting ...")
        if install_root.exists():
            shutil.rmtree(install_root)
        install_root.parent.mkdir(parents=True, exist_ok=True)

        with zipfile.ZipFile(zip_path) as zf:
            zf.extractall(install_root.parent)

        # Archive extracts to a `codeql/` directory
        extracted = install_root.parent / "codeql"
        if extracted != install_root and extracted.exists():
            if install_root.exists():
                shutil.rmtree(install_root)
            extracted.rename(install_root)

    if not binary_path.exists():
        raise RuntimeError(f"CodeQL binary not found at {binary_path} after extraction.")

    binary_path.chmod(binary_path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP)

    if symlink_path.exists() or symlink_path.is_symlink():
        symlink_path.unlink()
    symlink_path.symlink_to(binary_path)

    _print(f"CodeQL {tag} installed → {binary_path}")
    return binary_path


async def ensure_codeql() -> Optional[Path]:
    """Return the codeql binary path, installing it if missing."""
    if p := shutil.which("codeql"):
        return Path(p)
    try:
        return await install_codeql()
    except Exception as exc:  # noqa: BLE001
        _print(f"WARNING: Could not auto-install CodeQL: {exc}")
        return None


# ---------------------------------------------------------------------------
# osv-scanner installer
# ---------------------------------------------------------------------------

def _osv_asset_name(os_name: str, arch: str) -> str:
    """
    Asset names at google/osv-scanner:
      osv-scanner_linux_amd64
      osv-scanner_linux_arm64
      osv-scanner_darwin_amd64
      osv-scanner_darwin_arm64
    """
    os_key   = "darwin" if os_name == "macos" else "linux"
    arch_key = "arm64"  if arch == "arm64"    else "amd64"
    return f"osv-scanner_{os_key}_{arch_key}"


async def install_osv_scanner(force: bool = False) -> Path:
    """
    Install osv-scanner to ~/.local/bin/osv-scanner.
    Skips if already installed (pass force=True to reinstall).
    """
    _ensure_bin_dir_on_path()
    binary_path = BIN_DIR / "osv-scanner"

    if not force and binary_path.exists():
        _print(f"osv-scanner already installed at {binary_path}")
        return binary_path

    os_name, arch = _detect_platform()
    tag        = _github_latest_tag(_OSVSCANNER_REPO)
    asset_name = _osv_asset_name(os_name, arch)
    url        = _github_asset_url(_OSVSCANNER_REPO, tag, asset_name)

    _print(f"Installing osv-scanner {tag} for {os_name}/{arch}")

    with tempfile.TemporaryDirectory(prefix="shieldbot_osv_dl_") as tmp:
        bin_tmp = Path(tmp) / "osv-scanner"
        await _download_file(url, bin_tmp, f"osv-scanner {tag}")
        shutil.copy2(bin_tmp, binary_path)

    binary_path.chmod(
        binary_path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
    )
    _print(f"osv-scanner {tag} installed → {binary_path}")
    return binary_path


async def ensure_osv_scanner() -> Optional[Path]:
    """Return the osv-scanner binary path, installing it if missing."""
    if p := shutil.which("osv-scanner"):
        return Path(p)
    try:
        return await install_osv_scanner()
    except Exception as exc:  # noqa: BLE001
        _print(f"WARNING: Could not auto-install osv-scanner: {exc}")
        return None


# ---------------------------------------------------------------------------
# Dependabot CLI installer
# ---------------------------------------------------------------------------

def _dependabot_asset_name(tag: str, os_name: str, arch: str) -> str:
    """
    Asset names at dependabot/cli (confirmed from GitHub releases API):
      dependabot-v{tag}-darwin-amd64.tar.gz
      dependabot-v{tag}-darwin-arm64.tar.gz
      dependabot-v{tag}-linux-amd64.tar.gz
      dependabot-v{tag}-linux-arm64.tar.gz

    The tag includes the "v" prefix (e.g. "v1.85.0").
    """
    os_key   = "darwin" if os_name == "macos" else "linux"
    arch_key = "arm64"  if arch == "arm64"    else "amd64"
    return f"dependabot-{tag}-{os_key}-{arch_key}.tar.gz"


async def install_dependabot_cli(force: bool = False) -> Path:
    """
    Install the Dependabot CLI to ~/.local/bin/dependabot.
    Source: https://github.com/dependabot/cli/releases

    The binary is extracted from a tar.gz archive. No Docker is needed to
    install the binary itself; Docker is only needed at runtime when running
    `dependabot update` (which spins up ecosystem-specific updater containers).

    Skips if already installed (pass force=True to reinstall).
    """
    _ensure_bin_dir_on_path()
    binary_path = BIN_DIR / "dependabot"

    if not force and binary_path.exists():
        _print(f"Dependabot CLI already installed at {binary_path}")
        return binary_path

    os_name, arch = _detect_platform()
    tag        = _github_latest_tag(_DEPENDABOT_REPO)
    asset_name = _dependabot_asset_name(tag, os_name, arch)
    url        = _github_asset_url(_DEPENDABOT_REPO, tag, asset_name)

    _print(f"Installing Dependabot CLI {tag} for {os_name}/{arch}")

    with tempfile.TemporaryDirectory(prefix="shieldbot_dependabot_dl_") as tmp:
        tgz_path = Path(tmp) / asset_name
        await _download_file(url, tgz_path, f"Dependabot CLI {tag}")

        _print("Extracting ...")
        extract_dir = Path(tmp) / "extracted"
        extract_dir.mkdir()

        with tarfile.open(tgz_path, "r:gz") as tf:
            tf.extractall(extract_dir)

        # The archive contains a `dependabot` binary (may be at root or in a subdirectory)
        found_bin: Optional[Path] = None
        for candidate in sorted(extract_dir.rglob("dependabot")):
            if candidate.is_file():
                found_bin = candidate
                break

        if found_bin is None:
            raise RuntimeError(
                f"Could not find 'dependabot' binary inside {asset_name}. "
                "Archive layout may have changed — please report this."
            )

        shutil.copy2(found_bin, binary_path)

    binary_path.chmod(
        binary_path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
    )
    _print(f"Dependabot CLI {tag} installed → {binary_path}")
    return binary_path


async def ensure_dependabot_cli() -> Optional[Path]:
    """Return the dependabot binary path, installing it if missing."""
    if p := shutil.which("dependabot"):
        return Path(p)
    try:
        return await install_dependabot_cli()
    except Exception as exc:  # noqa: BLE001
        _print(f"WARNING: Could not auto-install Dependabot CLI: {exc}")
        return None


# ---------------------------------------------------------------------------
# Convenience: install / ensure all three tools at once
# ---------------------------------------------------------------------------

async def ensure_all_tools() -> dict[str, Optional[Path]]:
    """
    Install CodeQL, osv-scanner, and Dependabot CLI if missing.
    Runs all three installs in parallel. Returns a dict of paths (None on failure).
    """
    codeql_path, osv_path, dependabot_path = await asyncio.gather(
        ensure_codeql(),
        ensure_osv_scanner(),
        ensure_dependabot_cli(),
    )
    return {
        "codeql":      codeql_path,
        "osv-scanner": osv_path,
        "dependabot":  dependabot_path,
    }


# ---------------------------------------------------------------------------
# CLI entry point: `shieldbot-install`
# ---------------------------------------------------------------------------

def main() -> None:
    """
    Install CodeQL CLI, osv-scanner, and Dependabot CLI on the current system.

    Usage:
        shieldbot-install                      # install all three
        shieldbot-install --force              # reinstall even if already present
        shieldbot-install --codeql             # CodeQL only
        shieldbot-install --osv                # osv-scanner only
        shieldbot-install --dependabot         # Dependabot CLI only

    Installs to ~/.local/bin (no sudo required).
    Supports macOS (x86_64 / arm64) and Linux (x86_64 / arm64).
    """
    import argparse

    parser = argparse.ArgumentParser(
        prog="shieldbot-install",
        description=(
            "Install security scanning tools for shieldbot. "
            "Supports macOS + Linux (x86_64 / arm64). No sudo required."
        ),
    )
    parser.add_argument("--force",      action="store_true", help="Reinstall even if already present")
    parser.add_argument("--codeql",     action="store_true", help="Install CodeQL CLI only")
    parser.add_argument("--osv",        action="store_true", help="Install osv-scanner only")
    parser.add_argument("--dependabot", action="store_true", help="Install Dependabot CLI only")
    args = parser.parse_args()

    install_all = not args.codeql and not args.osv and not args.dependabot

    async def _run() -> None:
        tasks: list = []
        if args.codeql or install_all:
            tasks.append(("CodeQL",         install_codeql(force=args.force)))
        if args.osv or install_all:
            tasks.append(("osv-scanner",    install_osv_scanner(force=args.force)))
        if args.dependabot or install_all:
            tasks.append(("Dependabot CLI", install_dependabot_cli(force=args.force)))

        labels    = [t[0] for t in tasks]
        coroutines = [t[1] for t in tasks]
        results   = await asyncio.gather(*coroutines, return_exceptions=True)

        failed = False
        for label, result in zip(labels, results):
            if isinstance(result, Exception):
                print(f"[shieldbot-install] ERROR installing {label}: {result}", file=sys.stderr)
                failed = True
            else:
                print(f"[shieldbot-install] {label}: {result}", file=sys.stderr)

        if failed:
            sys.exit(1)

        print(
            f"\n[shieldbot-install] All done. Binaries installed to {BIN_DIR}\n\n"
            f"Add this to your shell profile (~/.bashrc, ~/.zshrc, etc.) if needed:\n"
            f'  export PATH="{BIN_DIR}:$PATH"',
            file=sys.stderr,
        )

    asyncio.run(_run())


if __name__ == "__main__":
    main()
