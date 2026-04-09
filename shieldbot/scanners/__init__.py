"""Scanner modules for shieldbot."""

from shieldbot.scanners.bandit_scanner import BanditScanner
from shieldbot.scanners.base import BaseScanner, deduplicate, run_all_parallel
from shieldbot.scanners.codeql_scanner import CodeQLScanner
from shieldbot.scanners.dependabot_scanner import DependabotScanner
from shieldbot.scanners.npm_audit_scanner import NpmAuditScanner
from shieldbot.scanners.pip_audit_scanner import PipAuditScanner
from shieldbot.scanners.ruff_scanner import RuffScanner
from shieldbot.scanners.secrets_scanner import SecretsScanner
from shieldbot.scanners.semgrep_scanner import SemgrepScanner
from shieldbot.scanners.trivy_scanner import TrivyScanner

__all__ = [
    "BaseScanner",
    "run_all_parallel",
    "deduplicate",
    "SemgrepScanner",
    "BanditScanner",
    "RuffScanner",
    "SecretsScanner",
    "PipAuditScanner",
    "NpmAuditScanner",
    "CodeQLScanner",
    "DependabotScanner",
    "TrivyScanner",
]
