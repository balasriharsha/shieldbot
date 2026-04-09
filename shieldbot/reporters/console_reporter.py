"""Rich terminal reporter for shieldbot security reports."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

from shieldbot.models import Finding, SecurityReport, Severity

console = Console()

_SEVERITY_COLORS = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}

_RISK_LABEL_COLORS = {
    "Critical": "bold red",
    "High": "red",
    "Medium": "yellow",
    "Low": "cyan",
    "Clean": "bold green",
}


def print_report(report: SecurityReport) -> None:
    """Print a full security report to the terminal."""
    console.print()

    # ── Header ──────────────────────────────────────────────────────────
    console.print(Panel(
        f"[bold white]AUTOBOT SECURITY SCAN REPORT[/bold white]\n"
        f"Repo: [dim]{report.repo_path}[/dim]\n"
        f"Scanned: [dim]{report.scan_timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}[/dim]  "
        f"Duration: [dim]{report.scan_duration_seconds:.1f}s[/dim]",
        border_style="blue",
        expand=False,
    ))

    # ── Risk score banner ────────────────────────────────────────────────
    if report.claude_analysis:
        risk_color = _RISK_LABEL_COLORS.get(report.claude_analysis.risk_label, "white")
        score = report.claude_analysis.risk_score
        label = report.claude_analysis.risk_label
        console.print(f"\n[bold]RISK SCORE:[/bold] [{risk_color}]{score}/100  [{label.upper()}][/{risk_color}]\n")
    else:
        # Compute naive risk from finding counts
        crit = report.findings_by_severity.get("critical", 0)
        high = report.findings_by_severity.get("high", 0)
        if crit > 0:
            console.print("\n[bold red]RISK: CRITICAL findings present — immediate action required[/bold red]\n")
        elif high > 0:
            console.print("\n[bold red]RISK: HIGH findings detected[/bold red]\n")
        else:
            console.print("\n[bold yellow]RISK: Review findings below[/bold yellow]\n")

    # ── Scanner summary table ────────────────────────────────────────────
    table = Table(title="Scan Summary", box=box.ROUNDED, show_header=True, header_style="bold blue")
    table.add_column("Scanner", style="cyan")
    table.add_column("Critical", style="bold red", justify="right")
    table.add_column("High", style="red", justify="right")
    table.add_column("Medium", style="yellow", justify="right")
    table.add_column("Low", style="cyan", justify="right")
    table.add_column("Info", style="dim", justify="right")
    table.add_column("Status")

    for result in report.scan_results:
        # Count by severity for this scanner
        counts: dict[str, int] = {s.value: 0 for s in Severity}
        for f in result.findings:
            if not f.duplicate_of:
                counts[f.severity.value] += 1

        status = "[green]OK[/green]" if result.success else f"[red]ERROR[/red]"
        if result.error_message and not result.success:
            status = f"[red]{result.error_message[:40]}[/red]"

        table.add_row(
            result.scanner,
            str(counts["critical"]) if counts["critical"] else "-",
            str(counts["high"]) if counts["high"] else "-",
            str(counts["medium"]) if counts["medium"] else "-",
            str(counts["low"]) if counts["low"] else "-",
            str(counts["info"]) if counts["info"] else "-",
            status,
        )

    console.print(table)
    console.print()

    # ── Executive summary ────────────────────────────────────────────────
    if report.claude_analysis and report.claude_analysis.executive_summary:
        console.print(Panel(
            report.claude_analysis.executive_summary,
            title="[bold]Executive Summary (Claude Analysis)[/bold]",
            border_style="blue",
        ))
        console.print()

    # ── Findings ─────────────────────────────────────────────────────────
    sev_order = {
        Severity.CRITICAL: 0, Severity.HIGH: 1,
        Severity.MEDIUM: 2, Severity.LOW: 3, Severity.INFO: 4,
    }
    canonical = [f for f in report.all_findings if not f.duplicate_of]
    canonical.sort(key=lambda f: sev_order.get(f.severity, 9))

    if not canonical:
        console.print("[green]No findings.[/green]")
    else:
        console.print(f"[bold]Findings ({len(canonical)})[/bold]\n")
        for f in canonical:
            _print_finding(f, report)

    # ── Top remediations ─────────────────────────────────────────────────
    if report.claude_analysis and report.claude_analysis.top_remediations:
        console.print(Panel(
            _format_remediations(report.claude_analysis.top_remediations),
            title="[bold]Top Remediation Priorities (Claude)[/bold]",
            border_style="green",
        ))

    console.print()
    _print_footer(report)


def _print_finding(f: Finding, report: SecurityReport) -> None:
    color = _SEVERITY_COLORS.get(f.severity, "white")
    fp_note = " [dim](possible false positive)[/dim]" if f.is_false_positive else ""
    if (
        report.claude_analysis
        and f.id in report.claude_analysis.false_positive_ids
    ):
        fp_note = " [dim italic](Claude: likely false positive)[/dim italic]"

    title = f"[{color}][{f.severity.value.upper()}] {f.title}[/{color}]{fp_note}"

    body_lines = [
        f"[dim]Rule:[/dim]    {f.rule_id}",
        f"[dim]File:[/dim]    {f.file_path}:{f.line_start}",
        f"[dim]Scanner:[/dim] {f.scanner}",
    ]
    if f.cwe_id:
        body_lines.append(f"[dim]CWE:[/dim]    {f.cwe_id}")
    if f.owasp_category:
        body_lines.append(f"[dim]OWASP:[/dim]  {f.owasp_category}")
    if f.cve_id:
        body_lines.append(f"[dim]CVE:[/dim]    {f.cve_id}")
    if f.code_snippet:
        snippet = f.code_snippet.strip()[:300]
        body_lines.append(f"\n[dim]Code:[/dim]\n[dim]{snippet}[/dim]")
    if f.remediation:
        body_lines.append(f"\n[dim]Fix:[/dim]    {f.remediation[:300]}")

    console.print(Panel("\n".join(body_lines), title=title, border_style=color.replace("bold ", "")))


def _format_remediations(remediations: list) -> str:
    lines = []
    for i, rem in enumerate(remediations[:10], 1):
        effort = rem.get("effort", "?")
        title = rem.get("title", "")
        steps = rem.get("steps", [])
        lines.append(f"{i}. [bold]{title}[/bold]  [dim](effort: {effort})[/dim]")
        for step in steps[:3]:
            lines.append(f"   • {step}")
    return "\n".join(lines)


def _print_footer(report: SecurityReport) -> None:
    total = report.total_findings
    crit = report.findings_by_severity.get("critical", 0)
    high = report.findings_by_severity.get("high", 0)
    med = report.findings_by_severity.get("medium", 0)
    low = report.findings_by_severity.get("low", 0)

    console.print(
        f"[dim]Total: {total} findings  |  "
        f"[bold red]Critical: {crit}[/bold red]  "
        f"[red]High: {high}[/red]  "
        f"[yellow]Medium: {med}[/yellow]  "
        f"[cyan]Low: {low}[/cyan][/dim]"
    )
    console.print()


def print_tool_check(tool_statuses: dict[str, tuple[bool, str]]) -> None:
    """Print tool availability check table."""
    table = Table(title="Scanner Tool Status", box=box.ROUNDED, header_style="bold blue")
    table.add_column("Tool")
    table.add_column("Status")
    table.add_column("Notes")

    for tool, (available, note) in tool_statuses.items():
        status = "[green]Available[/green]" if available else "[red]Not Found[/red]"
        table.add_row(tool, status, note)

    console.print(table)
