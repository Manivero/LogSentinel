"""Rich-based terminal output: the default CLI experience when no
`--output` is given, plus the post-run performance metrics summary table
every run displays regardless of output format.
"""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from src.core.models import AnalysisReport, PerformanceMetrics, Severity
from src.metrics.benchmark import BenchmarkResult

_SEVERITY_STYLE = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "bold yellow",
    Severity.LOW: "bold blue",
    Severity.INFO: "dim",
}


def _severity_text(severity: Severity) -> Text:
    return Text(severity.value, style=_SEVERITY_STYLE[severity])


def render_report(report: AnalysisReport, console: Console) -> None:
    """Print a human-readable summary of `report` to `console`."""
    action_note = "[bold red]YES[/bold red]" if report.requires_immediate_action else "No"
    header = (
        f"[bold]Model:[/bold] {report.model_used}   "
        f"[bold]Files:[/bold] {len(report.files_analyzed)}   "
        f"[bold]Detections:[/bold] {len(report.detections)}   "
        f"[bold]AI Analyses:[/bold] {len(report.ai_analyses)}   "
        f"[bold]Immediate action required:[/bold] {action_note}"
    )
    console.print(
        Panel(
            header,
            title=f"AI Log Analyzer Report \u2014 {report.highest_severity.value}",
            border_style=_SEVERITY_STYLE[report.highest_severity].split()[-1],
        )
    )

    if report.detections:
        table = Table(title="Detection Findings", show_lines=False)
        table.add_column("Severity")
        table.add_column("Rule")
        table.add_column("Category")
        table.add_column("Source")
        table.add_column("Description", overflow="fold")
        for match in report.detections:
            source = match.log_entry.source_ip or match.log_entry.host or "-"
            table.add_row(
                _severity_text(match.severity),
                f"{match.rule_id}\n{match.rule_name}",
                match.category,
                source,
                match.description,
            )
        console.print(table)
    else:
        console.print("[dim]No rule-based detections in this run.[/dim]")

    if report.ai_analyses:
        table = Table(title="AI Analysis", show_lines=True)
        table.add_column("Severity")
        table.add_column("Attack Type")
        table.add_column("Location")
        table.add_column("Summary", overflow="fold")
        table.add_column("Confidence")
        for record in report.ai_analyses:
            result = record.result
            location = "-"
            if record.log_entry is not None:
                location = f"{record.log_entry.source_file}:{record.log_entry.line_number}"
            attack_type = result.attack_type
            if record.degraded:
                attack_type = f"\u26a0\ufe0f {attack_type} (degraded)"
            table.add_row(
                _severity_text(result.severity),
                attack_type,
                location,
                result.summary,
                f"{result.confidence:.0%}",
            )
        console.print(table)
    else:
        console.print("[dim]No AI analyses in this run.[/dim]")

    context = report.cross_log_context
    if context is not None and context.recurring_ips:
        console.print(
            f"[bold]Recurring IPs across files:[/bold] {', '.join(context.recurring_ips)}"
        )


def render_metrics(metrics: PerformanceMetrics, console: Console) -> None:
    """Print the post-run performance metrics summary table.

    Required by the CLI after every analysis run regardless of which
    export formats were requested — this is terminal-only output, never
    written to a report file.
    """
    table = Table(title="Performance Metrics")
    table.add_column("Stage")
    table.add_column("Metric")
    table.add_column("Value", justify="right")

    table.add_row("Parsing", "Files parsed", str(metrics.parsing.files_parsed))
    table.add_row("Parsing", "Total lines", str(metrics.parsing.total_lines))
    table.add_row("Parsing", "Lines/sec", f"{metrics.parsing.lines_per_second:.1f}")
    table.add_row("Parsing", "Duration", f"{metrics.parsing.duration_seconds:.2f}s")

    table.add_row("Detection", "Events detected", str(metrics.detection.events_detected))
    table.add_row("Detection", "Rules evaluated", str(metrics.detection.rules_evaluated))
    table.add_row("Detection", "Events/sec", f"{metrics.detection.events_per_second:.1f}")
    table.add_row("Detection", "Duration", f"{metrics.detection.duration_seconds:.2f}s")

    table.add_row("AI Analysis", "Requests made", str(metrics.ai.requests_made))
    table.add_row("AI Analysis", "Cache hit rate", f"{metrics.ai.cache_hit_rate:.0%}")
    table.add_row("AI Analysis", "Tokens generated", str(metrics.ai.tokens_generated))
    table.add_row("AI Analysis", "Tokens/sec", f"{metrics.ai.tokens_per_second:.1f}")
    table.add_row("AI Analysis", "Degraded results", str(metrics.ai.degraded_results))
    table.add_row("AI Analysis", "Duration", f"{metrics.ai.duration_seconds:.2f}s")

    if metrics.reporting.formats_generated:
        table.add_row(
            "Reporting", "Formats generated", ", ".join(metrics.reporting.formats_generated)
        )
        table.add_row("Reporting", "Duration", f"{metrics.reporting.duration_seconds:.2f}s")

    table.add_row(
        "Total", "Wall clock time", f"{metrics.total_wall_time_seconds:.2f}s", style="bold"
    )

    console.print(table)


def render_benchmark(result: BenchmarkResult, console: Console) -> None:
    """Print aggregate timing statistics from a `--benchmark` run."""
    table = Table(title="Benchmark Results")
    table.add_column("Statistic")
    table.add_column("Value", justify="right")
    table.add_row("Label", result.label)
    table.add_row("Iterations", str(result.iterations))
    table.add_row("Min", f"{result.min_seconds:.3f}s")
    table.add_row("Max", f"{result.max_seconds:.3f}s")
    table.add_row("Mean", f"{result.mean_seconds:.3f}s")
    table.add_row("Median", f"{result.median_seconds:.3f}s")
    table.add_row("Std Dev", f"{result.stdev_seconds:.3f}s")
    console.print(table)
