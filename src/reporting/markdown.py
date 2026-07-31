"""Markdown report generator: readable, with a table of contents, severity
badges, and collapsible finding details.

Uses plain text/emoji badges rather than external shields.io images —
this report may well be read on a machine with no internet access, and a
badge that fails to load defeats the point of a badge. Collapsible
sections use GitHub-flavored `<details>`/`<summary>`, which is standard
Markdown-adjacent HTML supported by GitHub, GitLab, and most modern
renderers, degrading harmlessly to plain visible text in renderers that
don't support it.
"""

from __future__ import annotations

from src.core.models import AnalysisRecord, AnalysisReport, DetectionMatch, Severity

_SEVERITY_EMOJI = {
    Severity.CRITICAL: "\U0001f534",  # red circle
    Severity.HIGH: "\U0001f7e0",  # orange circle
    Severity.MEDIUM: "\U0001f7e1",  # yellow circle
    Severity.LOW: "\U0001f535",  # blue circle
    Severity.INFO: "\u26aa",  # white circle
}


def _badge(severity: Severity) -> str:
    return f"{_SEVERITY_EMOJI[severity]} **{severity.value}**"


def _render_header(report: AnalysisReport) -> list[str]:
    action_note = "\u26a0\ufe0f Yes" if report.requires_immediate_action else "No"
    return [
        "# AI Log Analyzer Report",
        "",
        f"**Generated:** {report.generated_at.isoformat()} &nbsp;|&nbsp; "
        f"**Tool version:** {report.tool_version} &nbsp;|&nbsp; "
        f"**Model:** `{report.model_used}`",
        "",
        f"**Highest severity:** {_badge(report.highest_severity)} &nbsp;|&nbsp; "
        f"**Files analyzed:** {len(report.files_analyzed)} &nbsp;|&nbsp; "
        f"**Detections:** {len(report.detections)} &nbsp;|&nbsp; "
        f"**AI analyses:** {len(report.ai_analyses)} &nbsp;|&nbsp; "
        f"**Immediate action required:** {action_note}",
        "",
    ]


def _render_toc() -> list[str]:
    return [
        "## Table of Contents",
        "",
        "- [Executive Summary](#executive-summary)",
        "- [Detection Findings](#detection-findings)",
        "- [AI Analysis](#ai-analysis)",
        "- [Cross-Log Context](#cross-log-context)",
        "- [Performance Metrics](#performance-metrics)",
        "",
    ]


def _render_summary(report: AnalysisReport) -> list[str]:
    lines = ["## Executive Summary", "", "**Files analyzed:**"]
    lines.extend(f"- `{f}`" for f in report.files_analyzed)
    lines.append("")

    by_severity: dict[Severity, int] = {}
    for match in report.detections:
        by_severity[match.severity] = by_severity.get(match.severity, 0) + 1
    for record in report.ai_analyses:
        by_severity[record.result.severity] = by_severity.get(record.result.severity, 0) + 1

    if by_severity:
        lines.append("**Findings by severity:**")
        lines.append("")
        lines.append("| Severity | Count |")
        lines.append("|---|---|")
        ordered = (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO)
        for severity in ordered:
            count = by_severity.get(severity, 0)
            if count:
                lines.append(f"| {_badge(severity)} | {count} |")
        lines.append("")
    return lines


def _render_detections(detections: list[DetectionMatch]) -> list[str]:
    lines = ["## Detection Findings", ""]
    if not detections:
        lines.extend(["_No rule-based detections in this run._", ""])
        return lines

    lines.append("| Severity | Rule | Category | Source | Description |")
    lines.append("|---|---|---|---|---|")
    for match in detections:
        source = match.log_entry.source_ip or match.log_entry.host or "-"
        description = match.description.replace("\n", " ").replace("|", "\\|")
        lines.append(
            f"| {_badge(match.severity)} | `{match.rule_id}` {match.rule_name} | "
            f"{match.category} | `{source}` | {description} |"
        )
    lines.append("")
    return lines


def _render_ai_analyses(analyses: list[AnalysisRecord]) -> list[str]:
    lines = ["## AI Analysis", ""]
    if not analyses:
        lines.extend(["_No AI analyses in this run._", ""])
        return lines

    for record in analyses:
        result = record.result
        location = ""
        if record.log_entry is not None:
            location = f" ({record.log_entry.source_file}:{record.log_entry.line_number})"
        degraded_note = ""
        if record.degraded:
            degraded_note = " \u26a0\ufe0f _degraded \u2014 automated analysis was inconclusive_"
        lines.append(
            f"<details>\n<summary>{_badge(result.severity)} \u2014 "
            f"<strong>{result.attack_type}</strong>{location}{degraded_note}</summary>\n"
        )
        lines.append(f"**Summary:** {result.summary}\n")
        lines.append(f"**Detailed Analysis:** {result.detailed_analysis}\n")
        lines.append(f"**Attacker Behavior:** {result.attacker_behavior}\n")
        if result.mitre_tactics:
            lines.append(f"**MITRE Tactics/Techniques:** {', '.join(result.mitre_tactics)}\n")
        if result.recommendations:
            lines.append("**Recommendations:**")
            lines.extend(f"- {rec}" for rec in result.recommendations)
            lines.append("")
        lines.append(f"**Confidence:** {result.confidence:.0%}")
        lines.append(
            f"**Model:** `{record.model_name}` &nbsp;|&nbsp; **From cache:** {record.from_cache}"
        )
        lines.append("\n</details>\n")
    return lines


def _render_context(report: AnalysisReport) -> list[str]:
    lines = ["## Cross-Log Context", ""]
    context = report.cross_log_context
    if context is None or context.total_entries == 0:
        lines.extend(["_No cross-log context available for this run._", ""])
        return lines

    lines.append(
        f"Analyzed **{context.total_entries}** entries across **{context.total_files}** file(s)."
    )
    lines.append("")
    if context.recurring_ips:
        lines.append("**IPs recurring across multiple sources:**")
        lines.extend(f"- `{ip}`" for ip in context.recurring_ips)
        lines.append("")
    top_ips = sorted(context.ip_activity.values(), key=lambda a: a.event_count, reverse=True)[:10]
    if top_ips:
        lines.append("| IP | Events | Files | Detection Categories |")
        lines.append("|---|---|---|---|")
        for activity in top_ips:
            categories = ", ".join(activity.detection_categories) or "-"
            lines.append(
                f"| `{activity.ip}` | {activity.event_count} | "
                f"{len(activity.source_files)} | {categories} |"
            )
        lines.append("")
    return lines


def _render_metrics(report: AnalysisReport) -> list[str]:
    lines = ["## Performance Metrics", ""]
    metrics = report.metrics
    if metrics is None:
        lines.extend(["_No performance metrics recorded for this run._", ""])
        return lines

    lines.append("| Stage | Metric | Value |")
    lines.append("|---|---|---|")
    lines.append(f"| Parsing | Files parsed | {metrics.parsing.files_parsed} |")
    lines.append(f"| Parsing | Lines/sec | {metrics.parsing.lines_per_second:.1f} |")
    lines.append(f"| Detection | Events detected | {metrics.detection.events_detected} |")
    lines.append(f"| Detection | Rules evaluated | {metrics.detection.rules_evaluated} |")
    lines.append(f"| AI Analysis | Requests made | {metrics.ai.requests_made} |")
    lines.append(f"| AI Analysis | Cache hit rate | {metrics.ai.cache_hit_rate:.0%} |")
    lines.append(f"| AI Analysis | Tokens/sec | {metrics.ai.tokens_per_second:.1f} |")
    lines.append(f"| Total | Wall clock time | {metrics.total_wall_time_seconds:.2f}s |")
    lines.append("")
    return lines


def render(report: AnalysisReport) -> str:
    """Render `report` as a complete Markdown document."""
    lines: list[str] = []
    lines.extend(_render_header(report))
    lines.extend(_render_toc())
    lines.extend(_render_summary(report))
    lines.extend(_render_detections(report.detections))
    lines.extend(_render_ai_analyses(report.ai_analyses))
    lines.extend(_render_context(report))
    lines.extend(_render_metrics(report))
    return "\n".join(lines)
