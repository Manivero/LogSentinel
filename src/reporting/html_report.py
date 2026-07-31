"""Self-contained, interactive HTML report generator.

Single-file output: all CSS and JS are inline, and nothing references an
external CDN, font, or script — this report may be opened on a machine
with no internet access, and a broken external reference would be a
poor experience for exactly the "100% local & offline" audience this
tool is built for.

Every finding is rendered server-side with `data-*` attributes; the
inline JS only ever toggles `display` based on the active severity/
search filters rather than re-rendering from a JSON blob, keeping the
generation code and the runtime behavior easy to reason about together.
"""

from __future__ import annotations

import html as html_lib

from src.core.models import AnalysisRecord, AnalysisReport, DetectionMatch, Severity

_SEVERITY_COLORS = {
    Severity.CRITICAL: "#dc2626",
    Severity.HIGH: "#ea580c",
    Severity.MEDIUM: "#ca8a04",
    Severity.LOW: "#2563eb",
    Severity.INFO: "#6b7280",
}

_STYLE = """
:root {
  --bg: #0f1115; --panel: #161922; --panel-2: #1d212c; --border: #2a2f3a;
  --text: #e5e7eb; --text-dim: #9ca3af; --accent: #3b82f6;
}
* { box-sizing: border-box; }
body {
  margin: 0; background: var(--bg); color: var(--text);
  font: 15px/1.55 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
}
header {
  padding: 28px 32px; background: var(--panel); border-bottom: 1px solid var(--border);
  position: sticky; top: 0; z-index: 10;
}
header h1 { margin: 0 0 6px; font-size: 22px; }
header .meta { color: var(--text-dim); font-size: 13px; }
main { max-width: 1100px; margin: 0 auto; padding: 24px 32px 64px; }
.stat-grid {
  display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
  gap: 12px; margin: 20px 0 28px;
}
.stat-card {
  background: var(--panel); border: 1px solid var(--border); border-radius: 10px;
  padding: 14px 16px;
}
.stat-card .value { font-size: 24px; font-weight: 700; }
.stat-card .label { color: var(--text-dim); font-size: 12px; text-transform: uppercase; letter-spacing: .04em; }
section { margin-bottom: 36px; }
section > h2 {
  font-size: 16px; text-transform: uppercase; letter-spacing: .05em; color: var(--text-dim);
  border-bottom: 1px solid var(--border); padding-bottom: 8px; margin-bottom: 16px;
}
.filter-bar {
  display: flex; flex-wrap: wrap; gap: 14px; align-items: center;
  background: var(--panel); border: 1px solid var(--border); border-radius: 10px;
  padding: 14px 16px; margin-bottom: 20px; position: sticky; top: 92px; z-index: 9;
}
.filter-bar label { display: flex; align-items: center; gap: 6px; font-size: 13px; cursor: pointer; }
.filter-bar input[type="search"] {
  flex: 1; min-width: 200px; background: var(--panel-2); border: 1px solid var(--border);
  border-radius: 6px; padding: 8px 10px; color: var(--text); font-size: 13px;
}
#result-count { color: var(--text-dim); font-size: 13px; margin-left: auto; }
.badge {
  display: inline-block; padding: 2px 9px; border-radius: 999px; font-size: 11px;
  font-weight: 700; letter-spacing: .03em; color: #0f1115;
}
.card {
  background: var(--panel); border: 1px solid var(--border); border-left: 4px solid var(--sev-color, var(--border));
  border-radius: 8px; padding: 16px 18px; margin-bottom: 12px;
}
.card .card-head { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; margin-bottom: 8px; }
.card .card-title { font-weight: 600; }
.card .card-meta { color: var(--text-dim); font-size: 12px; }
.card .card-body { color: var(--text); }
.card .card-body p { margin: 6px 0; }
.card .field-label { color: var(--text-dim); font-size: 12px; text-transform: uppercase; letter-spacing: .03em; }
.card code { background: var(--panel-2); padding: 1px 6px; border-radius: 4px; font-size: 13px; }
.card ul { margin: 4px 0; padding-left: 20px; }
table { width: 100%; border-collapse: collapse; font-size: 13px; }
th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid var(--border); }
th { color: var(--text-dim); font-weight: 600; text-transform: uppercase; font-size: 11px; }
.empty-note { color: var(--text-dim); font-style: italic; }
"""

_SCRIPT = """
(function () {
  var severityBoxes = Array.prototype.slice.call(document.querySelectorAll('.sev-filter'));
  var searchBox = document.getElementById('search-box');
  var cards = Array.prototype.slice.call(document.querySelectorAll('.card[data-severity]'));
  var counter = document.getElementById('result-count');

  function apply() {
    var activeSeverities = severityBoxes.filter(function (b) { return b.checked; })
      .map(function (b) { return b.value; });
    var query = (searchBox.value || '').toLowerCase().trim();
    var visible = 0;
    cards.forEach(function (card) {
      var severityOk = activeSeverities.indexOf(card.getAttribute('data-severity')) !== -1;
      var searchOk = !query || (card.getAttribute('data-search') || '').indexOf(query) !== -1;
      var show = severityOk && searchOk;
      card.style.display = show ? '' : 'none';
      if (show) { visible += 1; }
    });
    if (counter) { counter.textContent = 'Showing ' + visible + ' of ' + cards.length; }
  }

  severityBoxes.forEach(function (b) { b.addEventListener('change', apply); });
  if (searchBox) { searchBox.addEventListener('input', apply); }
  apply();
})();
"""


def _esc(value: object) -> str:
    return html_lib.escape(str(value), quote=True)


def _badge(severity: Severity) -> str:
    color = _SEVERITY_COLORS[severity]
    return f'<span class="badge" style="background:{color}">{_esc(severity.value)}</span>'


def _stat_card(value: object, label: str) -> str:
    return f'<div class="stat-card"><div class="value">{_esc(value)}</div><div class="label">{_esc(label)}</div></div>'


def _filter_bar() -> str:
    checkboxes = "\n".join(
        f'<label><input type="checkbox" class="sev-filter" value="{s.value}" checked> {_badge(s)}</label>'
        for s in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO)
    )
    return f"""
    <div class="filter-bar">
      {checkboxes}
      <input type="search" id="search-box" placeholder="Search IP, user, rule, text...">
      <span id="result-count"></span>
    </div>
    """


def _detection_card(match: DetectionMatch) -> str:
    entry = match.log_entry
    search_terms = " ".join(
        str(v).lower()
        for v in (
            match.rule_id,
            match.rule_name,
            match.category,
            entry.source_ip,
            entry.user,
            entry.host,
            entry.process,
            entry.message,
        )
        if v
    )
    return f"""
    <div class="card" data-severity="{match.severity.value}" data-search="{_esc(search_terms)}"
         style="--sev-color:{_SEVERITY_COLORS[match.severity]}">
      <div class="card-head">
        {_badge(match.severity)}
        <span class="card-title">{_esc(match.rule_name)}</span>
        <span class="card-meta">{_esc(match.rule_id)} &middot; {_esc(match.category)}</span>
      </div>
      <div class="card-body">
        <p>{_esc(match.description)}</p>
        <p><span class="field-label">Source:</span>
           <code>{_esc(entry.source_ip or entry.host or "-")}</code>
           {f" &middot; user <code>{_esc(entry.user)}</code>" if entry.user else ""}
           &middot; <code>{_esc(entry.source_file)}:{entry.line_number}</code></p>
        {f'<p><span class="field-label">MITRE:</span> {_esc(match.mitre_technique)}</p>' if match.mitre_technique else ""}
        {f'<p><span class="field-label">Detail:</span> {_esc(match.matched_pattern)}</p>' if match.matched_pattern else ""}
      </div>
    </div>
    """


def _ai_analysis_card(record: AnalysisRecord) -> str:
    result = record.result
    entry = record.log_entry
    search_terms = " ".join(
        str(v).lower()
        for v in (
            result.attack_type,
            result.summary,
            result.detailed_analysis,
            entry.source_ip if entry else None,
            entry.user if entry else None,
            entry.host if entry else None,
            entry.process if entry else None,
        )
        if v
    )
    location = f"{_esc(entry.source_file)}:{entry.line_number}" if entry else "-"
    recs = "".join(f"<li>{_esc(r)}</li>" for r in result.recommendations)
    degraded_note = (
        '<p class="empty-note">\u26a0\ufe0f Degraded result \u2014 automated analysis was inconclusive.</p>'
        if record.degraded
        else ""
    )
    return f"""
    <div class="card" data-severity="{result.severity.value}" data-search="{_esc(search_terms)}"
         style="--sev-color:{_SEVERITY_COLORS[result.severity]}">
      <div class="card-head">
        {_badge(result.severity)}
        <span class="card-title">{_esc(result.attack_type)}</span>
        <span class="card-meta">{location} &middot; confidence {result.confidence:.0%}</span>
      </div>
      <div class="card-body">
        {degraded_note}
        <p>{_esc(result.summary)}</p>
        <p><span class="field-label">Detailed analysis:</span> {_esc(result.detailed_analysis)}</p>
        <p><span class="field-label">Attacker behavior:</span> {_esc(result.attacker_behavior)}</p>
        {f'<p><span class="field-label">MITRE:</span> {_esc(", ".join(result.mitre_tactics))}</p>' if result.mitre_tactics else ""}
        {f'<p><span class="field-label">Recommendations:</span></p><ul>{recs}</ul>' if recs else ""}
        <p class="card-meta">Model: <code>{_esc(record.model_name)}</code>
           &middot; From cache: {record.from_cache}</p>
      </div>
    </div>
    """


def _context_section(report: AnalysisReport) -> str:
    context = report.cross_log_context
    if context is None or context.total_entries == 0:
        return "<section><h2>Cross-Log Context</h2><p class='empty-note'>No cross-log context available for this run.</p></section>"

    rows = ""
    top_ips = sorted(context.ip_activity.values(), key=lambda a: a.event_count, reverse=True)[:15]
    for activity in top_ips:
        categories = ", ".join(activity.detection_categories) or "-"
        rows += (
            f"<tr><td><code>{_esc(activity.ip)}</code></td><td>{activity.event_count}</td>"
            f"<td>{len(activity.source_files)}</td><td>{_esc(categories)}</td></tr>"
        )
    recurring = ", ".join(f"<code>{_esc(ip)}</code>" for ip in context.recurring_ips) or "none"
    return f"""
    <section>
      <h2>Cross-Log Context</h2>
      <p>Analyzed <strong>{context.total_entries}</strong> entries across
         <strong>{context.total_files}</strong> file(s). Recurring IPs: {recurring}</p>
      <table>
        <thead><tr><th>IP</th><th>Events</th><th>Files</th><th>Detection Categories</th></tr></thead>
        <tbody>{rows}</tbody>
      </table>
    </section>
    """


def _metrics_section(report: AnalysisReport) -> str:
    metrics = report.metrics
    if metrics is None:
        return "<section><h2>Performance Metrics</h2><p class='empty-note'>No performance metrics recorded for this run.</p></section>"
    return f"""
    <section>
      <h2>Performance Metrics</h2>
      <div class="stat-grid">
        {_stat_card(metrics.parsing.files_parsed, "Files Parsed")}
        {_stat_card(f"{metrics.parsing.lines_per_second:.0f}/s", "Parse Speed")}
        {_stat_card(metrics.detection.events_detected, "Events Detected")}
        {_stat_card(metrics.ai.requests_made, "AI Requests")}
        {_stat_card(f"{metrics.ai.cache_hit_rate:.0%}", "Cache Hit Rate")}
        {_stat_card(f"{metrics.total_wall_time_seconds:.1f}s", "Total Time")}
      </div>
    </section>
    """


def render(report: AnalysisReport) -> str:
    """Render `report` as a single self-contained HTML document."""
    detection_cards = "".join(_detection_card(m) for m in report.detections) or (
        "<p class='empty-note'>No rule-based detections in this run.</p>"
    )
    ai_cards = "".join(_ai_analysis_card(r) for r in report.ai_analyses) or (
        "<p class='empty-note'>No AI analyses in this run.</p>"
    )
    action_note = "\u26a0\ufe0f Yes" if report.requires_immediate_action else "No"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AI Log Analyzer Report - {_esc(report.report_id[:8])}</title>
<style>{_STYLE}</style>
</head>
<body>
<header>
  <h1>AI Log Analyzer Report</h1>
  <div class="meta">
    Generated {_esc(report.generated_at.isoformat())} &middot;
    Tool v{_esc(report.tool_version)} &middot;
    Model <code>{_esc(report.model_used)}</code>
  </div>
</header>
<main>
  <div class="stat-grid">
    {_stat_card(report.highest_severity.value, "Highest Severity")}
    {_stat_card(len(report.files_analyzed), "Files Analyzed")}
    {_stat_card(len(report.detections), "Detections")}
    {_stat_card(len(report.ai_analyses), "AI Analyses")}
    {_stat_card(action_note, "Immediate Action")}
  </div>

  <section>
    <h2>Findings</h2>
    {_filter_bar()}
    {detection_cards}
    {ai_cards}
  </section>

  {_context_section(report)}
  {_metrics_section(report)}
</main>
<script>{_SCRIPT}</script>
</body>
</html>
"""
