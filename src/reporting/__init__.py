"""Report generation in multiple formats from a single `AnalysisReport`.

Depends on `src.core` and `src.utils` only — reporting is a pure
presentation layer over the models already populated by every earlier
stage of the pipeline (parsing, detection, analysis).

- `json_report.py` — SIEM-compatible JSON export; also defines
  `build_siem_events`, the shared CEF-inspired event-flattening logic
  reused by `csv_report.py` so both formats describe the same events the
  same way.
- `csv_report.py` — flat CSV for spreadsheet/SIEM import.
- `markdown.py` — a readable report with a table of contents, severity
  badges, and collapsible finding details.
- `html_report.py` — a self-contained, offline-friendly interactive HTML
  report (inline CSS/JS, no CDN dependencies, no external requests).
- `terminal.py` — live Rich console output for the default CLI
  experience (summary tables, the post-run performance metrics table).

No templating engine dependency (no Jinja2) — every format is built with
plain string composition, keeping the dependency surface minimal per the
project's security-first philosophy (see PROGRESS.md convention #13).
"""
