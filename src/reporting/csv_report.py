"""Flat CSV report export for spreadsheet/SIEM import.

Reuses `json_report.build_siem_events` so the CSV describes the exact
same events, with the exact same field meanings, as the JSON export —
one source of truth for "what is an event" shared across both formats.
"""

from __future__ import annotations

import csv
import io

from src.core.models import AnalysisReport
from src.reporting.json_report import build_siem_events

# Fixed column order: spreadsheet/SIEM tools expect stable columns, not a
# variable set depending on which fields happen to be present on which
# event — list-valued fields (tags, recommendations) are joined with "; "
# since CSV cells can't hold structured data.
_COLUMNS = (
    "event_id",
    "source_type",
    "severity_label",
    "severity",
    "cat",
    "signature_id",
    "name",
    "msg",
    "mitre_technique",
    "confidence",
    "requires_immediate_action",
    "rt",
    "src",
    "dst",
    "spt",
    "dpt",
    "suser",
    "shost",
    "requestMethod",
    "request",
    "fname",
    "tags",
    "recommendations",
    "model_used",
    "from_cache",
    "degraded",
    "raw_log",
)

_LIST_FIELDS = {"tags", "recommendations"}


def render(report: AnalysisReport) -> str:
    """Render `report` as CSV text, ready to write to a file."""
    events = build_siem_events(report)
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=_COLUMNS, extrasaction="ignore")
    writer.writeheader()
    for event in events:
        row = dict(event)
        for field in _LIST_FIELDS:
            value = row.get(field)
            if isinstance(value, list):
                row[field] = "; ".join(str(v) for v in value)
        writer.writerow(row)
    return buffer.getvalue()
