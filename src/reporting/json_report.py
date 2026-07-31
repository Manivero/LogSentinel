"""SIEM-compatible JSON report export.

Defines `build_siem_events`, the single source of truth for how an
`AnalysisReport`'s detections and AI analyses flatten into individual
events — field names are CEF/LEEF-inspired (`src`, `dst`, `spt`, `dpt`,
`suser`, `shost`, `rt`, `cat`, `msg`) so downstream SIEM ingestion
(Splunk, ELK, Wazuh) can map them with minimal configuration, without
this actually being CEF/LEEF wire format (which is a specific single-line
syslog encoding this project has no reason to also implement).
`csv_report.py` reuses this exact function so both formats describe the
same events identically rather than maintaining two field mappings.
"""

from __future__ import annotations

import json
from typing import Any

from src.core.models import AnalysisRecord, AnalysisReport, DetectionMatch, LogEntry


def _log_entry_fields(entry: LogEntry | None) -> dict[str, Any]:
    """Fields shared by every event, sourced from the underlying LogEntry."""
    if entry is None:
        return {
            "rt": None,
            "src": None,
            "dst": None,
            "spt": None,
            "dpt": None,
            "suser": None,
            "shost": None,
            "request": None,
            "requestMethod": None,
            "fname": None,
            "raw_log": None,
        }
    return {
        "rt": entry.timestamp.isoformat() if entry.timestamp else None,
        "src": entry.source_ip,
        "dst": entry.dest_ip,
        "spt": entry.source_port,
        "dpt": entry.dest_port,
        "suser": entry.user,
        "shost": entry.host,
        "request": entry.http_path,
        "requestMethod": entry.http_method,
        "fname": entry.source_file,
        "raw_log": entry.raw_line,
    }


def _detection_event(match: DetectionMatch) -> dict[str, Any]:
    return {
        "event_id": match.match_id,
        "source_type": "detection",
        "severity": match.severity.cvss_scale,
        "severity_label": match.severity.value,
        "cat": match.category,
        "signature_id": match.rule_id,
        "name": match.rule_name,
        "msg": match.description,
        "mitre_technique": match.mitre_technique,
        "tags": match.tags,
        **_log_entry_fields(match.log_entry),
    }


def _ai_analysis_event(record: AnalysisRecord) -> dict[str, Any]:
    result = record.result
    return {
        "event_id": record.analysis_id,
        "source_type": "ai_analysis",
        "severity": result.severity.cvss_scale,
        "severity_label": result.severity.value,
        "cat": "ai_analysis",
        "signature_id": None,
        "name": result.attack_type,
        "msg": result.summary,
        "detailed_analysis": result.detailed_analysis,
        "attacker_behavior": result.attacker_behavior,
        "mitre_technique": ", ".join(result.mitre_tactics) if result.mitre_tactics else None,
        "recommendations": result.recommendations,
        "confidence": result.confidence,
        "requires_immediate_action": result.requires_immediate_action,
        "model_used": record.model_name,
        "from_cache": record.from_cache,
        "degraded": record.degraded,
        "related_detection_ids": record.related_detection_ids,
        **_log_entry_fields(record.log_entry),
    }


def build_siem_events(report: AnalysisReport) -> list[dict[str, Any]]:
    """Flatten every detection and AI analysis in `report` into one event list.

    Events are ordered: all detections first (in their original order),
    then all AI analyses — mirroring the pipeline order they were
    produced in, not re-sorted by severity or time, so the export is
    deterministic and traceable back to the run that produced it.
    """
    events: list[dict[str, Any]] = [_detection_event(m) for m in report.detections]
    events.extend(_ai_analysis_event(r) for r in report.ai_analyses)
    return events


def build_siem_document(report: AnalysisReport) -> dict[str, Any]:
    """Build the full SIEM-compatible JSON document as a plain dict."""
    return {
        "report_id": report.report_id,
        "generated_at": report.generated_at.isoformat(),
        "tool": "ai-log-analyzer",
        "tool_version": report.tool_version,
        "model_used": report.model_used,
        "knowledge_base_used": report.knowledge_base_used,
        "summary": {
            "files_analyzed": report.files_analyzed,
            "total_detections": len(report.detections),
            "total_ai_analyses": len(report.ai_analyses),
            "highest_severity": report.highest_severity.value,
            "highest_severity_score": report.highest_severity.cvss_scale,
            "requires_immediate_action": report.requires_immediate_action,
        },
        "events": build_siem_events(report),
    }


def render(report: AnalysisReport) -> str:
    """Render `report` as a formatted JSON string, ready to write to a file."""
    return json.dumps(build_siem_document(report), indent=2, default=str)
