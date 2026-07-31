"""Core Pydantic data models for AI Log Analyzer.

This module is the **single source of truth** for every structured data
shape used across the application: parsed log entries, detection results,
the canonical AI analysis response, cross-log correlation context, Ollama
metadata, knowledge-base records, performance metrics, and the final
aggregate report. Centralizing models here (rather than letting each
subsystem define its own) keeps JSON contracts consistent and makes
`Model.model_json_schema()` a reliable source of API/SIEM documentation.

All models are strict (`extra="forbid"`) unless explicitly noted, so typos
in constructed data fail fast during development rather than silently
dropping fields.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

__all__ = [
    "AIAnalysisResult",
    "AIMetrics",
    "AnalysisRecord",
    "AnalysisReport",
    "CacheStats",
    "CrossLogContext",
    "DetectionMatch",
    "DetectionMetrics",
    "DetectionRule",
    "IPActivity",
    "KnowledgeBaseStats",
    "KnowledgeChunk",
    "LogEntry",
    "LogFormat",
    "ModelInfo",
    "OllamaHealthStatus",
    "ParseResult",
    "ParsingMetrics",
    "PerformanceMetrics",
    "ReportingMetrics",
    "RetrievedContext",
    "RuleCondition",
    "Severity",
    "TimelineEvent",
]


def _utcnow() -> datetime:
    """Timezone-aware UTC now, used as a `default_factory` across models."""
    return datetime.now(UTC)


def _new_id() -> str:
    """Short unique identifier for correlating records within a run."""
    return uuid.uuid4().hex


# ============================================================================
# Enums
# ============================================================================


class Severity(StrEnum):
    """Normalized severity scale used across detection and AI analysis."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def rank(self) -> int:
        """Numeric rank for sorting; higher means more severe."""
        order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        return order.index(self)

    @property
    def cvss_scale(self) -> int:
        """Map to a 0-10 scale for SIEM/CEF/LEEF compatibility."""
        mapping = {
            Severity.CRITICAL: 10,
            Severity.HIGH: 8,
            Severity.MEDIUM: 5,
            Severity.LOW: 3,
            Severity.INFO: 0,
        }
        return mapping[self]

    @classmethod
    def from_score(cls, score: float) -> Severity:
        """Best-effort mapping from a 0-10 numeric score to a `Severity`."""
        if score >= 9:
            return cls.CRITICAL
        if score >= 7:
            return cls.HIGH
        if score >= 4:
            return cls.MEDIUM
        if score >= 1:
            return cls.LOW
        return cls.INFO


class LogFormat(StrEnum):
    """Recognized log formats. GENERIC/UNKNOWN cover the fallback parser."""

    SYSLOG = "syslog"
    AUTH_LOG = "auth_log"
    APACHE_COMMON = "apache_common"
    APACHE_COMBINED = "apache_combined"
    NGINX_ACCESS = "nginx_access"
    NGINX_ERROR = "nginx_error"
    JSON_LINES = "json_lines"
    CSV = "csv"
    WINDOWS_EVENT = "windows_event"
    GENERIC = "generic"
    UNKNOWN = "unknown"


# ============================================================================
# Log parsing models
# ============================================================================


class LogEntry(BaseModel):
    """A single normalized log record produced by a parser.

    Parsers are responsible for sanitizing `raw_line`/`message` (stripping
    control characters, enforcing length limits) *before* constructing this
    model — see `src.utils.security`. This model enforces structural
    constraints (types, ranges, a defensive global string-length cap) but
    does not itself decide what counts as "malicious" content.
    """

    model_config = ConfigDict(extra="forbid", str_max_length=32768)

    raw_line: str = Field(..., description="Original raw log line (post-sanitization).")
    line_number: int = Field(..., ge=1)
    source_file: str = Field(..., description="Path or identifier of the originating file.")
    format: LogFormat = LogFormat.UNKNOWN
    timestamp: datetime | None = None
    host: str | None = None
    process: str | None = None
    pid: int | None = Field(default=None, ge=0)
    source_ip: str | None = None
    dest_ip: str | None = None
    source_port: int | None = Field(default=None, ge=0, le=65535)
    dest_port: int | None = Field(default=None, ge=0, le=65535)
    user: str | None = None
    http_method: str | None = None
    http_path: str | None = None
    http_status: int | None = Field(default=None, ge=100, le=599)
    message: str = Field(..., description="The parsed/human-readable message body.")
    fields: dict[str, Any] = Field(
        default_factory=dict, description="Parser-specific structured extras."
    )

    @field_validator("source_ip", "dest_ip", "host", "process", "user")
    @classmethod
    def _blank_to_none(cls, v: str | None) -> str | None:
        if v is None:
            return None
        stripped = v.strip()
        return stripped or None


class ParseResult(BaseModel):
    """Outcome of parsing a single log file."""

    model_config = ConfigDict(extra="forbid")

    source_file: str
    detected_format: LogFormat
    parser_name: str
    confidence: float = Field(ge=0.0, le=1.0)
    entries: list[LogEntry] = Field(default_factory=list)
    total_lines: int = Field(ge=0)
    parsed_lines: int = Field(ge=0)
    skipped_lines: int = Field(ge=0)
    parse_duration_seconds: float = Field(ge=0.0)
    warnings: list[str] = Field(default_factory=list)


# ============================================================================
# Detection models (rule-based, non-AI)
# ============================================================================


class RuleCondition(BaseModel):
    """A single field-match condition within a `DetectionRule`.

    `field` addresses either a top-level `LogEntry` attribute directly
    (e.g. `"message"`, `"user"`, `"http_status"`) or a key inside
    `LogEntry.fields` via a `"fields.xxx"` dotted prefix (e.g.
    `"fields.auth_result"`). Evaluated by `src.detection.engine`.
    """

    model_config = ConfigDict(extra="forbid")

    field: str
    operator: Literal[
        "equals",
        "contains",
        "not_contains",
        "in",
        "regex",
        "exists",
        "not_exists",
        "gt",
        "gte",
        "lt",
        "lte",
    ]
    value: Any = None
    case_sensitive: bool = False


class DetectionRule(BaseModel):
    """A single data-driven detection rule, loaded from YAML.

    Two shapes in one model, distinguished by whether `threshold_count`
    is set:

    - **Simple rule** (`threshold_count is None`): fires once per log
      entry whose conditions match, combined via `condition_logic`.
    - **Threshold rule** (`threshold_count` set): fires once a group of
      matching entries — grouped by `threshold_group_by` (e.g.
      `source_ip`) — reaches `threshold_count` occurrences within
      `threshold_window_seconds`. Expresses rate-based patterns like
      brute-force login attempts or port scans without any bespoke
      Python per rule.
    """

    model_config = ConfigDict(extra="forbid")

    id: str
    name: str
    category: str
    severity: Severity
    description: str
    conditions: list[RuleCondition] = Field(default_factory=list)
    condition_logic: Literal["AND", "OR"] = "AND"
    mitre_technique: str | None = None
    tags: list[str] = Field(default_factory=list)
    enabled: bool = True
    threshold_count: int | None = Field(default=None, ge=2)
    threshold_window_seconds: int | None = Field(default=None, gt=0)
    threshold_group_by: str | None = None

    @field_validator("name", "category", "description")
    @classmethod
    def _strip_whitespace(cls, v: str) -> str:
        # YAML ">" folded block scalars (used for readable multi-line
        # descriptions in the bundled rule files) leave a trailing
        # newline; stripping here fixes it once for every consumer
        # (reporting, prompts, CLI output) rather than patching each one.
        return v.strip()

    @model_validator(mode="after")
    def _validate_threshold_pairing(self) -> DetectionRule:
        has_count = self.threshold_count is not None
        has_window = self.threshold_window_seconds is not None
        if has_count != has_window:
            raise ValueError(
                f"Rule '{self.id}': threshold_count and threshold_window_seconds "
                "must both be set together, or both omitted."
            )
        return self


class DetectionMatch(BaseModel):
    """A single rule-based detection against one log entry."""

    model_config = ConfigDict(extra="forbid")

    match_id: str = Field(default_factory=_new_id)
    rule_id: str
    rule_name: str
    category: str
    severity: Severity
    description: str
    log_entry: LogEntry
    matched_pattern: str | None = None
    mitre_technique: str | None = None
    tags: list[str] = Field(default_factory=list)
    detected_at: datetime = Field(default_factory=_utcnow)


# ============================================================================
# AI analysis models
# ============================================================================


class AIAnalysisResult(BaseModel):
    """Canonical JSON contract the LLM must produce for each analysis.

    This is the single source of truth for the AI response *shape* (see
    `src.core.schemas` for version metadata and prompt-ready rendering).
    Field constraints here are enforced during JSON repair/validation in
    `src.analysis.repair`, which is expected to coerce raw model output
    (e.g. truncate an over-long `recommendations` list) *before*
    constructing this model, since Pydantic will reject violations rather
    than silently truncate them.
    """

    model_config = ConfigDict(extra="forbid")

    severity: Severity
    attack_type: str = Field(..., min_length=1, max_length=200)
    summary: str = Field(..., min_length=1, max_length=500)
    detailed_analysis: str = Field(..., min_length=1, max_length=2000)
    attacker_behavior: str = Field(..., min_length=1, max_length=1000)
    mitre_tactics: list[str] = Field(default_factory=list, max_length=25)
    recommendations: list[str] = Field(default_factory=list, max_length=5)
    confidence: float = Field(..., ge=0.0, le=1.0)
    requires_immediate_action: bool

    @field_validator("mitre_tactics", "recommendations")
    @classmethod
    def _strip_and_drop_empty(cls, v: list[str]) -> list[str]:
        return [item.strip() for item in v if item and item.strip()]


class AnalysisRecord(BaseModel):
    """An `AIAnalysisResult` plus execution metadata for reporting/metrics."""

    model_config = ConfigDict(extra="forbid")

    analysis_id: str = Field(default_factory=_new_id)
    result: AIAnalysisResult
    log_entry: LogEntry | None = None
    related_detection_ids: list[str] = Field(default_factory=list)
    model_name: str
    prompt_version: str
    schema_version: str
    generated_at: datetime = Field(default_factory=_utcnow)
    latency_ms: float = Field(ge=0.0)
    from_cache: bool = False
    degraded: bool = Field(
        default=False,
        description="True if this record is a fallback produced after repair/retry failure.",
    )
    knowledge_context_used: bool = False
    prompt_tokens: int | None = None
    completion_tokens: int | None = None


# ============================================================================
# Cross-log context / correlation models
# ============================================================================


class TimelineEvent(BaseModel):
    """One entry in a cross-file correlated timeline."""

    model_config = ConfigDict(extra="forbid")

    timestamp: datetime | None
    source_file: str
    description: str
    severity: Severity
    ip: str | None = None


class IPActivity(BaseModel):
    """Aggregated activity for a single IP address across all analyzed files."""

    model_config = ConfigDict(extra="forbid")

    ip: str
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    event_count: int = 0
    source_files: list[str] = Field(default_factory=list)
    associated_users: list[str] = Field(default_factory=list)
    detection_categories: list[str] = Field(default_factory=list)


class CrossLogContext(BaseModel):
    """Session-scoped correlation built across all files in a single run.

    Exists only in memory for the duration of one CLI invocation — see
    ADR-0001 for the stateless-between-runs rationale. Never persisted
    unless the AI response cache stores derived analyses.
    """

    model_config = ConfigDict(extra="forbid")

    total_files: int = 0
    total_entries: int = 0
    ip_activity: dict[str, IPActivity] = Field(default_factory=dict)
    timeline: list[TimelineEvent] = Field(default_factory=list)
    recurring_ips: list[str] = Field(
        default_factory=list, description="IPs seen across 2+ source files."
    )

    def summarize(self, *, max_ips: int = 10, max_timeline: int = 20) -> str:
        """Render a compact textual summary suitable for prompt injection.

        Kept intentionally simple (plain text, no markup) since this text
        is embedded directly into LLM prompts alongside untrusted log
        content — see `src.analysis.sanitizer` for how that boundary is
        enforced.
        """
        lines: list[str] = [
            f"Files analyzed: {self.total_files}, total log entries: {self.total_entries}."
        ]
        if self.recurring_ips:
            lines.append(
                "IPs recurring across multiple sources: " + ", ".join(self.recurring_ips[:max_ips])
            )
        top_ips = sorted(self.ip_activity.values(), key=lambda a: a.event_count, reverse=True)
        for activity in top_ips[:max_ips]:
            detail = (
                f"- {activity.ip}: {activity.event_count} events across "
                f"{len(activity.source_files)} file(s)"
            )
            if activity.associated_users:
                detail += f", users: {', '.join(activity.associated_users[:5])}"
            lines.append(detail)
        if self.timeline:
            lines.append("Recent correlated timeline:")
            for event in self.timeline[-max_timeline:]:
                ts = event.timestamp.isoformat() if event.timestamp else "unknown-time"
                lines.append(f"  [{ts}] ({event.severity.value}) {event.description}")
        return "\n".join(lines)


# ============================================================================
# Ollama / model management models
# ============================================================================


class ModelInfo(BaseModel):
    """Metadata about a locally installed Ollama model (from `/api/tags`)."""

    model_config = ConfigDict(extra="allow")  # Ollama may add fields over time

    name: str
    size_bytes: int | None = None
    digest: str | None = None
    modified_at: datetime | None = None
    family: str | None = None
    parameter_size: str | None = None
    quantization_level: str | None = None

    @property
    def is_embedding_model(self) -> bool:
        """Heuristic: embedding models commonly include 'embed' in their name."""
        return "embed" in self.name.lower()


class OllamaHealthStatus(BaseModel):
    """Result of probing the local Ollama installation and server."""

    model_config = ConfigDict(extra="forbid")

    installed: bool = Field(
        description="Whether the `ollama` binary was found on PATH (diagnostic only)."
    )
    server_running: bool = Field(description="Whether the HTTP API responded successfully.")
    base_url: str
    version: str | None = None
    models: list[ModelInfo] = Field(default_factory=list)
    embedding_models: list[ModelInfo] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    checked_at: datetime = Field(default_factory=_utcnow)

    @property
    def is_healthy(self) -> bool:
        """Whether the application can use Ollama right now.

        Only requires the HTTP API to be reachable — the `ollama` binary
        itself may be absent from this environment (e.g. Ollama running in
        a separate Docker container) while the server is still fully usable.
        """
        return self.server_running and not self.errors


# ============================================================================
# Knowledge base (RAG) models
# ============================================================================


class KnowledgeChunk(BaseModel):
    """A chunk of source knowledge text prepared for embedding/indexing."""

    model_config = ConfigDict(extra="forbid")

    chunk_id: str = Field(default_factory=_new_id)
    source: str = Field(..., description="Origin identifier, e.g. 'mitre_attack:T1110'.")
    text: str = Field(..., max_length=8000)
    metadata: dict[str, Any] = Field(default_factory=dict)


class RetrievedContext(BaseModel):
    """A knowledge chunk retrieved for a specific query, with a similarity score."""

    model_config = ConfigDict(extra="forbid")

    chunk: KnowledgeChunk
    score: float = Field(ge=0.0, le=1.0)


class KnowledgeBaseStats(BaseModel):
    """Summary statistics for `knowledge-stats` CLI output."""

    model_config = ConfigDict(extra="forbid")

    enabled: bool
    total_documents: int = 0
    total_chunks: int = 0
    sources: dict[str, int] = Field(default_factory=dict)
    embedding_model: str | None = None
    persist_directory: str | None = None
    last_indexed_at: datetime | None = None


# ============================================================================
# Performance metrics models
# ============================================================================


class ParsingMetrics(BaseModel):
    model_config = ConfigDict(extra="forbid")

    files_parsed: int = 0
    total_lines: int = 0
    lines_per_second: float = 0.0
    duration_seconds: float = 0.0


class DetectionMetrics(BaseModel):
    model_config = ConfigDict(extra="forbid")

    events_detected: int = 0
    events_per_second: float = 0.0
    duration_seconds: float = 0.0
    rules_evaluated: int = 0


class AIMetrics(BaseModel):
    model_config = ConfigDict(extra="forbid")

    requests_made: int = 0
    cache_hits: int = 0
    cache_misses: int = 0
    tokens_generated: int = 0
    tokens_per_second: float = 0.0
    duration_seconds: float = 0.0
    retries: int = 0
    repairs_attempted: int = 0
    repairs_succeeded: int = 0
    degraded_results: int = 0

    @property
    def cache_hit_rate(self) -> float:
        total = self.cache_hits + self.cache_misses
        return (self.cache_hits / total) if total else 0.0


class ReportingMetrics(BaseModel):
    model_config = ConfigDict(extra="forbid")

    formats_generated: list[str] = Field(default_factory=list)
    duration_seconds: float = 0.0


class PerformanceMetrics(BaseModel):
    """Aggregate performance summary displayed at the end of every run."""

    model_config = ConfigDict(extra="forbid")

    parsing: ParsingMetrics = Field(default_factory=ParsingMetrics)
    detection: DetectionMetrics = Field(default_factory=DetectionMetrics)
    ai: AIMetrics = Field(default_factory=AIMetrics)
    reporting: ReportingMetrics = Field(default_factory=ReportingMetrics)
    total_wall_time_seconds: float = 0.0


class CacheStats(BaseModel):
    """Summary statistics for `cache-stats` CLI output."""

    model_config = ConfigDict(extra="forbid")

    enabled: bool
    directory: str
    entry_count: int = 0
    size_bytes: int = 0
    hits: int = 0
    misses: int = 0

    @property
    def hit_rate(self) -> float:
        total = self.hits + self.misses
        return (self.hits / total) if total else 0.0


# ============================================================================
# Aggregate report model
# ============================================================================


class AnalysisReport(BaseModel):
    """Top-level report combining every subsystem's output for one run.

    This is the object every `src.reporting.*` generator consumes to
    produce JSON/Markdown/HTML/CSV output.
    """

    model_config = ConfigDict(extra="forbid")

    report_id: str = Field(default_factory=_new_id)
    generated_at: datetime = Field(default_factory=_utcnow)
    tool_version: str
    model_used: str
    files_analyzed: list[str] = Field(default_factory=list)
    parse_results: list[ParseResult] = Field(default_factory=list)
    detections: list[DetectionMatch] = Field(default_factory=list)
    ai_analyses: list[AnalysisRecord] = Field(default_factory=list)
    cross_log_context: CrossLogContext | None = None
    metrics: PerformanceMetrics | None = None
    knowledge_base_used: bool = False

    @property
    def highest_severity(self) -> Severity:
        """Most severe finding across all AI analyses and detections, or INFO."""
        severities = [a.result.severity for a in self.ai_analyses] + [
            d.severity for d in self.detections
        ]
        return max(severities, key=lambda s: s.rank, default=Severity.INFO)

    @property
    def requires_immediate_action(self) -> bool:
        return any(a.result.requires_immediate_action for a in self.ai_analyses)
