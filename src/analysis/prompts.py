"""Versioned, injection-protected prompt construction.

Prompt *text* lives in `config/prompts/<version>/` as plain-text
templates (not Python string literals), so prompt changes are visible as
ordinary diffs and a new version can be added without touching this
module — just a new directory plus bumping
`AnalysisConfig.prompt_version`. This module's job is assembling those
templates with the canonical JSON schema (`src.core.schemas`) and
sanitized, boundary-wrapped log content (`src.analysis.sanitizer`) —
never analyzing untrusted content itself, and never embedding untrusted
content anywhere except inside the sanitizer's boundary wrapper.
"""

from __future__ import annotations

import string
from dataclasses import dataclass
from pathlib import Path

from src.analysis.sanitizer import sanitize_for_prompt
from src.core.exceptions import ConfigurationError
from src.core.models import CrossLogContext, LogEntry
from src.core.schemas import render_prompt_schema_block
from src.utils.security import strip_control_characters, truncate

_PROMPTS_ROOT = Path(__file__).resolve().parent.parent.parent / "config" / "prompts"

DEFAULT_PROMPT_VERSION = "v1"
DEFAULT_MAX_LOG_ENTRY_LENGTH = 4000
DEFAULT_MAX_CROSS_LOG_CONTEXT_LENGTH = 2000
DEFAULT_MAX_KNOWLEDGE_CONTEXT_LENGTH = 3000

#: LogEntry attributes surfaced alongside the raw line in the evidence
#: block. Every value is defensively re-sanitized (see
#: `_build_evidence_text`) since these are themselves extracted from
#: untrusted content, not any safer than `raw_line` itself.
_STRUCTURED_FIELD_NAMES = (
    "host",
    "process",
    "source_ip",
    "dest_ip",
    "user",
    "http_method",
    "http_path",
    "http_status",
)


@dataclass
class BuiltPrompt:
    """A fully assembled prompt pair, ready to send to Ollama."""

    system: str
    user: str
    version: str
    injection_indicators: list[str]


def _load_template(version: str, filename: str) -> string.Template:
    path = _PROMPTS_ROOT / version / filename
    try:
        return string.Template(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ConfigurationError(f"Prompt template not found: {path}") from exc


def _build_evidence_text(entry: LogEntry) -> str:
    """Compose a compact, LLM-friendly summary of a LogEntry's parsed
    fields alongside its raw line, all defensively re-sanitized.

    Uses `field=value` formatting rather than `field: value` throughout —
    deliberately, not cosmetically: the sanitizer's own
    `fake_role_marker` heuristic looks for colon-style chat-role prefixes
    like `"user: <message>"`, and a naive `f"user: {value}"` here would
    make this module's *own* formatting trip its *own* injection
    detector on every entry with a `user` field, masking real positives
    under constant false ones. `=` sidesteps that collision entirely.
    """
    lines = [f"raw_line={strip_control_characters(entry.raw_line)}"]
    lines.append(f"format={entry.format.value}")
    if entry.timestamp is not None:
        lines.append(f"timestamp={entry.timestamp.isoformat()}")
    for name in _STRUCTURED_FIELD_NAMES:
        value = getattr(entry, name)
        if value is not None:
            lines.append(f"{name}={strip_control_characters(str(value))}")
    return "\n".join(lines)


def build_analysis_prompt(
    entry: LogEntry,
    *,
    version: str = DEFAULT_PROMPT_VERSION,
    cross_log_context: CrossLogContext | None = None,
    knowledge_context: str | None = None,
    max_log_length: int = DEFAULT_MAX_LOG_ENTRY_LENGTH,
) -> BuiltPrompt:
    """Build a system + user prompt pair for analyzing a single log entry.

    Args:
        entry: The log entry to analyze. Its raw line and relevant parsed
            fields are combined, sanitized, and boundary-wrapped as a
            single unit — see `src.analysis.sanitizer`.
        version: Prompt template version; must match a directory under
            `config/prompts/`.
        cross_log_context: Optional session-scoped correlation context
            (recurring IPs, timeline) included as background, not as the
            primary subject of analysis.
        knowledge_context: Optional retrieved RAG context (MITRE ATT&CK /
            Sigma / OWASP references) included as background reference
            material.
        max_log_length: Maximum sanitized evidence length in characters.

    Returns:
        A `BuiltPrompt` with the assembled system/user text and any
        injection indicators detected in the entry (for logging/metrics
        — see `src.analysis.sanitizer` for why this is a signal, not a
        filter).

    Raises:
        ConfigurationError: If the template files for `version` are
            missing.
    """
    evidence_text = _build_evidence_text(entry)
    sanitized = sanitize_for_prompt(evidence_text, max_length=max_log_length)

    system_template = _load_template(version, "system_prompt.txt")
    system = system_template.substitute(
        schema_block=render_prompt_schema_block(),
        boundary_open=sanitized.boundary_open,
        boundary_close=sanitized.boundary_close,
    )

    context_block = ""
    if cross_log_context is not None:
        summary = truncate(cross_log_context.summarize(), DEFAULT_MAX_CROSS_LOG_CONTEXT_LENGTH)
        context_block = (
            "\nCross-log correlation context (background only; the log evidence "
            f"below remains the primary subject of analysis):\n{summary}\n"
        )

    knowledge_block = ""
    if knowledge_context:
        truncated_knowledge = truncate(knowledge_context, DEFAULT_MAX_KNOWLEDGE_CONTEXT_LENGTH)
        knowledge_block = (
            "\nReference knowledge (MITRE ATT&CK / Sigma / OWASP context, "
            f"background only):\n{truncated_knowledge}\n"
        )

    user_template = _load_template(version, "user_template.txt")
    user = user_template.substitute(
        context_block=context_block,
        knowledge_block=knowledge_block,
        wrapped_log_data=sanitized.wrapped_text,
    )

    return BuiltPrompt(
        system=system,
        user=user,
        version=version,
        injection_indicators=sanitized.injection_indicators,
    )
