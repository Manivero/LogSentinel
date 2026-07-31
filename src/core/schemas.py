"""Canonical AI response schema: the JSON contract between the LLM and the
rest of the application.

`AIAnalysisResult` (in `src.core.models`) is the single source of truth for
the *shape* of a valid AI response. This module is the single source of
truth for everything *about* that shape: its semantic version, a
prompt-ready textual description, a canonical worked example, and helpers
for exporting the strict JSON Schema (e.g. for documentation or SIEM
contract publishing).

Bump `AI_RESPONSE_SCHEMA_VERSION` whenever `AIAnalysisResult`'s fields,
types, or constraints change in a way that could affect prompts or cached
results, and bump the prompt version in lockstep (see ADR-0004) — cache
keys are derived from the prompt version, not this schema version, so the
two must be kept in sync by convention rather than by code.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Final

from src.core.models import AIAnalysisResult

AI_RESPONSE_SCHEMA_VERSION: Final[str] = "1.0.0"

CANONICAL_RESPONSE_EXAMPLE: Final[dict[str, Any]] = {
    "severity": "HIGH",
    "attack_type": "Brute Force Authentication Attempt",
    "summary": (
        "Repeated failed SSH logins from a single external IP targeting the "
        "root account within a short time window."
    ),
    "detailed_analysis": (
        "The evidence shows twelve consecutive authentication failures for "
        "user 'root' originating from IP 203.0.113.5 within roughly ninety "
        "seconds. The uniform timing and targeting of a privileged account "
        "name are consistent with an automated credential-guessing tool "
        "rather than a human operator mistyping a password."
    ),
    "attacker_behavior": (
        "Automated, systematic credential guessing against a privileged "
        "account, with no successful authentication observed in the "
        "provided evidence."
    ),
    "mitre_tactics": ["TA0006", "T1110"],
    "recommendations": [
        "Block or rate-limit source IP 203.0.113.5 at the perimeter firewall.",
        "Disable password-based SSH authentication in favor of key-based auth.",
        "Deploy fail2ban or an equivalent adaptive rate limiter on SSH.",
        "Confirm the root account cannot authenticate remotely.",
    ],
    "confidence": 0.87,
    "requires_immediate_action": True,
}

PROMPT_SCHEMA_DESCRIPTION: Final[str] = """\
Respond with a single JSON object and NOTHING else (no markdown fences, no \
prose before or after). The object must contain EXACTLY these fields:

  "severity": one of "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO"
  "attack_type": short string naming the attack or activity type
  "summary": string, at most 500 characters
  "detailed_analysis": string, at most 2000 characters
  "attacker_behavior": string, at most 1000 characters
  "mitre_tactics": array of MITRE ATT&CK tactic/technique IDs, may be empty
  "recommendations": array of up to 5 short, actionable strings
  "confidence": number between 0.0 and 1.0
  "requires_immediate_action": boolean
"""


def get_ai_response_json_schema() -> dict[str, Any]:
    """Return the strict, pydantic-generated JSON Schema for `AIAnalysisResult`."""
    return AIAnalysisResult.model_json_schema()


def get_ai_response_json_schema_str(*, indent: int = 2) -> str:
    """Return the JSON Schema as a formatted string (docs, `--help`, exports)."""
    return json.dumps(get_ai_response_json_schema(), indent=indent, sort_keys=False)


def render_prompt_schema_block() -> str:
    """Render a compact schema description plus a worked example for LLM prompts.

    A full JSON Schema document (with `$defs`/titles/etc.) burns tokens and
    tends to confuse smaller local models, so prompts get this hand-tuned,
    compact rendering instead. Kept in sync with `AIAnalysisResult` by
    `validate_example_matches_schema`, which unit tests call directly.
    """
    example = json.dumps(CANONICAL_RESPONSE_EXAMPLE, indent=2)
    return f"{PROMPT_SCHEMA_DESCRIPTION}\nExample of a valid response:\n{example}"


def validate_example_matches_schema() -> AIAnalysisResult:
    """Validate that `CANONICAL_RESPONSE_EXAMPLE` satisfies `AIAnalysisResult`.

    Used by tests to catch schema drift: if a field is added, renamed, or
    constrained differently in `AIAnalysisResult`, this raises a
    `pydantic.ValidationError` until the example above is updated to match.
    """
    return AIAnalysisResult.model_validate(CANONICAL_RESPONSE_EXAMPLE)


def get_schema_fingerprint() -> str:
    """Stable short hash of the current schema, for diagnostics/logging.

    Not used in cache keys directly (cache keys use `prompt_version`, which
    should be bumped in lockstep with schema changes per ADR-0004) but
    useful for asserting the running schema matches an expected value, e.g.
    in a CI check that the schema hasn't silently drifted.
    """
    schema_json = json.dumps(get_ai_response_json_schema(), sort_keys=True)
    payload = f"{AI_RESPONSE_SCHEMA_VERSION}:{schema_json}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:12]
