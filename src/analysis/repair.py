"""JSON repair and schema validation for AI responses.

Local LLMs — especially smaller or quantized models — sometimes wrap JSON
in markdown code fences, leave a trailing comma, emit a stray sentence
before or after the object, or get a field's type slightly wrong (e.g.
`"confidence": 87` instead of `0.87`). This module attempts a series of
increasingly aggressive, purely mechanical repairs — never asking the
model to fix itself — and validates the result against the canonical
`AIAnalysisResult` schema.

Retrying the underlying AI request when repair fails entirely is
`src.analysis.ai_analyzer`'s responsibility, not this module's — a
function here only ever looks at one response string at a time and
either returns a valid result or raises.
"""

from __future__ import annotations

import json
import re
from typing import Any

from pydantic import ValidationError

from src.core.exceptions import JSONRepairError
from src.core.models import AIAnalysisResult, Severity
from src.utils.logger import get_logger

logger = get_logger("analysis.repair")

_CODE_FENCE_RE = re.compile(r"^```(?:json)?\s*|\s*```$", re.IGNORECASE | re.MULTILINE)
_TRAILING_COMMA_RE = re.compile(r",(\s*[}\]])")

_STRING_FIELD_LIMITS = {
    "attack_type": 200,
    "summary": 500,
    "detailed_analysis": 2000,
    "attacker_behavior": 1000,
}
_TRUNCATION_SUFFIX = "...[truncated]"


def _strip_code_fences(text: str) -> str:
    return _CODE_FENCE_RE.sub("", text).strip()


def _extract_json_object(text: str) -> str | None:
    """Extract the first balanced `{...}` block via brace matching.

    More robust than a naive `\\{.*\\}` regex: correctly ignores braces
    that appear inside quoted string values (e.g. a log message quoted
    inside the JSON that itself contains `{` or `}`) instead of matching
    too much or too little.
    """
    start = text.find("{")
    if start == -1:
        return None
    depth = 0
    in_string = False
    escape = False
    for i in range(start, len(text)):
        ch = text[i]
        if in_string:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[start : i + 1]
    return None


def _remove_trailing_commas(text: str) -> str:
    return _TRAILING_COMMA_RE.sub(r"\1", text)


def _coerce_to_schema_bounds(data: dict[str, Any]) -> dict[str, Any]:
    """Soft-repair common out-of-bounds shapes before strict validation.

    Truncates over-length strings/lists to their schema maximums (instead
    of letting Pydantic reject the *entire* response over one over-long
    field) and normalizes a couple of common model quirks: severity given
    in the wrong case, confidence given on a 0-100 scale instead of
    0.0-1.0.
    """
    coerced = dict(data)

    severity = coerced.get("severity")
    if isinstance(severity, str):
        coerced["severity"] = severity.strip().upper()

    confidence = coerced.get("confidence")
    if isinstance(confidence, int | float) and confidence > 1.0:
        coerced["confidence"] = min(1.0, confidence / 100.0)

    for field, limit in _STRING_FIELD_LIMITS.items():
        value = coerced.get(field)
        if isinstance(value, str) and len(value) > limit:
            cut = max(0, limit - len(_TRUNCATION_SUFFIX))
            coerced[field] = value[:cut] + _TRUNCATION_SUFFIX

    recommendations = coerced.get("recommendations")
    if isinstance(recommendations, list) and len(recommendations) > 5:
        coerced["recommendations"] = recommendations[:5]

    mitre_tactics = coerced.get("mitre_tactics")
    if isinstance(mitre_tactics, list) and len(mitre_tactics) > 25:
        coerced["mitre_tactics"] = mitre_tactics[:25]

    return coerced


def repair_and_validate(raw_response: str) -> AIAnalysisResult:
    """Attempt to parse and validate `raw_response` as an `AIAnalysisResult`.

    Tries, in order: direct parse, code-fence stripping, brace-matched
    object extraction, trailing-comma removal — revalidating after each
    step so the least invasive successful repair wins, and every
    candidate also goes through `_coerce_to_schema_bounds` before
    validation.

    Raises:
        JSONRepairError: If no combination of repairs produces a valid
            `AIAnalysisResult`. Callers (typically `ai_analyzer`) decide
            whether to retry the underlying AI request or fall back to a
            degraded result — this function never does either itself.
    """
    fenced_stripped = _strip_code_fences(raw_response)
    extracted = _extract_json_object(fenced_stripped)

    candidates: list[str] = [raw_response]
    if fenced_stripped != raw_response:
        candidates.append(fenced_stripped)
    if extracted:
        candidates.append(extracted)
        candidates.append(_remove_trailing_commas(extracted))

    last_error: BaseException | None = None
    for candidate in candidates:
        try:
            data = json.loads(candidate)
        except json.JSONDecodeError as exc:
            last_error = exc
            continue
        if not isinstance(data, dict):
            last_error = TypeError(f"Top-level JSON value is {type(data).__name__}, not an object")
            continue
        try:
            return AIAnalysisResult.model_validate(_coerce_to_schema_bounds(data))
        except ValidationError as exc:
            last_error = exc
            continue

    raise JSONRepairError(
        "Could not repair AI response into valid JSON matching the schema.",
        details={"error": str(last_error), "response_preview": raw_response[:200]},
    )


def build_degraded_result(*, reason: str, raw_response_preview: str = "") -> AIAnalysisResult:
    """Construct a safe, always-valid fallback result when repair and the
    caller's retry both fail.

    Downstream reporting never has to special-case a "missing" analysis
    this way — only a zero-confidence one that's honest about the
    failure and tells the analyst to look at the entry manually.
    """
    detail = f"Automated JSON repair failed: {reason}."
    if raw_response_preview:
        detail += f" Raw response preview: {raw_response_preview[:300]}"
    return AIAnalysisResult(
        severity=Severity.INFO,
        attack_type="Analysis Unavailable",
        summary=(
            "The AI model did not return a usable structured response for "
            "this entry after repair and retry."
        ),
        detailed_analysis=detail,
        attacker_behavior="Unknown - analysis could not be completed for this entry.",
        mitre_tactics=[],
        recommendations=["Review this log entry manually; automated analysis was inconclusive."],
        confidence=0.0,
        requires_immediate_action=False,
    )
