"""Prompt injection protection.

Every log entry is untrusted, potentially adversary-controlled input.
This module is the layer between raw log content and an LLM prompt, and
implements defense in depth:

1. Reuse `utils.security.strip_control_characters` (terminal/ANSI
   defense) as a baseline — cheap insurance even though parsing already
   applies it, since this is the last point before untrusted content
   reaches a prompt.
2. Length-cap the content so no single entry can consume the whole
   context window or balloon request cost.
3. Neutralize any substring that could collide with our own boundary
   delimiters, so content can't "escape" its data wrapper by forging a
   closing tag.
4. Wrap the result in a boundary pair using a fresh random nonce per
   call, so even a wrapper-escape attempt can't predict the exact tag to
   forge (see `secrets.token_hex`).
5. Heuristically flag (never silently rewrite) common injection
   phrasings, so the *detection* itself becomes a useful signal — an
   entry that looks like it's trying to manipulate an automated analyzer
   is itself a security-relevant observation worth surfacing, not just
   something to defend against.

The wrapping + explicit system-prompt instruction (see `prompts.py`) is
the primary defense; heuristic pattern detection is a secondary signal
for logging and analyst awareness, not a content filter — there is no
way to enumerate every possible injection phrasing, so this module never
pretends detection alone is a complete defense.
"""

from __future__ import annotations

import re
import secrets
from dataclasses import dataclass

from src.utils.security import strip_control_characters, truncate

DEFAULT_MAX_LENGTH = 4000

# Matches our own boundary delimiter shape (with or without a token, with
# or without the closing "END_" prefix), so any occurrence *inside*
# untrusted content — regardless of whether the attacker knows the exact
# per-request nonce — is neutralized before wrapping.
_BOUNDARY_COLLISION_RE = re.compile(
    r"<<<\s*/?\s*(?:END_)?LOG_DATA[_A-Za-z0-9]*\s*>>>", re.IGNORECASE
)

# Practical, non-exhaustive heuristic signals for common prompt-injection
# phrasings. Deliberately not exhaustive — enumerating every known
# jailbreak phrasing is not a solvable problem, and false confidence in a
# pattern list is worse than an honest "this is a secondary signal, not a
# filter." Named so a match is loggable/reportable without needing to
# reproduce the matched text itself.
_INJECTION_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "ignore_instructions",
        re.compile(
            r"ignore\s+(all\s+)?(previous|prior|above|preceding)\s+instructions?", re.IGNORECASE
        ),
    ),
    (
        "role_override",
        re.compile(
            r"\byou\s+are\s+now\s+(in\s+)?(a\s+)?(developer|admin|unrestricted|jailbreak)\s*mode\b",
            re.IGNORECASE,
        ),
    ),
    ("fake_role_marker", re.compile(r"(?:^|\n)\s*(system|assistant|user)\s*:\s", re.IGNORECASE)),
    ("chatml_marker", re.compile(r"<\|im_(start|end)\|>", re.IGNORECASE)),
    ("fake_system_tag", re.compile(r"</?system>", re.IGNORECASE)),
    (
        "instruction_override_claim",
        re.compile(
            r"new\s+instructions?\s+from\s+(the\s+)?(admin|developer|system)", re.IGNORECASE
        ),
    ),
    (
        "reveal_prompt_request",
        re.compile(r"(reveal|output|print|show)\s+(your\s+)?(system\s+)?prompt", re.IGNORECASE),
    ),
    (
        "forget_identity",
        re.compile(r"forget\s+(you\s+are|your\s+instructions|everything\s+above)", re.IGNORECASE),
    ),
    (
        "markdown_instruction_header",
        re.compile(r"^#{1,6}\s*(system|instructions?|admin)\b", re.IGNORECASE | re.MULTILINE),
    ),
)


@dataclass
class SanitizationResult:
    """Output of `sanitize_for_prompt`: sanitized content, ready to embed."""

    original_length: int
    sanitized_text: str
    was_truncated: bool
    injection_indicators: list[str]
    boundary_token: str
    wrapped_text: str

    @property
    def boundary_open(self) -> str:
        return f"<<<LOG_DATA_{self.boundary_token}>>>"

    @property
    def boundary_close(self) -> str:
        return f"<<<END_LOG_DATA_{self.boundary_token}>>>"


def detect_injection_indicators(text: str) -> list[str]:
    """Return the names of heuristic injection patterns found in `text`.

    An empty list means no *known* pattern matched — not that the
    content is safe; absence of evidence is not evidence of absence, and
    this list is a secondary signal, never the primary defense (see
    module docstring).
    """
    return [name for name, pattern in _INJECTION_PATTERNS if pattern.search(text)]


def neutralize_boundary_collisions(text: str) -> str:
    """Strip any substring that could be mistaken for our boundary delimiters."""
    return _BOUNDARY_COLLISION_RE.sub("[delimiter-like sequence removed]", text)


def sanitize_for_prompt(text: str, *, max_length: int = DEFAULT_MAX_LENGTH) -> SanitizationResult:
    """Prepare untrusted text for safe inclusion in an LLM prompt.

    Applies, in order: control-character/ANSI stripping, length capping,
    injection-pattern detection (on the cleaned text, before
    neutralization, so pattern names reflect what was actually present),
    boundary-collision neutralization, and random-nonce boundary
    wrapping.
    """
    original_length = len(text)
    cleaned = strip_control_characters(text)
    was_truncated = len(cleaned) > max_length
    cleaned = truncate(cleaned, max_length)

    indicators = detect_injection_indicators(cleaned)
    neutralized = neutralize_boundary_collisions(cleaned)

    token = secrets.token_hex(8)
    result = SanitizationResult(
        original_length=original_length,
        sanitized_text=neutralized,
        was_truncated=was_truncated,
        injection_indicators=indicators,
        boundary_token=token,
        wrapped_text="",  # filled in below, once boundary_open/close are available
    )
    result.wrapped_text = f"{result.boundary_open}\n{neutralized}\n{result.boundary_close}"
    return result
