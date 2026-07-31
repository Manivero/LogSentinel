"""General-purpose security utilities.

These are content-agnostic defensive helpers used across the codebase:
stripping terminal/control-character injection, validating IP-like
strings, and providing a safe subprocess wrapper. LLM-prompt-specific
defenses (injection-pattern detection, data-marker wrapping) live in
`src.analysis.sanitizer`, which builds on top of
`strip_control_characters` from this module rather than duplicating it.
"""

from __future__ import annotations

import ipaddress
import re
import subprocess
from collections.abc import Sequence

# Matches ANSI/VT100 escape sequences (color codes, cursor movement, OSC
# sequences, etc.) that could otherwise manipulate a terminal when log
# content is rendered by a human-facing tool such as Rich.
_ANSI_ESCAPE_RE = re.compile(
    r"\x1b\[[0-9;?]*[a-zA-Z]"  # CSI sequences, e.g. cursor movement / colors
    r"|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)"  # OSC sequences (terminated by BEL or ST)
    r"|\x1b[@-_]"  # other two-character escape sequences
)

# C0/C1 control characters except common whitespace (\t \n \r).
_CONTROL_CHAR_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\x80-\x9f]")


def strip_control_characters(text: str) -> str:
    """Remove ANSI escape sequences and non-printable control characters.

    Defends against terminal/log injection where log content contains
    escape sequences designed to manipulate a terminal (cursor movement,
    fake prompts, hidden text) when rendered by a human-facing tool.
    Tabs, newlines, and carriage returns are preserved.
    """
    without_ansi = _ANSI_ESCAPE_RE.sub("", text)
    return _CONTROL_CHAR_RE.sub("", without_ansi)


def truncate(text: str, max_length: int, *, suffix: str = "...[truncated]") -> str:
    """Truncate `text` to `max_length`, appending `suffix` if truncated."""
    if len(text) <= max_length:
        return text
    cut = max(0, max_length - len(suffix))
    return text[:cut] + suffix


def is_valid_ip(value: str) -> bool:
    """Return True if `value` parses as a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def run_subprocess_safely(
    args: Sequence[str],
    *,
    timeout_seconds: float = 30.0,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    """Run an external command safely.

    Always invoked with an argument list and `shell=False`, eliminating
    shell-injection risk; never accepts a single command string. Intended
    only for trusted, developer-specified commands (e.g. probing for the
    `ollama` binary) — never with log content anywhere in `args`.

    Raises:
        TypeError: If `args` is a single string instead of a sequence.
        subprocess.TimeoutExpired: If the command exceeds `timeout_seconds`.
        subprocess.CalledProcessError: If `check=True` and the command
            exits non-zero.
    """
    if isinstance(args, str):  # defensive: reject accidental shell-string usage
        raise TypeError("args must be a sequence of strings, not a single string")
    return subprocess.run(  # noqa: S603 - args is a list, shell is never used
        list(args),
        shell=False,
        capture_output=True,
        text=True,
        timeout=timeout_seconds,
        check=check,
    )
