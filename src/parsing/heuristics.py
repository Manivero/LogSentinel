"""Format-detection heuristics shared across parsers and the fallback path.

These are pure pattern-matching helpers: given a sample of (already
sanitized/truncated) log lines, estimate how strongly they match a known
shape. Used both by built-in parsers to implement `detect_confidence` and
by the generic fallback parser to still extract *some* structure
(timestamp, IP addresses) from an otherwise-unrecognized format.

Security note: every regex here avoids nested/overlapping quantifiers (the
classic `(a+)+` shape) that cause catastrophic backtracking on adversarial
input. Combined with the line-length cap enforced upstream
(`SecurityConfig.max_line_length`, applied before any of these functions
ever see a line), this keeps regex evaluation time bounded even on
untrusted log content.
"""

from __future__ import annotations

import csv
import io
import json
import re
from datetime import UTC, datetime
from typing import Any

from src.utils.security import is_valid_ip

# --- Timestamp patterns -----------------------------------------------------

# RFC 3164 syslog: "Jul 26 10:00:00" (no year; year is inferred by convention)
_SYSLOG_TS_RE = re.compile(r"^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}")

# ISO 8601 / RFC 3339: "2026-01-15T10:00:00Z" or with offset/fractional seconds
_ISO8601_TS_RE = re.compile(
    r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?"
)

# Apache/nginx bracketed timestamp: "[10/Oct/2023:13:55:36 +0000]"
_APACHE_TS_RE = re.compile(r"\[(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}\s+[+-]\d{4})\]")

_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_IPV6_RE = re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{0,4}\b")

_APACHE_COMBINED_RE = re.compile(r'^\S+ \S+ \S+ \[[^\]]+\] "[^"]*" \d{3} \S+ "[^"]*" "[^"]*"')
_APACHE_COMMON_RE = re.compile(r'^\S+ \S+ \S+ \[[^\]]+\] "[^"]*" \d{3} \S+\s*$')
_NGINX_ERROR_RE = re.compile(r"^\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2}\s+\[\w+\]\s+\d+#\d+:")


def matches_ratio(lines: list[str], pattern: re.Pattern[str]) -> float:
    """Fraction of non-empty `lines` that `pattern` matches (search, not match)."""
    non_empty = [line for line in lines if line.strip()]
    if not non_empty:
        return 0.0
    hits = sum(1 for line in non_empty if pattern.search(line))
    return hits / len(non_empty)


def looks_like_syslog(lines: list[str]) -> float:
    """Confidence that `lines` follow RFC 3164 syslog framing."""
    return matches_ratio(lines, _SYSLOG_TS_RE)


def looks_like_json_lines(lines: list[str]) -> float:
    """Confidence that each line is a standalone JSON object."""
    non_empty = [line for line in lines if line.strip()]
    if not non_empty:
        return 0.0
    hits = 0
    for line in non_empty:
        try:
            parsed = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            continue
        if isinstance(parsed, dict):
            hits += 1
    return hits / len(non_empty)


def looks_like_csv(lines: list[str]) -> tuple[float, str]:
    """Confidence that `lines` are CSV, plus the sniffed delimiter.

    Returns `(confidence, delimiter)`; falls back to `","` as the
    delimiter when sniffing is inconclusive. Individual parsers that
    actually consume CSV (see `src.parsing.parsers.CSVParser`) re-sniff
    the delimiter from the real header row rather than trusting this
    value, since this is only ever called with a sample.
    """
    non_empty = [line for line in lines if line.strip()]
    if len(non_empty) < 2:
        return 0.0, ","
    sample = "\n".join(non_empty[:20])
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=",;\t|")
        delimiter = dialect.delimiter
    except csv.Error:
        delimiter = ","

    rows = list(csv.reader(io.StringIO(sample), delimiter=delimiter))
    if len(rows) < 2:
        return 0.0, delimiter
    column_counts = [len(row) for row in rows]
    most_common = max(set(column_counts), key=column_counts.count)
    if most_common <= 1:
        return 0.0, delimiter
    consistent = sum(1 for c in column_counts if c == most_common) / len(column_counts)
    return consistent, delimiter


def looks_like_apache_combined(lines: list[str]) -> float:
    """Confidence that `lines` follow the Apache/nginx combined log format."""
    return matches_ratio(lines, _APACHE_COMBINED_RE)


def looks_like_apache_common(lines: list[str]) -> float:
    """Confidence that `lines` follow the Apache/nginx common log format.

    Anchored at the end (no trailing quoted fields), so combined-format
    lines score zero here and don't get double-claimed by both parsers.
    """
    return matches_ratio(lines, _APACHE_COMMON_RE)


def looks_like_nginx_error(lines: list[str]) -> float:
    """Confidence that `lines` follow the nginx error log format."""
    return matches_ratio(lines, _NGINX_ERROR_RE)


def extract_ip_addresses(text: str) -> list[str]:
    """Extract plausible IPv4/IPv6 addresses from free text, validated."""
    candidates = _IPV4_RE.findall(text) + _IPV6_RE.findall(text)
    return [c for c in candidates if is_valid_ip(c)]


def extract_best_effort_timestamp(text: str) -> datetime | None:
    """Try several known timestamp shapes against `text`, in order.

    Returns the first successful parse, or `None`. Intended for the
    generic fallback parser dealing with an unrecognized format — parsers
    that already know their exact timestamp shape parse it directly
    instead of going through this best-effort path.

    Always returns a timezone-aware `datetime`: formats with an explicit
    offset are trusted as-is, formats without one are assumed UTC, so
    every `LogEntry.timestamp` across every parser stays consistently
    comparable (mixing naive and aware datetimes raises `TypeError` the
    moment anything tries to sort or compare them, e.g. the detection
    engine's cross-file time-window correlation).
    """
    iso_match = _ISO8601_TS_RE.search(text)
    if iso_match:
        raw = iso_match.group(0)
        normalized = raw[:-1] + "+0000" if raw.endswith("Z") else raw
        for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z"):
            try:
                return datetime.strptime(normalized, fmt)  # already tz-aware via %z
            except ValueError:
                continue
        try:
            return datetime.strptime(normalized, "%Y-%m-%d %H:%M:%S").replace(tzinfo=UTC)
        except ValueError:
            pass

    apache_match = _APACHE_TS_RE.search(text)
    if apache_match:
        try:
            return datetime.strptime(apache_match.group(1), "%d/%b/%Y:%H:%M:%S %z")
        except ValueError:
            pass

    return None


def first_present(data: dict[str, Any], keys: tuple[str, ...]) -> Any | None:
    """First non-empty value in `data` among `keys`, checked in order."""
    for key in keys:
        if key in data and data[key] not in (None, ""):
            return data[key]
    return None
