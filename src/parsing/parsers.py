"""Built-in log format parsers.

Each parser is a small, focused `BaseParser` subclass registered into the
default parser registry at import time via the `@register_parser`
decorator. Adding a new format means adding a new class here (or in a
separate module that also imports `register_parser`) — nothing else needs
to change, which is the point of the plugin architecture (see ADR-0002).
"""

from __future__ import annotations

import csv
import io
import json
import re
from datetime import UTC, datetime
from typing import Any, ClassVar

from src.core.models import LogEntry, LogFormat
from src.parsing import heuristics
from src.parsing.base_parser import BaseParser
from src.parsing.registry import register_parser

# ============================================================================
# Syslog / auth.log
# ============================================================================

_SYSLOG_LINE_RE = re.compile(
    r"^(?:<(?P<pri>\d+)>)?"
    r"(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<process>[\w.\-/]+?)(?:\[(?P<pid>\d+)\])?:\s*"
    r"(?P<message>.*)$"
)

# RFC 3164 timestamps omit the year; assume the current year, which is
# correct for freshly-collected logs (the overwhelmingly common case for a
# tool analyzing recent activity). A SIEM ingesting the JSON export can
# re-attach the true year from file metadata if that assumption doesn't
# hold for a given archive.
_SYSLOG_YEAR_FALLBACK = datetime.now().year


def _parse_syslog_timestamp(raw: str) -> datetime | None:
    # RFC 3164 has no timezone field; assume UTC so every LogEntry.timestamp
    # across every parser is consistently timezone-aware and therefore
    # safely comparable/sortable (see detection engine cross-file
    # correlation, which sorts entries from many sources by timestamp).
    try:
        return datetime.strptime(f"{_SYSLOG_YEAR_FALLBACK} {raw}", "%Y %b %d %H:%M:%S").replace(
            tzinfo=UTC
        )
    except ValueError:
        return None


@register_parser
class SyslogParser(BaseParser):
    """RFC 3164-style syslog: `Mon DD HH:MM:SS host process[pid]: message`."""

    name: ClassVar[str] = "syslog"
    log_format: ClassVar[LogFormat] = LogFormat.SYSLOG

    def detect_confidence(self, sample_lines: list[str]) -> float:
        return heuristics.looks_like_syslog(sample_lines)

    def parse_line(self, line: str, line_number: int, source_file: str) -> LogEntry | None:
        match = _SYSLOG_LINE_RE.match(line)
        if match is None:
            return None
        groups = match.groupdict()
        return LogEntry(
            raw_line=line,
            line_number=line_number,
            source_file=source_file,
            format=self.log_format,
            timestamp=_parse_syslog_timestamp(groups["timestamp"]),
            host=groups["host"],
            process=groups["process"],
            pid=int(groups["pid"]) if groups["pid"] else None,
            message=groups["message"],
            fields={"priority": groups["pri"]} if groups["pri"] else {},
        )


_AUTH_KEYWORDS = (
    "sshd",
    "sudo",
    "su:",
    "login",
    "authentication failure",
    "failed password",
    "accepted password",
    "accepted publickey",
    "session opened",
    "session closed",
    "useradd",
    "userdel",
    "usermod",
    "pam_unix",
    "invalid user",
)

_FAILED_AUTH_RE = re.compile(
    r"failed password|authentication failure|invalid user",
    re.IGNORECASE,
)
_ACCEPTED_AUTH_RE = re.compile(
    r"accepted password|accepted publickey|session opened", re.IGNORECASE
)
_USER_FROM_RE = re.compile(r"for(?:\s+invalid user)?\s+(\S+)\s+from\s+(\S+)", re.IGNORECASE)
# sshd also emits a bare "Invalid user X from Y" pre-auth notice with no
# leading "for" — a distinct phrasing from "Failed password for invalid
# user X from Y" above, and easy to miss (this was, in fact, missed in
# the first version of this parser and caught during detection-rule
# testing: AUTH-005's threshold_group_by=source_ip silently grouped every
# such line under "unknown" instead of the real attacker IP).
_INVALID_USER_NO_FOR_RE = re.compile(r"^Invalid user\s+(\S+)\s+from\s+(\S+)", re.IGNORECASE)


@register_parser
class AuthLogParser(SyslogParser):
    """Syslog-framed authentication events (auth.log / secure).

    Reuses `SyslogParser`'s line structure but additionally extracts
    `user`, `source_ip`, and an `auth_result` field, and requires a real
    density of authentication-related keywords (not just syslog shape) to
    outrank the more generic `SyslogParser` during detection.
    """

    name: ClassVar[str] = "auth_log"
    log_format: ClassVar[LogFormat] = LogFormat.AUTH_LOG
    priority: ClassVar[int] = 10  # outranks plain SyslogParser on confidence ties

    def detect_confidence(self, sample_lines: list[str]) -> float:
        syslog_confidence = heuristics.looks_like_syslog(sample_lines)
        if syslog_confidence < 0.3:
            return 0.0
        non_empty = [line.lower() for line in sample_lines if line.strip()]
        if not non_empty:
            return 0.0
        keyword_hits = sum(1 for line in non_empty if any(kw in line for kw in _AUTH_KEYWORDS))
        keyword_ratio = keyword_hits / len(non_empty)
        if keyword_ratio <= 0.1:
            return 0.0
        # Matches (not dilutes) the parent's confidence once auth content
        # is confirmed present; `priority` above breaks the resulting tie.
        return syslog_confidence

    def parse_line(self, line: str, line_number: int, source_file: str) -> LogEntry | None:
        entry = super().parse_line(line, line_number, source_file)
        if entry is None:
            return None
        fields: dict[str, Any] = dict(entry.fields)
        user = entry.user
        source_ip = entry.source_ip
        user_match = _USER_FROM_RE.search(entry.message)
        if user_match:
            user = user_match.group(1)
            source_ip = user_match.group(2)
        else:
            no_for_match = _INVALID_USER_NO_FOR_RE.match(entry.message)
            if no_for_match:
                user = no_for_match.group(1)
                source_ip = no_for_match.group(2)
        if _FAILED_AUTH_RE.search(entry.message):
            fields["auth_result"] = "failed"
        elif _ACCEPTED_AUTH_RE.search(entry.message):
            fields["auth_result"] = "accepted"
        return entry.model_copy(
            update={
                "format": self.log_format,
                "user": user,
                "source_ip": source_ip,
                "fields": fields,
            }
        )


# ============================================================================
# Apache / nginx access logs
# ============================================================================

_COMMON_LOG_RE = re.compile(
    r"^(?P<host>\S+)\s+(?P<ident>\S+)\s+(?P<user>\S+)\s+"
    r"\[(?P<timestamp>[^\]]+)\]\s+"
    r'"(?P<request>[^"]*)"\s+(?P<status>\d{3})\s+(?P<bytes>\S+)'
)
_COMBINED_EXTRA_RE = re.compile(r'\s+"(?P<referer>[^"]*)"\s+"(?P<user_agent>[^"]*)"\s*$')
_REQUEST_LINE_RE = re.compile(r"^(?P<method>[A-Z]+)\s+(?P<path>\S+)\s+HTTP/[\d.]+$")


def _parse_apache_timestamp(raw: str) -> datetime | None:
    try:
        return datetime.strptime(raw, "%d/%b/%Y:%H:%M:%S %z")
    except ValueError:
        return None


def _build_web_log_entry(
    groups: dict[str, str | None],
    line: str,
    line_number: int,
    source_file: str,
    log_format: LogFormat,
) -> LogEntry:
    request = groups.get("request") or ""
    request_match = _REQUEST_LINE_RE.match(request)
    method = request_match.group("method") if request_match else None
    path = request_match.group("path") if request_match else None
    status = groups.get("status")
    bytes_sent = groups.get("bytes")
    fields: dict[str, Any] = {}
    if bytes_sent and bytes_sent != "-":
        fields["bytes_sent"] = bytes_sent
    referer = groups.get("referer")
    user_agent = groups.get("user_agent")
    if referer and referer != "-":
        fields["referer"] = referer
    if user_agent:
        fields["user_agent"] = user_agent
    user = groups.get("user")
    timestamp_raw = groups.get("timestamp")
    return LogEntry(
        raw_line=line,
        line_number=line_number,
        source_file=source_file,
        format=log_format,
        timestamp=_parse_apache_timestamp(timestamp_raw) if timestamp_raw else None,
        source_ip=groups.get("host"),
        user=user if user and user != "-" else None,
        http_method=method,
        http_path=path,
        http_status=int(status) if status and status.isdigit() else None,
        message=request or line,
        fields=fields,
    )


@register_parser
class CombinedLogFormatParser(BaseParser):
    """Apache/nginx combined access log format (common + referer + user-agent).

    This is the default access-log format for both Apache and nginx, so
    one parser covers both without duplicating the regex.
    """

    name: ClassVar[str] = "apache_combined"
    log_format: ClassVar[LogFormat] = LogFormat.APACHE_COMBINED

    def detect_confidence(self, sample_lines: list[str]) -> float:
        return heuristics.looks_like_apache_combined(sample_lines)

    def parse_line(self, line: str, line_number: int, source_file: str) -> LogEntry | None:
        common_match = _COMMON_LOG_RE.match(line)
        if common_match is None:
            return None
        extra_match = _COMBINED_EXTRA_RE.search(line)
        if extra_match is None:
            return None
        groups: dict[str, str | None] = {**common_match.groupdict(), **extra_match.groupdict()}
        return _build_web_log_entry(groups, line, line_number, source_file, self.log_format)


@register_parser
class CommonLogFormatParser(BaseParser):
    """Apache/nginx common access log format (no referer/user-agent)."""

    name: ClassVar[str] = "apache_common"
    log_format: ClassVar[LogFormat] = LogFormat.APACHE_COMMON

    def detect_confidence(self, sample_lines: list[str]) -> float:
        return heuristics.looks_like_apache_common(sample_lines)

    def parse_line(self, line: str, line_number: int, source_file: str) -> LogEntry | None:
        match = _COMMON_LOG_RE.match(line)
        if match is None:
            return None
        # Reject lines that are actually combined-format (extra quoted
        # fields present) so the two parsers never both claim the same line.
        if _COMBINED_EXTRA_RE.search(line):
            return None
        groups: dict[str, str | None] = dict(match.groupdict())
        return _build_web_log_entry(groups, line, line_number, source_file, self.log_format)


# ============================================================================
# nginx error log
# ============================================================================

_NGINX_ERROR_LINE_RE = re.compile(
    r"^(?P<timestamp>\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"\[(?P<level>\w+)\]\s+(?P<pid>\d+)#(?P<tid>\d+):\s*"
    r"(?P<message>.*)$"
)
_NGINX_CLIENT_RE = re.compile(r"client:\s*([\d.:a-fA-F]+)")
_NGINX_SEVERITY_HINT = {
    "emerg": "CRITICAL",
    "alert": "CRITICAL",
    "crit": "CRITICAL",
    "error": "HIGH",
    "warn": "MEDIUM",
    "notice": "LOW",
    "info": "INFO",
}


@register_parser
class NginxErrorLogParser(BaseParser):
    """nginx error log: `YYYY/MM/DD HH:MM:SS [level] pid#tid: message`."""

    name: ClassVar[str] = "nginx_error"
    log_format: ClassVar[LogFormat] = LogFormat.NGINX_ERROR

    def detect_confidence(self, sample_lines: list[str]) -> float:
        return heuristics.looks_like_nginx_error(sample_lines)

    def parse_line(self, line: str, line_number: int, source_file: str) -> LogEntry | None:
        match = _NGINX_ERROR_LINE_RE.match(line)
        if match is None:
            return None
        groups = match.groupdict()
        message = groups["message"]
        client_match = _NGINX_CLIENT_RE.search(message)
        try:
            timestamp = datetime.strptime(groups["timestamp"], "%Y/%m/%d %H:%M:%S").replace(
                tzinfo=UTC
            )
        except ValueError:
            timestamp = None
        return LogEntry(
            raw_line=line,
            line_number=line_number,
            source_file=source_file,
            format=self.log_format,
            timestamp=timestamp,
            pid=int(groups["pid"]),
            source_ip=client_match.group(1) if client_match else None,
            message=message,
            fields={
                "nginx_level": groups["level"],
                "severity_hint": _NGINX_SEVERITY_HINT.get(groups["level"], "INFO"),
            },
        )


# ============================================================================
# JSON Lines (structured / cloud-native logs)
# ============================================================================

_TIMESTAMP_KEYS = ("timestamp", "time", "@timestamp", "ts", "datetime")
_MESSAGE_KEYS = ("message", "msg", "log", "text")
_LEVEL_KEYS = ("level", "severity", "loglevel", "log_level")
_HOST_KEYS = ("host", "hostname")
_IP_KEYS = ("ip", "client_ip", "source_ip", "src_ip", "remote_addr")
_USER_KEYS = ("user", "username", "actor")


def _stringify(value: Any) -> str | None:
    return str(value) if value is not None else None


def _parse_flexible_timestamp(value: Any) -> datetime | None:
    """Parse a timestamp from a JSON/CSV value of unknown but plausible type.

    Formats that include an explicit offset (`%z`) are trusted as-is;
    formats with no timezone information fall back to an explicit UTC
    assumption so every `LogEntry.timestamp` in the system is
    consistently timezone-aware (see `_parse_syslog_timestamp` for the
    same rationale).
    """
    if isinstance(value, int | float):
        try:
            return datetime.fromtimestamp(value, tz=UTC)
        except (ValueError, OverflowError, OSError):
            return None
    if isinstance(value, str):
        normalized = value[:-1] + "+0000" if value.endswith("Z") else value
        for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z"):
            try:
                return datetime.strptime(normalized, fmt)  # already tz-aware via %z
            except ValueError:
                continue
        try:
            return datetime.strptime(normalized, "%Y-%m-%d %H:%M:%S").replace(tzinfo=UTC)
        except ValueError:
            return None
    return None


@register_parser
class JSONLinesParser(BaseParser):
    """One standalone JSON object per line (common for cloud/structured logs)."""

    name: ClassVar[str] = "json_lines"
    log_format: ClassVar[LogFormat] = LogFormat.JSON_LINES

    def detect_confidence(self, sample_lines: list[str]) -> float:
        return heuristics.looks_like_json_lines(sample_lines)

    def parse_line(self, line: str, line_number: int, source_file: str) -> LogEntry | None:
        try:
            data = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            return None
        if not isinstance(data, dict):
            return None

        message = heuristics.first_present(data, _MESSAGE_KEYS)
        level = heuristics.first_present(data, _LEVEL_KEYS)
        remaining = {
            k: v for k, v in data.items() if k not in _TIMESTAMP_KEYS and k not in _MESSAGE_KEYS
        }
        if level is not None:
            remaining.setdefault("level", level)

        return LogEntry(
            raw_line=line,
            line_number=line_number,
            source_file=source_file,
            format=self.log_format,
            timestamp=_parse_flexible_timestamp(heuristics.first_present(data, _TIMESTAMP_KEYS)),
            host=_stringify(heuristics.first_present(data, _HOST_KEYS)),
            source_ip=_stringify(heuristics.first_present(data, _IP_KEYS)),
            user=_stringify(heuristics.first_present(data, _USER_KEYS)),
            message=str(message) if message is not None else line,
            fields=remaining,
        )


# ============================================================================
# CSV
# ============================================================================


def _sniff_delimiter(line: str) -> str:
    try:
        return csv.Sniffer().sniff(line, delimiters=",;\t|").delimiter
    except csv.Error:
        return ","


@register_parser
class CSVParser(BaseParser):
    """Generic CSV/TSV logs with a header row.

    Unlike the other parsers, CSV inherently needs to remember the header
    row to interpret subsequent rows — safe here because the factory
    instantiates a fresh parser per file (see `BaseParser` docstring), so
    `self._header` never leaks across files. The delimiter is re-sniffed
    from the real header line the first time `parse_line` runs, rather
    than trusted from `detect_confidence`'s sample-based guess, so this
    parser works correctly even if it's selected via a forced `--format`
    that skips detection entirely.
    """

    name: ClassVar[str] = "csv"
    log_format: ClassVar[LogFormat] = LogFormat.CSV

    def __init__(self) -> None:
        super().__init__()
        self._header: list[str] | None = None
        self._delimiter = ","

    def detect_confidence(self, sample_lines: list[str]) -> float:
        confidence, _delimiter = heuristics.looks_like_csv(sample_lines)
        return confidence

    def parse_line(self, line: str, line_number: int, source_file: str) -> LogEntry | None:
        if self._header is None:
            self._delimiter = _sniff_delimiter(line)
            row = next(csv.reader(io.StringIO(line), delimiter=self._delimiter), None)
            if not row:
                return None
            self._header = [h.strip() or f"column_{i}" for i, h in enumerate(row)]
            return None  # the header row is not itself a log entry

        header = self._header
        row = next(csv.reader(io.StringIO(line), delimiter=self._delimiter), None)
        if row is None:
            return None
        data: dict[str, str] = dict(zip(header, row, strict=False))
        timestamp_raw = heuristics.first_present(data, _TIMESTAMP_KEYS)
        return LogEntry(
            raw_line=line,
            line_number=line_number,
            source_file=source_file,
            format=self.log_format,
            timestamp=_parse_flexible_timestamp(timestamp_raw) if timestamp_raw else None,
            source_ip=_stringify(heuristics.first_present(data, _IP_KEYS)),
            user=_stringify(heuristics.first_present(data, _USER_KEYS)),
            message=_stringify(heuristics.first_present(data, _MESSAGE_KEYS)) or line,
            fields=data,
        )


# ============================================================================
# Generic fallback (last resort — never confidently claims a format)
# ============================================================================


@register_parser
class GenericLineParser(BaseParser):
    """Last-resort fallback: wraps every non-blank line as a minimal LogEntry.

    Never wins confidence-based ranking directly (`is_fallback = True`
    excludes it — see `ParserRegistry.competitive`) but is always
    available so an unrecognized format still produces *something*
    analyzable rather than failing outright, per the "fall back to a
    generic line-by-line parser" requirement.
    """

    name: ClassVar[str] = "generic"
    log_format: ClassVar[LogFormat] = LogFormat.GENERIC
    is_fallback: ClassVar[bool] = True

    def detect_confidence(self, sample_lines: list[str]) -> float:
        return 0.1  # only ever selected via the factory's explicit fallback path

    def parse_line(self, line: str, line_number: int, source_file: str) -> LogEntry | None:
        ips = heuristics.extract_ip_addresses(line)
        return LogEntry(
            raw_line=line,
            line_number=line_number,
            source_file=source_file,
            format=self.log_format,
            timestamp=heuristics.extract_best_effort_timestamp(line),
            source_ip=ips[0] if ips else None,
            message=line,
            fields={"extracted_ips": ips} if len(ips) > 1 else {},
        )
