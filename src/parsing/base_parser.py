"""Abstract base class for log format parsers (the plugin interface).

Every parser implements two methods (`detect_confidence`, `parse_line`)
and inherits a `parse()` template method that handles file reading,
encoding/size validation, per-line sanitization, and per-line error
isolation — so a single malformed line can never abort parsing of an
otherwise-good file. See ADR-0002 for the rationale behind this
template-method design.
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from pathlib import Path
from typing import ClassVar

from src.core.config import SecurityConfig
from src.core.models import LogEntry, LogFormat, ParseResult
from src.utils.logger import get_logger
from src.utils.security import strip_control_characters, truncate
from src.utils.validators import validate_file_size, validate_text_encoding

logger = get_logger("parsing.base_parser")


class BaseParser(ABC):
    """Abstract interface every log format parser must implement.

    Subclasses are instantiated fresh once per file by
    `src.parsing.factory.ParserFactory`, so it is safe for a parser to
    keep per-file mutable state on `self` (e.g. a CSV parser remembering
    its header row) — that state never leaks across files.
    """

    #: Unique, stable identifier used in the registry and in CLI output.
    name: ClassVar[str]
    #: The `LogFormat` this parser produces `LogEntry.format` values for.
    log_format: ClassVar[LogFormat]
    #: Excluded from confidence-based ranking; used only as the last-resort
    #: fallback when no competitive parser clears the threshold.
    is_fallback: ClassVar[bool] = False
    #: Tie-breaker for confidence-based selection. When two parsers report
    #: equal confidence, the one with higher `priority` wins. Exists for
    #: parsers that specialize a more generic parent (e.g. `AuthLogParser`
    #: building on `SyslogParser`'s shape): a specialization can validly
    #: report the *same* confidence as its parent once its own criteria
    #: are met, and has no numeric way to score strictly higher once the
    #: parent is already at the 1.0 ceiling — priority resolves that tie
    #: deliberately instead of relying on confidence-formula tricks.
    priority: ClassVar[int] = 0

    @abstractmethod
    def detect_confidence(self, sample_lines: list[str]) -> float:
        """Estimate (0.0-1.0) how confidently this parser can handle `sample_lines`.

        `sample_lines` are already sanitized (control characters stripped)
        and length-capped, matching what `parse_line` will receive.
        """

    @abstractmethod
    def parse_line(self, line: str, line_number: int, source_file: str) -> LogEntry | None:
        """Parse one sanitized, length-capped line into a `LogEntry`.

        Returns `None` if the line does not match this parser's expected
        shape (e.g. a header/continuation line) — a normal, expected
        outcome, not an error condition. Raising an exception is reserved
        for genuinely unexpected failures; `parse()` catches and logs any
        exception here and treats it the same as returning `None`, so a
        parser does not need its own defensive try/except in the typical
        case.
        """

    def parse(
        self,
        path: Path,
        security_config: SecurityConfig,
        *,
        confidence: float = 1.0,
    ) -> ParseResult:
        """Parse `path` into a `ParseResult`. Concrete template method.

        Validates file size and encoding, then reads line by line,
        stripping control characters and enforcing the configured maximum
        line length *before* handing each line to `parse_line`, and
        isolating per-line failures so they degrade to a skipped line
        rather than aborting the whole file.

        Args:
            confidence: The format-detection confidence to record on the
                result, typically supplied by `ParserFactory.detect()`.
                Defaults to 1.0 for direct/forced use (e.g. tests, or an
                explicit `--format` override where detection never ran).
        """
        start = time.monotonic()
        validate_file_size(path, max_bytes=security_config.max_file_size_bytes)
        encoding = validate_text_encoding(path, allowed_encodings=security_config.allowed_encodings)

        entries: list[LogEntry] = []
        warnings: list[str] = []
        total_lines = 0
        skipped_lines = 0

        with path.open("r", encoding=encoding, errors="replace") as fh:
            for raw_line in fh:
                if total_lines >= security_config.max_lines_per_file:
                    warnings.append(
                        f"Stopped after max_lines_per_file={security_config.max_lines_per_file}"
                    )
                    break
                total_lines += 1
                line_number = total_lines

                line = strip_control_characters(raw_line.rstrip("\r\n"))
                line = truncate(line, security_config.max_line_length)
                if not line.strip():
                    skipped_lines += 1
                    continue

                try:
                    entry = self.parse_line(line, line_number, str(path))
                except Exception as exc:  # one bad line must never abort the whole file
                    logger.debug(
                        "Parser '%s' failed on %s line %d: %s",
                        self.name,
                        path,
                        line_number,
                        exc,
                    )
                    entry = None

                if entry is None:
                    skipped_lines += 1
                else:
                    entries.append(entry)

        return ParseResult(
            source_file=str(path),
            detected_format=self.log_format,
            parser_name=self.name,
            confidence=confidence,
            entries=entries,
            total_lines=total_lines,
            parsed_lines=len(entries),
            skipped_lines=skipped_lines,
            parse_duration_seconds=time.monotonic() - start,
            warnings=warnings,
        )
