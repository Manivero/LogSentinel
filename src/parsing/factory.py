"""Auto-detection and parsing orchestration.

Ties together the parser registry (`src.parsing.registry`) and each
parser's `detect_confidence`/`parse` to answer one question: "given this
file, which parser should handle it, and what does parsing it produce?"

This is the module CLI/pipeline code calls; it is the only place that
needs to know about sampling, thresholds, and the fallback-on-low-
confidence policy. Importing this module also imports
`src.parsing.parsers`, which registers all built-in parsers as a side
effect — callers never need to import the parsers module directly.
"""

from __future__ import annotations

from pathlib import Path

from src.core.config import ParsingConfig, SecurityConfig
from src.core.exceptions import UnsupportedFormatError
from src.core.models import LogFormat, ParseResult

# Imported for the registration side effect: every built-in parser class
# registers itself into `default_registry` at import time.
from src.parsing import parsers as _built_in_parsers  # noqa: F401
from src.parsing.base_parser import BaseParser
from src.parsing.registry import ParserRegistry, default_registry
from src.utils.logger import get_logger
from src.utils.security import strip_control_characters, truncate
from src.utils.validators import (
    validate_file_size,
    validate_log_file_path,
    validate_text_encoding,
)

logger = get_logger("parsing.factory")


class ParserFactory:
    """Selects and runs the right parser for a given log file."""

    def __init__(
        self,
        *,
        security_config: SecurityConfig,
        parsing_config: ParsingConfig | None = None,
        registry: ParserRegistry | None = None,
    ) -> None:
        self._security_config = security_config
        self._parsing_config = parsing_config or ParsingConfig()
        self._registry = registry or default_registry

    def detect(self, path: Path) -> tuple[type[BaseParser], float]:
        """Sample `path` and return the best-matching parser class and its confidence.

        Falls back to the registry's fallback parser (see
        `ParserRegistry.fallback`) if no competitive parser clears the
        configured confidence threshold.

        Raises:
            UnsupportedFormatError: If nothing clears the threshold *and*
                no fallback parser is registered (should not happen with
                the built-ins registered, but guards a misconfigured
                custom registry).
        """
        sample = self._read_sample(path)
        best_cls: type[BaseParser] | None = None
        best_confidence = 0.0
        best_priority = 0
        for parser_cls in self._registry.competitive():
            confidence = parser_cls().detect_confidence(sample)
            logger.debug("Parser '%s' confidence for %s: %.2f", parser_cls.name, path, confidence)
            if best_cls is None or (confidence, parser_cls.priority) > (
                best_confidence,
                best_priority,
            ):
                best_confidence = confidence
                best_priority = parser_cls.priority
                best_cls = parser_cls

        if best_cls is not None and best_confidence >= self._parsing_config.confidence_threshold:
            return best_cls, best_confidence

        fallback_cls = self._registry.fallback()
        if fallback_cls is None:
            raise UnsupportedFormatError(
                f"No parser reached the confidence threshold for {path} and no "
                "fallback parser is registered.",
                details={
                    "best_confidence": best_confidence,
                    "threshold": self._parsing_config.confidence_threshold,
                },
            )
        return fallback_cls, best_confidence

    def parse_file(
        self, path: str | Path, *, forced_format: LogFormat | None = None
    ) -> ParseResult:
        """Validate, detect (unless `forced_format` is given), and parse `path`.

        Raises:
            FileAccessError, FileTooLargeError, FileEncodingError: from
                the underlying validators in `src.utils.validators`.
            UnsupportedFormatError: see `detect()`.
        """
        resolved = validate_log_file_path(
            path, allowed_roots=self._security_config.allowed_log_roots
        )
        validate_file_size(resolved, max_bytes=self._security_config.max_file_size_bytes)
        validate_text_encoding(resolved, allowed_encodings=self._security_config.allowed_encodings)

        if forced_format is not None:
            parser_cls = self._find_by_format(forced_format)
            confidence = 1.0
        else:
            parser_cls, confidence = self.detect(resolved)

        logger.info(
            "Parsing %s with '%s' parser (confidence=%.2f)",
            resolved,
            parser_cls.name,
            confidence,
        )
        parser = parser_cls()
        return parser.parse(resolved, self._security_config, confidence=confidence)

    def _find_by_format(self, log_format: LogFormat) -> type[BaseParser]:
        for parser_cls in self._registry.all():
            if parser_cls.log_format == log_format:
                return parser_cls
        raise UnsupportedFormatError(f"No registered parser produces format '{log_format.value}'.")

    def _read_sample(self, path: Path) -> list[str]:
        """Read and sanitize the first `sample_lines` non-blank lines of `path`."""
        encoding = validate_text_encoding(
            path, allowed_encodings=self._security_config.allowed_encodings
        )
        lines: list[str] = []
        with path.open("r", encoding=encoding, errors="replace") as fh:
            for raw_line in fh:
                if len(lines) >= self._parsing_config.sample_lines:
                    break
                cleaned = strip_control_characters(raw_line.rstrip("\r\n"))
                cleaned = truncate(cleaned, self._security_config.max_line_length)
                if cleaned.strip():
                    lines.append(cleaned)
        return lines
