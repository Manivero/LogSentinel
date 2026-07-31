"""Custom exception hierarchy for AI Log Analyzer.

Every exception raised by application code inherits from
`AILogAnalyzerError`, so callers can catch application-specific errors
distinctly from third-party or standard library exceptions. Exceptions are
grouped by subsystem so callers can catch broadly (e.g. `OllamaError`) or
narrowly (e.g. `ModelNotFoundError`) as appropriate.

Design note: not every exception defined here is necessarily raised by the
current set of implemented modules — some are reserved for subsystems still
being built (see PROGRESS.md), analogous to how a stable public API often
declares its full error surface up front.
"""

from __future__ import annotations

from typing import Any

__all__ = [
    "AILogAnalyzerError",
    "AnalysisError",
    "CacheError",
    "ConfigurationError",
    "ContextCorrelationError",
    "DetectionError",
    "EmbeddingError",
    "FileAccessError",
    "FileEncodingError",
    "FileTooLargeError",
    "JSONRepairError",
    "KnowledgeBaseError",
    "ModelNotFoundError",
    "NoModelsAvailableError",
    "OllamaConnectionError",
    "OllamaError",
    "OllamaNotInstalledError",
    "OllamaServerError",
    "OllamaTimeoutError",
    "ParsingError",
    "PromptInjectionDetectedError",
    "ReportGenerationError",
    "ResponseValidationError",
    "RuleLoadError",
    "SecurityValidationError",
    "UnsupportedFormatError",
    "VectorStoreError",
]


class AILogAnalyzerError(Exception):
    """Base exception for all application-specific errors.

    Attributes:
        message: Human-readable error description.
        details: Optional structured context for logging/debugging (never
            put untrusted log content here verbatim without truncation —
            error details may be surfaced in CLI output).
    """

    def __init__(self, message: str, *, details: dict[str, Any] | None = None) -> None:
        self.message = message
        self.details = details or {}
        super().__init__(message)

    def __str__(self) -> str:
        if self.details:
            detail_str = ", ".join(f"{k}={v!r}" for k, v in self.details.items())
            return f"{self.message} ({detail_str})"
        return self.message


# ---------------------------------------------------------------------------
# Configuration errors
# ---------------------------------------------------------------------------
class ConfigurationError(AILogAnalyzerError):
    """Raised when application configuration is invalid or cannot be loaded."""


# ---------------------------------------------------------------------------
# Ollama subsystem errors
# ---------------------------------------------------------------------------
class OllamaError(AILogAnalyzerError):
    """Base class for all Ollama-related errors."""


class OllamaNotInstalledError(OllamaError):
    """Raised when the `ollama` binary cannot be found on the system.

    Purely diagnostic in most flows — Ollama may run in a separate Docker
    container with no local binary, which is a fully supported deployment
    and not an error by itself.
    """


class OllamaConnectionError(OllamaError):
    """Raised when the Ollama HTTP server cannot be reached."""


class OllamaServerError(OllamaError):
    """Raised when the Ollama server returns an unexpected error response."""


class OllamaTimeoutError(OllamaError):
    """Raised when a request to the Ollama server exceeds its timeout budget."""


class ModelNotFoundError(OllamaError):
    """Raised when a requested model is not installed locally."""

    def __init__(self, model_name: str, available_models: list[str] | None = None) -> None:
        self.model_name = model_name
        self.available_models = available_models or []
        message = f"Model '{model_name}' not found locally."
        super().__init__(message, details={"model": model_name, "available": self.available_models})


class NoModelsAvailableError(OllamaError):
    """Raised when no models are installed and no usable default can be selected."""


# ---------------------------------------------------------------------------
# Parsing errors
# ---------------------------------------------------------------------------
class ParsingError(AILogAnalyzerError):
    """Base class for all log parsing errors."""


class UnsupportedFormatError(ParsingError):
    """Raised when no parser can confidently handle a given log format."""


class FileTooLargeError(ParsingError):
    """Raised when a log file exceeds the configured maximum size."""


class FileEncodingError(ParsingError):
    """Raised when a log file cannot be decoded with any allowed encoding."""


class FileAccessError(ParsingError):
    """Raised when a log file cannot be safely accessed (missing, unreadable,
    not a regular file, or outside an allowed directory)."""


# ---------------------------------------------------------------------------
# Detection errors
# ---------------------------------------------------------------------------
class DetectionError(AILogAnalyzerError):
    """Base class for rule-based detection engine errors."""


class RuleLoadError(DetectionError):
    """Raised when detection rules cannot be loaded or are malformed."""


class ContextCorrelationError(DetectionError):
    """Raised when cross-log context correlation fails unrecoverably.

    Correlation failures should normally degrade gracefully (skip
    correlation, continue analysis) rather than raise this — reserved for
    genuinely unexpected internal errors.
    """


# ---------------------------------------------------------------------------
# Analysis / AI errors
# ---------------------------------------------------------------------------
class AnalysisError(AILogAnalyzerError):
    """Base class for AI analysis errors."""


class PromptInjectionDetectedError(AnalysisError):
    """Raised when high-risk prompt injection content is detected and blocked
    rather than merely neutralized (see `src.analysis.sanitizer`)."""


class ResponseValidationError(AnalysisError):
    """Raised when an AI response fails schema validation after repair attempts."""


class JSONRepairError(AnalysisError):
    """Raised when malformed JSON from the model cannot be automatically repaired."""


# ---------------------------------------------------------------------------
# Cache errors
# ---------------------------------------------------------------------------
class CacheError(AILogAnalyzerError):
    """Base class for caching subsystem errors.

    Cache failures should generally degrade to a cache-miss (log a warning,
    proceed without caching) rather than aborting analysis.
    """


# ---------------------------------------------------------------------------
# Knowledge base / RAG errors
# ---------------------------------------------------------------------------
class KnowledgeBaseError(AILogAnalyzerError):
    """Base class for knowledge base (RAG) errors."""


class EmbeddingError(KnowledgeBaseError):
    """Raised when generating an embedding vector fails."""


class VectorStoreError(KnowledgeBaseError):
    """Raised when the vector store cannot be accessed, written to, or queried."""


# ---------------------------------------------------------------------------
# Reporting errors
# ---------------------------------------------------------------------------
class ReportGenerationError(AILogAnalyzerError):
    """Raised when a report cannot be generated in the requested format."""


# ---------------------------------------------------------------------------
# Security / validation errors
# ---------------------------------------------------------------------------
class SecurityValidationError(AILogAnalyzerError):
    """Raised when input fails a security validation check (e.g. path
    traversal, disallowed encoding, oversized payload)."""
