"""Application configuration loading and validation.

Precedence (highest wins): CLI flags (applied by callers after loading) >
environment variables > user-supplied config file (`--config`) > bundled
`config/default.yaml` > in-code field defaults.

Configuration is intentionally plain `pydantic.BaseModel` (not
`BaseSettings`) so precedence is explicit, linear, and easy to test, rather
than relying on a settings-source resolution order buried in a third-party
library.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from src.core.exceptions import ConfigurationError

# Bundled default config, relative to the repository root (src/core/config.py
# -> src/core -> src -> repo root).
_PACKAGE_ROOT = Path(__file__).resolve().parent.parent.parent
DEFAULT_CONFIG_PATH: Path = _PACKAGE_ROOT / "config" / "default.yaml"

DEFAULT_MODEL_PREFERENCE: list[str] = [
    "qwen2.5:7b",
    "qwen2.5:14b",
    "llama3.2",
    "mistral",
    "gemma3",
]


# ============================================================================
# Configuration sections
# ============================================================================


class OllamaConfig(BaseModel):
    """Ollama connection, model selection, and request behavior."""

    model_config = ConfigDict(extra="forbid")

    host: str = "http://localhost:11434"
    request_timeout_seconds: float = Field(default=120.0, gt=0)
    connect_timeout_seconds: float = Field(default=10.0, gt=0)
    default_model: str | None = Field(
        default=None, description="Explicit model name; None enables auto-selection."
    )
    model_preference: list[str] = Field(default_factory=lambda: list(DEFAULT_MODEL_PREFERENCE))
    embedding_model: str = "nomic-embed-text"
    stream_default_cli: bool = True
    stream_default_api: bool = False
    max_concurrent_requests: int = Field(default=3, ge=1, le=32)
    max_retries: int = Field(default=2, ge=0, le=10)
    retry_backoff_seconds: float = Field(default=1.5, ge=0.0)


class SecurityConfig(BaseModel):
    """Defense-in-depth limits applied to all untrusted log input."""

    model_config = ConfigDict(extra="forbid")

    max_file_size_bytes: int = Field(default=100 * 1024 * 1024, gt=0)
    max_line_length: int = Field(default=32768, gt=0)
    max_lines_per_file: int = Field(default=2_000_000, gt=0)
    allowed_encodings: list[str] = Field(default_factory=lambda: ["utf-8", "utf-8-sig", "ascii"])
    allowed_log_roots: list[str] = Field(
        default_factory=list,
        description="Optional allowlist of directories log files must reside under.",
    )


class CacheConfig(BaseModel):
    """AI response cache behavior."""

    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    directory: Path = Field(default_factory=lambda: Path.home() / ".ai-log-analyzer" / "cache")
    ttl_seconds: int = Field(default=24 * 60 * 60, gt=0)
    max_size_bytes: int = Field(default=1 * 1024 * 1024 * 1024, gt=0)

    @field_validator("directory")
    @classmethod
    def _expand_directory(cls, v: Path) -> Path:
        return v.expanduser()


class KnowledgeConfig(BaseModel):
    """Optional RAG knowledge base configuration."""

    model_config = ConfigDict(extra="forbid")

    enabled: bool = False
    source_directory: Path | None = None
    persist_directory: Path = Field(
        default_factory=lambda: Path.home() / ".ai-log-analyzer" / "knowledge_index"
    )
    top_k: int = Field(default=5, ge=1, le=50)
    similarity_threshold: float = Field(default=0.3, ge=0.0, le=1.0)
    chunk_size: int = Field(default=800, ge=100)
    chunk_overlap: int = Field(default=100, ge=0)
    knowledge_version: str = "v1"

    @field_validator("persist_directory")
    @classmethod
    def _expand_persist_directory(cls, v: Path) -> Path:
        return v.expanduser()

    @field_validator("source_directory")
    @classmethod
    def _expand_source_directory(cls, v: Path | None) -> Path | None:
        return v.expanduser() if v is not None else None


class ParsingConfig(BaseModel):
    """Log format auto-detection behavior.

    Deliberately separate from `DetectionConfig` (the rule-based security
    detection engine) to avoid the two very different meanings of
    "detection" in this codebase colliding: *format* detection here picks
    a parser; *threat* detection (src/detection/) matches security rules.
    """

    model_config = ConfigDict(extra="forbid")

    sample_lines: int = Field(
        default=50,
        ge=1,
        le=1000,
        description="Lines sampled from a file to score candidate parsers.",
    )
    confidence_threshold: float = Field(
        default=0.5,
        ge=0.0,
        le=1.0,
        description="Minimum confidence required before falling back to the generic parser.",
    )


class DetectionConfig(BaseModel):
    """Rule-based (security) detection engine configuration."""

    model_config = ConfigDict(extra="forbid")

    rules_directory: Path | None = Field(
        default=None, description="None uses the bundled rules under src/detection/rules."
    )
    enabled_categories: list[str] = Field(
        default_factory=list, description="Empty means all categories are enabled."
    )

    @field_validator("rules_directory")
    @classmethod
    def _expand_rules_directory(cls, v: Path | None) -> Path | None:
        return v.expanduser() if v is not None else None


class LoggingConfig(BaseModel):
    """Application (not log-analysis) logging behavior."""

    model_config = ConfigDict(extra="forbid")

    level: str = "INFO"
    json_logs: bool = False
    log_file: Path | None = None

    @field_validator("log_file")
    @classmethod
    def _expand_log_file(cls, v: Path | None) -> Path | None:
        return v.expanduser() if v is not None else None


class AnalysisConfig(BaseModel):
    """AI analysis behavior not specific to the Ollama transport."""

    model_config = ConfigDict(extra="forbid")

    prompt_version: str = "v1"
    context_window_tokens: int = Field(default=8192, gt=0)
    max_context_log_lines: int = Field(
        default=1, ge=1, description="Number of neighboring lines of context sent per finding."
    )


class AppConfig(BaseModel):
    """Root application configuration."""

    model_config = ConfigDict(extra="forbid")

    ollama: OllamaConfig = Field(default_factory=OllamaConfig)
    security: SecurityConfig = Field(default_factory=SecurityConfig)
    cache: CacheConfig = Field(default_factory=CacheConfig)
    knowledge: KnowledgeConfig = Field(default_factory=KnowledgeConfig)
    parsing: ParsingConfig = Field(default_factory=ParsingConfig)
    detection: DetectionConfig = Field(default_factory=DetectionConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    analysis: AnalysisConfig = Field(default_factory=AnalysisConfig)


# ============================================================================
# Loading & merging
# ============================================================================


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    """Recursively merge `override` into `base`, returning a new dict."""
    result = dict(base)
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def _load_yaml(path: Path) -> dict[str, Any]:
    """Load a YAML file into a dict, raising `ConfigurationError` on failure."""
    try:
        with path.open("r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
    except OSError as exc:
        raise ConfigurationError(f"Could not read config file: {path}") from exc
    except yaml.YAMLError as exc:
        raise ConfigurationError(f"Invalid YAML in config file: {path}") from exc
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ConfigurationError(f"Config file must contain a YAML mapping: {path}")
    return data


def _set_nested(data: dict[str, Any], path: tuple[str, ...], value: Any) -> None:
    cursor = data
    for key in path[:-1]:
        nxt = cursor.setdefault(key, {})
        if not isinstance(nxt, dict):
            return  # a scalar already occupies this path; skip rather than corrupt it
        cursor = nxt
    cursor[path[-1]] = value


def _str_to_bool(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _mb_to_bytes(value: str) -> int:
    return int(float(value) * 1024 * 1024)


# (env_var, nested_key_path, caster) — applied in order after YAML merging.
_ENV_OVERRIDES: list[tuple[str, tuple[str, ...], Callable[[str], Any]]] = [
    ("AI_LOG_ANALYZER_OLLAMA_HOST", ("ollama", "host"), str),
    ("AI_LOG_ANALYZER_OLLAMA_MODEL", ("ollama", "default_model"), str),
    ("AI_LOG_ANALYZER_OLLAMA_EMBEDDING_MODEL", ("ollama", "embedding_model"), str),
    ("AI_LOG_ANALYZER_OLLAMA_TIMEOUT", ("ollama", "request_timeout_seconds"), float),
    ("AI_LOG_ANALYZER_LOG_LEVEL", ("logging", "level"), str),
    ("AI_LOG_ANALYZER_CACHE_ENABLED", ("cache", "enabled"), _str_to_bool),
    ("AI_LOG_ANALYZER_CACHE_DIR", ("cache", "directory"), str),
    ("AI_LOG_ANALYZER_CACHE_TTL_SECONDS", ("cache", "ttl_seconds"), int),
    ("AI_LOG_ANALYZER_MAX_FILE_SIZE_MB", ("security", "max_file_size_bytes"), _mb_to_bytes),
    ("AI_LOG_ANALYZER_KNOWLEDGE_ENABLED", ("knowledge", "enabled"), _str_to_bool),
    ("AI_LOG_ANALYZER_KNOWLEDGE_DIR", ("knowledge", "source_directory"), str),
    ("AI_LOG_ANALYZER_PROMPT_VERSION", ("analysis", "prompt_version"), str),
]


def _apply_env_overrides(data: dict[str, Any]) -> dict[str, Any]:
    """Apply supported `AI_LOG_ANALYZER_*` environment variable overrides."""
    result = dict(data)
    for env_var, key_path, caster in _ENV_OVERRIDES:
        raw = os.environ.get(env_var)
        if not raw:
            continue
        try:
            value = caster(raw)
        except (TypeError, ValueError) as exc:
            raise ConfigurationError(
                f"Invalid value for environment variable {env_var}: {raw!r}"
            ) from exc
        _set_nested(result, key_path, value)
    return result


def load_config(config_path: Path | str | None = None) -> AppConfig:
    """Load, merge, and validate application configuration.

    Args:
        config_path: Optional path to a user-supplied YAML config file that
            is deep-merged over the bundled defaults.

    Returns:
        A validated `AppConfig`.

    Raises:
        ConfigurationError: If a YAML file is invalid, a referenced config
            path does not exist, an environment override is malformed, or
            the merged configuration fails Pydantic validation.
    """
    merged: dict[str, Any] = {}

    if DEFAULT_CONFIG_PATH.exists():
        merged = _deep_merge(merged, _load_yaml(DEFAULT_CONFIG_PATH))

    if config_path is not None:
        resolved = Path(config_path).expanduser()
        if not resolved.exists():
            raise ConfigurationError(f"Config file not found: {resolved}")
        merged = _deep_merge(merged, _load_yaml(resolved))

    merged = _apply_env_overrides(merged)

    try:
        return AppConfig(**merged)
    except ValidationError as exc:
        raise ConfigurationError("Invalid configuration", details={"errors": exc.errors()}) from exc


def default_config() -> AppConfig:
    """Return an `AppConfig` built purely from in-code defaults (no files/env).

    Useful for tests that need a config without touching the filesystem or
    environment.
    """
    return AppConfig()
