"""Prompt-version-aware AI response caching.

Cache keys incorporate the log entry text, model name, prompt version,
and knowledge-base version, so bumping any of those — a new prompt
template, a different model, a re-indexed knowledge base — automatically
invalidates only the entries that are actually stale. No manual cache
clearing is required for routine iteration; `--no-cache` (a CLI concern,
not this module's) remains available to bypass the cache entirely for a
single run.

Every method degrades to a cache-miss (or a silent no-op write) on any
underlying storage error rather than raising: a corrupted or unwritable
cache directory should never prevent analysis from running, only make it
slower — consistent with the rest of the codebase's graceful-degradation
philosophy (see PROGRESS.md).
"""

from __future__ import annotations

import contextlib
import hashlib
from pathlib import Path

import diskcache

from src.core.models import AnalysisRecord, CacheStats
from src.utils.logger import get_logger

logger = get_logger("analysis.cache")

# Field separator unlikely to appear in any component, keeping the key
# derivation unambiguous (e.g. a log line ending in "gpt-4" then a
# component boundary can't be confused with a model literally named
# "...gpt-4" concatenated with the next field).
_KEY_SEPARATOR = "\x1f"


def compute_cache_key(
    *, log_entry_text: str, model_name: str, prompt_version: str, knowledge_version: str
) -> str:
    """Derive a stable cache key from everything that affects the AI response.

    Any change to any of the four inputs changes the key, so a cached
    entry is never served for a different model, prompt version, or
    knowledge-base state than the one that actually produced it.
    """
    payload = _KEY_SEPARATOR.join([log_entry_text, model_name, prompt_version, knowledge_version])
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class ResponseCache:
    """Thin, defensively-wrapped adapter over `diskcache.Cache`."""

    def __init__(self, directory: Path, *, ttl_seconds: int, size_limit_bytes: int) -> None:
        self.directory = directory
        self._ttl_seconds = ttl_seconds
        self._hits = 0
        self._misses = 0
        self._cache: diskcache.Cache | None
        try:
            directory.mkdir(parents=True, exist_ok=True)
            self._cache = diskcache.Cache(str(directory), size_limit=size_limit_bytes)
        except OSError as exc:
            logger.warning(
                "Could not open cache directory %s (%s); caching disabled for this run.",
                directory,
                exc,
            )
            self._cache = None

    @property
    def enabled(self) -> bool:
        return self._cache is not None

    @property
    def hits(self) -> int:
        return self._hits

    @property
    def misses(self) -> int:
        return self._misses

    def get(self, key: str) -> AnalysisRecord | None:
        """Return a cached `AnalysisRecord` for `key`, or `None` on any miss/failure."""
        if self._cache is None:
            return None
        try:
            raw = self._cache.get(key, default=None)
        except (OSError, diskcache.Timeout) as exc:
            logger.warning("Cache read failed for key %s...: %s", key[:12], exc)
            return None
        if raw is None:
            self._misses += 1
            return None
        try:
            record = AnalysisRecord.model_validate_json(raw)
        except ValueError as exc:
            logger.warning(
                "Cached entry for key %s... failed schema validation, treating as a "
                "miss (likely a stale entry from an older schema version): %s",
                key[:12],
                exc,
            )
            self._misses += 1
            return None
        self._hits += 1
        return record

    def set(self, key: str, record: AnalysisRecord) -> None:
        """Store `record` under `key`. Never raises; failures are logged and swallowed."""
        if self._cache is None:
            return
        try:
            self._cache.set(key, record.model_dump_json(), expire=self._ttl_seconds)
        except (OSError, diskcache.Timeout) as exc:
            logger.warning("Cache write failed for key %s...: %s", key[:12], exc)

    def clear(self) -> int:
        """Clear every cached entry. Returns the number removed (0 if disabled/failed)."""
        if self._cache is None:
            return 0
        try:
            count = len(self._cache)
            self._cache.clear()
            return count
        except OSError as exc:
            logger.warning("Cache clear failed: %s", exc)
            return 0

    def to_stats_model(self) -> CacheStats:
        """Snapshot current cache state as a `CacheStats` model (for `cache-stats`)."""
        entry_count = 0
        size_bytes = 0
        if self._cache is not None:
            try:
                entry_count = len(self._cache)
                size_bytes = self._cache.volume()
            except OSError as exc:
                logger.warning("Could not read cache stats: %s", exc)
        return CacheStats(
            enabled=self.enabled,
            directory=str(self.directory),
            entry_count=entry_count,
            size_bytes=size_bytes,
            hits=self._hits,
            misses=self._misses,
        )

    def close(self) -> None:
        if self._cache is not None:
            with contextlib.suppress(OSError):
                self._cache.close()
