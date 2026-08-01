"""Performance metrics collection across pipeline stages.

`MetricsCollector` accumulates raw counts as each pipeline stage runs
(via context managers that time the stage, plus explicit `record_*`
calls for what happened during it) and computes derived rates
(lines/sec, events/sec, tokens/sec) once at the end via `finalize()` —
never incrementally, since a stage's duration is only fully known once
its `with` block exits.

Token counts are approximated from response text length (chars / 4),
matching the same heuristic `src.ollama.streaming.StreamResult` uses for
live streaming metrics — Ollama does not report exact per-request token
counts in a model-agnostic way, so an approximation keeps this feature
useful without hardcoding any particular model's tokenizer.
"""

from __future__ import annotations

import time
from collections.abc import Iterator
from contextlib import contextmanager

from src.analysis.cache import ResponseCache
from src.core.models import AnalysisRecord, DetectionMatch, ParseResult, PerformanceMetrics

# Below this, elapsed time is dominated by timer resolution/scheduling
# noise rather than real work; see `finalize()`.
_MIN_DURATION_FOR_RATE = 0.01


class MetricsCollector:
    """Accumulates counts and stage durations into a `PerformanceMetrics`."""

    def __init__(self) -> None:
        self._metrics = PerformanceMetrics()
        self._wall_start: float | None = None

    def start(self) -> None:
        """Mark the start of the whole run, for total wall-clock time."""
        self._wall_start = time.monotonic()

    @contextmanager
    def time_parsing(self) -> Iterator[None]:
        start = time.monotonic()
        try:
            yield
        finally:
            self._metrics.parsing.duration_seconds += time.monotonic() - start

    @contextmanager
    def time_detection(self) -> Iterator[None]:
        start = time.monotonic()
        try:
            yield
        finally:
            self._metrics.detection.duration_seconds += time.monotonic() - start

    @contextmanager
    def time_ai_analysis(self) -> Iterator[None]:
        start = time.monotonic()
        try:
            yield
        finally:
            self._metrics.ai.duration_seconds += time.monotonic() - start

    @contextmanager
    def time_reporting(self) -> Iterator[None]:
        start = time.monotonic()
        try:
            yield
        finally:
            self._metrics.reporting.duration_seconds += time.monotonic() - start

    def record_parse_result(self, result: ParseResult) -> None:
        self._metrics.parsing.files_parsed += 1
        self._metrics.parsing.total_lines += result.total_lines

    def record_detections(self, matches: list[DetectionMatch], *, rules_evaluated: int) -> None:
        self._metrics.detection.events_detected += len(matches)
        self._metrics.detection.rules_evaluated = rules_evaluated

    def record_ai_analysis(self, record: AnalysisRecord) -> None:
        self._metrics.ai.requests_made += 1
        if record.degraded:
            self._metrics.ai.degraded_results += 1
        approx_tokens = max(1, len(record.result.detailed_analysis + record.result.summary) // 4)
        self._metrics.ai.tokens_generated += approx_tokens

    def record_cache_stats(self, cache: ResponseCache) -> None:
        """Copy hit/miss counts from the cache's own authoritative counters.

        `ResponseCache` already tracks this correctly; this avoids a
        second, potentially-drifting count derived from
        `AnalysisRecord.from_cache` per record.
        """
        self._metrics.ai.cache_hits = cache.hits
        self._metrics.ai.cache_misses = cache.misses

    def record_reporting(self, formats: list[str]) -> None:
        self._metrics.reporting.formats_generated = formats

    def finalize(self) -> PerformanceMetrics:
        """Compute derived rates and total wall-clock time, and return the result.

        Rates are only computed when a stage's duration clears
        `_MIN_DURATION_FOR_RATE`; below that, elapsed time is dominated
        by timer resolution and scheduling noise rather than real work,
        and dividing by it produces a huge, misleading rate (e.g. an
        analysis served entirely from cache can complete in
        microseconds) rather than 0.0 or an omitted rate.

        Safe to call more than once (e.g. to peek at metrics before a
        run fully completes); each call recomputes rates from current
        totals rather than mutating them further.
        """
        parsing = self._metrics.parsing
        if parsing.duration_seconds > _MIN_DURATION_FOR_RATE:
            parsing.lines_per_second = parsing.total_lines / parsing.duration_seconds

        detection = self._metrics.detection
        if detection.duration_seconds > _MIN_DURATION_FOR_RATE:
            detection.events_per_second = detection.events_detected / detection.duration_seconds

        ai = self._metrics.ai
        if ai.duration_seconds > _MIN_DURATION_FOR_RATE:
            ai.tokens_per_second = ai.tokens_generated / ai.duration_seconds

        if self._wall_start is not None:
            self._metrics.total_wall_time_seconds = time.monotonic() - self._wall_start

        return self._metrics
