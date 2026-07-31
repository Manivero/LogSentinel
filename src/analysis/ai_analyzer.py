"""Model-agnostic AI security analysis.

Ties together the Ollama client, prompt construction, JSON repair, and
response caching into a single `analyze_entry` / `analyze_many` entry
point. Model-agnostic by construction: nothing here ever references a
specific model name — `model_name` always comes from
`src.ollama.manager.select_model`, applied by the caller (typically the
CLI), never hardcoded.

This module decides *when* to analyze, cache, retry, and degrade; it
never decides *which* entries are worth analyzing in the first place —
that's an orchestration decision for the caller. In the intended usage,
the caller is the CLI, and it passes entries flagged by
`src.detection.engine.DetectionEngine` (plus optionally a
`CrossLogContext`) rather than every single parsed line, since running an
LLM over an entire firehose of benign log lines would be both wasteful
and slow — the rule engine's job is exactly to filter that firehose down
to what's worth a closer, AI-assisted look.
"""

from __future__ import annotations

import time
from collections.abc import Sequence
from dataclasses import dataclass

from src.analysis.cache import ResponseCache, compute_cache_key
from src.analysis.prompts import build_analysis_prompt
from src.analysis.repair import build_degraded_result, repair_and_validate
from src.core.exceptions import JSONRepairError, OllamaConnectionError, OllamaError
from src.core.models import AnalysisRecord, CrossLogContext, LogEntry
from src.core.schemas import AI_RESPONSE_SCHEMA_VERSION
from src.ollama.client import OllamaClient
from src.ollama.streaming import consume_stream
from src.utils.concurrency import bounded_gather
from src.utils.logger import get_logger

logger = get_logger("analysis.ai_analyzer")


@dataclass
class AnalyzerSettings:
    """Behavioral configuration for one `AIAnalyzer` instance.

    Deliberately a plain dataclass, not `AppConfig` itself: an analyzer
    only needs these seven values, and taking them explicitly keeps this
    module decoupled from the full configuration tree (easier to
    construct in tests, easier to reason about what actually affects
    analysis behavior).
    """

    model_name: str
    prompt_version: str = "v1"
    knowledge_version: str = "none"
    use_cache: bool = True
    stream: bool = False
    live_render: bool = False
    max_retries_on_repair_failure: int = 1


class AIAnalyzer:
    """Analyzes individual log entries using a local Ollama model."""

    def __init__(
        self,
        client: OllamaClient,
        settings: AnalyzerSettings,
        *,
        cache: ResponseCache | None = None,
    ) -> None:
        self._client = client
        self._settings = settings
        self._cache = cache

    async def analyze_entry(
        self,
        entry: LogEntry,
        *,
        cross_log_context: CrossLogContext | None = None,
        knowledge_context: str | None = None,
    ) -> AnalysisRecord:
        """Analyze a single log entry, using the cache when possible.

        Never raises for AI-side failures: after repair and one retry
        (configurable via `AnalyzerSettings.max_retries_on_repair_failure`),
        an unrecoverable response degrades to a low-confidence
        `AnalysisRecord` (see `src.analysis.repair.build_degraded_result`)
        rather than propagating an exception, so one bad entry — or one
        struggling model — can never abort an entire analysis run.
        Degraded results are never cached, so a transient failure doesn't
        permanently poison the cache for that entry.
        """
        cache_key = compute_cache_key(
            log_entry_text=entry.raw_line,
            model_name=self._settings.model_name,
            prompt_version=self._settings.prompt_version,
            knowledge_version=self._settings.knowledge_version,
        )

        if self._settings.use_cache and self._cache is not None:
            cached = self._cache.get(cache_key)
            if cached is not None:
                logger.debug("Cache hit for entry at %s:%d", entry.source_file, entry.line_number)
                return cached.model_copy(update={"from_cache": True})

        record = await self._analyze_uncached(entry, cross_log_context, knowledge_context)

        if self._settings.use_cache and self._cache is not None and not record.degraded:
            self._cache.set(cache_key, record)

        return record

    async def analyze_many(
        self,
        entries: Sequence[LogEntry],
        *,
        max_concurrency: int,
        cross_log_context: CrossLogContext | None = None,
        knowledge_context: str | None = None,
    ) -> list[AnalysisRecord]:
        """Analyze many entries with bounded concurrency (see `utils.concurrency`).

        A single entry's failure never aborts the batch — `analyze_entry`
        already degrades gracefully on its own, so this just fans work
        out and preserves input order in the result.
        """

        async def worker(entry: LogEntry) -> AnalysisRecord:
            return await self.analyze_entry(
                entry, cross_log_context=cross_log_context, knowledge_context=knowledge_context
            )

        return await bounded_gather(list(entries), worker, max_concurrency=max_concurrency)

    async def _analyze_uncached(
        self,
        entry: LogEntry,
        cross_log_context: CrossLogContext | None,
        knowledge_context: str | None,
    ) -> AnalysisRecord:
        prompt = build_analysis_prompt(
            entry,
            version=self._settings.prompt_version,
            cross_log_context=cross_log_context,
            knowledge_context=knowledge_context,
        )
        if prompt.injection_indicators:
            logger.info(
                "Prompt-injection indicator(s) detected in entry at %s:%d: %s",
                entry.source_file,
                entry.line_number,
                prompt.injection_indicators,
            )

        start = time.monotonic()
        attempts = self._settings.max_retries_on_repair_failure + 1
        last_raw_response = ""
        last_error = "unknown error"

        for attempt in range(attempts):
            try:
                raw = await self._generate(prompt.system, prompt.user)
            except OllamaError as exc:
                last_error = str(exc)
                logger.warning(
                    "Ollama request failed for entry at %s:%d (attempt %d/%d): %s",
                    entry.source_file,
                    entry.line_number,
                    attempt + 1,
                    attempts,
                    exc,
                )
                continue

            last_raw_response = raw
            try:
                result = repair_and_validate(raw)
            except JSONRepairError as exc:
                last_error = str(exc)
                logger.warning(
                    "JSON repair failed for entry at %s:%d (attempt %d/%d): %s",
                    entry.source_file,
                    entry.line_number,
                    attempt + 1,
                    attempts,
                    exc,
                )
                continue

            return AnalysisRecord(
                result=result,
                log_entry=entry,
                model_name=self._settings.model_name,
                prompt_version=self._settings.prompt_version,
                schema_version=AI_RESPONSE_SCHEMA_VERSION,
                latency_ms=(time.monotonic() - start) * 1000,
                from_cache=False,
                degraded=False,
                knowledge_context_used=knowledge_context is not None,
            )

        logger.error(
            "Analysis failed for entry at %s:%d after %d attempt(s); returning a "
            "degraded result: %s",
            entry.source_file,
            entry.line_number,
            attempts,
            last_error,
        )
        degraded_result = build_degraded_result(
            reason=last_error, raw_response_preview=last_raw_response
        )
        return AnalysisRecord(
            result=degraded_result,
            log_entry=entry,
            model_name=self._settings.model_name,
            prompt_version=self._settings.prompt_version,
            schema_version=AI_RESPONSE_SCHEMA_VERSION,
            latency_ms=(time.monotonic() - start) * 1000,
            from_cache=False,
            degraded=True,
            knowledge_context_used=knowledge_context is not None,
        )

    async def _generate(self, system: str, user: str) -> str:
        """Run one generation, branching on streaming vs non-streaming.

        Both paths converge on plain text so the repair/validation logic
        above never needs to know which mode produced it. A stream that
        is interrupted with no usable output at all is treated as a
        connection failure (raises `OllamaConnectionError`), so it flows
        through the same retry loop as any other transient Ollama error.
        """
        if not self._settings.stream:
            return await self._client.generate(
                model=self._settings.model_name,
                prompt=user,
                system=system,
                response_format="json",
            )

        chunks = self._client.generate_stream(
            model=self._settings.model_name,
            prompt=user,
            system=system,
            response_format="json",
        )
        stream_result = await consume_stream(chunks, live_render=self._settings.live_render)
        if not stream_result.text:
            raise OllamaConnectionError(
                stream_result.error or "Streaming response produced no output"
            )
        return stream_result.text
