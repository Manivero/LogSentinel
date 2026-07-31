"""Streaming response aggregation and live console rendering.

`src.ollama.client.OllamaClient.generate_stream` yields raw text chunks.
This module wraps that stream to (a) accumulate the full response, (b)
optionally render tokens live to the terminal via Rich, (c) track basic
timing for the tokens/sec performance metric, and (d) degrade gracefully
if the user interrupts mid-stream — returning whatever was collected
rather than losing it.
"""

from __future__ import annotations

import time
from collections.abc import AsyncIterator
from dataclasses import dataclass

from rich.console import Console

from src.core.exceptions import OllamaError
from src.utils.logger import get_logger

logger = get_logger("ollama.streaming")


@dataclass
class StreamResult:
    """Outcome of consuming a streamed generation."""

    text: str
    chunk_count: int
    duration_seconds: float
    interrupted: bool = False
    error: str | None = None

    @property
    def approx_tokens(self) -> int:
        """Rough token estimate (chars / 4) used only for the tokens/sec metric.

        This is a heuristic, not a real tokenizer count — Ollama does not
        return exact generated-token counts on `/api/generate` stream
        chunks in a model-agnostic way, so an approximation keeps the
        performance-metrics feature useful without hardcoding any
        particular model's tokenizer.
        """
        return max(1, len(self.text) // 4)

    @property
    def tokens_per_second(self) -> float:
        if self.duration_seconds <= 0:
            return 0.0
        return self.approx_tokens / self.duration_seconds


async def consume_stream(
    stream: AsyncIterator[str],
    *,
    live_render: bool = False,
    console: Console | None = None,
) -> StreamResult:
    """Consume a text-chunk stream into a `StreamResult`.

    Args:
        stream: An async iterator of text chunks, e.g. from
            `OllamaClient.generate_stream`.
        live_render: If True, print each chunk to `console` as it arrives.
        console: Rich console to render to when `live_render` is True;
            defaults to a new `Console(stderr=True)` so live token output
            never contaminates piped stdout (e.g. `--format json > file`).

    Returns:
        A `StreamResult` with whatever text was collected, even if the
        user interrupted the stream (Ctrl+C) partway through. Genuine
        `asyncio.CancelledError` cancellation is intentionally NOT caught
        here and propagates normally, per asyncio cancellation semantics.
    """
    render_console = console or Console(stderr=True)
    chunks: list[str] = []
    chunk_count = 0
    interrupted = False
    error_message: str | None = None
    start = time.monotonic()

    try:
        async for chunk in stream:
            chunks.append(chunk)
            chunk_count += 1
            if live_render:
                render_console.print(chunk, end="", markup=False, highlight=False)
    except OllamaError as exc:
        interrupted = True
        error_message = str(exc)
        logger.warning("Stream interrupted: %s", exc)
    except KeyboardInterrupt:
        interrupted = True
        error_message = "Stream interrupted by user (Ctrl+C)"
        logger.info("Stream interrupted by user.")
    finally:
        if live_render and chunks:
            render_console.print()  # final newline after streamed tokens

    duration = time.monotonic() - start
    return StreamResult(
        text="".join(chunks),
        chunk_count=chunk_count,
        duration_seconds=duration,
        interrupted=interrupted,
        error=error_message,
    )
