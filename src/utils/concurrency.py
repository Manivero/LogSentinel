"""Async concurrency helpers for batch processing.

Provides a semaphore-bounded task runner so the application never exceeds
the configured number of concurrent Ollama requests (or other bounded
resources), regardless of how many log entries need analysis.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Sequence

from src.utils.logger import get_logger

logger = get_logger("utils.concurrency")


async def bounded_gather[T, R](
    items: Sequence[T],
    worker: Callable[[T], Awaitable[R]],
    *,
    max_concurrency: int,
    on_error: Callable[[T, Exception], R] | None = None,
) -> list[R]:
    """Run `worker(item)` for every item with at most `max_concurrency` in flight.

    Preserves input order in the returned list. If `on_error` is provided,
    exceptions from `worker` are caught per-item and converted to a
    fallback result via `on_error(item, exception)` rather than aborting
    the whole batch — this is what lets one malformed log entry or one
    failed AI request degrade gracefully instead of crashing an entire run.

    Args:
        items: The items to process.
        worker: An async callable applied to each item.
        max_concurrency: Maximum number of `worker` coroutines running at once.
        on_error: Optional handler converting an exception into a fallback
            result of type `R`. If omitted, exceptions propagate and cancel
            the batch (via `asyncio.gather`'s default behavior).

    Returns:
        Results in the same order as `items`.

    Raises:
        ValueError: If `max_concurrency` is less than 1.
    """
    if max_concurrency < 1:
        raise ValueError("max_concurrency must be >= 1")

    semaphore = asyncio.Semaphore(max_concurrency)

    async def _run(item: T) -> R:
        async with semaphore:
            try:
                return await worker(item)
            except Exception as exc:
                if on_error is not None:
                    logger.warning("Task failed, using fallback result: %s", exc)
                    return on_error(item, exc)
                raise

    return await asyncio.gather(*(_run(item) for item in items))


async def run_with_timeout[R](
    coro: Awaitable[R],
    *,
    timeout_seconds: float,
    timeout_message: str = "Operation timed out",
) -> R:
    """Await `coro` with a timeout, raising `TimeoutError(timeout_message)`.

    Thin wrapper around `asyncio.timeout` for a consistent error message
    across the codebase.

    Raises:
        TimeoutError: If `coro` does not complete within `timeout_seconds`.
    """
    try:
        async with asyncio.timeout(timeout_seconds):
            return await coro
    except TimeoutError as exc:
        raise TimeoutError(timeout_message) from exc
