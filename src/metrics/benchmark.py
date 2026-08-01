"""Benchmarking utilities: repeated-run timing for stable performance comparisons.

Used by the CLI's `--benchmark` flag to run the same operation multiple
times and report aggregate statistics (min/max/mean/median/stdev), which
is far more useful for comparing configurations (models, prompt
versions, hardware) than a single run's numbers — a single run can be
skewed by OS scheduling noise, cold caches, or model warm-up time.
"""

from __future__ import annotations

import statistics
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field


@dataclass
class BenchmarkResult:
    """Aggregate timing statistics across repeated runs of some operation."""

    label: str
    iterations: int
    durations_seconds: list[float] = field(default_factory=list)

    @property
    def min_seconds(self) -> float:
        return min(self.durations_seconds) if self.durations_seconds else 0.0

    @property
    def max_seconds(self) -> float:
        return max(self.durations_seconds) if self.durations_seconds else 0.0

    @property
    def mean_seconds(self) -> float:
        return statistics.mean(self.durations_seconds) if self.durations_seconds else 0.0

    @property
    def median_seconds(self) -> float:
        return statistics.median(self.durations_seconds) if self.durations_seconds else 0.0

    @property
    def stdev_seconds(self) -> float:
        if len(self.durations_seconds) < 2:
            return 0.0
        return statistics.stdev(self.durations_seconds)


async def run_benchmark[T](
    label: str,
    operation: Callable[[], Awaitable[T]],
    *,
    iterations: int,
) -> tuple[BenchmarkResult, list[T]]:
    """Run `operation` `iterations` times, timing each independently.

    Returns:
        A `(BenchmarkResult, results)` pair — the aggregate timing
        statistics, plus every individual call's return value in order
        (e.g. so a caller can also verify results were consistent across
        runs, not just fast).

    Raises:
        ValueError: If `iterations` is less than 1.
    """
    if iterations < 1:
        raise ValueError("iterations must be >= 1")

    durations: list[float] = []
    results: list[T] = []
    for _ in range(iterations):
        start = time.monotonic()
        result = await operation()
        durations.append(time.monotonic() - start)
        results.append(result)

    return BenchmarkResult(label=label, iterations=iterations, durations_seconds=durations), results
