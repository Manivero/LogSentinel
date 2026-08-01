"""Performance metrics collection and benchmarking.

Depends on `src.core` only (plus `src.analysis.cache` for reading a
`ResponseCache`'s own hit/miss counters).

- `collector.py` — `MetricsCollector`: times each pipeline stage and
  accumulates counts into a `PerformanceMetrics` (already fully modeled
  in `core/models.py`), computing derived rates once at the end via
  `finalize()`.
- `benchmark.py` — repeated-run timing utility for the CLI's
  `--benchmark` flag, producing min/max/mean/median/stdev statistics
  that are far more stable than a single run's numbers.
"""
