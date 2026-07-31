"""Rule-based (non-AI) security detection.

Depends on `src.core`, `src.utils`, and `src.parsing` (consumes `LogEntry`
objects produced by the parsing layer).

- `rules.py` — loads `DetectionRule` objects from YAML files (bundled
  defaults under `rules/`, or a user-supplied directory).
- `engine.py` — evaluates entries against loaded rules, including
  threshold/rate-based rules (e.g. brute-force detection).
- `context.py` — cross-log correlation: builds a `CrossLogContext` from
  all entries and detections in a single analysis run.

Rules are entirely data-driven (YAML, not Python), so extending detection
coverage never requires a code change — see `rules/auth.yaml`,
`rules/web.yaml`, `rules/network.yaml` for the bundled rule set.
"""
