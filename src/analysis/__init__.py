"""AI-powered security analysis of individual log entries.

Depends on `src.core`, `src.utils`, and `src.ollama` (never `src.parsing`
or `src.detection` directly — this package receives already-parsed
`LogEntry` objects and optional `CrossLogContext`, it doesn't produce
them).

- `sanitizer.py` — prompt-injection defense: every log entry is
  untrusted data, wrapped in randomized boundary markers before it ever
  reaches a prompt.
- `prompts.py` — versioned prompt assembly (templates live in
  `config/prompts/<version>/`, not as Python string literals).
- `repair.py` — mechanical JSON repair and schema validation for
  imperfect model output.
- `cache.py` — prompt-version-aware response caching.
- `ai_analyzer.py` — ties the above together with
  `src.ollama.client.OllamaClient` into a single `analyze_entry` /
  `analyze_many` entry point.
"""
