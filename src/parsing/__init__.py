"""Log format parsing: a plugin architecture for turning raw log files into
normalized `LogEntry` records.

Depends on `src.core` and `src.utils` only.

- `base_parser.BaseParser` — the plugin interface every parser implements.
- `heuristics` — reusable pattern-matching helpers used to score format
  matches and to extract best-effort structure in the generic fallback.
- `registry` — decouples "which parsers exist" from "which one wins";
  new parsers register themselves and need no other code changes.
- `parsers` — the built-in parser implementations.
- `factory.ParserFactory` — the orchestration entry point: sample, score,
  select, validate, parse.

See ADR-0002 for the design rationale.
"""
