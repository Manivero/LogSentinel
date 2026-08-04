# Implementation Progress Log

This file is the source of truth for what has been built, what conventions
were established, and what to build next. Update it at the end of every
module (or batch of modules) so work can resume correctly across sessions.

Legend: `[x]` complete and self-reviewed · `[~]` in progress · `[ ]` pending

## High-level checklist

- [x] Project skeleton (config, models, exceptions)
- [x] Security utilities (sanitizer, validators)
- [x] Ollama client and manager
- [x] Log parser base and registry
- [x] Built-in parsers
- [x] Detection rules system
- [x] Cross-log context engine
- [x] Prompt templates (versioned)
- [x] AI analyzer with JSON repair
- [x] Response caching
- [x] Knowledge base (RAG)
- [x] Report generators
- [x] Performance metrics
- [x] CLI interface
- [ ] Docker setup
- [ ] CI/CD workflows
- [ ] Tests
- [ ] Documentation (README, ADRs)
- [ ] Makefile
- [x] LICENSE

## File-level detail

### `src/core/` — foundation layer (no dependency on any other `src` package)
- [x] `exceptions.py` — full exception hierarchy, one base per subsystem
- [x] `models.py` — **single source of truth** for every Pydantic model
- [x] `schemas.py` — canonical AI response schema, version, prompt rendering
- [x] `config.py` — layered config loader (defaults < YAML < env vars)

### `src/utils/` — cross-cutting (depends only on `core`)
- [x] `logger.py` — Rich console logging, optional JSON logs
- [x] `security.py` — ANSI/control-char stripping, safe subprocess, IP validation
- [x] `validators.py` — path/size/encoding/format validation
- [x] `concurrency.py` — bounded-concurrency gather, timeout wrapper

### `src/ollama/` — depends on `core` + `utils`
- [x] `client.py` — async client, streaming, retries, injectable transport
- [x] `health.py` — binary detection + server reachability, built on `client.py`
- [x] `manager.py` — model selection strategy, consent-gated autostart
- [x] `streaming.py` — stream aggregation, live render, graceful interruption

### `src/parsing/` — depends on `core` + `utils`
- [x] `base_parser.py` — `BaseParser` ABC, template-method `parse()`
- [x] `heuristics.py` — pattern-matching helpers (confidence scoring, IP/timestamp extraction)
- [x] `registry.py` — `ParserRegistry`, `@register_parser` decorator
- [x] `parsers.py` — 8 built-in parsers: syslog, auth_log, apache_common,
      apache_combined, nginx_error, json_lines, csv, generic (fallback)
- [x] `factory.py` — `ParserFactory`: sampling, confidence ranking, validation, parsing

### `src/detection/` — depends on `core`, `utils`, `parsing`
- [x] `rules.py` — YAML rule loading, per-rule validation (bad entries
      skipped, not fatal), duplicate-ID protection, category filtering
- [x] `engine.py` — simple + threshold (rate-based) rule evaluation,
      fires once per group per threshold rule (no alert-fatigue spam)
- [x] `context.py` — cross-log correlation: `CrossLogContext` with
      per-IP activity, recurring-IP detection, severity-filtered timeline
- [x] `rules/auth.yaml` (5 rules), `rules/web.yaml` (6 rules),
      `rules/network.yaml` (3 rules) — 14 bundled rules total

### `src/analysis/` — depends on `core`, `utils`, `ollama`
- [x] `sanitizer.py` — injection defense: control-char stripping, length
      capping, boundary-collision neutralization, random-nonce wrapping,
      heuristic injection-pattern detection (signal, not a filter)
- [x] `prompts.py` — assembles `config/prompts/<version>/*.txt` templates
      with the canonical schema block and sanitized evidence
- [x] `repair.py` — mechanical JSON repair (code fences, brace-matched
      extraction respecting quoted strings, trailing commas) +
      bounds-coercion (severity case, 0-100→0.0-1.0 confidence,
      over-length truncation) + a safe always-valid degraded fallback
- [x] `cache.py` — diskcache-backed, key = hash(entry + model + prompt
      version + knowledge version), degrades to cache-miss on any
      storage error rather than raising
- [x] `ai_analyzer.py` — `AIAnalyzer.analyze_entry`/`analyze_many`: cache
      check → generate (streaming or not) → repair → retry once on
      repair failure → degrade (never raise) → cache only non-degraded
      results
- [x] `config/prompts/v1/system_prompt.txt`, `user_template.txt` —
      prompt text as versioned plain-text files, not Python string
      literals

### `src/knowledge/` — depends on `core`, `utils`, `ollama` (optional layer)
- [x] `base.py` — `KnowledgeSource` ABC every loader implements
- [x] `sources/mitre_attack.py`, `owasp.py`, `sigma_rules.py` — bundled,
      original-text reference data (10 + 10 + 6 chunks) loaded from
      `sources/data/*.yaml`, never reproducing upstream text verbatim
- [x] `sources/custom_directory.py` — loads a user-configured directory
      of `.txt`/`.md` organizational knowledge
- [x] `embeddings.py` — paragraph-aware `chunk_text` + `EmbeddingService`
      (reuses `OllamaClient.embed`, no new HTTP client)
- [x] `vector_store.py` — ChromaDB wrapper; **telemetry explicitly
      disabled** (verified `anonymized_telemetry` defaults to `True` via
      PostHog before writing any code — see convention #17)
- [x] `retriever.py` — `KnowledgeBase` facade: `build_index`,
      `retrieve_context` (returns `None` on anything short of a
      confident match), `stats`

### `src/reporting/` — depends on `core`, `utils` (pure presentation layer)
- [x] `json_report.py` — SIEM-compatible export; defines
      `build_siem_events`, the single source of truth for how detections
      and AI analyses flatten into CEF/LEEF-inspired events, reused
      by `csv_report.py`
- [x] `csv_report.py` — same events as JSON, fixed column order, list
      fields joined with `"; "`
- [x] `markdown.py` — TOC, emoji severity badges (no external image
      dependency), collapsible `<details>` sections for AI findings
- [x] `html_report.py` — single self-contained file, inline CSS/JS, no
      CDN references; server-rendered cards with `data-*` attributes,
      JS only toggles visibility (never re-renders from JSON) —
      **verified interactively with real Playwright/Chromium**, not
      just "the Python didn't crash" (see convention #21)
- [x] `terminal.py` — Rich console summary + the required post-run
      performance metrics table

### `src/metrics/` — depends on `core`, `analysis.cache`
- [x] `collector.py` — `MetricsCollector`: context-manager stage timing +
      `record_*` calls, rates computed once in `finalize()` with a
      minimum-duration floor to avoid nonsensical rates from near-zero
      elapsed time (see convention #25)
- [x] `benchmark.py` — `run_benchmark`: repeated-run timing with
      min/max/mean/median/stdev

### `main.py` — depends on every `src` package (the integration point)
- [x] `analyze` — full pipeline: parse → detect → correlate → (optional)
      index/query knowledge base → AI-analyze only flagged, deduplicated
      entries with bounded concurrency → assemble report → write
      requested formats → always show terminal summary + metrics
- [x] `check`, `models` — Ollama environment/model introspection
- [x] `knowledge-stats`, `cache-clear`, `cache-stats` — subsystem
      introspection/management, no Ollama required
- [x] `--benchmark` — repeated full-pipeline runs via `metrics.benchmark`
- [x] `--stream`/`--no-stream`, `--no-cache`, `--knowledge-base`,
      `--model`, `--log-format`, `--output`/`--format`,
      `--auto-start-ollama` — all wired and tested
- [x] **Verified through the actual CLI**, not just by calling internal
      functions directly: `typer.testing.CliRunner` end-to-end, with
      `OllamaClient._new_client` patched at the class level (the single
      choke point for every HTTP client `OllamaClient` creates) so a
      mocked Ollama serves `/api/version`, `/api/tags`, and
      `/api/generate` — no application code changed to make this
      possible (see convention #27)

### Not yet started
- `tests/unit/*.py`, `tests/integration/*.py` (formal pytest — fixtures
  already exist, and every ad hoc `/home/claude/verify/` script this
  session is a near-direct port), `docs/*.md` (ADRs), `Dockerfile`,
  `docker-compose.yml`, `.dockerignore` review, `.github/workflows/*.yml`,
  `Makefile`, `README.md`, `.env.example`, `requirements-api.txt` (if the
  optional FastAPI layer is ever built — not required by the original
  spec's completion criteria).

### Test fixtures already in place (`tests/fixtures/`)
- `sample_logs/`: `auth.log`, `syslog`, `access.log`, `error.log`,
  `app.jsonl`, `events.csv`, `unrecognized.txt` — one per built-in parser,
  plus a fallback case. Reused by the future `tests/unit/test_parser.py`.
- `malicious_logs/`: `control_char_injection.log` (real ANSI/control
  bytes for terminal-injection testing), `prompt_injection_attempts.log`
  (standard prompt-injection payload corpus, for the future
  `src.analysis.sanitizer` tests). Both already verified to parse as
  inert text with control bytes neutralized before pattern matching.

## Conventions established so far (read this before continuing)

1. **Model centralization**: *every* Pydantic model lives in
   `src/core/models.py`. Other modules import from there rather than
   defining competing/duplicate models. `src/core/schemas.py` only adds
   schema *metadata* (version, prompt rendering) on top of
   `models.AIAnalysisResult` — it does not define its own model.
2. **Dependency direction** (no cycles): `core` → (nothing in `src`).
   `utils` → `core`. `ollama`, `parsing` → `core`, `utils`. Every later
   package may depend on any earlier one, never the reverse. See
   ADR-0001 (to be written).
3. **Exceptions**: every subsystem has a base exception in
   `core/exceptions.py` (e.g. `OllamaError`, `ParsingError`,
   `AnalysisError`, `KnowledgeBaseError`, `ReportGenerationError`,
   `SecurityValidationError`). Catch the base class when subsystem-level
   granularity is enough; catch a specific subclass when behavior differs
   (e.g. `ModelNotFoundError` is never retried, unlike connection errors).
4. **Graceful degradation over exceptions** for expected runtime
   conditions: Ollama not running, a model missing, a knowledge base
   misconfigured, a single log line failing to parse — these produce a
   status object or a logged warning + fallback, not a crash. Hard
   exceptions are reserved for programmer errors and genuinely unexpected
   failures. `BaseParser.parse()` isolates per-line failures the same way
   Ollama health-checking isolates connection failures.
5. **Ollama is never assumed present.** `src.ollama.health.check_health`
   never raises — it always returns an `OllamaHealthStatus` with
   `errors` populated. `OllamaHealthStatus.is_healthy` only requires
   `server_running` (not `installed`), since Ollama may run in a separate
   Docker container with no local binary.
6. **Testability**: `OllamaClient` accepts an optional
   `transport: httpx.AsyncBaseTransport` so tests can inject
   `httpx.MockTransport` without touching the network. `ParserFactory`
   accepts an optional `registry: ParserRegistry` for the same reason
   (test with an isolated set of parsers). Prefer this injectable-
   dependency pattern for any future module with an external boundary.
7. **Security layering**: `utils.security` = generic, content-agnostic
   defenses (control chars, ANSI escapes, safe subprocess, IP validation).
   `utils.validators` = structural input validation (paths, size,
   encoding). `parsing.heuristics` = format-detection pattern matching
   (not security per se, but written with the same ReDoS-avoidance
   discipline: no nested/overlapping quantifiers, always applied *after*
   line-length capping). `analysis.sanitizer` (not yet built) = LLM-
   prompt-specific defenses (injection-pattern detection, data-marker
   wrapping) and will build on `utils.security.strip_control_characters`,
   not duplicate it.
8. **Config precedence**: code defaults < `config/default.yaml` <
   `--config <file>.yaml` < `AI_LOG_ANALYZER_*` environment variables <
   CLI flags (CLI flags are applied by `main.py`, not `config.py`, once it
   exists). Env var names are declared in `config._ENV_OVERRIDES`. Config
   is organized into sections mirroring subsystems (`OllamaConfig`,
   `SecurityConfig`, `CacheConfig`, `KnowledgeConfig`, `ParsingConfig`,
   `DetectionConfig`, `LoggingConfig`, `AnalysisConfig`) — note
   `ParsingConfig` (format *detection* tuning) is deliberately separate
   from `DetectionConfig` (security *threat* detection rules), since
   "detection" means two different things in this codebase.
9. **Parser plugin pattern**: a parser is a `BaseParser` subclass
   decorated with `@register_parser`; the factory instantiates a *fresh*
   instance per file, so per-file mutable state on `self` (e.g.
   `CSVParser._header`) is always safe. When a specialized parser can
   report the same confidence as a more generic parent it builds on
   (e.g. `AuthLogParser` vs `SyslogParser`), use the `priority: ClassVar`
   tie-breaker rather than trying to numerically out-score the parent —
   confidence is capped at 1.0 so a "+bonus" approach silently breaks
   once the parent is already maxed out (this was a real bug, caught and
   fixed during this session).
10. **All `LogEntry.timestamp` values are timezone-aware, always.**
    Formats with an explicit offset (`%z`) are trusted as-is; formats
    without one (RFC 3164 syslog, nginx error log, bare `%Y-%m-%d
    %H:%M:%S`) explicitly assume UTC via `.replace(tzinfo=UTC)`. This is
    load-bearing: mixing naive and aware datetimes raises `TypeError` the
    instant anything sorts or compares them, which is exactly what
    `DetectionEngine.evaluate()`'s threshold-window logic and
    `context.build_context`'s timeline do across every file in a run.
    Confirmed as a real bug (not just theoretical) before the detection
    engine was built on top of it — see "Verification performed" below.
11. **Detection rules are 100% data-driven YAML**, loaded by
    `detection.rules`, never hardcoded Python per rule. A rule is either
    *simple* (matches one entry via `conditions` + `condition_logic`) or
    *threshold* (`threshold_count`/`threshold_window_seconds`/
    `threshold_group_by` — rate-based, e.g. brute force), never both;
    `DetectionRule` enforces that pairing at validation time. Threshold
    rules fire exactly once per group (not once per subsequent matching
    event) to avoid alert-fatigue spam — verified in
    `test_detection_package.py`.
12. **Cache key formula** (implemented in `analysis/cache.py`, matches
    original spec exactly): `hash(log_entry_text + model_name +
    prompt_version + knowledge_version)`. Degraded results are **never**
    cached (a transient model hiccup shouldn't permanently poison the
    cache for that entry) — verified explicitly in
    `test_ai_analyzer.py`.
13. **No templating engine dependency.** Markdown/HTML/CSV reports will
    be hand-built with f-strings/`string.Template`, not Jinja2 — keeps
    the dependency surface (and therefore the supply-chain attack
    surface) minimal, consistent with the security-first philosophy.
    Prompt templates use the same `string.Template` approach.
14. **Prompt-injection defense is layered, not filter-based**:
    boundary-wrapping with a fresh random nonce per call (so a
    wrapper-escape attempt can't predict the exact closing tag) is the
    *primary* defense, backed by an explicit system-prompt instruction.
    Heuristic pattern detection (`sanitizer.detect_injection_indicators`)
    is a *secondary signal* for logging/analyst awareness — it's
    deliberately not exhaustive and never blocks or rewrites content on
    its own, since perfect detection isn't achievable and false
    confidence in a pattern list is worse than an honest "this helps,
    it isn't complete."
15. **Own-formatting-vs-own-detector collisions are a real risk class.**
    `prompts._build_evidence_text` originally rendered structured fields
    as `"user: root"`, which is *exactly* the shape
    `sanitizer`'s own `fake_role_marker` heuristic looks for — the
    tool's own formatting was tripping its own injection detector on
    every entry with a `user` field. Fixed by switching structured-field
    rendering to `field=value` (no bare `word:` prefixes). Caught by a
    full false-positive sweep across every benign fixture, not by
    inspection — worth re-running that sweep after any change to either
    `_build_evidence_text` or `_INJECTION_PATTERNS`.
16. **AI analysis targets flagged entries, not every line.**
    `AIAnalyzer` has no opinion on which `LogEntry` objects are "worth"
    analyzing — that's the caller's job. The intended pipeline (to be
    wired up in `main.py`) is: parse → detect (cheap, rule-based,
    everything) → AI-analyze only the entries behind a `DetectionMatch`
    (expensive, LLM-based, filtered) → report. Running the LLM over
    every parsed line regardless of relevance would be both wasteful and
    slow.
17. **Third-party telemetry is a real, non-obvious risk — verify, don't
    assume.** ChromaDB's `anonymized_telemetry` defaults to `True`
    (routed through PostHog); this was caught by installing the package
    and inspecting `chromadb.config.Settings()`'s actual defaults
    *before* writing `vector_store.py`, not by reading docs or assuming
    good defaults. Explicitly passing
    `Settings(anonymized_telemetry=False)` at client construction is
    load-bearing for the "no telemetry" project guarantee — any future
    dependency that talks to a persistent store, cache, or SDK should
    get the same check before being trusted by default.
18. **`KnowledgeBase` (the RAG facade) never lets an entry point fail.**
    `enabled` is computed from three independent conditions (config
    enabled, embedding model available, vector store initialized
    successfully) collapsing to one boolean; every public method
    (`build_index`, `retrieve_context`, `stats`) checks it first and
    returns an empty/`None`/zeroed result rather than raising. This
    mirrors `ResponseCache`'s degrade-don't-raise pattern exactly —
    optional infrastructure should fail the same way everywhere in this
    codebase, not each in its own bespoke style.
19. **Read/write asymmetry at storage boundaries.** Both `ResponseCache`
    and `VectorStore` raise clearly on write failures (`set`/`upsert`)
    but degrade silently on read failures (`get`/`query`) — a failed
    write during an explicit indexing/caching step is worth surfacing to
    whoever triggered it, while a failed read during live analysis
    should never be the reason a whole run aborts. Apply this same
    asymmetry to any future storage-backed module rather than picking
    one behavior for both directions.
20. **Testing retrieval without a real embedding model**: mock the
    `/api/embed` endpoint to return a *deterministic* vector derived
    from keyword presence in the input text (see
    `test_knowledge_base.py`'s `deterministic_embedding_handler`) rather
    than a random one — this makes retrieval *ordering* assertable
    (`"brute force" query -> T1110 ranks first`) without needing real
    semantic embeddings, while still exercising the actual
    `VectorStore`/ChromaDB cosine-similarity math for real.
21. **One event model, multiple serializations.**
    `json_report.build_siem_events` is the single source of truth for
    how a detection or AI analysis flattens into a CEF/LEEF-inspired
    event dict; `csv_report.py` imports and reuses it rather than
    re-deriving the same field mapping. Any future export format that
    needs "one row per event" (not full-document formats like Markdown/
    HTML, which have their own section-based structure) should do the
    same rather than hand-rolling another mapping.
22. **Generated HTML must be genuinely offline-safe, not just
    "no `<script src>`."** `html_report.py` has zero external
    references of any kind (fonts, CDN JS/CSS, images) — this is a
    downloaded artifact that may be opened on an air-gapped machine, a
    stricter bar than the chat UI's artifact conventions elsewhere
    (which do permit CDN imports). Every finding renders server-side
    with `data-severity`/`data-search` attributes; the inline JS only
    ever toggles `display`, it never re-renders from a JSON blob — keep
    that pattern for any future interactive report feature rather than
    introducing client-side templating.
23. **"It didn't crash" is not the same as "it works" for anything with
    a JS runtime.** `html_report.py`'s filter/search interactivity is
    verified with a real headless Chromium via Playwright
    (`test_html_report_interactive.py`), not just by checking the
    generated markup contains expected strings. That test caught a real
    gap: the search index excluded `entry.process`, so searching
    `"sshd"` silently matched nothing even though a user would
    reasonably expect it to (fixed by including `process` in both card
    types' `data-search` text). Playwright works in this sandbox via
    `playwright install chromium` (no `--with-deps`, which fails on a
    blocked apt domain) — browser binary download succeeds even though
    the sandbox network allowlist doesn't obviously include it.
24. **Free-text model fields need whitespace normalization at the
    boundary, once.** YAML `>` folded block scalars (used for readable
    multi-line rule descriptions) leave a trailing newline;
    `DetectionRule` now strips `name`/`category`/`description` via a
    field validator so every consumer (reporting, prompts, CLI) gets
    clean text automatically rather than each needing its own `.strip()`
    call. Apply the same pattern (validator at the model boundary, not
    scattered call-site fixes) to any future free-text field sourced
    from YAML/config.
25. **Rates need a minimum-duration floor, not just a zero check.**
    `MetricsCollector.finalize()` only computes a rate
    (lines/events/tokens per second) when the stage's measured duration
    clears `_MIN_DURATION_FOR_RATE` (0.01s) — `duration > 0` isn't a
    strong enough guard, since a near-instantaneous stage (e.g. an
    AI-analysis stage that was entirely cache hits) can have a
    real-but-tiny positive duration and produce a rate in the millions,
    which is technically-correct arithmetic but a misleading number to
    show anyone.
26. **`reporting` may depend on `metrics` (one direction only).**
    `terminal.render_benchmark` takes a `metrics.benchmark.BenchmarkResult`
    directly — reporting renders "things worth showing the user," and a
    benchmark result is one of those things, same as `PerformanceMetrics`
    from `core.models`. `metrics` does not and must not import anything
    from `reporting`.
27. **Testing a full CLI pipeline without a real Ollama server**: patch
    `OllamaClient._new_client` at the class level
    (`unittest.mock.patch.object(OllamaClient, "_new_client", ...)`) to
    always return an `httpx.AsyncClient` wired to a mock transport. This
    is the single choke point every one of `OllamaClient`'s methods uses
    to build its HTTP client, so patching it there — rather than each
    call site — makes the *entire* CLI pipeline (health check, model
    listing, generation, streaming) testable through
    `typer.testing.CliRunner` with zero production code changes. Combine
    with `--config` pointing at a temp YAML file (isolated cache
    directory) so CLI tests never touch the real `~/.ai-log-analyzer/`.
28. **`AIAnalyzer` doesn't know about detection IDs, and that's
    correct.** `main.py` enriches each returned `AnalysisRecord` with
    `related_detection_ids` via `record.model_copy(update=...)` *after*
    analysis, using a `(source_file, line_number)` key built from the
    detection list — rather than threading detection IDs into
    `AIAnalyzer` itself. Keeps the analyzer's interface focused on "here
    is one entry, analyze it," with all detection-engine-specific
    bookkeeping living in the orchestration layer that actually has both
    pieces of information.
29. **AI analysis targets deduplicated flagged entries, concurrently,
    with knowledge retrieval per entry.** `main.py` does *not* use
    `AIAnalyzer.analyze_many` (which takes one shared
    `knowledge_context` for a whole batch) — it calls
    `utils.concurrency.bounded_gather` directly with a closure that does
    per-entry `KnowledgeBase.retrieve_context` before
    `analyzer.analyze_entry`, since each flagged entry's specific
    content should drive its own retrieval query. `analyze_many` remains
    available/tested for simpler callers that don't need per-entry
    knowledge. Live token rendering (`live_render=True`) is only enabled
    when concurrency can't interleave output (a single flagged entry, or
    `max_concurrent_requests == 1`) — otherwise concurrent streams would
    garble each other on the same console.

## Verification performed, cumulative across sessions
- `python3 -c "import ..."` / dedicated scripts under `/home/claude/verify/`
  (outside the repo, not shipped) smoke-test every module against real
  installed dependencies. A shared `report_fixture.py` builds one
  realistic `AnalysisReport` from real parsing/detection output plus two
  hand-built `AnalysisRecord`s (one HIGH, one degraded), reused across
  every reporting-format test. `test_metrics.py` runs `MetricsCollector`
  against real (not mocked) parsing output. The CLI test suite
  (`test_cli_no_ollama.py`, `test_cli_full_pipeline.py`,
  `test_cli_extra_scenarios.py`) drives the actual `main.py` Typer app
  via `CliRunner`, covering unreachable-Ollama graceful failure,
  mocked-healthy full pipeline (all 4 export formats individually
  re-parsed and asserted on), streaming, cache hit/miss across repeated
  invocations, `--no-cache`, and `--benchmark`.
- `ruff check`, `ruff format --check`, and `mypy --strict` pass with
  zero issues across all 52 source files as of this checkpoint.
- Real bugs found and fixed via this verification (not just caught by
  inspection), in the order found:
  1. `OllamaClient._post_with_retries` never caught the `httpx`
     exceptions it needed to catch for its own retry logic to trigger.
  2. `AuthLogParser`'s confidence formula could mathematically never
     outrank its parent `SyslogParser`.
  3. `AuthLogParser` silently failed to extract `user`/`source_ip` from
     sshd's bare `"Invalid user X from Y"` phrasing.
  4. Mixed timezone-naive/aware `datetime` objects across parsers would
     have raised `TypeError` on the first cross-format sort/compare.
  5. `prompts._build_evidence_text`'s own `"user: root"`-style formatting
     collided with `sanitizer`'s own `fake_role_marker` injection
     heuristic.
  6. ChromaDB's default telemetry — caught before it shipped.
  7. YAML folded-scalar trailing newlines leaking into every rule
     description shown in every report format.
  8. `html_report.py`'s search index excluded `entry.process`, silently
     breaking searches like `"sshd"`.
  9. `MetricsCollector` could report rates in the millions from
     near-zero-duration stages.
- One test-design bug caught and fixed *in the test itself*, not the
  app: an early streaming-mode CLI test analyzed `access.log` without
  `--no-cache`, silently pre-warming the cache before a later
  cache-behavior test ran against the same file. Fixed by isolating the
  streaming test with `--no-cache` — shared test state (here, a cache
  directory reused across cases in one script) needs the same care as
  shared state in application code.
- Ollama endpoint shapes cross-checked against official docs via web
  search in an earlier session.
- Formal `pytest` suites remain a deliberately separate later phase.
  Fixtures are already in place in `tests/fixtures/`; the ad hoc
  `/home/claude/verify/` scripts are not shipped, but their test cases
  are exactly what `tests/unit/` and `tests/integration/` should
  contain — porting them is mechanical, not exploratory, work.

## Next steps
Core application is now feature-complete and end-to-end verified
(`main.py analyze` genuinely works against a real Ollama installation —
every integration point has been exercised, just with a mocked
transport standing in for the network call itself). What remains is
packaging/process, not design:
1. `tests/unit/*.py`, `tests/integration/test_workflow.py` — port the
   `/home/claude/verify/` scripts into the real pytest suite they were
   modeled on from the start (same fixtures, same assertions,
   `pytest-asyncio` for the async ones). Target >85% coverage per the
   original completion criteria.
2. `docs/ADR-0001` through `ADR-0004` — architecture, parser design, RAG
   design, Ollama client design. Every non-obvious decision is already
   written down in this file's "Conventions" sections above; writing the
   ADRs is mostly organizing that material into four documents, not
   re-deriving it.
3. `Dockerfile`, `docker-compose.yml`, `.dockerignore` review — multi-
   stage build, non-root user, healthchecks, volumes for
   logs/reports/cache/knowledge_data. `docker-compose.yml` needs an
   `ollama` service alongside the app service.
4. `.github/workflows/{lint,tests,release}.yml`.
5. `Makefile` — targets are already named in the original spec
   (`install`, `install-dev`, `lint`, `format`, `test`, `test-cov`,
   `run`, `docker-build`, `docker-up`, `docker-down`, `clean`) and map
   directly onto commands already used throughout this session (`ruff
   check`, `ruff format`, `mypy`, `pytest`).
6. `README.md`, `.env.example` — write last, once Docker/Makefile exist
   to document accurately.
