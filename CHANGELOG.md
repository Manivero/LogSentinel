# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial project scaffolding: directory layout, packaging (`pyproject.toml`,
  `requirements.txt`), MIT license, changelog, and version file.
- Custom exception hierarchy for every subsystem (`src/core/exceptions.py`).
- Core domain models covering log entries, parse results, rule-based
  detections, the canonical AI analysis schema, cross-log correlation
  context, Ollama metadata, knowledge-base records, performance metrics,
  and the aggregate report (`src/core/models.py`).
- Canonical AI response JSON Schema, semantic versioning, and a
  prompt-ready rendering of the schema (`src/core/schemas.py`).
- Layered configuration system — code defaults < bundled `config/default.yaml`
  < user config file < environment variables (`src/core/config.py`).
- Security and validation utilities: ANSI/control-character stripping
  (terminal-injection defense), safe subprocess execution, path-traversal-safe
  file validation, size/encoding checks, and export-format validation
  (`src/utils/`).
- Structured application logging (Rich console + optional JSON) with
  markup disabled to prevent log-content injection into the terminal
  (`src/utils/logger.py`).
- Bounded-concurrency async batch helper and timeout wrapper
  (`src/utils/concurrency.py`).
- Model-agnostic async Ollama client with streaming and non-streaming
  generation, embeddings (with `/api/embed` → `/api/embeddings` fallback),
  model listing, version check, model pulling, retries with backoff, and
  dependency-injectable HTTP transport for testing (`src/ollama/client.py`).
- Ollama health checking, distinguishing local-binary detection from actual
  server reachability (`src/ollama/health.py`).
- Model selection strategy (explicit → configured default → preference list
  → any installed model), best-effort consent-gated server autostart, and
  installation guidance rendering (`src/ollama/manager.py`).
- Streaming response aggregation with optional live console rendering and
  graceful handling of user interruption (`src/ollama/streaming.py`).
- Parser plugin architecture: `BaseParser` abstract interface with a
  shared template-method `parse()` (validation, sanitization, per-line
  error isolation), a dependency-free `ParserRegistry`, and format-
  detection heuristics with ReDoS-conscious regex design
  (`src/parsing/base_parser.py`, `registry.py`, `heuristics.py`).
- Eight built-in log parsers covering syslog, auth.log (with
  user/source-IP/result extraction), Apache/nginx common and combined
  access logs, nginx error logs, JSON Lines, CSV, and a generic
  best-effort fallback for unrecognized formats (`src/parsing/parsers.py`).
- `ParserFactory`: samples a file, scores every registered parser by
  confidence, selects the best match (with an explicit priority
  tie-breaker for specialized parsers), falls back to the generic parser
  below threshold, and enforces path/size/encoding validation before
  parsing (`src/parsing/factory.py`).
- Test fixtures for every built-in parser plus two malicious-input
  fixtures (ANSI/control-character injection, prompt-injection payload
  corpus) under `tests/fixtures/`.
- `DetectionRule`/`RuleCondition` models with a validator enforcing that
  threshold-based fields are set together or not at all
  (`src/core/models.py`).
- Rule-based detection engine supporting both single-entry rules and
  rate/threshold rules (e.g. "5 failed logins from one IP in 120s"),
  firing once per group to avoid alert-fatigue spam
  (`src/detection/engine.py`).
- Data-driven YAML rule loading with per-rule validation (invalid entries
  are skipped, not fatal) and duplicate-ID protection
  (`src/detection/rules.py`).
- 14 bundled detection rules across authentication, web-attack, and
  network-anomaly categories, including SSH brute force, SQL injection,
  path traversal, XSS, vulnerability-scanner signatures, and port-scan
  detection (`src/detection/rules/*.yaml`).
- Cross-log correlation: per-IP activity profiles, recurring-IP detection
  across files, and a severity-filtered timeline, with a plain-text
  summary renderer for LLM prompt injection (`src/detection/context.py`).
- Prompt-injection defense layer: control-character stripping, length
  capping, boundary-collision neutralization, and random-nonce boundary
  wrapping, plus a non-exhaustive heuristic injection-pattern detector
  used as a logging/analyst-awareness signal rather than a content filter
  (`src/analysis/sanitizer.py`).
- Versioned prompt construction assembling plain-text templates
  (`config/prompts/v1/`) with the canonical JSON schema and sanitized,
  boundary-wrapped log evidence (`src/analysis/prompts.py`).
- Mechanical JSON repair (code-fence stripping, brace-matched object
  extraction that correctly ignores braces inside quoted strings,
  trailing-comma removal) with schema-bounds coercion (severity
  case-normalization, 0-100→0.0-1.0 confidence scaling, over-length
  field/list truncation) and an always-valid degraded fallback for
  unrecoverable responses (`src/analysis/repair.py`).
- Prompt-version-aware, diskcache-backed response caching that degrades
  to a cache-miss (never raises) on any storage error, and never caches
  degraded analysis results (`src/analysis/cache.py`).
- `AIAnalyzer`: ties the above together with `src.ollama.client` into
  `analyze_entry`/`analyze_many`, supporting both streaming and
  non-streaming generation, bounded-concurrency batch analysis, and a
  cache → generate → repair → retry-once → degrade pipeline that never
  raises for AI-side failures (`src/analysis/ai_analyzer.py`).
- Optional, fully local RAG knowledge base: `KnowledgeSource` interface,
  bundled MITRE ATT&CK (10 techniques), OWASP Top 10 (10 categories), and
  Sigma-style detection-concept (6 concepts) reference data in original
  wording, plus a loader for user-supplied organizational knowledge
  directories (`src/knowledge/base.py`, `src/knowledge/sources/`).
- Paragraph-aware text chunking and an Ollama-backed embedding service
  reusing the existing `OllamaClient` rather than a new HTTP client
  (`src/knowledge/embeddings.py`).
- Local, persistent ChromaDB vector store wrapper with analytics
  telemetry explicitly disabled and deliberate read/write error-handling
  asymmetry (queries degrade silently, writes raise clearly)
  (`src/knowledge/vector_store.py`).
- `KnowledgeBase` facade tying sources, embeddings, and the vector store
  into `build_index`/`retrieve_context`/`stats`, remaining fully optional
  and gracefully degrading at every entry point
  (`src/knowledge/retriever.py`).
- Five report formats over a single `AnalysisReport`: SIEM-compatible
  JSON with CEF/LEEF-inspired field names (`src`, `dst`, `spt`, `dpt`,
  `suser`, `shost`, `rt`) and 0-10 numeric severity
  (`src/reporting/json_report.py`); flat CSV reusing the exact same
  event mapping (`src/reporting/csv_report.py`); Markdown with a table of
  contents, emoji severity badges, and collapsible AI-finding details
  (`src/reporting/markdown.py`); a self-contained, offline-safe
  interactive HTML report with zero external references and JS-based
  severity/search filtering, verified with real headless-Chromium
  Playwright tests (`src/reporting/html_report.py`); and Rich console
  output including the required post-run performance metrics table
  (`src/reporting/terminal.py`).
- `MetricsCollector`: context-manager stage timing plus count recording
  for parsing, detection, AI analysis, and reporting, computing derived
  rates (lines/events/tokens per second) once at the end with a
  minimum-duration floor to avoid nonsensical rates from near-zero
  elapsed time (`src/metrics/collector.py`).
- `run_benchmark`: repeated-run timing utility producing min/max/mean/
  median/stdev statistics for the `--benchmark` CLI flag, plus a
  terminal renderer for the results (`src/metrics/benchmark.py`,
  `reporting.terminal.render_benchmark`).

### Security
- ChromaDB's `anonymized_telemetry` setting (routed through PostHog)
  defaults to `True` upstream; explicitly disabled at vector-store client
  construction. Verified by inspecting the dependency's actual defaults
  before writing any integration code, not assumed from documentation —
  see `src/knowledge/vector_store.py` module docstring.

### Fixed
- `OllamaClient._post_with_retries` now correctly catches the `httpx`
  exceptions needed to trigger its own retry logic (previously never
  caught them at all).
- `AuthLogParser` no longer silently loses to its parent `SyslogParser`
  during format detection when both report the same confidence; resolved
  with an explicit priority tie-breaker rather than a numeric confidence
  bonus (which broke once confidence hit its 1.0 ceiling).
- `AuthLogParser` now correctly extracts `user`/`source_ip` from sshd's
  `"Invalid user X from Y"` phrasing (previously only matched phrasings
  containing the word "for").
- Every parser now produces timezone-aware `LogEntry.timestamp` values
  (explicit UTC assumption where the source format has no offset), fixing
  a `TypeError` when sorting/comparing entries parsed from different log
  formats together.
- `analysis.prompts._build_evidence_text` no longer renders structured
  fields as `"user: root"`, which collided with the sanitizer's own
  `fake_role_marker` injection heuristic and produced a false-positive
  injection indicator on nearly every entry with a `user` field; switched
  to `field=value` formatting throughout.
- `DetectionRule.name`/`category`/`description` are now stripped of
  incidental whitespace at the model boundary, fixing trailing newlines
  from YAML `>` folded block scalars that were leaking into every rule
  description shown in every report format.
- `html_report.py`'s finding-card search index now includes
  `LogEntry.process`, fixing searches like `"sshd"` or `"sudo"` that
  previously matched nothing despite being exactly what a user would
  expect to search for — caught by an interactive Playwright test, not
  static inspection of the generated markup.
- `MetricsCollector` no longer reports rates (events/sec, tokens/sec) in
  the millions when a stage's measured duration is near-zero (e.g. an
  AI-analysis stage that was entirely cache hits); rate calculation now
  requires a minimum duration floor before dividing.

[Unreleased]: https://github.com/your-username/ai-log-analyzer/compare/v0.1.0...HEAD
