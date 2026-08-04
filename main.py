#!/usr/bin/env python3
"""AI Log Analyzer — CLI entry point.

Wires every subsystem built under `src/` into the commands documented in
README.md:

    analyze         Analyze one or more log files/directories.
    check           Check the local Ollama installation and environment.
    models          List models installed in the local Ollama instance.
    knowledge-stats Show statistics about the local knowledge base index.
    cache-clear     Clear the AI response cache.
    cache-stats     Show AI response cache statistics.

Pipeline order for `analyze`: load config -> ensure Ollama is ready and
select a model -> parse every file -> run rule-based detection over
every entry -> build cross-log context -> (optionally) index/query the
knowledge base -> AI-analyze only the entries behind a detection (never
every parsed line — see PROGRESS.md convention #16) -> assemble an
AnalysisReport -> write any requested export formats -> always show a
terminal summary and performance metrics.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Coroutine
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Any

import typer
from rich.console import Console

from src.analysis.ai_analyzer import AIAnalyzer, AnalyzerSettings
from src.analysis.cache import ResponseCache
from src.core.config import AppConfig, KnowledgeConfig, load_config
from src.core.exceptions import (
    AILogAnalyzerError,
    ModelNotFoundError,
    NoModelsAvailableError,
)
from src.core.models import (
    AnalysisRecord,
    AnalysisReport,
    LogEntry,
    LogFormat,
    ParseResult,
)
from src.detection.context import build_context
from src.detection.engine import DetectionEngine
from src.detection.rules import load_default_rules
from src.knowledge.base import KnowledgeSource
from src.knowledge.retriever import KnowledgeBase
from src.knowledge.sources.custom_directory import CustomDirectorySource
from src.knowledge.sources.mitre_attack import MitreAttackSource
from src.knowledge.sources.owasp import OwaspSource
from src.knowledge.sources.sigma_rules import SigmaRulesSource
from src.metrics.benchmark import run_benchmark
from src.metrics.collector import MetricsCollector
from src.ollama import health as ollama_health
from src.ollama import manager as ollama_manager
from src.ollama.client import OllamaClient
from src.parsing.factory import ParserFactory
from src.reporting import csv_report, html_report, json_report, markdown, terminal
from src.utils.concurrency import bounded_gather
from src.utils.logger import configure_logging, get_logger
from src.utils.validators import validate_export_formats

REPO_ROOT = Path(__file__).resolve().parent

app = typer.Typer(
    name="ai-log-analyzer",
    help="Fully local, offline, AI-powered security log analyzer.",
    add_completion=False,
    no_args_is_help=True,
)
console = Console()
error_console = Console(stderr=True)
logger = get_logger("cli")

_FORMAT_RENDERERS: dict[str, tuple[Callable[[AnalysisReport], str], str]] = {
    "json": (json_report.render, "json"),
    "md": (markdown.render, "md"),
    "html": (html_report.render, "html"),
    "csv": (csv_report.render, "csv"),
}


@dataclass
class CLIState:
    """Shared state resolved once in the top-level callback."""

    config: AppConfig


def _read_tool_version() -> str:
    try:
        return (REPO_ROOT / "VERSION").read_text(encoding="utf-8").strip()
    except OSError:
        return "0.0.0-unknown"


def _run_async(coro: Coroutine[Any, Any, None]) -> None:
    """Run an async command body, translating known errors into clean CLI output."""
    try:
        asyncio.run(coro)
    except AILogAnalyzerError as exc:
        error_console.print(f"[bold red]Error:[/bold red] {exc}")
        raise typer.Exit(code=1) from exc
    except KeyboardInterrupt:
        error_console.print("\n[yellow]Interrupted.[/yellow]")
        raise typer.Exit(code=130) from None


@app.callback()
def main_callback(
    ctx: typer.Context,
    config_path: Annotated[
        Path | None, typer.Option("--config", help="Path to a custom YAML config file.")
    ] = None,
    log_level: Annotated[
        str, typer.Option("--log-level", help="Application log level.")
    ] = "WARNING",
) -> None:
    """AI Log Analyzer: a fully local, offline, AI-powered security log analyzer."""
    configure_logging(log_level)
    try:
        cfg = load_config(config_path)
    except AILogAnalyzerError as exc:
        error_console.print(f"[bold red]Configuration error:[/bold red] {exc}")
        raise typer.Exit(code=1) from exc
    ctx.obj = CLIState(config=cfg)


# ============================================================================
# analyze
# ============================================================================


def _expand_paths(paths: list[Path]) -> list[Path]:
    """Expand a mix of files and directories into a flat list of files.

    Directories are scanned non-recursively — a typical log directory
    (e.g. `/var/log`) mixes unrelated files and subdirectories, and
    silently recursing into all of them risks pulling in files the user
    never intended to analyze.
    """
    results: list[Path] = []
    for p in paths:
        if p.is_dir():
            for child in sorted(p.iterdir()):
                if child.is_file():
                    results.append(child)
        elif p.is_file():
            results.append(p)
        else:
            error_console.print(f"[yellow]Warning: path not found, skipping: {p}[/yellow]")
    return results


def _resolve_forced_format(value: str | None) -> LogFormat | None:
    if value is None:
        return None
    try:
        return LogFormat(value)
    except ValueError as exc:
        valid = ", ".join(f.value for f in LogFormat)
        raise typer.BadParameter(f"Invalid log format '{value}'. Valid options: {valid}") from exc


def _build_knowledge_sources(kb_config: KnowledgeConfig) -> list[KnowledgeSource]:
    sources: list[KnowledgeSource] = [MitreAttackSource(), OwaspSource(), SigmaRulesSource()]
    if kb_config.source_directory is not None:
        sources.append(
            CustomDirectorySource(
                kb_config.source_directory,
                chunk_size=kb_config.chunk_size,
                chunk_overlap=kb_config.chunk_overlap,
            )
        )
    return sources


async def _prepare_knowledge_base(
    cfg: AppConfig,
    *,
    client: OllamaClient,
    embedding_model: str | None,
    knowledge_base_dir: Path | None,
) -> KnowledgeBase | None:
    if not cfg.knowledge.enabled and knowledge_base_dir is None:
        return None
    kb_config = cfg.knowledge.model_copy(update={"enabled": True})
    if knowledge_base_dir is not None:
        kb_config = kb_config.model_copy(update={"source_directory": knowledge_base_dir})

    kb = KnowledgeBase(kb_config, client=client, embedding_model=embedding_model)
    if not kb.enabled:
        console.print(
            "[yellow]Knowledge base requested but unavailable "
            "(no embedding model or vector store init failed); continuing without it.[/yellow]"
        )
        return None

    with console.status("Indexing knowledge base..."):
        stats = await kb.build_index(_build_knowledge_sources(kb_config))
    console.print(
        f"Knowledge base ready: {stats.total_chunks} chunk(s) from {len(stats.sources)} source(s)."
    )
    return kb


async def _execute_pipeline(
    cfg: AppConfig,
    log_files: list[Path],
    *,
    model_override: str | None,
    stream: bool,
    knowledge_base_dir: Path | None,
    no_cache: bool,
    forced_format: LogFormat | None,
    auto_start_ollama: bool,
    requested_formats: list[str],
) -> tuple[AnalysisReport, MetricsCollector]:
    """Run the full parse -> detect -> correlate -> analyze -> report pipeline once."""
    collector = MetricsCollector()
    collector.start()

    with console.status("Checking Ollama..."):
        health = await ollama_manager.ensure_ready(cfg.ollama, auto_start=auto_start_ollama)
    if not health.server_running:
        console.print(ollama_manager.format_installation_guidance(health, cfg.ollama))
        raise typer.Exit(code=1)

    try:
        model_name, reason = ollama_manager.select_model(
            health, cfg.ollama, requested_model=model_override
        )
    except (ModelNotFoundError, NoModelsAvailableError):
        console.print(ollama_manager.format_installation_guidance(health, cfg.ollama))
        raise
    console.print(f"[green]Using model:[/green] {model_name} [dim]({reason})[/dim]")

    client = OllamaClient(
        cfg.ollama.host,
        request_timeout_seconds=cfg.ollama.request_timeout_seconds,
        connect_timeout_seconds=cfg.ollama.connect_timeout_seconds,
        max_retries=cfg.ollama.max_retries,
        retry_backoff_seconds=cfg.ollama.retry_backoff_seconds,
    )

    # --- parsing ---
    factory = ParserFactory(security_config=cfg.security, parsing_config=cfg.parsing)
    parse_results: list[ParseResult] = []
    all_entries: list[LogEntry] = []
    with collector.time_parsing():
        for path in log_files:
            try:
                result = factory.parse_file(path, forced_format=forced_format)
            except AILogAnalyzerError as exc:
                error_console.print(f"[yellow]Skipping {path}: {exc}[/yellow]")
                continue
            parse_results.append(result)
            all_entries.extend(result.entries)
            collector.record_parse_result(result)
            console.print(
                f"  Parsed [bold]{path}[/bold] as {result.detected_format.value} "
                f"({result.parsed_lines}/{result.total_lines} lines, "
                f"confidence {result.confidence:.0%})"
            )

    if not all_entries:
        error_console.print("[yellow]No log entries were successfully parsed.[/yellow]")
        raise typer.Exit(code=1)

    # --- detection ---
    rules = load_default_rules(
        rules_directory=cfg.detection.rules_directory,
        enabled_categories=cfg.detection.enabled_categories or None,
    )
    engine = DetectionEngine(rules)
    with collector.time_detection():
        detections = engine.evaluate(all_entries)
        collector.record_detections(detections, rules_evaluated=len(rules))
    console.print(f"[bold]{len(detections)}[/bold] rule-based detection(s) found.")

    context = build_context(all_entries, detections)

    # --- knowledge base (optional) ---
    embedding_model = ollama_manager.select_embedding_model(health, cfg.ollama)
    knowledge_base = await _prepare_knowledge_base(
        cfg, client=client, embedding_model=embedding_model, knowledge_base_dir=knowledge_base_dir
    )

    # --- AI analysis: only entries behind a detection, deduplicated ---
    seen_keys: set[tuple[str, int]] = set()
    flagged_entries: list[LogEntry] = []
    related_ids: dict[tuple[str, int], list[str]] = {}
    for match in detections:
        key = (match.log_entry.source_file, match.log_entry.line_number)
        related_ids.setdefault(key, []).append(match.match_id)
        if key not in seen_keys:
            seen_keys.add(key)
            flagged_entries.append(match.log_entry)

    cache: ResponseCache | None = None
    use_cache = cfg.cache.enabled and not no_cache
    if use_cache:
        cache = ResponseCache(
            cfg.cache.directory,
            ttl_seconds=cfg.cache.ttl_seconds,
            size_limit_bytes=cfg.cache.max_size_bytes,
        )

    analyzer = AIAnalyzer(
        client,
        AnalyzerSettings(
            model_name=model_name,
            prompt_version=cfg.analysis.prompt_version,
            knowledge_version=cfg.knowledge.knowledge_version,
            use_cache=use_cache,
            stream=stream,
            # Live token rendering only makes sense with no concurrent
            # interleaving: a single flagged entry, or the concurrency
            # cap forced to 1. Otherwise concurrent streams would garble
            # each other's output on the same console.
            live_render=stream
            and (len(flagged_entries) <= 1 or cfg.ollama.max_concurrent_requests == 1),
        ),
        cache=cache,
    )

    async def _analyze_one(entry: LogEntry) -> AnalysisRecord:
        knowledge_context = None
        if knowledge_base is not None and knowledge_base.enabled:
            knowledge_context = await knowledge_base.retrieve_context(entry.raw_line)
        record = await analyzer.analyze_entry(
            entry, cross_log_context=context, knowledge_context=knowledge_context
        )
        key = (entry.source_file, entry.line_number)
        return record.model_copy(update={"related_detection_ids": related_ids.get(key, [])})

    ai_records: list[AnalysisRecord] = []
    with collector.time_ai_analysis():
        if flagged_entries:
            console.print(
                f"Running AI analysis on [bold]{len(flagged_entries)}[/bold] flagged "
                f"entr{'y' if len(flagged_entries) == 1 else 'ies'}..."
            )
            ai_records = await bounded_gather(
                flagged_entries, _analyze_one, max_concurrency=cfg.ollama.max_concurrent_requests
            )
            for record in ai_records:
                collector.record_ai_analysis(record)
        if cache is not None:
            collector.record_cache_stats(cache)
            cache.close()

    # --- assemble report; embedded metrics reflect parse+detect+AI only,
    # since reporting duration is only known after this point (the
    # terminal display after write-out shows the complete, final
    # numbers via a second `finalize()` call — see PROGRESS.md
    # convention #25 area for why this asymmetry is an accepted tradeoff) ---
    report = AnalysisReport(
        tool_version=_read_tool_version(),
        model_used=model_name,
        files_analyzed=[str(f) for f in log_files],
        parse_results=parse_results,
        detections=detections,
        ai_analyses=ai_records,
        cross_log_context=context,
        metrics=collector.finalize(),
        knowledge_base_used=knowledge_base is not None and knowledge_base.enabled,
    )

    with collector.time_reporting():
        if requested_formats:
            _write_reports(report, requested_formats)
            collector.record_reporting(requested_formats)

    return report, collector


def _write_reports(report: AnalysisReport, formats: list[str], output: Path | None = None) -> None:
    base = output or Path("ai-log-analyzer-report")
    for fmt in formats:
        renderer, extension = _FORMAT_RENDERERS[fmt]
        out_path = base.with_suffix(f".{extension}")
        try:
            out_path.write_text(renderer(report), encoding="utf-8")
        except OSError as exc:
            error_console.print(f"[red]Could not write {out_path}: {exc}[/red]")
            continue
        console.print(f"Wrote {fmt.upper()} report to [bold]{out_path}[/bold]")


@app.command()
def analyze(
    ctx: typer.Context,
    paths: Annotated[list[Path], typer.Argument(help="Log files or directories to analyze.")],
    model: Annotated[
        str | None, typer.Option("--model", help="Explicit Ollama model name.")
    ] = None,
    stream: Annotated[
        bool | None,
        typer.Option("--stream/--no-stream", help="Use Ollama's streaming API for generation."),
    ] = None,
    knowledge_base: Annotated[
        Path | None,
        typer.Option(
            "--knowledge-base",
            help="Directory of custom knowledge to index alongside bundled sources.",
        ),
    ] = None,
    output: Annotated[
        Path, typer.Option("--output", help="Output file path prefix (extension added per format).")
    ] = Path("ai-log-analyzer-report"),
    formats: Annotated[
        str, typer.Option("--format", help="Comma-separated export formats: json,md,html,csv")
    ] = "",
    benchmark: Annotated[
        bool,
        typer.Option(
            "--benchmark", help="Run the full pipeline multiple times and report timing statistics."
        ),
    ] = False,
    benchmark_iterations: Annotated[
        int, typer.Option("--benchmark-iterations", help="Iterations for --benchmark.")
    ] = 3,
    no_cache: Annotated[
        bool, typer.Option("--no-cache", help="Bypass the AI response cache for this run.")
    ] = False,
    log_format: Annotated[
        str | None,
        typer.Option("--log-format", help="Force a specific parser instead of auto-detecting."),
    ] = None,
    auto_start_ollama: Annotated[
        bool,
        typer.Option("--auto-start-ollama", help="Attempt to start Ollama if it isn't running."),
    ] = False,
) -> None:
    """Analyze one or more log files/directories for security-relevant activity."""
    cfg: AppConfig = ctx.obj.config
    log_files = _expand_paths(paths)
    if not log_files:
        error_console.print("[bold red]No log files found in the given paths.[/bold red]")
        raise typer.Exit(code=1)

    requested_formats = validate_export_formats(formats) if formats.strip() else []
    effective_stream = stream if stream is not None else cfg.ollama.stream_default_cli
    forced_format = _resolve_forced_format(log_format)

    async def _run() -> None:
        if benchmark:
            iteration = 0

            async def _one_iteration() -> AnalysisReport:
                nonlocal iteration
                iteration += 1
                console.rule(f"Benchmark iteration {iteration}/{benchmark_iterations}")
                report, _collector = await _execute_pipeline(
                    cfg,
                    log_files,
                    model_override=model,
                    stream=effective_stream,
                    knowledge_base_dir=knowledge_base,
                    no_cache=no_cache,
                    forced_format=forced_format,
                    auto_start_ollama=auto_start_ollama,
                    requested_formats=[],
                )
                return report

            bench_result, reports = await run_benchmark(
                "full analysis pipeline", _one_iteration, iterations=benchmark_iterations
            )
            console.rule("Benchmark Complete")
            terminal.render_report(reports[-1], console)
            terminal.render_benchmark(bench_result, console)
            if requested_formats:
                _write_reports(reports[-1], requested_formats, output)
            return

        report, collector = await _execute_pipeline(
            cfg,
            log_files,
            model_override=model,
            stream=effective_stream,
            knowledge_base_dir=knowledge_base,
            no_cache=no_cache,
            forced_format=forced_format,
            auto_start_ollama=auto_start_ollama,
            requested_formats=requested_formats,
        )
        if requested_formats:
            _write_reports(report, requested_formats, output)
        final_metrics = collector.finalize()
        terminal.render_report(report, console)
        terminal.render_metrics(final_metrics, console)

    _run_async(_run())


# ============================================================================
# check
# ============================================================================


@app.command()
def check(ctx: typer.Context) -> None:
    """Check the local Ollama installation and environment."""
    cfg: AppConfig = ctx.obj.config

    async def _run() -> None:
        with console.status("Checking Ollama..."):
            health = await ollama_health.check_health(cfg.ollama.host)

        table_rows = [
            ("Binary found on PATH", "Yes" if health.installed else "No (may be containerized)"),
            ("Server reachable", "Yes" if health.server_running else "No"),
            ("Version", health.version or "-"),
            ("Models installed", str(len(health.models))),
            ("Embedding models", str(len(health.embedding_models))),
        ]
        from rich.table import Table

        table = Table(title="Ollama Environment Check")
        table.add_column("Check")
        table.add_column("Status")
        for name, value in table_rows:
            table.add_row(name, value)
        console.print(table)

        for err in health.errors:
            error_console.print(f"[red]Error:[/red] {err}")

        if not health.is_healthy:
            console.print(ollama_manager.format_installation_guidance(health, cfg.ollama))
            raise typer.Exit(code=1)
        console.print("[bold green]Ollama is healthy and ready.[/bold green]")

    _run_async(_run())


# ============================================================================
# models
# ============================================================================


@app.command()
def models(ctx: typer.Context) -> None:
    """List models installed in the local Ollama instance."""
    cfg: AppConfig = ctx.obj.config

    async def _run() -> None:
        with console.status("Fetching installed models..."):
            health = await ollama_health.check_health(cfg.ollama.host)
        if not health.server_running:
            error_console.print("[red]Ollama is not reachable.[/red]")
            console.print(ollama_manager.format_installation_guidance(health, cfg.ollama))
            raise typer.Exit(code=1)
        if not health.models:
            console.print("[yellow]No models installed.[/yellow]")
            console.print(
                f"Pull a recommended model with: ollama pull {cfg.ollama.model_preference[0]}"
            )
            return

        from rich.table import Table

        table = Table(title="Installed Ollama Models")
        table.add_column("Name")
        table.add_column("Family")
        table.add_column("Parameters")
        table.add_column("Quantization")
        table.add_column("Size")
        table.add_column("Type")
        for m in sorted(health.models, key=lambda x: x.name):
            size = f"{m.size_bytes / 1e9:.1f} GB" if m.size_bytes else "-"
            kind = "Embedding" if m.is_embedding_model else "Generation"
            table.add_row(
                m.name,
                m.family or "-",
                m.parameter_size or "-",
                m.quantization_level or "-",
                size,
                kind,
            )
        console.print(table)

    _run_async(_run())


# ============================================================================
# knowledge-stats
# ============================================================================


@app.command(name="knowledge-stats")
def knowledge_stats(ctx: typer.Context) -> None:
    """Show statistics about the local knowledge base index."""
    cfg: AppConfig = ctx.obj.config

    async def _run() -> None:
        if not cfg.knowledge.enabled:
            console.print(
                "[yellow]Knowledge base is disabled in configuration "
                "(knowledge.enabled: false).[/yellow]"
            )
            return

        health = await ollama_health.check_health(cfg.ollama.host)
        client = OllamaClient(cfg.ollama.host)
        embedding_model = ollama_manager.select_embedding_model(health, cfg.ollama)
        kb = KnowledgeBase(cfg.knowledge, client=client, embedding_model=embedding_model)
        stats = kb.stats()

        from rich.table import Table

        table = Table(title="Knowledge Base Statistics")
        table.add_column("Field")
        table.add_column("Value")
        table.add_row("Enabled", str(stats.enabled))
        table.add_row("Total documents", str(stats.total_documents))
        table.add_row("Total chunks", str(stats.total_chunks))
        table.add_row("Embedding model", stats.embedding_model or "-")
        table.add_row("Persist directory", stats.persist_directory or "-")
        table.add_row(
            "Last indexed", stats.last_indexed_at.isoformat() if stats.last_indexed_at else "never"
        )
        for source, count in sorted(stats.sources.items()):
            table.add_row(f"  {source}", str(count))
        console.print(table)

    _run_async(_run())


# ============================================================================
# cache-clear / cache-stats
# ============================================================================


@app.command(name="cache-clear")
def cache_clear(ctx: typer.Context) -> None:
    """Clear the AI response cache."""
    cfg: AppConfig = ctx.obj.config
    cache = ResponseCache(
        cfg.cache.directory,
        ttl_seconds=cfg.cache.ttl_seconds,
        size_limit_bytes=cfg.cache.max_size_bytes,
    )
    count = cache.clear()
    cache.close()
    console.print(f"Cleared [bold]{count}[/bold] cached entr{'y' if count == 1 else 'ies'}.")


@app.command(name="cache-stats")
def cache_stats(ctx: typer.Context) -> None:
    """Show AI response cache statistics."""
    cfg: AppConfig = ctx.obj.config
    cache = ResponseCache(
        cfg.cache.directory,
        ttl_seconds=cfg.cache.ttl_seconds,
        size_limit_bytes=cfg.cache.max_size_bytes,
    )
    stats = cache.to_stats_model()
    cache.close()

    from rich.table import Table

    table = Table(title="Cache Statistics")
    table.add_column("Field")
    table.add_column("Value")
    table.add_row("Enabled", str(stats.enabled))
    table.add_row("Directory", stats.directory)
    table.add_row("Entries", str(stats.entry_count))
    table.add_row("Size", f"{stats.size_bytes / 1024:.1f} KB")
    table.add_row("Hits (this session)", str(stats.hits))
    table.add_row("Misses (this session)", str(stats.misses))
    console.print(table)


if __name__ == "__main__":
    app()
