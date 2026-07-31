"""Ollama environment management: readiness checks, model selection, and
best-effort server autostart.

This module contains the *decision logic* for which model to use and
whether/how to bring Ollama up; `src.ollama.client` and `src.ollama.health`
provide the underlying I/O primitives.
"""

from __future__ import annotations

import asyncio
import time

from src.core.config import OllamaConfig
from src.core.exceptions import ModelNotFoundError, NoModelsAvailableError
from src.core.models import OllamaHealthStatus
from src.ollama.health import check_health, detect_local_binary
from src.utils.logger import get_logger

logger = get_logger("ollama.manager")

_AUTOSTART_POLL_INTERVAL_SECONDS = 0.5


async def ensure_ready(
    config: OllamaConfig,
    *,
    auto_start: bool = False,
    autostart_timeout_seconds: float = 15.0,
) -> OllamaHealthStatus:
    """Check Ollama readiness, optionally attempting to start the server.

    Args:
        config: Ollama configuration (base URL, timeouts).
        auto_start: If True and the server is not running but the `ollama`
            binary is found, attempt to launch `ollama serve` in the
            background and wait for it to become reachable. Callers
            (typically the CLI) should only pass `True` after obtaining
            explicit user consent — this module never assumes consent on
            its own.
        autostart_timeout_seconds: How long to wait for the server to
            become reachable after starting it.

    Returns:
        The resulting `OllamaHealthStatus` (reflects the post-autostart
        state if autostart was attempted).
    """
    status = await check_health(config.host, timeout_seconds=config.connect_timeout_seconds)
    if status.server_running or not auto_start:
        return status

    binary_path = detect_local_binary()
    if not binary_path:
        logger.warning("Ollama server is not running and no local binary was found to start it.")
        return status

    started = await _attempt_autostart(
        binary_path, config.host, timeout_seconds=autostart_timeout_seconds
    )
    if not started:
        return status

    return await check_health(config.host, timeout_seconds=config.connect_timeout_seconds)


async def _attempt_autostart(binary_path: str, base_url: str, *, timeout_seconds: float) -> bool:
    """Launch `ollama serve` in the background and poll until reachable.

    Uses `asyncio.create_subprocess_exec` (never a shell) so the event loop
    is never blocked while spawning the process. The resulting `Process`
    handle is intentionally discarded: `ollama serve` is meant to keep
    running as a detached background service outlasting this function,
    not to be waited on.
    """
    try:
        await asyncio.create_subprocess_exec(
            binary_path,
            "serve",
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
            stdin=asyncio.subprocess.DEVNULL,
            start_new_session=True,
        )
    except OSError as exc:
        logger.warning("Failed to start Ollama server: %s", exc)
        return False

    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        status = await check_health(base_url, timeout_seconds=2.0)
        if status.server_running:
            logger.info("Ollama server started successfully.")
            return True
        await asyncio.sleep(_AUTOSTART_POLL_INTERVAL_SECONDS)

    logger.warning("Ollama server did not become reachable within %.0fs.", timeout_seconds)
    return False


def select_model(
    health: OllamaHealthStatus,
    config: OllamaConfig,
    *,
    requested_model: str | None = None,
) -> tuple[str, str]:
    """Choose which model to use and explain why.

    Selection order:
      1. `requested_model` (explicit `--model` flag), if it is installed.
      2. `config.default_model`, if configured and installed.
      3. The first installed model from `config.model_preference`.
      4. Any other installed, non-embedding model.

    Returns:
        `(model_name, reason)` — `reason` is a short human-readable
        explanation suitable for CLI display.

    Raises:
        ModelNotFoundError: `requested_model` was given but is not installed.
        NoModelsAvailableError: No usable model is installed at all.
    """
    installed_names = {m.name for m in health.models}
    non_embedding_models = [m for m in health.models if not m.is_embedding_model]

    if requested_model is not None:
        if requested_model in installed_names:
            return requested_model, "explicitly requested via --model"
        raise ModelNotFoundError(requested_model, available_models=sorted(installed_names))

    if config.default_model is not None:
        if config.default_model in installed_names:
            return config.default_model, "configured default_model"
        logger.warning(
            "Configured default_model '%s' is not installed; falling back to auto-selection.",
            config.default_model,
        )

    for preferred in config.model_preference:
        if preferred in installed_names:
            return preferred, f"first available match from preference list ({preferred})"

    if non_embedding_models:
        fallback = non_embedding_models[0]
        return fallback.name, "no preferred model installed; using first available model"

    raise NoModelsAvailableError(
        "No usable Ollama models are installed.",
        details={"installed": sorted(installed_names)},
    )


def select_embedding_model(health: OllamaHealthStatus, config: OllamaConfig) -> str | None:
    """Choose an embedding model for RAG, or None if none is installed."""
    installed_names = {m.name for m in health.models}
    if config.embedding_model in installed_names:
        return config.embedding_model
    if health.embedding_models:
        return health.embedding_models[0].name
    return None


def format_installation_guidance(health: OllamaHealthStatus, config: OllamaConfig) -> str:
    """Render human-readable next steps when Ollama or a model is missing."""
    if not health.installed and not health.server_running:
        return (
            "Ollama does not appear to be installed or reachable.\n"
            "Install it from https://ollama.com/download, then run: ollama serve"
        )
    if not health.server_running:
        return (
            f"Ollama is installed but not reachable at {health.base_url}.\n"
            "Start it with: ollama serve"
        )
    if not health.models:
        return (
            "Ollama is running but no models are installed.\n"
            f"Pull a recommended model with: ollama pull {config.model_preference[0]}"
        )
    return ""
