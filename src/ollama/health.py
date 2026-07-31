"""Ollama environment detection and health checks.

Distinguishes two independent signals:
  - `binary_found`: whether an `ollama` executable is visible on PATH.
    Purely diagnostic — used to give better installation guidance. Absent
    in containerized deployments where Ollama runs as a separate service.
  - `server_running`: whether the Ollama HTTP API actually responds. This
    is the only signal that matters functionally; the application only
    ever needs network access to the API, never the local binary.

Built entirely on `src.ollama.client.OllamaClient` rather than issuing its
own raw HTTP calls, so there is exactly one place that knows how to talk
to Ollama's wire protocol.
"""

from __future__ import annotations

import shutil

from src.core.exceptions import OllamaError
from src.core.models import ModelInfo, OllamaHealthStatus
from src.ollama.client import OllamaClient
from src.utils.logger import get_logger

logger = get_logger("ollama.health")


def detect_local_binary() -> str | None:
    """Return the resolved path to the `ollama` binary if present on PATH."""
    return shutil.which("ollama")


async def check_health(base_url: str, *, timeout_seconds: float = 5.0) -> OllamaHealthStatus:
    """Probe the Ollama server and summarize its health and available models.

    Never raises: connection failures, timeouts, and API errors are
    captured in `OllamaHealthStatus.errors` so callers can always render a
    helpful status without wrapping this in their own try/except.
    """
    binary_path = detect_local_binary()
    client = OllamaClient(
        base_url,
        request_timeout_seconds=timeout_seconds,
        connect_timeout_seconds=timeout_seconds,
        max_retries=0,
    )

    errors: list[str] = []
    version: str | None = None
    server_running = False
    models: list[ModelInfo] = []

    try:
        version = await client.get_version()
        server_running = True
    except OllamaError as exc:
        errors.append(str(exc))

    if server_running:
        try:
            models = await client.list_models()
        except OllamaError as exc:
            errors.append(str(exc))

    embedding_models = [m for m in models if m.is_embedding_model]

    return OllamaHealthStatus(
        installed=binary_path is not None,
        server_running=server_running,
        base_url=base_url,
        version=version,
        models=models,
        embedding_models=embedding_models,
        errors=errors,
    )
