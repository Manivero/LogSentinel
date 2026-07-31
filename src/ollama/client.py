"""Model-agnostic async Ollama HTTP client.

Wraps Ollama's `/api/generate`, `/api/embed` (with `/api/embeddings`
fallback), `/api/tags`, `/api/version`, and `/api/pull` endpoints behind a
small async interface with both streaming and non-streaming generation,
bounded timeouts, retries with backoff, and a uniform exception hierarchy
(`src.core.exceptions.OllamaError` and subclasses).

Never hardcodes a model name — every method takes `model` as a required
argument, so the application works with any model the user has installed,
present or future.

Endpoint shapes verified against the official Ollama API reference:
https://github.com/ollama/ollama/blob/main/docs/api.md and
https://docs.ollama.com/capabilities/embeddings (2026).
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from typing import Any

import httpx

from src.core.exceptions import (
    ModelNotFoundError,
    OllamaConnectionError,
    OllamaError,
    OllamaServerError,
    OllamaTimeoutError,
)
from src.core.models import ModelInfo
from src.utils.logger import get_logger

logger = get_logger("ollama.client")

# Low temperature favors consistent, analytical output over creative
# variation — appropriate for security analysis regardless of which model
# is selected. Callers may override via the `options` argument.
DEFAULT_GENERATE_OPTIONS: dict[str, Any] = {"temperature": 0.2}


class OllamaClient:
    """Async client for a local Ollama server.

    Args:
        base_url: Ollama server base URL.
        request_timeout_seconds: Overall request timeout.
        connect_timeout_seconds: TCP connect timeout.
        max_retries: Retries for transient connection/timeout/server errors.
            Model-not-found errors are never retried (retrying cannot fix a
            missing model).
        retry_backoff_seconds: Base delay between retries (linear backoff).
        transport: Optional `httpx.AsyncBaseTransport` override, used to
            inject `httpx.MockTransport` in tests without touching the
            network. Production callers should leave this as `None`.
    """

    def __init__(
        self,
        base_url: str = "http://localhost:11434",
        *,
        request_timeout_seconds: float = 120.0,
        connect_timeout_seconds: float = 10.0,
        max_retries: int = 2,
        retry_backoff_seconds: float = 1.5,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self._timeout = httpx.Timeout(
            timeout=request_timeout_seconds, connect=connect_timeout_seconds
        )
        self._max_retries = max_retries
        self._retry_backoff_seconds = retry_backoff_seconds
        self._transport = transport

    def _new_client(self) -> httpx.AsyncClient:
        """Create a short-lived AsyncClient bound to this instance's config."""
        return httpx.AsyncClient(
            base_url=self.base_url, timeout=self._timeout, transport=self._transport
        )

    # ------------------------------------------------------------------
    # Generation
    # ------------------------------------------------------------------

    async def generate(
        self,
        *,
        model: str,
        prompt: str,
        system: str | None = None,
        options: dict[str, Any] | None = None,
        response_format: str | dict[str, Any] | None = None,
    ) -> str:
        """Generate a complete (non-streaming) response.

        Args:
            response_format: `"json"` for loose JSON-mode decoding, a JSON
                Schema dict for strict structured-output decoding (newer
                Ollama versions), or `None` for unconstrained text.

        Raises:
            OllamaConnectionError, OllamaTimeoutError, OllamaServerError,
            ModelNotFoundError: see module docstring / exceptions module.
        """
        payload = self._build_payload(
            model, prompt, system, options, stream=False, response_format=response_format
        )
        data = await self._post_with_retries("/api/generate", payload)
        return str(data.get("response", ""))

    async def generate_stream(
        self,
        *,
        model: str,
        prompt: str,
        system: str | None = None,
        options: dict[str, Any] | None = None,
        response_format: str | dict[str, Any] | None = None,
    ) -> AsyncIterator[str]:
        """Generate a response as an async stream of text chunks.

        Each yielded item is an incremental text fragment; concatenate them
        for the full response. Not retried automatically — streaming
        responses may already be partially rendered to the user, so
        `src.ollama.streaming.consume_stream` handles graceful degradation
        on interruption instead of blindly retrying here.
        """
        payload = self._build_payload(
            model, prompt, system, options, stream=True, response_format=response_format
        )
        try:
            async with (
                self._new_client() as client,
                client.stream("POST", "/api/generate", json=payload) as response,
            ):
                await self._raise_for_status(response, model=model)
                async for line in response.aiter_lines():
                    if not line.strip():
                        continue
                    try:
                        chunk = json.loads(line)
                    except json.JSONDecodeError:
                        logger.warning("Skipping malformed stream chunk from Ollama.")
                        continue
                    text = chunk.get("response")
                    if text:
                        yield text
                    if chunk.get("done"):
                        break
        except httpx.ConnectError as exc:
            raise OllamaConnectionError(f"Lost connection to Ollama at {self.base_url}") from exc
        except httpx.TimeoutException as exc:
            raise OllamaTimeoutError(f"Ollama streaming request to {model} timed out") from exc

    # ------------------------------------------------------------------
    # Embeddings
    # ------------------------------------------------------------------

    async def embed(self, *, model: str, text: str) -> list[float]:
        """Generate an L2-normalized embedding vector for `text`.

        Tries the current `/api/embed` endpoint first (`input`/`embeddings`
        fields, batch-capable) and falls back to the legacy
        `/api/embeddings` endpoint (`prompt`/`embedding` fields) on any
        failure, keeping the client compatible across Ollama server
        versions without configuration.
        """
        try:
            data = await self._post_with_retries("/api/embed", {"model": model, "input": text})
            embeddings = data.get("embeddings")
            if isinstance(embeddings, list) and embeddings and isinstance(embeddings[0], list):
                return [float(x) for x in embeddings[0]]
        except OllamaError:
            logger.debug("/api/embed unavailable or failed; falling back to /api/embeddings.")

        data = await self._post_with_retries("/api/embeddings", {"model": model, "prompt": text})
        embedding = data.get("embedding")
        if not isinstance(embedding, list) or not embedding:
            raise OllamaServerError("Ollama returned no embedding vector", details={"model": model})
        return [float(x) for x in embedding]

    # ------------------------------------------------------------------
    # Model management / introspection
    # ------------------------------------------------------------------

    async def list_models(self) -> list[ModelInfo]:
        """List locally installed models via `/api/tags`."""
        async with self._new_client() as client:
            try:
                response = await client.get("/api/tags")
            except httpx.ConnectError as exc:
                raise OllamaConnectionError(f"Cannot connect to Ollama at {self.base_url}") from exc
            except httpx.TimeoutException as exc:
                raise OllamaTimeoutError("Timed out listing Ollama models") from exc
            await self._raise_for_status(response, model="")
            payload = response.json()
            return [ModelInfo.model_validate(_normalize_tag(m)) for m in payload.get("models", [])]

    async def get_version(self) -> str | None:
        """Return the Ollama server version string, or None if unreported."""
        async with self._new_client() as client:
            try:
                response = await client.get("/api/version")
            except httpx.ConnectError as exc:
                raise OllamaConnectionError(f"Cannot connect to Ollama at {self.base_url}") from exc
            except httpx.TimeoutException as exc:
                raise OllamaTimeoutError("Timed out getting Ollama version") from exc
            await self._raise_for_status(response, model="")
            data = response.json()
            version = data.get("version")
            return str(version) if version is not None else None

    async def pull_model(self, *, model: str) -> AsyncIterator[dict[str, Any]]:
        """Pull (download) a model, yielding raw `/api/pull` progress events.

        Callers render progress (e.g. a Rich progress bar keyed on the
        `completed`/`total` byte counts); this method never prints
        anything itself. Has no request timeout (downloads can be large
        and slow) — the caller can cancel the enclosing task to abort.
        """
        payload = {"model": model, "stream": True}
        # Intentionally unbounded: model downloads can be large and slow, and
        # this is never called with untrusted input (model names come from
        # the CLI operator, not log content). Callers cancel the enclosing
        # task to abort rather than relying on a timeout.
        client = httpx.AsyncClient(
            base_url=self.base_url,
            timeout=None,  # noqa: S113 - intentional; see comment above
            transport=self._transport,
        )
        try:
            async with client, client.stream("POST", "/api/pull", json=payload) as response:
                await self._raise_for_status(response, model=model)
                async for line in response.aiter_lines():
                    if not line.strip():
                        continue
                    try:
                        yield json.loads(line)
                    except json.JSONDecodeError:
                        continue
        except httpx.ConnectError as exc:
            raise OllamaConnectionError(f"Cannot connect to Ollama at {self.base_url}") from exc

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _post_with_retries(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        last_error: OllamaError | None = None
        for attempt in range(self._max_retries + 1):
            try:
                return await self._do_post(path, payload)
            except ModelNotFoundError:
                raise  # retrying will never help
            except (OllamaConnectionError, OllamaTimeoutError, OllamaServerError) as exc:
                last_error = exc
                if attempt < self._max_retries:
                    logger.warning(
                        "Ollama request to %s failed (attempt %d/%d): %s. Retrying...",
                        path,
                        attempt + 1,
                        self._max_retries + 1,
                        exc,
                    )
                    await asyncio.sleep(self._retry_backoff_seconds * (attempt + 1))
        assert last_error is not None
        raise last_error

    async def _do_post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        async with self._new_client() as client:
            try:
                response = await client.post(path, json=payload)
            except httpx.ConnectError as exc:
                raise OllamaConnectionError(f"Cannot connect to Ollama at {self.base_url}") from exc
            except httpx.TimeoutException as exc:
                raise OllamaTimeoutError(f"Ollama request to {path} timed out") from exc
            model = str(payload.get("model", ""))
            await self._raise_for_status(response, model=model)
            result: dict[str, Any] = response.json()
            return result

    async def _raise_for_status(self, response: httpx.Response, *, model: str) -> None:
        if response.status_code < 400:
            return
        body = await self._safe_read_json(response)
        error_message = (
            str(body.get("error")) if body.get("error") else f"HTTP {response.status_code}"
        )
        if response.status_code == 404 and model and "not found" in error_message.lower():
            raise ModelNotFoundError(model)
        if response.status_code >= 500:
            raise OllamaServerError(
                f"Ollama server error ({response.status_code}): {error_message}"
            )
        raise OllamaServerError(f"Ollama request failed ({response.status_code}): {error_message}")

    @staticmethod
    async def _safe_read_json(response: httpx.Response) -> dict[str, Any]:
        try:
            if not response.is_closed:
                await response.aread()
            data = response.json()
            return data if isinstance(data, dict) else {}
        except (json.JSONDecodeError, httpx.HTTPError):
            return {}

    @staticmethod
    def _build_payload(
        model: str,
        prompt: str,
        system: str | None,
        options: dict[str, Any] | None,
        *,
        stream: bool,
        response_format: str | dict[str, Any] | None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "model": model,
            "prompt": prompt,
            "stream": stream,
            "options": {**DEFAULT_GENERATE_OPTIONS, **(options or {})},
        }
        if system:
            payload["system"] = system
        if response_format is not None:
            payload["format"] = response_format
        return payload


def _normalize_tag(raw: dict[str, Any]) -> dict[str, Any]:
    """Map an `/api/tags` entry onto `ModelInfo` field names."""
    details = raw.get("details")
    details_dict = details if isinstance(details, dict) else {}
    return {
        "name": raw.get("name") or raw.get("model"),
        "size_bytes": raw.get("size"),
        "digest": raw.get("digest"),
        "modified_at": raw.get("modified_at"),
        "family": details_dict.get("family"),
        "parameter_size": details_dict.get("parameter_size"),
        "quantization_level": details_dict.get("quantization_level"),
    }
