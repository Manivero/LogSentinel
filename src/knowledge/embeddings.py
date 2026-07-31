"""Chunking and Ollama embedding integration.

Wraps `src.ollama.client.OllamaClient.embed` — this module never opens
its own HTTP connection, reusing the same client (and therefore the same
retry/timeout/error-handling behavior) as every other Ollama call in the
codebase, per the project's established testability/reuse convention.
"""

from __future__ import annotations

from src.core.exceptions import EmbeddingError, OllamaError
from src.core.models import KnowledgeChunk
from src.ollama.client import OllamaClient
from src.utils.concurrency import bounded_gather
from src.utils.logger import get_logger

logger = get_logger("knowledge.embeddings")

_EmbeddedChunk = tuple[KnowledgeChunk, list[float]]


def chunk_text(text: str, *, chunk_size: int, overlap: int) -> list[str]:
    """Split `text` into overlapping chunks of roughly `chunk_size` characters.

    Splits on paragraph boundaries (blank lines) where possible, so a
    chunk rarely cuts a sentence in half, falling back to a hard
    character split for a single paragraph longer than `chunk_size`.

    Raises:
        ValueError: If `chunk_size` is not positive.
    """
    if chunk_size <= 0:
        raise ValueError("chunk_size must be positive")
    effective_overlap = overlap if 0 <= overlap < chunk_size else chunk_size // 4

    paragraphs = [p.strip() for p in text.split("\n\n") if p.strip()]
    if not paragraphs:
        return []

    chunks: list[str] = []
    current = ""
    for paragraph in paragraphs:
        candidate = f"{current}\n\n{paragraph}" if current else paragraph
        if len(candidate) <= chunk_size:
            current = candidate
            continue
        if current:
            chunks.append(current)
        if len(paragraph) <= chunk_size:
            current = paragraph
        else:
            # A single paragraph longer than chunk_size: hard-split it.
            step = chunk_size - effective_overlap
            for start in range(0, len(paragraph), step):
                chunks.append(paragraph[start : start + chunk_size])
            current = ""
    if current:
        chunks.append(current)
    return chunks


class EmbeddingService:
    """Generates embedding vectors for knowledge chunks via Ollama."""

    def __init__(self, client: OllamaClient, model: str) -> None:
        self._client = client
        self._model = model

    async def embed_text(self, text: str) -> list[float]:
        """Embed a single piece of text.

        Raises:
            EmbeddingError: If the underlying Ollama call fails.
        """
        try:
            return await self._client.embed(model=self._model, text=text)
        except OllamaError as exc:
            raise EmbeddingError(f"Failed to embed text: {exc}") from exc

    async def embed_chunks(
        self, chunks: list[KnowledgeChunk], *, max_concurrency: int
    ) -> list[_EmbeddedChunk]:
        """Embed many chunks with bounded concurrency.

        Chunks that fail to embed are logged and dropped rather than
        aborting the whole batch — indexing should make as much progress
        as it can rather than requiring every single chunk to succeed.
        """

        async def worker(chunk: KnowledgeChunk) -> _EmbeddedChunk | None:
            try:
                vector = await self.embed_text(chunk.text)
            except EmbeddingError as exc:
                logger.warning("Skipping chunk %s: %s", chunk.chunk_id, exc)
                return None
            return (chunk, vector)

        def on_error(chunk: KnowledgeChunk, exc: Exception) -> _EmbeddedChunk | None:
            logger.warning("Skipping chunk %s after unexpected error: %s", chunk.chunk_id, exc)
            return None

        results = await bounded_gather(
            chunks, worker, max_concurrency=max_concurrency, on_error=on_error
        )
        return [r for r in results if r is not None]
