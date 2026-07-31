"""ChromaDB-backed persistent vector store.

Chroma's own embedding functions are never used — this project brings
its own embeddings from Ollama (`src.knowledge.embeddings`) and only
uses Chroma for storage and similarity search.

Chroma's analytics telemetry (`anonymized_telemetry`, routed through
PostHog) defaults to `True`. This is explicitly disabled at client
construction below: confirmed by installing chromadb and inspecting
`chromadb.config.Settings()`'s defaults directly rather than assuming,
since a "100% local, no telemetry" tool would otherwise silently phone
home through this one dependency.

Broad `except Exception` is used deliberately (not carelessly) around
Chroma calls: Chroma 1.x is Rust-backed internally and its exception
surface isn't fully closed/predictable the way, say, `httpx`'s is, and
this module's entire purpose is to never let a storage-layer issue be a
single point of failure for the rest of the application — consistent
with `KnowledgeBaseError` and friends being designed for graceful
degradation, not hard failure.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import chromadb
from chromadb.config import Settings

from src.core.exceptions import VectorStoreError
from src.core.models import KnowledgeChunk, RetrievedContext
from src.utils.logger import get_logger

logger = get_logger("knowledge.vector_store")

_COLLECTION_NAME = "ai_log_analyzer_knowledge"
_METADATA_RESERVED_KEYS = {"source"}


class VectorStore:
    """Persistent, local ChromaDB collection for knowledge chunks + embeddings."""

    def __init__(self, persist_directory: Path) -> None:
        self.persist_directory = persist_directory
        self._client: Any = None
        self._collection: Any = None
        try:
            persist_directory.mkdir(parents=True, exist_ok=True)
            self._client = chromadb.PersistentClient(
                path=str(persist_directory),
                settings=Settings(anonymized_telemetry=False, allow_reset=True),
            )
            self._collection = self._client.get_or_create_collection(
                name=_COLLECTION_NAME, metadata={"hnsw:space": "cosine"}
            )
        except Exception as exc:
            logger.warning(
                "Could not initialize vector store at %s (%s); the knowledge base will be "
                "unavailable for this run.",
                persist_directory,
                exc,
            )
            self._client = None
            self._collection = None

    @property
    def enabled(self) -> bool:
        return self._collection is not None

    def upsert(self, chunks: list[KnowledgeChunk], embeddings: list[list[float]]) -> None:
        """Store or update `chunks` with their corresponding `embeddings`.

        Raises:
            VectorStoreError: On any underlying storage failure. Unlike
                the read-path methods below, this does not silently
                degrade — a failed *write* during indexing is worth
                surfacing distinctly so the indexing pipeline can report
                it, rather than silently producing an incomplete index.
        """
        if self._collection is None:
            raise VectorStoreError("Vector store is not initialized.")
        if len(chunks) != len(embeddings):
            raise VectorStoreError(
                "chunks and embeddings must be the same length",
                details={"chunks": len(chunks), "embeddings": len(embeddings)},
            )
        if not chunks:
            return
        try:
            self._collection.upsert(
                ids=[c.chunk_id for c in chunks],
                embeddings=embeddings,
                documents=[c.text for c in chunks],
                metadatas=[_prepare_metadata(c) for c in chunks],
            )
        except Exception as exc:
            raise VectorStoreError(f"Failed to upsert {len(chunks)} chunk(s)") from exc

    def query(self, query_embedding: list[float], *, top_k: int) -> list[RetrievedContext]:
        """Return up to `top_k` chunks most similar to `query_embedding`.

        Never raises: a query failure during live analysis degrades to
        an empty result (no knowledge context this time) rather than
        aborting the analysis — see module docstring.
        """
        if self._collection is None:
            return []
        try:
            raw = self._collection.query(query_embeddings=[query_embedding], n_results=top_k)
        except Exception as exc:
            logger.warning("Vector store query failed: %s", exc)
            return []
        return _parse_query_results(raw)

    def count(self) -> int:
        if self._collection is None:
            return 0
        try:
            result: int = self._collection.count()
            return result
        except Exception as exc:
            logger.warning("Vector store count failed: %s", exc)
            return 0

    def source_counts(self) -> dict[str, int]:
        """Count indexed chunks per top-level source (e.g. `mitre_attack`)."""
        counts: dict[str, int] = {}
        for metadata in self._all_metadata():
            source = str(metadata.get("source", "unknown")).split(":")[0]
            counts[source] = counts.get(source, 0) + 1
        return counts

    def document_count(self) -> int:
        """Count distinct logical documents (chunk sources with any trailing
        `#N` chunk-index suffix stripped) — e.g. a custom file split into
        5 chunks counts as 1 document but 5 chunks."""
        bases = {str(m.get("source", "")).split("#")[0] for m in self._all_metadata()}
        bases.discard("")
        return len(bases)

    def _all_metadata(self) -> list[dict[str, Any]]:
        if self._collection is None:
            return []
        try:
            all_items = self._collection.get(include=["metadatas"])
        except Exception as exc:
            logger.warning("Could not read vector store metadata: %s", exc)
            return []
        return [m or {} for m in (all_items.get("metadatas") or [])]

    def reset(self) -> None:
        """Delete every indexed chunk."""
        if self._client is None or self._collection is None:
            return
        try:
            self._client.delete_collection(_COLLECTION_NAME)
            self._collection = self._client.get_or_create_collection(
                name=_COLLECTION_NAME, metadata={"hnsw:space": "cosine"}
            )
        except Exception as exc:
            logger.warning("Vector store reset failed: %s", exc)


def _prepare_metadata(chunk: KnowledgeChunk) -> dict[str, str | int | float | bool]:
    """Chroma metadata values must be str/int/float/bool; stringify anything else."""
    flattened: dict[str, str | int | float | bool] = {"source": chunk.source}
    for key, value in chunk.metadata.items():
        if key in _METADATA_RESERVED_KEYS:
            continue
        flattened[key] = value if isinstance(value, str | int | float | bool) else str(value)
    return flattened


def _parse_query_results(raw: dict[str, Any]) -> list[RetrievedContext]:
    ids = (raw.get("ids") or [[]])[0]
    documents = (raw.get("documents") or [[]])[0]
    distances = (raw.get("distances") or [[]])[0]
    metadatas = (raw.get("metadatas") or [[]])[0]

    results: list[RetrievedContext] = []
    for i, chunk_id in enumerate(ids):
        document = documents[i] if i < len(documents) else ""
        distance = distances[i] if i < len(distances) else 1.0
        metadata = metadatas[i] if i < len(metadatas) else {}
        source = str((metadata or {}).get("source", "unknown"))
        # Cosine distance (0 = identical) -> similarity (1 = identical),
        # clamped since floating-point noise can push distance slightly
        # outside [0, 2] for near-duplicate or near-orthogonal vectors.
        similarity = max(0.0, min(1.0, 1.0 - distance))
        chunk = KnowledgeChunk(
            chunk_id=chunk_id,
            source=source,
            text=document or "",
            metadata={k: v for k, v in (metadata or {}).items() if k != "source"},
        )
        results.append(RetrievedContext(chunk=chunk, score=similarity))
    return results
