"""RAG retrieval layer and public knowledge-base facade.

`KnowledgeBase` is this package's single public entry point: it decides
whether the knowledge base is usable at all (per `KnowledgeConfig.enabled`
and whether an embedding model is actually available), builds the index
from every configured `KnowledgeSource`, and answers "what's relevant to
this query?" as a single rendered text block ready for
`src.analysis.prompts.build_analysis_prompt`.

Every public method degrades gracefully: a disabled or unavailable
knowledge base returns empty/`None` results, never raises, and
`src.analysis.ai_analyzer` never needs to know whether RAG is active —
it just receives `knowledge_context=None` and proceeds normally, exactly
as if the caller had never asked for retrieval at all.
"""

from __future__ import annotations

from datetime import UTC, datetime

from src.core.config import KnowledgeConfig
from src.core.exceptions import EmbeddingError, KnowledgeBaseError, VectorStoreError
from src.core.models import KnowledgeBaseStats, RetrievedContext
from src.knowledge.base import KnowledgeSource
from src.knowledge.embeddings import EmbeddingService
from src.knowledge.vector_store import VectorStore
from src.ollama.client import OllamaClient
from src.utils.logger import get_logger

logger = get_logger("knowledge.retriever")

_DEFAULT_INDEX_CONCURRENCY = 3


class KnowledgeBase:
    """Public facade for the optional RAG knowledge layer."""

    def __init__(
        self,
        config: KnowledgeConfig,
        *,
        client: OllamaClient,
        embedding_model: str | None,
    ) -> None:
        self._config = config
        self._embedding_model = embedding_model
        self._last_indexed_at: datetime | None = None
        self._vector_store: VectorStore | None = None
        self._embedding_service: EmbeddingService | None = None

        if not config.enabled:
            logger.debug("Knowledge base disabled via configuration.")
            return
        if embedding_model is None:
            logger.warning("Knowledge base enabled but no embedding model is available; disabling.")
            return

        self._vector_store = VectorStore(config.persist_directory)
        if not self._vector_store.enabled:
            self._vector_store = None
            return
        self._embedding_service = EmbeddingService(client, embedding_model)

    @property
    def enabled(self) -> bool:
        """Whether retrieval can actually be attempted right now."""
        return self._vector_store is not None and self._embedding_service is not None

    async def build_index(self, sources: list[KnowledgeSource]) -> KnowledgeBaseStats:
        """Load, embed, and index every source. Returns the resulting stats.

        A source that fails to load, or a chunk that fails to embed, is
        logged and skipped rather than aborting the whole run — indexing
        makes as much progress as it can. Never raises.
        """
        if not self.enabled or self._embedding_service is None or self._vector_store is None:
            return self.stats()

        all_chunks = []
        for source in sources:
            try:
                chunks = source.load()
                logger.info("Loaded %d chunk(s) from source '%s'", len(chunks), source.name)
                all_chunks.extend(chunks)
            except KnowledgeBaseError as exc:
                logger.warning("Skipping knowledge source '%s': %s", source.name, exc)

        if not all_chunks:
            logger.warning("No knowledge chunks loaded from any source; index is empty.")
            return self.stats()

        embedded = await self._embedding_service.embed_chunks(
            all_chunks, max_concurrency=_DEFAULT_INDEX_CONCURRENCY
        )
        if not embedded:
            logger.warning("No chunks could be embedded; index remains empty.")
            return self.stats()

        try:
            self._vector_store.upsert([c for c, _ in embedded], [v for _, v in embedded])
            self._last_indexed_at = datetime.now(UTC)
            logger.info("Indexed %d chunk(s) into the knowledge base.", len(embedded))
        except VectorStoreError as exc:
            logger.warning("Indexing failed while writing to the vector store: %s", exc)

        return self.stats()

    async def retrieve_context(self, query_text: str) -> str | None:
        """Retrieve and render relevant knowledge for `query_text`.

        Returns `None` (not an empty string) when the knowledge base is
        disabled, unavailable, or nothing clears
        `KnowledgeConfig.similarity_threshold` — callers pass this
        straight through to
        `build_analysis_prompt(knowledge_context=...)`, which already
        treats `None` as "no knowledge block". Never raises.
        """
        if not self.enabled or self._embedding_service is None or self._vector_store is None:
            return None
        try:
            query_embedding = await self._embedding_service.embed_text(query_text)
        except EmbeddingError as exc:
            logger.warning("Could not embed query for retrieval: %s", exc)
            return None

        results = self._vector_store.query(query_embedding, top_k=self._config.top_k)
        relevant = [r for r in results if r.score >= self._config.similarity_threshold]
        if not relevant:
            return None
        return render_context_block(relevant)

    def stats(self) -> KnowledgeBaseStats:
        """Snapshot current knowledge-base state (for the `knowledge-stats` command)."""
        if self._vector_store is None:
            return KnowledgeBaseStats(enabled=False)
        return KnowledgeBaseStats(
            enabled=self.enabled,
            total_documents=self._vector_store.document_count(),
            total_chunks=self._vector_store.count(),
            sources=self._vector_store.source_counts(),
            embedding_model=self._embedding_model,
            persist_directory=str(self._config.persist_directory),
            last_indexed_at=self._last_indexed_at,
        )


def render_context_block(results: list[RetrievedContext]) -> str:
    """Render retrieved chunks as plain text for prompt injection.

    Kept intentionally simple (no markup) since this text is embedded
    directly into LLM prompts as background reference material — see
    `src.analysis.prompts.build_analysis_prompt`'s `knowledge_context`
    parameter, which wraps this output in its own labeled section.
    """
    blocks = [
        f"[{result.chunk.source}] (relevance: {result.score:.2f})\n{result.chunk.text}"
        for result in results
    ]
    return "\n\n".join(blocks)
