"""Abstract knowledge source interface.

A `KnowledgeSource` is anything that can be loaded into a list of
`KnowledgeChunk` objects for indexing. Bundled sources
(`src.knowledge.sources.mitre_attack`, `.sigma_rules`, `.owasp`) read
static YAML reference data shipped with the package; a custom directory
source reads whatever the user points `KnowledgeConfig.source_directory`
at. The indexing pipeline (`src.knowledge.retriever.KnowledgeBase`)
treats every source identically through this interface.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import ClassVar

from src.core.models import KnowledgeChunk


class KnowledgeSource(ABC):
    """A loadable source of reference knowledge chunks."""

    #: Short, stable identifier stored in `KnowledgeChunk.source` prefix
    #: and reported in `KnowledgeBaseStats.sources` (e.g. `"mitre_attack"`).
    name: ClassVar[str]

    @abstractmethod
    def load(self) -> list[KnowledgeChunk]:
        """Load and return this source's knowledge chunks.

        Implementations should raise `src.core.exceptions.KnowledgeBaseError`
        (or a subclass) on failure — the indexing pipeline catches this
        per-source so one broken source doesn't prevent the others from
        loading, rather than swallowing errors silently here.
        """
