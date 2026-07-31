"""Custom organizational knowledge source: a user-supplied directory.

Loads and chunks plain-text/Markdown files from
`KnowledgeConfig.source_directory`, letting an organization add its own
runbooks, past-incident notes, or internal detection documentation to
the knowledge base without any code change.
"""

from __future__ import annotations

from pathlib import Path
from typing import ClassVar

from src.core.exceptions import KnowledgeBaseError
from src.core.models import KnowledgeChunk
from src.knowledge.base import KnowledgeSource
from src.knowledge.embeddings import chunk_text
from src.utils.logger import get_logger

logger = get_logger("knowledge.sources.custom_directory")

_SUPPORTED_EXTENSIONS = {".txt", ".md"}
_MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024  # 5 MB is generous for reference documents


class CustomDirectorySource(KnowledgeSource):
    """Loads `.txt`/`.md` files from a user-configured directory."""

    name: ClassVar[str] = "custom"

    def __init__(self, directory: Path, *, chunk_size: int, chunk_overlap: int) -> None:
        self.directory = directory
        self._chunk_size = chunk_size
        self._chunk_overlap = chunk_overlap

    def load(self) -> list[KnowledgeChunk]:
        """Raises `KnowledgeBaseError` if the directory itself doesn't
        exist; individual unreadable files are skipped with a warning
        rather than aborting the whole load, since one bad file
        shouldn't prevent the rest of an organization's knowledge base
        from being indexed."""
        if not self.directory.exists() or not self.directory.is_dir():
            raise KnowledgeBaseError(f"Custom knowledge directory not found: {self.directory}")

        chunks: list[KnowledgeChunk] = []
        for path in sorted(self.directory.rglob("*")):
            if not path.is_file() or path.suffix.lower() not in _SUPPORTED_EXTENSIONS:
                continue
            try:
                if path.stat().st_size > _MAX_FILE_SIZE_BYTES:
                    logger.warning("Skipping oversized knowledge file: %s", path)
                    continue
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                logger.warning("Skipping unreadable knowledge file %s: %s", path, exc)
                continue

            relative = path.relative_to(self.directory)
            pieces = chunk_text(text, chunk_size=self._chunk_size, overlap=self._chunk_overlap)
            for index, piece in enumerate(pieces):
                chunks.append(
                    KnowledgeChunk(
                        source=f"{self.name}:{relative}#{index}",
                        text=piece,
                        metadata={"file": str(relative), "chunk_index": index},
                    )
                )
        return chunks
