"""OWASP Top 10 reference knowledge source.

Loads the bundled category reference in `data/owasp.yaml` — see that
file's header comment for scope and sourcing notes.
"""

from __future__ import annotations

from typing import ClassVar

from src.core.exceptions import KnowledgeBaseError
from src.core.models import KnowledgeChunk
from src.knowledge.base import KnowledgeSource
from src.knowledge.sources import load_yaml_data


class OwaspSource(KnowledgeSource):
    """Bundled OWASP Top 10 category reference."""

    name: ClassVar[str] = "owasp"

    def load(self) -> list[KnowledgeChunk]:
        data = load_yaml_data("owasp.yaml")
        categories = data.get("categories")
        if not isinstance(categories, list):
            raise KnowledgeBaseError("owasp.yaml is missing a 'categories' list")

        chunks: list[KnowledgeChunk] = []
        for entry in categories:
            if not isinstance(entry, dict) or "id" not in entry:
                continue
            category_id = str(entry["id"])
            name = str(entry.get("name", ""))
            text = (
                f"OWASP {category_id}: {name}\n"
                f"{str(entry.get('description', '')).strip()}\n"
                f"Typical log evidence: {str(entry.get('log_evidence', '')).strip()}"
            )
            chunks.append(
                KnowledgeChunk(
                    source=f"{self.name}:{category_id}",
                    text=text,
                    metadata={"category_id": category_id, "name": name},
                )
            )
        return chunks
