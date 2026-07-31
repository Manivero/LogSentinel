"""Sigma-style detection concept reference knowledge source.

Loads the bundled detection concepts in `data/sigma_rules.yaml` — see
that file's header comment for scope and sourcing notes (original
summaries in the spirit of the Sigma project's rule format, not a
reproduction of any specific upstream rule).
"""

from __future__ import annotations

from typing import ClassVar

from src.core.exceptions import KnowledgeBaseError
from src.core.models import KnowledgeChunk
from src.knowledge.base import KnowledgeSource
from src.knowledge.sources import load_yaml_data


class SigmaRulesSource(KnowledgeSource):
    """Bundled Sigma-style detection concept reference."""

    name: ClassVar[str] = "sigma_rules"

    def load(self) -> list[KnowledgeChunk]:
        data = load_yaml_data("sigma_rules.yaml")
        concepts = data.get("concepts")
        if not isinstance(concepts, list):
            raise KnowledgeBaseError("sigma_rules.yaml is missing a 'concepts' list")

        chunks: list[KnowledgeChunk] = []
        for entry in concepts:
            if not isinstance(entry, dict) or "id" not in entry:
                continue
            concept_id = str(entry["id"])
            name = str(entry.get("name", ""))
            text = (
                f"Detection concept {concept_id}: {name} "
                f"(Category: {entry.get('category', 'unknown')})\n"
                f"{str(entry.get('description', '')).strip()}\n"
                f"Detection logic summary: {str(entry.get('detection_logic_summary', '')).strip()}"
            )
            chunks.append(
                KnowledgeChunk(
                    source=f"{self.name}:{concept_id}",
                    text=text,
                    metadata={"concept_id": concept_id, "name": name},
                )
            )
        return chunks
