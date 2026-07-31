"""MITRE ATT&CK reference knowledge source.

Loads the curated technique subset in `data/mitre_attack.yaml` — see
that file's header comment for scope and sourcing notes.
"""

from __future__ import annotations

from typing import ClassVar

from src.core.exceptions import KnowledgeBaseError
from src.core.models import KnowledgeChunk
from src.knowledge.base import KnowledgeSource
from src.knowledge.sources import load_yaml_data


class MitreAttackSource(KnowledgeSource):
    """Bundled MITRE ATT&CK technique reference."""

    name: ClassVar[str] = "mitre_attack"

    def load(self) -> list[KnowledgeChunk]:
        data = load_yaml_data("mitre_attack.yaml")
        techniques = data.get("techniques")
        if not isinstance(techniques, list):
            raise KnowledgeBaseError("mitre_attack.yaml is missing a 'techniques' list")

        chunks: list[KnowledgeChunk] = []
        for entry in techniques:
            if not isinstance(entry, dict) or "id" not in entry:
                continue
            technique_id = str(entry["id"])
            name = str(entry.get("name", ""))
            text = (
                f"MITRE ATT&CK {technique_id}: {name} "
                f"(Tactic: {entry.get('tactic', 'unknown')})\n"
                f"{str(entry.get('description', '')).strip()}\n"
                f"Typical log evidence: {str(entry.get('log_evidence', '')).strip()}"
            )
            chunks.append(
                KnowledgeChunk(
                    source=f"{self.name}:{technique_id}",
                    text=text,
                    metadata={"technique_id": technique_id, "name": name},
                )
            )
        return chunks
