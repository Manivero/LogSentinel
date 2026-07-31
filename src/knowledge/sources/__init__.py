"""Bundled reference knowledge source loaders.

Each loader (`mitre_attack.py`, `owasp.py`, `sigma_rules.py`) reads its
static YAML data file from `data/` and converts it into `KnowledgeChunk`
objects; `custom_directory.py` loads a user-configured directory of
plain-text/Markdown files instead. See `src.knowledge.base.KnowledgeSource`
for the common interface.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from src.core.exceptions import KnowledgeBaseError

DATA_DIR = Path(__file__).resolve().parent / "data"


def load_yaml_data(filename: str) -> dict[str, Any]:
    """Read and parse a bundled YAML data file from `sources/data/`.

    Raises:
        KnowledgeBaseError: If the file is missing, unreadable, not
            valid YAML, or not a top-level mapping.
    """
    path = DATA_DIR / filename
    try:
        with path.open("r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
    except OSError as exc:
        raise KnowledgeBaseError(f"Could not read bundled knowledge data: {path}") from exc
    except yaml.YAMLError as exc:
        raise KnowledgeBaseError(f"Invalid YAML in bundled knowledge data: {path}") from exc
    if not isinstance(data, dict):
        raise KnowledgeBaseError(f"Bundled knowledge data must be a YAML mapping: {path}")
    return data
