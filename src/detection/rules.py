"""Detection rule loading and management.

Rules are entirely data-driven: YAML files under `src/detection/rules/`
(bundled defaults) or a user-supplied directory
(`DetectionConfig.rules_directory`) define what to look for — never
Python code. Adding a new detection means adding a new YAML entry, not
writing a new class, which is what keeps the rule set auditable and
extensible without touching the codebase.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from src.core.exceptions import RuleLoadError
from src.core.models import DetectionRule
from src.utils.logger import get_logger

logger = get_logger("detection.rules")

#: Rules bundled with the package (src/detection/rules.py -> src/detection/rules/).
BUNDLED_RULES_DIRECTORY: Path = Path(__file__).resolve().parent / "rules"


def load_rules_from_file(path: Path) -> list[DetectionRule]:
    """Load and validate all rules defined in a single YAML file.

    Expects a top-level `rules:` list. A rule that fails validation is
    logged and skipped rather than aborting the whole file, so one typo
    in a custom rule file doesn't silently disable every bundled rule
    too — callers get partial, correct results instead of nothing.

    Raises:
        RuleLoadError: If the file cannot be read or is not valid YAML,
            or its top-level shape isn't a `rules:` mapping.
    """
    try:
        with path.open("r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
    except OSError as exc:
        raise RuleLoadError(f"Could not read rule file: {path}") from exc
    except yaml.YAMLError as exc:
        raise RuleLoadError(f"Invalid YAML in rule file: {path}") from exc

    if data is None:
        return []
    if not isinstance(data, dict) or "rules" not in data:
        raise RuleLoadError(f"Rule file must contain a top-level 'rules:' list: {path}")
    raw_rules = data["rules"]
    if not isinstance(raw_rules, list):
        raise RuleLoadError(f"'rules:' must be a list in {path}")

    rules: list[DetectionRule] = []
    for index, raw_rule in enumerate(raw_rules):
        rule = _validate_one_rule(raw_rule, source=path, index=index)
        if rule is not None:
            rules.append(rule)
    return rules


def _validate_one_rule(raw_rule: Any, *, source: Path, index: int) -> DetectionRule | None:
    if not isinstance(raw_rule, dict):
        logger.warning("Skipping malformed rule entry %d in %s (not a mapping).", index, source)
        return None
    try:
        return DetectionRule.model_validate(raw_rule)
    except ValidationError as exc:
        rule_id = raw_rule.get("id", f"<entry {index}>")
        logger.warning("Skipping invalid rule '%s' in %s: %s", rule_id, source, exc)
        return None


def load_rules_from_directory(
    directory: Path, *, enabled_categories: list[str] | None = None
) -> list[DetectionRule]:
    """Load and validate every `*.yaml`/`*.yml` rule file in `directory`.

    Args:
        directory: Directory to scan (non-recursive).
        enabled_categories: If non-empty, only rules whose `category` is
            in this list are returned. Empty/None means all categories.

    Duplicate rule IDs across files are logged and the first occurrence
    wins — later files never silently overwrite an earlier rule.

    Raises:
        RuleLoadError: If `directory` does not exist or is not a directory.
    """
    if not directory.exists() or not directory.is_dir():
        raise RuleLoadError(f"Rules directory not found: {directory}")

    seen_ids: dict[str, Path] = {}
    rules: list[DetectionRule] = []
    for rule_file in sorted(directory.glob("*.yaml")) + sorted(directory.glob("*.yml")):
        for rule in load_rules_from_file(rule_file):
            if rule.id in seen_ids:
                logger.warning(
                    "Duplicate rule id '%s' in %s (already defined in %s); skipping.",
                    rule.id,
                    rule_file,
                    seen_ids[rule.id],
                )
                continue
            seen_ids[rule.id] = rule_file
            rules.append(rule)

    if enabled_categories:
        allowed = set(enabled_categories)
        rules = [r for r in rules if r.category in allowed]

    logger.info("Loaded %d detection rule(s) from %s", len(rules), directory)
    return rules


def load_default_rules(
    *,
    rules_directory: Path | None = None,
    enabled_categories: list[str] | None = None,
) -> list[DetectionRule]:
    """Load rules from `rules_directory`, or the bundled defaults if `None`.

    This is the entry point `DetectionEngine` construction should use in
    normal operation; `load_rules_from_directory`/`load_rules_from_file`
    remain available directly for tests or advanced composition (e.g.
    merging bundled rules with a custom directory).
    """
    directory = rules_directory or BUNDLED_RULES_DIRECTORY
    return load_rules_from_directory(directory, enabled_categories=enabled_categories)
