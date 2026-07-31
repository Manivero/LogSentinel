"""Rule-based detection engine.

Evaluates every parsed `LogEntry` against the loaded `DetectionRule`s.
Simple rules match a single entry directly; threshold rules track
occurrences grouped by a field (e.g. `source_ip`) within a time window and
fire once when the configured count is reached, which is how this engine
expresses rate-based patterns like brute-force login attempts or port
scans without any bespoke Python per rule — see `src.detection.rules`.
"""

from __future__ import annotations

import re
from collections import defaultdict
from datetime import timedelta
from typing import Any

from src.core.models import DetectionMatch, DetectionRule, LogEntry, RuleCondition
from src.utils.logger import get_logger

logger = get_logger("detection.engine")

_DEFAULT_THRESHOLD_GROUP_FIELD = "source_ip"
_UNKNOWN_GROUP_KEY = "unknown"


def _get_field_value(entry: LogEntry, field_path: str) -> Any:
    """Resolve a dotted field path against a LogEntry, e.g. `'fields.auth_result'`."""
    if field_path.startswith("fields."):
        return entry.fields.get(field_path.removeprefix("fields."))
    return getattr(entry, field_path, None)


def _evaluate_condition(entry: LogEntry, condition: RuleCondition) -> bool:
    value = _get_field_value(entry, condition.field)
    op = condition.operator

    if op == "exists":
        return value is not None
    if op == "not_exists":
        return value is None
    if value is None:
        return False  # every remaining operator needs an actual value to compare against

    text_value = str(value)
    compare_text = text_value if condition.case_sensitive else text_value.lower()

    if op in ("equals", "contains", "not_contains"):
        target = str(condition.value)
        target = target if condition.case_sensitive else target.lower()
        if op == "equals":
            return compare_text == target
        if op == "contains":
            return target in compare_text
        return target not in compare_text

    if op == "in":
        options = condition.value if isinstance(condition.value, list) else [condition.value]
        normalized = [str(o) if condition.case_sensitive else str(o).lower() for o in options]
        return compare_text in normalized

    if op == "regex":
        flags = 0 if condition.case_sensitive else re.IGNORECASE
        try:
            return re.search(str(condition.value), text_value, flags) is not None
        except re.error:
            logger.warning(
                "Invalid regex in rule condition on field '%s': %r",
                condition.field,
                condition.value,
            )
            return False

    if op in ("gt", "gte", "lt", "lte"):
        try:
            numeric_value = float(value)
            numeric_target = float(condition.value)
        except (TypeError, ValueError):
            return False
        comparisons = {
            "gt": numeric_value > numeric_target,
            "gte": numeric_value >= numeric_target,
            "lt": numeric_value < numeric_target,
            "lte": numeric_value <= numeric_target,
        }
        return comparisons[op]

    logger.warning("Unknown rule operator: %r", op)
    return False


def _matches_rule(entry: LogEntry, rule: DetectionRule) -> bool:
    if not rule.conditions:
        return False
    results = [_evaluate_condition(entry, c) for c in rule.conditions]
    return any(results) if rule.condition_logic == "OR" else all(results)


class DetectionEngine:
    """Evaluates log entries against loaded rules, including threshold rules."""

    def __init__(self, rules: list[DetectionRule]) -> None:
        enabled = [r for r in rules if r.enabled]
        self._simple_rules = [r for r in enabled if r.threshold_count is None]
        self._threshold_rules = [r for r in enabled if r.threshold_count is not None]
        logger.info(
            "Detection engine ready: %d simple rule(s), %d threshold rule(s)",
            len(self._simple_rules),
            len(self._threshold_rules),
        )

    def evaluate(self, entries: list[LogEntry]) -> list[DetectionMatch]:
        """Evaluate all entries against all rules.

        Entries are sorted by timestamp internally (entries without a
        timestamp keep their original relative order via a stable sort,
        treated as occurring at the very start) before threshold-window
        logic runs, so callers never need to pre-sort merged, multi-file
        entry lists themselves.
        """
        ordered = sorted(entries, key=lambda e: (e.timestamp is not None, e.timestamp))

        matches: list[DetectionMatch] = []
        for entry in ordered:
            matches.extend(self._evaluate_simple(entry))
        matches.extend(self._evaluate_thresholds(ordered))
        return matches

    def _evaluate_simple(self, entry: LogEntry) -> list[DetectionMatch]:
        return [
            self._build_match(rule, entry)
            for rule in self._simple_rules
            if _matches_rule(entry, rule)
        ]

    def _evaluate_thresholds(self, entries: list[LogEntry]) -> list[DetectionMatch]:
        matches: list[DetectionMatch] = []
        for rule in self._threshold_rules:
            matches.extend(self._evaluate_single_threshold_rule(rule, entries))
        return matches

    def _evaluate_single_threshold_rule(
        self, rule: DetectionRule, entries: list[LogEntry]
    ) -> list[DetectionMatch]:
        threshold_count = rule.threshold_count
        threshold_window_seconds = rule.threshold_window_seconds
        if threshold_count is None or threshold_window_seconds is None:
            # Unreachable given DetectionRule's threshold-pairing validator,
            # but degrade gracefully (skip this rule) rather than crash if
            # a future change ever loosens that guarantee.
            return []

        window = timedelta(seconds=threshold_window_seconds)
        group_field = rule.threshold_group_by or _DEFAULT_THRESHOLD_GROUP_FIELD

        groups: dict[str, list[LogEntry]] = defaultdict(list)
        fired_groups: set[str] = set()
        results: list[DetectionMatch] = []

        for entry in entries:
            if not _matches_rule(entry, rule):
                continue
            group_key = str(_get_field_value(entry, group_field) or _UNKNOWN_GROUP_KEY)
            if group_key in fired_groups:
                continue  # already alerted for this group; don't re-fire per event

            bucket = groups[group_key]
            bucket.append(entry)
            if entry.timestamp is not None:
                cutoff = entry.timestamp - window
                bucket = [e for e in bucket if e.timestamp is None or e.timestamp >= cutoff]
                groups[group_key] = bucket

            if len(bucket) >= threshold_count:
                results.append(
                    self._build_match(
                        rule,
                        entry,
                        matched_pattern=(
                            f"{len(bucket)} matching events within "
                            f"{threshold_window_seconds}s (grouped by {group_field}={group_key})"
                        ),
                    )
                )
                fired_groups.add(group_key)

        return results

    @staticmethod
    def _build_match(
        rule: DetectionRule, entry: LogEntry, *, matched_pattern: str | None = None
    ) -> DetectionMatch:
        return DetectionMatch(
            rule_id=rule.id,
            rule_name=rule.name,
            category=rule.category,
            severity=rule.severity,
            description=rule.description,
            log_entry=entry,
            matched_pattern=matched_pattern,
            mitre_technique=rule.mitre_technique,
            tags=rule.tags,
        )
