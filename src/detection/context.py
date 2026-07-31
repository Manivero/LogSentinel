"""Cross-log contextual analysis.

Builds a `CrossLogContext` — recurring IPs across files, a correlated
timeline, per-IP activity profiles — from every parsed entry and
detection in a single analysis run. This is session-scoped and
stateless between CLI invocations by design (see ADR-0001): the context
object lives only in memory for the duration of one `analyze` run and is
never persisted, so there is nothing to clean up and nothing accumulates
across unrelated runs.
"""

from __future__ import annotations

from src.core.models import CrossLogContext, DetectionMatch, IPActivity, LogEntry, TimelineEvent
from src.utils.logger import get_logger

logger = get_logger("detection.context")

#: Only detections at or above this severity are added to the timeline,
#: keeping the context summary passed to the AI (see
#: `CrossLogContext.summarize`) focused on what actually matters rather
#: than every INFO-level rule match.
_TIMELINE_MIN_RANK = 1  # Severity.LOW.rank — excludes INFO only


def build_context(entries: list[LogEntry], detections: list[DetectionMatch]) -> CrossLogContext:
    """Correlate parsed entries and rule detections into a `CrossLogContext`.

    Args:
        entries: Every `LogEntry` from every file in this analysis run.
        detections: Every `DetectionMatch` produced by the detection
            engine for those same entries.

    Returns:
        A populated `CrossLogContext`. Never raises: correlation is a
        best-effort enrichment layer, not a required step, so any
        unexpected shape in the input degrades to a smaller/emptier
        context rather than aborting the analysis.
    """
    source_files = {e.source_file for e in entries}
    ip_activity = _build_ip_activity(entries, detections)
    recurring = sorted(
        ip for ip, activity in ip_activity.items() if len(activity.source_files) >= 2
    )
    timeline = _build_timeline(detections)

    context = CrossLogContext(
        total_files=len(source_files),
        total_entries=len(entries),
        ip_activity=ip_activity,
        timeline=timeline,
        recurring_ips=recurring,
    )
    logger.info(
        "Built cross-log context: %d file(s), %d entries, %d distinct IP(s), %d recurring",
        context.total_files,
        context.total_entries,
        len(ip_activity),
        len(recurring),
    )
    return context


def _build_ip_activity(
    entries: list[LogEntry], detections: list[DetectionMatch]
) -> dict[str, IPActivity]:
    activity: dict[str, IPActivity] = {}

    for entry in entries:
        if not entry.source_ip:
            continue
        profile = activity.setdefault(entry.source_ip, IPActivity(ip=entry.source_ip))
        profile.event_count += 1
        if entry.source_file not in profile.source_files:
            profile.source_files.append(entry.source_file)
        if entry.user and entry.user not in profile.associated_users:
            profile.associated_users.append(entry.user)
        if entry.timestamp is not None:
            if profile.first_seen is None or entry.timestamp < profile.first_seen:
                profile.first_seen = entry.timestamp
            if profile.last_seen is None or entry.timestamp > profile.last_seen:
                profile.last_seen = entry.timestamp

    for match in detections:
        ip = match.log_entry.source_ip
        if not ip or ip not in activity:
            continue
        if match.category not in activity[ip].detection_categories:
            activity[ip].detection_categories.append(match.category)

    return activity


def _build_timeline(detections: list[DetectionMatch]) -> list[TimelineEvent]:
    significant = [d for d in detections if d.severity.rank >= _TIMELINE_MIN_RANK]
    ordered = sorted(
        significant, key=lambda d: (d.log_entry.timestamp is not None, d.log_entry.timestamp)
    )
    return [
        TimelineEvent(
            timestamp=d.log_entry.timestamp,
            source_file=d.log_entry.source_file,
            description=f"[{d.rule_id}] {d.rule_name}",
            severity=d.severity,
            ip=d.log_entry.source_ip,
        )
        for d in ordered
    ]
