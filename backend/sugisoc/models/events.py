"""Normalized security event models (untrusted input is preserved as evidence)."""

from dataclasses import dataclass
from datetime import UTC, datetime

from sugisoc.collectors.file_collector import LogRecord


@dataclass(frozen=True)
class SecurityEvent:
    source_id: str
    byte_offset: int
    source_path: str
    raw_line: str
    event_type: str
    username: str | None
    source_ip: str | None
    occurred_at: str | None


def normalize(record: LogRecord) -> SecurityEvent:
    """Recognize common SSH auth events; preserve unsupported records as 'other'."""
    import re

    line = record.line
    event_type = "other"
    username = None
    source_ip = None
    match = re.search(
        r"(?:Failed|Accepted) (?:password|publickey) for (?:invalid user )?"
        r"(?P<user>\S+) from (?P<ip>\S+)",
        line,
    )
    if match:
        event_type = "login_failure" if "Failed " in match.group(0) else "login_success"
        username = match.group("user")
        source_ip = match.group("ip")
    # Syslog timestamps lack year and timezone: do not invent them.
    # Only accept an explicit ISO-8601 timestamp with timezone.
    occurred_at = None
    timestamp = re.match(
        r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2}))", line
    )
    if timestamp:
        try:
            parsed = datetime.fromisoformat(timestamp.group(1).replace("Z", "+00:00"))
            occurred_at = parsed.astimezone(UTC).isoformat()
        except ValueError:
            pass
    return SecurityEvent(
        source_id=record.source_id,
        byte_offset=record.byte_offset,
        source_path=record.path,
        raw_line=line,
        event_type=event_type,
        username=username,
        source_ip=source_ip,
        occurred_at=occurred_at,
    )
