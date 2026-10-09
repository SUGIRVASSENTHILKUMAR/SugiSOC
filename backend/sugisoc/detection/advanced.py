"""Offline ATT&CK-aligned detection enrichment with evidence-backed rules.

Mappings describe relevant ATT&CK techniques, not a verdict of compromise.
"""

from collections import defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sugisoc.detection.alert_store import AlertStore
from sugisoc.detection.engine import Finding, detect
from sugisoc.services.event_store import EventStore

TECHNIQUES = {
    "AUTH-BRUTE-001": ("T1110.001", "Password Guessing"),
    "AUTH-SPRAY-002": ("T1110.003", "Password Spraying"),
    "AUTH-SUCCESS-003": ("T1078", "Valid Accounts"),
    "AUTH-DISTRIBUTED-004": ("T1110.001", "Password Guessing"),
}


@dataclass(frozen=True)
class AnnotatedFinding:
    finding: Finding
    technique_id: str
    technique_name: str
    confidence_note: str


def annotate(finding: Finding) -> AnnotatedFinding:
    """Link known rules to ATT&CK; reject unknown rules rather than guess."""
    technique_id, name = TECHNIQUES[finding.rule_id]
    return AnnotatedFinding(
        finding,
        technique_id,
        name,
        "Rule matched observed events; technique mapping is not proof of malicious intent.",
    )


def _parse_timestamp(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if result.tzinfo is None or result.utcoffset() is None:
        return None
    return result.astimezone(UTC)


def detect_distributed_guessing(
    events: list[dict], *, window_seconds: int = 300, min_ips: int = 3
) -> list[Finding]:
    """Detect failures against one account coming from multiple source IPs.

    Different from a single-source spray. Not inherently an attack: NAT, VPNs,
    and legitimate account use require an analyst's contextual investigation.
    """
    if not 1 <= window_seconds <= 3600 or not 2 <= min_ips <= 50:
        raise ValueError("Invalid detection parameters")
    grouped: dict[str, list[tuple[datetime, dict]]] = defaultdict(list)
    for event in events:
        stamp = _parse_timestamp(event.get("occurred_at"))
        if (
            stamp is not None
            and event.get("event_type") == "login_failure"
            and isinstance(event.get("id"), int)
            and event["id"] > 0
            and isinstance(event.get("username"), str)
            and event["username"]
            and isinstance(event.get("source_ip"), str)
            and event["source_ip"]
        ):
            grouped[event["username"]].append((stamp, event))
    findings = []
    period = timedelta(seconds=window_seconds)
    for user, records in sorted(grouped.items()):
        records.sort(key=lambda x: (x[0], x[1]["id"]))
        index = 0
        while index < len(records):
            begin = records[index][0]
            window = [e for stamp, e in records[index:] if stamp <= begin + period]
            sources = {e["source_ip"] for e in window}
            if len(sources) >= min_ips:
                findings.append(
                    Finding(
                        "AUTH-DISTRIBUTED-004",
                        "high",
                        "Multi-source password guessing suspected",
                        f"{len(sources)} distinct source IPs failed authentication for {user} "
                        f"within {window_seconds} seconds; investigate for legitimate activity.",
                        tuple(sorted({e["id"] for e in window})),
                        sorted(sources)[0],
                        user,
                    )
                )
                index += len(window)
            else:
                index += 1
    return findings


def advanced_findings(events: list[dict]) -> list[AnnotatedFinding]:
    """Combine existing rules with the new rule, preserving evidence IDs."""
    return [annotate(f) for f in [*detect(events), *detect_distributed_guessing(events)]]


def run_advanced_detection(store: EventStore, alerts: AlertStore, *, limit: int = 500) -> int:
    """Persist reproducible findings; existing alert keys prevent duplicates."""
    if not 1 <= limit <= 500:
        raise ValueError("limit must be 1..500")
    return sum(alerts.save(a.finding) for a in advanced_findings(store.search(limit=limit)))
