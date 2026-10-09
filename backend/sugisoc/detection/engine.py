"""Deterministic security detections with evidence IDs and explicit time windows.

Only timezone-aware, parseable event timestamps are eligible. This is deliberate:
we never fabricate times for undated syslog events.
"""

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    title: str
    explanation: str
    evidence_ids: tuple[int, ...]
    source_ip: str
    username: str | None


def _time(event: dict) -> datetime | None:
    value = event.get("occurred_at")
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo and parsed.utcoffset() is not None else None


def detect(events: list[dict], *, window_seconds: int = 120) -> list[Finding]:
    """Find brute-force, password spray and failure-followed-by-success patterns.

    Findings are evidence-backed but not proof of compromise. Thresholds are
    illustrative and must be tuned against a real environment.
    """
    if not 1 <= window_seconds <= 3600:
        raise ValueError("window_seconds must be between 1 and 3600")
    valid = []
    for event in events:
        stamp = _time(event)
        if (
            stamp is not None
            and event.get("event_type") in {"login_failure", "login_success"}
            and event.get("source_ip")
            and isinstance(event.get("id"), int)
        ):
            valid.append((stamp, event))
    valid.sort(key=lambda pair: (pair[0], pair[1]["id"]))
    by_ip: dict[str, list[tuple[datetime, dict]]] = defaultdict(list)
    for pair in valid:
        by_ip[pair[1]["source_ip"]].append(pair)
    findings: list[Finding] = []
    delta = timedelta(seconds=window_seconds)
    for ip, entries in by_ip.items():
        # Emit at most one alert of each rule for a given IP and rule window,
        # anchored on the earliest as-yet-unprocessed failure.
        index = 0
        while index < len(entries):
            start, first = entries[index]
            if first["event_type"] != "login_failure":
                index += 1
                continue
            window = [e for t, e in entries[index:] if start <= t <= start + delta]
            failures = [e for e in window if e["event_type"] == "login_failure"]
            if len(failures) >= 5:
                findings.append(
                    Finding(
                        "AUTH-BRUTE-001",
                        "medium",
                        "Repeated authentication failures",
                        f"{len(failures)} failed logins from {ip} within {window_seconds}s",
                        tuple(e["id"] for e in failures),
                        ip,
                        None,
                    )
                )
            users = {e.get("username") for e in failures if e.get("username")}
            if len(users) >= 3 and len(failures) >= 3:
                findings.append(
                    Finding(
                        "AUTH-SPRAY-002",
                        "high",
                        "Possible password spraying",
                        f"Failed logins against {len(users)} accounts from {ip}",
                        tuple(e["id"] for e in failures),
                        ip,
                        None,
                    )
                )
            successes = [e for e in window if e["event_type"] == "login_success"]
            for success in successes:
                same_user = [e for e in failures if e.get("username") == success.get("username")]
                if len(same_user) >= 3 and success.get("username"):
                    # Verify all evidence precedes the success, not just the window start.
                    earlier = [e for e in same_user if _time(e) <= _time(success)]
                    if len(earlier) >= 3:
                        findings.append(
                            Finding(
                                "AUTH-SUCCESS-003",
                                "high",
                                "Login success after failures",
                                f"Successful login for {success['username']} after repeated failures",
                                tuple(e["id"] for e in earlier) + (success["id"],),
                                ip,
                                success["username"],
                            )
                        )
                        break
            # Non-overlapping windows avoid flooding the analyst with duplicate patterns.
            index += max(1, len(window))
    return findings
