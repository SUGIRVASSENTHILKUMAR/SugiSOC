"""Detection regression tests with controlled event time."""

from datetime import UTC, datetime, timedelta

import pytest
from sugisoc.detection.engine import detect

BASE = datetime(2026, 10, 9, 10, 0, tzinfo=UTC)


def event(
    i: int,
    kind: str = "login_failure",
    user: str = "alice",
    ip: str = "192.0.2.1",
    seconds: int = 0,
) -> dict:
    return {
        "id": i,
        "event_type": kind,
        "username": user,
        "source_ip": ip,
        "occurred_at": (BASE + timedelta(seconds=seconds)).isoformat(),
    }


def test_normal_failure_is_not_an_attack() -> None:
    assert not detect([event(1), event(2, seconds=4)])


def test_brute_force_has_evidence() -> None:
    found = detect([event(i, seconds=i) for i in range(1, 6)])
    assert len(found) == 1
    assert found[0].rule_id == "AUTH-BRUTE-001"
    assert found[0].evidence_ids == (1, 2, 3, 4, 5)


def test_spray_multiple_accounts() -> None:
    found = detect([event(i, user=f"account{i}", seconds=i) for i in range(1, 6)])
    assert {finding.rule_id for finding in found} == {"AUTH-BRUTE-001", "AUTH-SPRAY-002"}


def test_success_after_failure() -> None:
    entries = [event(i, seconds=i) for i in range(1, 5)] + [event(5, "login_success", seconds=6)]
    found = detect(entries)
    assert [item.rule_id for item in found] == ["AUTH-SUCCESS-003"]
    assert found[0].evidence_ids[-1] == 5


def test_no_cross_source_or_account_correlation() -> None:
    entries = [event(i, ip="192.0.2.1", seconds=i) for i in range(1, 4)]
    entries.append(event(4, "login_success", user="other", ip="192.0.2.1", seconds=5))
    entries.append(event(5, "login_success", ip="192.0.2.2", seconds=6))
    assert not detect(entries)


def test_no_time_is_not_invented() -> None:
    entries = [dict(event(i), occurred_at=None) for i in range(1, 9)]
    assert not detect(entries)


def test_outside_window_not_grouped() -> None:
    assert not detect([event(i, seconds=i * 200) for i in range(1, 6)])


def test_invalid_threshold() -> None:
    with pytest.raises(ValueError):
        detect([], window_seconds=0)
