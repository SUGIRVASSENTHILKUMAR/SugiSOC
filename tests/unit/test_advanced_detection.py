"""Phase 07 advanced detector, technique annotations, and enrichment tests."""

import json
from pathlib import Path

import pytest
from sugisoc.detection.advanced import (
    annotate,
    detect_distributed_guessing,
    run_advanced_detection,
)
from sugisoc.detection.alert_store import AlertStore
from sugisoc.detection.engine import Finding
from sugisoc.detection.intelligence import load_indicators, lookup_ip
from sugisoc.models.events import SecurityEvent
from sugisoc.services.event_store import EventStore


def record(n: int, ip: str, user: str = "alex", time: str = "2026-10-09T10:00:00Z") -> dict:
    return {
        "id": n,
        "source_ip": ip,
        "username": user,
        "event_type": "login_failure",
        "occurred_at": time,
    }


def test_distributed_detection_evidence() -> None:
    rows = [record(i, f"192.0.2.{i}") for i in range(1, 4)]
    findings = detect_distributed_guessing(rows)
    assert len(findings) == 1
    assert findings[0].rule_id == "AUTH-DISTRIBUTED-004"
    assert findings[0].evidence_ids == (1, 2, 3)
    assert annotate(findings[0]).technique_id == "T1110.001"


def test_normal_or_incomplete_events_not_flagged() -> None:
    assert not detect_distributed_guessing([record(1, "192.0.2.1")])
    rows = [record(1, "192.0.2.1"), record(2, "192.0.2.2")]
    rows.append(record(3, "192.0.2.3", time="2026-10-09T10:40:00Z"))
    assert not detect_distributed_guessing(rows)
    assert not detect_distributed_guessing([dict(record(1, "192.0.2.1"), occurred_at=None)])


def test_invalid_parameters() -> None:
    with pytest.raises(ValueError):
        detect_distributed_guessing([], window_seconds=0)
    with pytest.raises(ValueError):
        detect_distributed_guessing([], min_ips=1)


def test_known_and_unknown_techniques() -> None:
    base = Finding("AUTH-SPRAY-002", "high", "Title", "Reason", (1,), "192.0.2.1", "alex")
    assert annotate(base).technique_id == "T1110.003"
    with pytest.raises(KeyError):
        annotate(Finding("UNKNOWN", "low", "Title", "Reason", (1,), "192.0.2.1", None))


def test_offline_indicators(tmp_path: Path) -> None:
    path = tmp_path / "indicators.json"
    path.write_text(
        json.dumps(
            [
                {
                    "ip": "192.0.2.11",
                    "source": "test-fixture",
                    "context": "Synthetic example, not a threat verdict",
                }
            ]
        )
    )
    data = load_indicators(path)
    assert lookup_ip("192.0.2.11", data)["matched"] is True
    assert lookup_ip("192.0.2.12", data)["matched"] is False
    path.write_text(json.dumps([{"ip": "not-an-ip", "source": "x", "context": "y"}]))
    with pytest.raises(ValueError):
        load_indicators(path)


def test_store_run_is_idempotent(tmp_path: Path) -> None:
    db = tmp_path / "events.db"
    events, alerts = EventStore(db), AlertStore(db)
    for i in range(1, 4):
        event = SecurityEvent(
            source_id="test",
            byte_offset=i,
            source_path="fixture.log",
            raw_line=f"failed {i}",
            event_type="login_failure",
            username="alex",
            source_ip=f"192.0.2.{i}",
            occurred_at="2026-10-09T10:00:00+00:00",
        )
        assert events.insert(event)
    assert run_advanced_detection(events, alerts) == 1
    assert run_advanced_detection(events, alerts) == 0
    assert len(alerts.list_alerts()) == 1
