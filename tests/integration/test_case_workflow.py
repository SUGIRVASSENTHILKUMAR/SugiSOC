"""Real ingestion -> detection -> investigation workflow tests."""

from pathlib import Path

from sugisoc.collectors.file_collector import LogRecord
from sugisoc.correlation.cases import CaseStore
from sugisoc.detection.alert_store import AlertStore, run_detection
from sugisoc.models.events import normalize
from sugisoc.services.event_store import EventStore


def _pipeline(tmp_path: Path):
    db = tmp_path / "soc.sqlite"
    events = EventStore(db)
    alerts = AlertStore(db)
    cases = CaseStore(db)
    for i in range(5):
        line = f"2026-10-09T10:00:{i:02d}Z Failed password for alice from 192.0.2.10"
        assert events.insert(normalize(LogRecord("auth.log", line, i * 100, "sourceA")))
    assert run_detection(events, alerts) == 1
    return events, alerts, cases


def test_end_to_end_case_with_original_evidence(tmp_path: Path) -> None:
    _, _, cases = _pipeline(tmp_path)
    assert cases.correlate() == 1
    case = cases.list_cases()[0]
    assert case["alert_count"] == 1
    result = cases.investigation(case["case_id"])
    assert result is not None
    assert len(result["timeline"]) == 5
    assert result["alerts"][0]["rule_id"] == "AUTH-BRUTE-001"
    assert all("Failed password" in e["raw_line"] for e in result["timeline"])
    assert [e["id"] for e in result["timeline"]] == sorted(e["id"] for e in result["timeline"])


def test_replay_keeps_case_and_analyst_state(tmp_path: Path) -> None:
    _, _, cases = _pipeline(tmp_path)
    assert cases.correlate() == 1
    key = cases.list_cases()[0]["case_id"]
    assert cases.set_status(key, "investigating")
    note_id = cases.add_note(key, "Sugirvas", "Checking user history")
    assert note_id > 0
    assert cases.correlate() == 0
    result = CaseStore(cases.database).investigation(key)
    assert result["case"]["status"] == "investigating"
    assert len(result["notes"]) == 1


def test_unknown_case_and_invalid_note(tmp_path: Path) -> None:
    import pytest

    _, _, cases = _pipeline(tmp_path)
    assert not cases.set_status("missing", "closed")
    assert cases.investigation("missing") is None
    with pytest.raises(KeyError):
        cases.add_note("missing", "analyst", "note")
    with pytest.raises(ValueError):
        cases.set_status("missing", "not-valid")
    assert cases.correlate() == 1
    with pytest.raises(ValueError):
        cases.add_note(cases.list_cases()[0]["case_id"], "", "note")


def test_missing_evidence_is_not_correlated(tmp_path: Path) -> None:
    _, alerts, cases = _pipeline(tmp_path)
    import sqlite3

    with sqlite3.connect(alerts.database) as db:
        db.execute("UPDATE detection_alerts SET evidence_ids=?", ("[999999]",))
    assert cases.correlate() == 0
    assert cases.list_cases() == []


def test_cross_ip_evidence_is_not_correlated(tmp_path: Path) -> None:
    events, alerts, cases = _pipeline(tmp_path)
    other = normalize(
        LogRecord(
            "auth.log",
            "2026-10-09T10:00:50Z Failed password for b from 192.0.2.99",
            600,
            "sourceA",
        )
    )
    assert events.insert(other)
    import json
    import sqlite3

    new_id = events.search(source_ip="192.0.2.99")[0]["id"]
    with sqlite3.connect(alerts.database) as db:
        db.execute(
            "UPDATE detection_alerts SET evidence_ids=?", (json.dumps([1, 2, 3, 4, new_id]),)
        )
    assert cases.correlate() == 0
