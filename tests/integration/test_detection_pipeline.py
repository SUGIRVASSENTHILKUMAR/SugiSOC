"""Phase 03 evidence database to Phase 04 alert database end-to-end."""

from pathlib import Path

from sugisoc.collectors.file_collector import LogRecord
from sugisoc.detection.alert_store import AlertStore, run_detection
from sugisoc.models.events import normalize
from sugisoc.services.event_store import EventStore


def test_detect_replay_and_evidence_link(tmp_path: Path) -> None:
    db = tmp_path / "security.db"
    store = EventStore(db)
    alerts = AlertStore(db)
    for i in range(5):
        source = LogRecord(
            "auth.log",
            f"2026-10-09T10:00:{i:02d}Z Failed password for alice from 192.0.2.1",
            i * 100,
            "sourceA",
        )
        assert store.insert(normalize(source))
    assert run_detection(store, alerts) == 1
    assert run_detection(store, alerts) == 0
    result = alerts.list_alerts()
    assert len(result) == 1
    assert result[0]["rule_id"] == "AUTH-BRUTE-001"
    ids = result[0]["evidence_ids"]
    assert len(ids) == 5
    assert set(ids) == {row["id"] for row in store.search()}
