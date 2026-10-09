"""Security data normalization and database regression tests."""

from pathlib import Path

import pytest
from sugisoc.collectors.file_collector import LogRecord
from sugisoc.models.events import normalize
from sugisoc.services.event_store import EventStore


def record(text: str, offset: int = 0) -> LogRecord:
    return LogRecord("/test/auth.log", text, offset, "device:inode")


def test_normalizes_failure_and_success() -> None:
    failed = normalize(record("Failed password for invalid user bob from 192.0.2.1 port 22"))
    success = normalize(record("Accepted publickey for alice from 192.0.2.2 port 22"))
    assert (failed.event_type, failed.username, failed.source_ip) == (
        "login_failure",
        "bob",
        "192.0.2.1",
    )
    assert (success.event_type, success.username) == ("login_success", "alice")


def test_unknown_input_preserves_evidence() -> None:
    event = normalize(record("Some unsupported 🛡 event"))
    assert event.event_type == "other"
    assert event.raw_line == "Some unsupported 🛡 event"
    assert event.occurred_at is None


def test_timestamp_only_when_timezone_present() -> None:
    a = normalize(record("2026-10-09T12:30:00+05:30 Failed password for a from 192.0.2.3"))
    b = normalize(record("Oct 09 12:30:00 Failed password for a from 192.0.2.3"))
    assert a.occurred_at == "2026-10-09T07:00:00+00:00"
    assert b.occurred_at is None


def test_duplicate_is_ignored_and_persists(tmp_path: Path) -> None:
    db = tmp_path / "events.db"
    store = EventStore(db)
    event = normalize(record("Failed password for bob from 192.0.2.1"))
    assert store.insert(event)
    assert not store.insert(event)
    assert EventStore(db).count() == 1


def test_filter_search_and_original_evidence(tmp_path: Path) -> None:
    store = EventStore(tmp_path / "events.db")
    store.insert(normalize(record("Failed password for bob from 192.0.2.1", 0)))
    store.insert(normalize(record("Accepted password for alice from 192.0.2.2", 100)))
    found = store.search(event_type="login_failure", username="bob", source_ip="192.0.2.1")
    assert len(found) == 1
    assert "Failed password" in found[0]["raw_line"]
    assert store.search(username="nobody") == []


def test_injection_is_data_not_sql(tmp_path: Path) -> None:
    store = EventStore(tmp_path / "events.db")
    store.insert(normalize(record("Failed password for bob from 192.0.2.1")))
    assert store.search(username="bob' OR 1=1 --") == []
    assert store.count() == 1


def test_limits(tmp_path: Path) -> None:
    store = EventStore(tmp_path / "events.db")
    with pytest.raises(ValueError):
        store.search(limit=501)
    with pytest.raises(ValueError):
        store.search(offset=-1)
