"""Phase 02 collector -> Phase 03 database end-to-end tests."""

from pathlib import Path

from sugisoc.services.event_store import EventStore
from sugisoc.services.ingestion import ingest_file


def test_ingest_restart_append_and_replay(tmp_path: Path) -> None:
    path = tmp_path / "auth.log"
    state = tmp_path / "state"
    store = EventStore(tmp_path / "events.db")
    path.write_text("Failed password for bob from 192.0.2.1\n")
    assert ingest_file(path, state, store) == 1
    assert ingest_file(path, state, store) == 0
    with path.open("a") as stream:
        stream.write("Accepted password for alice from 192.0.2.2\n")
    assert ingest_file(path, state, EventStore(tmp_path / "events.db")) == 1
    assert store.count() == 2
    # Force replay by clearing checkpoint: dedup must happen at database level.
    for checkpoint in state.glob("*.json"):
        checkpoint.unlink()
    assert ingest_file(path, state, store) == 2
    assert store.count() == 2


def test_empty_and_partial_lines(tmp_path: Path) -> None:
    path = tmp_path / "auth.log"
    store = EventStore(tmp_path / "events.db")
    path.write_bytes(b"\nFailed password for bob from 192.0.2.1\npartial")
    assert ingest_file(path, tmp_path / "state", store) == 1
    assert store.count() == 1
    with path.open("ab") as stream:
        stream.write(b" next\n")
    assert ingest_file(path, tmp_path / "state", store) == 1
    assert store.count() == 2
