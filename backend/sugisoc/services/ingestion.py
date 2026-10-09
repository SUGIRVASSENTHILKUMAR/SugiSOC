"""Connect the Phase 02 collector to the Phase 03 database."""

from pathlib import Path

from sugisoc.collectors.file_collector import collect_file
from sugisoc.models.events import normalize
from sugisoc.services.event_store import EventStore


def ingest_file(log_file: Path, state_dir: Path, store: EventStore) -> int:
    """Number of lines acknowledged by the collector, including existing rows."""

    def consume(record) -> None:
        store.insert(normalize(record))

    return collect_file(log_file, state_dir, consume)
