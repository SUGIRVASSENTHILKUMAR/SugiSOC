"""Run a reproducible, read-only log import and SugiSOC detection pipeline.

Lab imports use separate local state and database files; never attack a host.
"""

import argparse
import json
from pathlib import Path

from sugisoc.correlation.cases import CaseStore
from sugisoc.detection.advanced import run_advanced_detection
from sugisoc.detection.alert_store import AlertStore
from sugisoc.services.event_store import EventStore
from sugisoc.services.ingestion import ingest_file


def run_lab(log_file: Path, database: Path, state_dir: Path) -> dict[str, int]:
    """Import real logs, run detection, and correlate cases with replay safety."""
    if not log_file.is_file():
        raise FileNotFoundError(log_file)
    events = EventStore(database)
    alerts = AlertStore(database)
    cases = CaseStore(database)
    accepted = ingest_file(log_file, state_dir, events)
    new_alerts = run_advanced_detection(events, alerts)
    new_cases = cases.correlate()
    return {
        "lines_accepted": accepted,
        "events_stored": events.count(),
        "new_alerts": new_alerts,
        "new_cases": new_cases,
        "total_cases": len(cases.list_cases()),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Local SugiSOC evidence lab import")
    parser.add_argument("log_file", type=Path, help="Exported journal authentication log")
    parser.add_argument("--database", type=Path, default=Path(".collection-state/lab.db"))
    parser.add_argument("--state", type=Path, default=Path(".collection-state/lab-checkpoints"))
    args = parser.parse_args()
    print(json.dumps(run_lab(args.log_file, args.database, args.state), indent=2))


if __name__ == "__main__":
    main()
