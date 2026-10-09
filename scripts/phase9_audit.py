"""Read-only SQLite integrity and reproducible evidence replay audit.

Usage: python scripts/phase9_audit.py [--database PATH] [--evidence PATH]
No existing SugiSOC database is modified. Evidence replay uses a temporary database.
"""

import argparse
import json
import sqlite3
import tempfile
from pathlib import Path

from sugisoc.services.lab_runner import run_lab


def audit_database(path: Path) -> dict:
    if not path.is_file():
        return {"database_present": False, "integrity": "not_checked"}
    # SQLite URI mode=ro prevents accidentally creating or modifying the database.
    with sqlite3.connect(f"file:{path.resolve()}?mode=ro", uri=True) as conn:
        integrity = conn.execute("PRAGMA integrity_check").fetchone()[0]
        tables = sorted(
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            )
        )
    return {"database_present": True, "integrity": integrity, "tables": tables}


def replay_evidence(path: Path) -> dict:
    with tempfile.TemporaryDirectory(prefix="sugisoc-audit-") as temp:
        root = Path(temp)
        first = run_lab(path, root / "isolated.db", root / "checkpoints")
        second = run_lab(path, root / "isolated.db", root / "checkpoints")
        result = {"first": first, "replay": second}
        result["replay_passed"] = (
            second["lines_accepted"] == 0
            and second["new_alerts"] == 0
            and second["new_cases"] == 0
            and second["events_stored"] == first["events_stored"]
        )
        return result


def main() -> None:
    parser = argparse.ArgumentParser(description="SugiSOC Phase 09 read-only integrity audit")
    parser.add_argument("--database", type=Path, default=Path(".collection-state/lab.db"))
    parser.add_argument("--evidence", type=Path)
    args = parser.parse_args()
    report = {"database": audit_database(args.database)}
    if args.evidence:
        report["evidence_replay"] = replay_evidence(args.evidence)
    print(json.dumps(report, indent=2))
    if report["database"].get("integrity") not in ("ok", "not_checked"):
        raise SystemExit("FAILED: SQLite integrity check")
    if args.evidence and not report["evidence_replay"]["replay_passed"]:
        raise SystemExit("FAILED: duplicate replay detected")


if __name__ == "__main__":
    main()
