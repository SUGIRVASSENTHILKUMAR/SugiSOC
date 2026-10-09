"""Deterministic, evidence-verified case correlation and analyst workflow.

Local Phase 05 prototype: one case per source IP per UTC event day. This is
NOT identity attribution, and must not be treated as proof of compromise.
"""

import hashlib
import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

_SCHEMA = """
CREATE TABLE IF NOT EXISTS investigation_cases (
 case_id TEXT PRIMARY KEY, source_ip TEXT NOT NULL, event_day TEXT NOT NULL,
 status TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open','investigating','closed')),
 created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
 UNIQUE(source_ip, event_day)
);
CREATE TABLE IF NOT EXISTS case_alerts (
 case_id TEXT NOT NULL REFERENCES investigation_cases(case_id),
 alert_key TEXT NOT NULL REFERENCES detection_alerts(alert_key),
 PRIMARY KEY(case_id,alert_key)
);
CREATE TABLE IF NOT EXISTS case_notes (
 note_id INTEGER PRIMARY KEY AUTOINCREMENT,
 case_id TEXT NOT NULL REFERENCES investigation_cases(case_id),
 analyst TEXT NOT NULL, body TEXT NOT NULL,
 created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE INDEX IF NOT EXISTS idx_case_alerts_alert ON case_alerts(alert_key);
"""
VALID_STATUSES = frozenset({"open", "investigating", "closed"})


def _day(value: str | None) -> str | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            return None
        return parsed.astimezone(UTC).date().isoformat()
    except (TypeError, ValueError):
        return None


class CaseStore:
    def __init__(self, database: Path) -> None:
        self.database = Path(database)
        self.database.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as db:
            db.executescript(_SCHEMA)

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.database, timeout=15)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys = ON")
        return db

    def correlate(self) -> int:
        """Link alerts with validated event evidence into daily source-IP cases.

        Missing, mismatched, cross-source or undated evidence is not linked.
        Replays are idempotent; existing notes and analyst statuses are retained.
        """
        created = 0
        with self._connect() as db:
            alerts = db.execute(
                "SELECT alert_key, source_ip, evidence_ids FROM detection_alerts ORDER BY alert_key"
            ).fetchall()
            for alert in alerts:
                try:
                    ids = json.loads(alert["evidence_ids"])
                except (ValueError, TypeError):
                    continue
                if (
                    not isinstance(ids, list)
                    or not ids
                    or len(ids) > 500
                    or any(type(i) is not int or i <= 0 for i in ids)
                    or len(set(ids)) != len(ids)
                ):
                    continue
                placeholders = ",".join("?" for _ in ids)
                evidence = db.execute(
                    f"SELECT id,source_ip,occurred_at FROM security_events WHERE id IN ({placeholders})",
                    ids,
                ).fetchall()
                if len(evidence) != len(ids):
                    continue
                days = {_day(row["occurred_at"]) for row in evidence}
                if (
                    None in days
                    or len(days) != 1
                    or any(row["source_ip"] != alert["source_ip"] for row in evidence)
                ):
                    continue
                day = days.pop()
                key = hashlib.sha256(f"{alert['source_ip']}\0{day}".encode()).hexdigest()[:24]
                cursor = db.execute(
                    "INSERT OR IGNORE INTO investigation_cases(case_id,source_ip,event_day) VALUES(?,?,?)",
                    (key, alert["source_ip"], day),
                )
                created += cursor.rowcount
                db.execute(
                    "INSERT OR IGNORE INTO case_alerts(case_id,alert_key) VALUES(?,?)",
                    (key, alert["alert_key"]),
                )
            db.commit()
        return created

    def list_cases(self) -> list[dict]:
        with self._connect() as db:
            return [
                dict(row)
                for row in db.execute("""
                SELECT c.*, COUNT(a.alert_key) AS alert_count
                FROM investigation_cases c LEFT JOIN case_alerts a ON c.case_id=a.case_id
                GROUP BY c.case_id ORDER BY c.event_day DESC,c.case_id
            """).fetchall()
            ]

    def investigation(self, case_id: str) -> dict | None:
        """Return ordered alert, evidence and analyst-note data for a case."""
        with self._connect() as db:
            case = db.execute(
                "SELECT * FROM investigation_cases WHERE case_id=?", (case_id,)
            ).fetchone()
            if case is None:
                return None
            alerts = [
                dict(row)
                for row in db.execute(
                    """
                SELECT a.* FROM detection_alerts a
                JOIN case_alerts ca ON ca.alert_key=a.alert_key
                WHERE ca.case_id=? ORDER BY a.created_at,a.alert_key
            """,
                    (case_id,),
                ).fetchall()
            ]
            ids = sorted({i for a in alerts for i in json.loads(a["evidence_ids"])})
            timeline = []
            if ids:
                placeholders = ",".join("?" for _ in ids)
                timeline = [
                    dict(row)
                    for row in db.execute(
                        f"""SELECT * FROM security_events WHERE id IN ({placeholders})
                        ORDER BY occurred_at,id""",
                        ids,
                    ).fetchall()
                ]
            notes = [
                dict(row)
                for row in db.execute(
                    "SELECT * FROM case_notes WHERE case_id=? ORDER BY note_id", (case_id,)
                ).fetchall()
            ]
            return {"case": dict(case), "alerts": alerts, "timeline": timeline, "notes": notes}

    def set_status(self, case_id: str, status: str) -> bool:
        if status not in VALID_STATUSES:
            raise ValueError("Invalid case status")
        with self._connect() as db:
            result = db.execute(
                "UPDATE investigation_cases SET status=? WHERE case_id=?", (status, case_id)
            )
            db.commit()
            return result.rowcount == 1

    def add_note(self, case_id: str, analyst: str, body: str) -> int:
        analyst, body = analyst.strip(), body.strip()
        if not 1 <= len(analyst) <= 100 or not 1 <= len(body) <= 5000:
            raise ValueError("Analyst and note must be nonempty and within length limits")
        with self._connect() as db:
            if (
                db.execute(
                    "SELECT 1 FROM investigation_cases WHERE case_id=?", (case_id,)
                ).fetchone()
                is None
            ):
                raise KeyError("Unknown case ID")
            cursor = db.execute(
                "INSERT INTO case_notes(case_id,analyst,body) VALUES(?,?,?)",
                (case_id, analyst, body),
            )
            db.commit()
            return int(cursor.lastrowid)
