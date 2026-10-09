"""Idempotent SQLite alert persistence with evidence references."""

import hashlib
import json
import sqlite3
from pathlib import Path

from sugisoc.detection.engine import Finding, detect
from sugisoc.services.event_store import EventStore

_SCHEMA = """
CREATE TABLE IF NOT EXISTS detection_alerts (
    alert_key TEXT PRIMARY KEY, rule_id TEXT NOT NULL, severity TEXT NOT NULL,
    title TEXT NOT NULL, explanation TEXT NOT NULL, source_ip TEXT NOT NULL,
    username TEXT, evidence_ids TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open','investigating','closed')),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE INDEX IF NOT EXISTS idx_alerts_rule ON detection_alerts(rule_id);
"""


class AlertStore:
    def __init__(self, database: Path) -> None:
        self.database = Path(database)
        self.database.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.database) as connection:
            connection.executescript(_SCHEMA)

    def save(self, finding: Finding) -> bool:
        identity = json.dumps([finding.rule_id, finding.source_ip, finding.evidence_ids])
        key = hashlib.sha256(identity.encode()).hexdigest()
        with sqlite3.connect(self.database) as connection:
            cursor = connection.execute(
                """INSERT OR IGNORE INTO detection_alerts
                (alert_key,rule_id,severity,title,explanation,source_ip,username,evidence_ids)
                VALUES (?,?,?,?,?,?,?,?)""",
                (
                    key,
                    finding.rule_id,
                    finding.severity,
                    finding.title,
                    finding.explanation,
                    finding.source_ip,
                    finding.username,
                    json.dumps(finding.evidence_ids),
                ),
            )
            return cursor.rowcount == 1

    def list_alerts(self) -> list[dict]:
        with sqlite3.connect(self.database) as connection:
            connection.row_factory = sqlite3.Row
            rows = connection.execute(
                "SELECT * FROM detection_alerts ORDER BY created_at DESC, alert_key"
            ).fetchall()
            return [{**dict(row), "evidence_ids": json.loads(row["evidence_ids"])} for row in rows]


def run_detection(store: EventStore, alerts: AlertStore, *, limit: int = 500) -> int:
    """Run bounded batch detection; returns newly inserted alert count.

    Phase 09 will add watermark-based streaming and comprehensive historical scans.
    """
    events = store.search(limit=limit)
    return sum(alerts.save(finding) for finding in detect(events))
