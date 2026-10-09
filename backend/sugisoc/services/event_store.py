"""SQLite-backed append-only evidence store for normalized security events."""

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from sugisoc.models.events import SecurityEvent

_SCHEMA = """
CREATE TABLE IF NOT EXISTS security_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_id TEXT NOT NULL,
    byte_offset INTEGER NOT NULL CHECK(byte_offset >= 0),
    source_path TEXT NOT NULL,
    raw_line TEXT NOT NULL,
    event_type TEXT NOT NULL,
    username TEXT,
    source_ip TEXT,
    occurred_at TEXT,
    ingested_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    UNIQUE(source_id, byte_offset)
);
CREATE INDEX IF NOT EXISTS idx_events_type ON security_events(event_type);
CREATE INDEX IF NOT EXISTS idx_events_username ON security_events(username);
CREATE INDEX IF NOT EXISTS idx_events_ip ON security_events(source_ip);
CREATE INDEX IF NOT EXISTS idx_events_time ON security_events(occurred_at);
"""


class EventStore:
    def __init__(self, database: Path) -> None:
        self.database = Path(database)
        self.database.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.executescript(_SCHEMA)

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.database, timeout=15)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except BaseException:
            conn.rollback()
            raise
        finally:
            conn.close()

    def insert(self, event: SecurityEvent) -> bool:
        """Return True only for a new event; replay safely ignored."""
        with self._connect() as conn:
            cursor = conn.execute(
                """INSERT OR IGNORE INTO security_events
                (source_id, byte_offset, source_path, raw_line, event_type,
                 username, source_ip, occurred_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    event.source_id,
                    event.byte_offset,
                    event.source_path,
                    event.raw_line,
                    event.event_type,
                    event.username,
                    event.source_ip,
                    event.occurred_at,
                ),
            )
            return cursor.rowcount == 1

    def count(self) -> int:
        with self._connect() as conn:
            return int(conn.execute("SELECT COUNT(*) FROM security_events").fetchone()[0])

    def search(
        self,
        *,
        event_type: str | None = None,
        username: str | None = None,
        source_ip: str | None = None,
        after: str | None = None,
        before: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict]:
        if not 1 <= limit <= 500:
            raise ValueError("limit must be between 1 and 500")
        if offset < 0:
            raise ValueError("offset must be nonnegative")
        clauses = []
        params: list[str | int] = []
        for field, value in (
            ("event_type", event_type),
            ("username", username),
            ("source_ip", source_ip),
        ):
            if value is not None:
                clauses.append(f"{field} = ?")
                params.append(value)
        if after is not None:
            clauses.append("occurred_at >= ?")
            params.append(after)
        if before is not None:
            clauses.append("occurred_at <= ?")
            params.append(before)
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        sql = "SELECT * FROM security_events" + where + " ORDER BY id DESC LIMIT ? OFFSET ?"
        with self._connect() as conn:
            return [dict(row) for row in conn.execute(sql, [*params, limit, offset]).fetchall()]
