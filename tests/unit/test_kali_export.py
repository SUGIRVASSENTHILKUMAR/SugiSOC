"""Journal export preserves timestamps and never invents missing evidence."""

import io
import json
from datetime import UTC, datetime


def test_export_keeps_real_timestamp_and_rejects_unsupported_entries() -> None:
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
    from export_kali_journal import convert

    micros = str(int(datetime(2026, 10, 9, 1, 30, tzinfo=UTC).timestamp() * 1_000_000))
    lines = [
        {
            "MESSAGE": "Failed password for alex from 192.0.2.4 port 22 ssh2",
            "__REALTIME_TIMESTAMP": micros,
        },
        {"MESSAGE": "Other journal entry", "__REALTIME_TIMESTAMP": micros},
        {
            "MESSAGE": "Accepted publickey for alex from 192.0.2.4 port 22",
            "__REALTIME_TIMESTAMP": "bad",
        },
        {"MESSAGE": "Failed password for alex from 192.0.2.4 port 22"},
    ]
    source = io.StringIO("\n".join(json.dumps(row) for row in lines))
    output = io.StringIO()
    assert convert(source, output) == 1
    assert output.getvalue().startswith("2026-10-09T01:30:00+00:00 Failed password")
