"""Convert genuine SSH journal JSON records to time-explicit SugiSOC log lines.

On Kali Linux run: sudo journalctl -u ssh -o json --no-pager | python3 scripts/export_kali_journal.py > kali-ssh.log
The script never generates fake authentication events.
"""

import json
import sys
from datetime import UTC, datetime


def convert(source, destination) -> int:
    """Keep SSH auth events with real journal timestamps; reject invalid entries."""
    count = 0
    for line in source:
        try:
            item = json.loads(line)
            message = item["MESSAGE"]
            timestamp = item["__REALTIME_TIMESTAMP"]
            if not isinstance(message, str) or not isinstance(timestamp, str):
                continue
            if not message.startswith(
                ("Failed password ", "Accepted password ", "Accepted publickey ")
            ):
                continue
            microseconds = int(timestamp)
            if microseconds < 0:
                continue
            stamp = datetime.fromtimestamp(microseconds / 1_000_000, tz=UTC)
            destination.write(f"{stamp.isoformat()} {message.replace(chr(10), ' ')}\n")
            count += 1
        except (KeyError, ValueError, TypeError, OverflowError, OSError):
            continue
    return count


if __name__ == "__main__":
    result = convert(sys.stdin, sys.stdout)
    print(f"Exported {result} genuine SSH auth records", file=sys.stderr)
