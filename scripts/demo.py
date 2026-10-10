"""Reproducible synthetic SugiSOC detection demonstration."""

import json
import tempfile
from pathlib import Path

from sugisoc.services.lab_runner import run_lab


def execute_demo(workspace: Path) -> dict:
    """Run ingestion, detection, correlation, and replay checks."""
    if workspace.exists() and any(workspace.iterdir()):
        raise ValueError("Demo workspace must be empty")

    workspace.mkdir(parents=True, exist_ok=True)

    log = workspace / "synthetic-auth.log"
    database = workspace / "demo.sqlite3"
    state = workspace / "checkpoints"

    lines = [
        (
            f"2026-10-09T01:30:{i:02d}+00:00 "
            f"Failed password for demo from 192.0.2.44 "
            f"port 22 ssh2"
        )
        for i in range(6)
    ]

    log.write_text("\n".join(lines) + "\n", encoding="utf-8")

    if len(log.read_text(encoding="utf-8").splitlines()) != 6:
        raise RuntimeError("Synthetic fixture line count incorrect")

    first = run_lab(log, database, state)

    if first["lines_accepted"] != 6:
        raise RuntimeError(
            f"Expected six accepted events; received {first}"
        )

    replay = run_lab(log, database, state)

    if first["events_stored"] != 6:
        raise RuntimeError(f"Unexpected stored events: {first}")

    if first["new_alerts"] < 1 or first["new_cases"] < 1:
        raise RuntimeError(f"Detection/correlation failed: {first}")

    if any(replay[key] != 0 for key in (
        "lines_accepted", "new_alerts", "new_cases"
    )):
        raise RuntimeError(f"Replay introduced duplicates: {replay}")

    if replay["events_stored"] != 6:
        raise RuntimeError("Replay changed evidence count")

    return {"first_run": first, "replay": replay}


def main() -> None:
    """Run a complete disposable demonstration."""
    with tempfile.TemporaryDirectory(prefix="sugisoc-demo-") as folder:
        result = execute_demo(Path(folder))

    print(json.dumps(result, indent=2))
    print("\nSUGISOC DEMO PASSED")
    print("Synthetic events: 6")
    print("Evidence-backed alert and case: VERIFIED")
    print("Replay protection: VERIFIED")
    print("SSH connections performed: 0")


if __name__ == "__main__":
    main()
