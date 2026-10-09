"""Genuine SugiSOC collector-to-detection-to-case integration on fixture events."""

from pathlib import Path

from sugisoc.services.lab_runner import run_lab


def test_end_to_end_lab_and_replay(tmp_path: Path) -> None:
    path = tmp_path / "journal-export.log"
    path.write_text(
        "".join(
            f"2026-10-09T01:30:{i:02d}+00:00 Failed password for alex from 192.0.2.4 port 22 ssh2\n"
            for i in range(6)
        ),
        encoding="utf-8",
    )
    db = tmp_path / "lab.db"
    state = tmp_path / "state"
    first = run_lab(path, db, state)
    assert first["lines_accepted"] == 6
    assert first["events_stored"] == 6
    assert first["new_alerts"] >= 1
    assert first["new_cases"] >= 1
    second = run_lab(path, db, state)
    assert second["lines_accepted"] == 0
    assert second["new_alerts"] == 0
    assert second["new_cases"] == 0
    assert second["events_stored"] == 6


def test_missing_file_never_creates_evidence(tmp_path: Path) -> None:
    import pytest

    with pytest.raises(FileNotFoundError):
        run_lab(tmp_path / "missing.log", tmp_path / "db.sqlite", tmp_path / "state")
