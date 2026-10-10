"""Tests for the reviewer-facing synthetic quick demo."""

from pathlib import Path

import pytest

from scripts.demo import execute_demo


def test_quick_demo(tmp_path: Path):
    result = execute_demo(tmp_path / "demo")
    assert result["first_run"]["lines_accepted"] == 6
    assert result["first_run"]["events_stored"] == 6
    assert result["first_run"]["new_alerts"] >= 1
    assert result["first_run"]["new_cases"] >= 1
    assert result["replay"]["lines_accepted"] == 0
    assert result["replay"]["new_alerts"] == 0
    assert result["replay"]["new_cases"] == 0


def test_existing_workspace_is_rejected(tmp_path: Path):
    folder = tmp_path / "demo"
    folder.mkdir()
    (folder / "existing.txt").write_text("do not overwrite")
    with pytest.raises(ValueError):
        execute_demo(folder)
