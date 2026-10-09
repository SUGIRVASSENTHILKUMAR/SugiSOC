"""Log collector regression tests."""

from pathlib import Path

import pytest
from sugisoc.collectors.file_collector import collect_file


def test_read_and_checkpoint_no_duplicates(tmp_path: Path) -> None:
    log = tmp_path / "auth.log"
    log.write_text("failed\nsucceeded\n", encoding="utf-8")
    got = []
    state = tmp_path / "state"
    assert collect_file(log, state, got.append) == 2
    assert [record.line for record in got] == ["failed", "succeeded"]
    assert collect_file(log, state, got.append) == 0
    assert len(got) == 2
    assert got[0].byte_offset == 0
    assert got[1].byte_offset == len(b"failed\n")


def test_appended_and_partial_lines(tmp_path: Path) -> None:
    log = tmp_path / "auth.log"
    log.write_bytes(b"first\nunfinished")
    got = []
    state = tmp_path / "state"
    assert collect_file(log, state, got.append) == 1
    assert collect_file(log, state, got.append) == 0
    with log.open("ab") as output:
        output.write(b" end\n")
    assert collect_file(log, state, got.append) == 1
    assert [r.line for r in got] == ["first", "unfinished end"]


def test_invalid_utf8_and_blank_lines(tmp_path: Path) -> None:
    log = tmp_path / "auth.log"
    log.write_bytes(b" \nfailed:\xff\n")
    got = []
    assert collect_file(log, tmp_path / "state", got.append) == 1
    assert "\ufffd" in got[0].line


def test_missing_file(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        collect_file(tmp_path / "missing", tmp_path / "state", lambda _: None)


def test_rotate_same_path_new_inode(tmp_path: Path) -> None:
    log = tmp_path / "auth.log"
    log.write_text("before\n")
    state = tmp_path / "state"
    got = []
    collect_file(log, state, got.append)
    log.rename(tmp_path / "auth.log.1")
    log.write_text("after\n")
    assert collect_file(log, state, got.append) == 1
    assert [r.line for r in got] == ["before", "after"]
    assert got[0].source_id != got[1].source_id


def test_truncated_file(tmp_path: Path) -> None:
    log = tmp_path / "auth.log"
    log.write_text("a much longer original line\n")
    state = tmp_path / "state"
    got = []
    collect_file(log, state, got.append)
    log.write_text("new\n")
    assert collect_file(log, state, got.append) == 1
    assert got[-1].line == "new"


def test_consumer_failure_never_advances_failed_line(tmp_path: Path) -> None:
    log = tmp_path / "auth.log"
    log.write_text("one\ntwo\n")
    state = tmp_path / "state"
    got = []

    def consumer(record):
        if record.line == "two":
            raise RuntimeError("downstream failed")
        got.append(record)

    with pytest.raises(RuntimeError):
        collect_file(log, state, consumer)
    retried = []
    assert collect_file(log, state, retried.append) == 1
    assert retried[0].line == "two"


def test_checkpoint_separate_per_file(tmp_path: Path) -> None:
    a = tmp_path / "a.log"
    b = tmp_path / "b.log"
    a.write_text("a\n")
    b.write_text("b\n")
    got = []
    state = tmp_path / "state"
    assert collect_file(a, state, got.append) == 1
    assert collect_file(b, state, got.append) == 1
    assert collect_file(a, state, got.append) == 0
