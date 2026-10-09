"""Reliable, byte-offset based local log collection with durable checkpoints."""

import json
import os
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class LogRecord:
    path: str
    line: str
    byte_offset: int
    source_id: str


def _checkpoint_path(path: Path, state_dir: Path) -> Path:
    import hashlib

    key = hashlib.sha256(str(path.resolve()).encode()).hexdigest()
    return state_dir / f"{key}.json"


def collect_file(
    path: Path,
    state_dir: Path,
    consume: Callable[[LogRecord], None],
) -> int:
    """Consume complete lines; checkpoint each accepted line.

    Delivery is *at least once*, not exactly once: a crash after downstream
    processing but before a checkpoint write may replay one record.
    The downstream consumer should use (source_id, byte_offset) to deduplicate.
    """
    path = Path(path).resolve()
    state_dir = Path(state_dir)
    if not path.is_file():
        raise FileNotFoundError(path)
    state_dir.mkdir(parents=True, exist_ok=True)
    checkpoint = _checkpoint_path(path, state_dir)
    info = path.stat()
    source_id = f"{info.st_dev}:{info.st_ino}"
    position = 0
    if checkpoint.exists():
        stored = json.loads(checkpoint.read_text(encoding="utf-8"))
        if stored.get("source_id") == source_id:
            position = int(stored.get("position", 0))
            if position < 0 or position > info.st_size:
                position = 0

    processed = 0
    with path.open("rb") as stream:
        # fstat prevents a race between stat() and open() switching source files.
        opened = os.fstat(stream.fileno())
        opened_id = f"{opened.st_dev}:{opened.st_ino}"
        if opened_id != source_id:
            source_id = opened_id
            position = 0
        stream.seek(position)
        while True:
            offset = stream.tell()
            line = stream.readline()
            if not line:
                break
            # A partial trailing line isn't ready yet: next poll will replay it.
            if not line.endswith(b"\n"):
                break
            value = line.rstrip(b"\r\n").decode("utf-8", errors="replace")
            if value.strip():
                consume(LogRecord(str(path), value, offset, source_id))
                processed += 1
            # Atomic checkpoint write prevents partial JSON after interruption.
            fd, temp_name = tempfile.mkstemp(dir=state_dir, prefix=".checkpoint-")
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as output:
                    json.dump({"source_id": source_id, "position": stream.tell()}, output)
                    output.flush()
                    os.fsync(output.fileno())
                os.replace(temp_name, checkpoint)
            finally:
                if os.path.exists(temp_name):
                    os.unlink(temp_name)
    return processed
