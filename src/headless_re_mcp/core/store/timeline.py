from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

JsonObject = dict[str, Any]
_MAX_LINES = 10_000
_MAX_BYTES = 8 * 1024 * 1024
# Trimming rewrites the file, so it runs at a high-water mark and cuts back to a
# low one. Rewriting on every append made each one cost the size of the file:
# 4000 appends onto a 2 MB timeline took nine seconds, and the last thousand of
# those took three. Every tool call writes here, so that slowdown was the
# session's, not just the log's.
_TRIM_TO_BYTES = 6 * 1024 * 1024


def session_timeline_path(artifact_root: Path, session_id: str) -> Path:
    return artifact_root.expanduser().resolve() / "sessions" / session_id / "timeline.jsonl"


def append_session_timeline(
    path: Path,
    *,
    event: str,
    message: str,
    details: JsonObject | None = None,
) -> JsonObject:
    path.parent.mkdir(parents=True, exist_ok=True)
    entry = {
        "at": datetime.now(UTC).isoformat(),
        "event": event,
        "message": message,
        "details": dict(details or {}),
    }
    line = (json.dumps(entry, ensure_ascii=False) + "\n").encode("utf-8")
    size = path.stat().st_size if path.is_file() else 0
    if size + len(line) > _MAX_BYTES:
        size = _trim_timeline(path, reserve=len(line))
    # Appended rather than rewritten, which gives up whole-file atomicity for one
    # line. A torn line fails to parse and list_session_timeline already skips
    # those; a torn diagnostic log is a better trade than a session that slows
    # down as it runs.
    with path.open("ab+") as stream:
        if size:
            stream.seek(-1, os.SEEK_END)
            if stream.read(1) != b"\n":
                stream.write(b"\n")
        stream.write(line)
    return entry


def _trim_timeline(path: Path, *, reserve: int) -> int:
    """Rewrite the file with the newest entries that fit, and return its new size.

    Both caps apply here rather than per append: the line cap cannot be enforced
    without counting lines, and counting means reading the file. Between trims
    the line count is therefore only bounded by the byte cap, which is the one
    that protects readers, since list_session_timeline loads the whole file.
    """
    budget = max(0, _TRIM_TO_BYTES - reserve)
    kept: list[bytes] = []
    total = 0
    for raw in reversed(path.read_bytes().splitlines(keepends=True)):
        if total + len(raw) > budget or len(kept) >= _MAX_LINES - 1:
            break
        kept.append(raw)
        total += len(raw)
    kept.reverse()
    payload = b"".join(kept)
    partial = path.with_suffix(path.suffix + ".partial")
    partial.write_bytes(payload)
    partial.replace(path)
    return len(payload)


def list_session_timeline(path: Path, *, offset: int = 0, limit: int = 100) -> JsonObject:
    if not path.is_file():
        return {"events": [], "count": 0, "total": 0, "offset": offset, "limit": limit, "has_more": False}
    lines = path.read_text(encoding="utf-8").splitlines()
    total = len(lines)
    limit = max(1, min(limit, 256))
    offset = max(0, offset)
    chunk = lines[offset : offset + limit]
    events = []
    for line in chunk:
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return {
        "events": events,
        "count": len(events),
        "total": total,
        "offset": offset,
        "limit": limit,
        "has_more": offset + len(events) < total,
        "path": str(path),
    }
