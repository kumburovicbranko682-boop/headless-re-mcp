from __future__ import annotations

import json
import os
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path
from threading import Lock
from typing import Any
from uuid import uuid4

JsonObject = dict[str, Any]
_MAX_LINES = 10_000
_MAX_BYTES = 8 * 1024 * 1024
# Trimming rewrites the file, so it runs at a high-water mark and cuts back to a
# low one. Rewriting on every append made each one cost the size of the file:
# 4000 appends onto a 2 MB timeline took nine seconds, and the last thousand of
# those took three. Every tool call writes here, so that slowdown was the
# session's, not just the log's.
_TRIM_TO_BYTES = 6 * 1024 * 1024

# Trimming rewrites the file, and on Windows replacing one that another thread
# still holds open for append fails outright, so the two have to be serialised.
# Striped rather than one lock per path: the stripe count bounds the memory a
# long-lived process spends on this, and two unrelated sessions sharing a stripe
# wait microseconds for each other.
_STRIPES = tuple(Lock() for _ in range(64))


def _timeline_lock(path: Path) -> Lock:
    return _STRIPES[hash(str(path)) % len(_STRIPES)]


def session_timeline_path(artifact_root: Path, session_id: str) -> Path:
    return artifact_root.expanduser().resolve() / "sessions" / session_id / "timeline.jsonl"


def append_session_timeline(
    path: Path,
    *,
    event: str,
    message: str,
    details: JsonObject | None = None,
) -> JsonObject:
    """Append one diagnostic entry. Reports a write failure, never raises it.

    This is a log, not a result. Raising made a full volume fail the operation
    that had already succeeded and was only recording that it had -- the caller
    saw internal_error for a dump that was on disk. One call site guarded it and
    the shared one did not, so the answer depended on which path reached here.
    ``write_failed`` in the returned entry is how a caller that wants to say so
    finds out.
    """
    entry = {
        "at": datetime.now(UTC).isoformat(),
        "event": event,
        "message": message,
        "details": dict(details or {}),
    }
    line = (json.dumps(entry, ensure_ascii=False) + "\n").encode("utf-8")
    try:
        with _timeline_lock(path):
            path.parent.mkdir(parents=True, exist_ok=True)
            size = path.stat().st_size if path.is_file() else 0
            if size + len(line) > _MAX_BYTES:
                size = _trim_timeline(path, reserve=len(line))
            # Appended rather than rewritten, which gives up whole-file atomicity
            # for one line. A torn line fails to parse and list_session_timeline
            # already skips those; a torn diagnostic log is a better trade than a
            # session that slows down as it runs.
            with path.open("ab+") as stream:
                if size:
                    stream.seek(-1, os.SEEK_END)
                    if stream.read(1) != b"\n":
                        stream.write(b"\n")
                stream.write(line)
    except OSError as exc:
        entry["write_failed"] = f"{type(exc).__name__}: {exc}"
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
    # Unique per trim. Nothing serialises appends to one session, so two that
    # cross the cap together would otherwise share this path, and on Windows
    # replacing a file the other still holds open is a sharing violation.
    partial = path.with_suffix(f"{path.suffix}.{uuid4().hex}.partial")
    try:
        partial.write_bytes(payload)
        partial.replace(path)
    except OSError:
        with suppress(OSError):
            partial.unlink()
        raise
    return len(payload)


def list_session_timeline(path: Path, *, offset: int = 0, limit: int = 100) -> JsonObject:
    """Read a page of the timeline. Reports a read it could not make.

    Under the same lock as the writers. Trimming replaces the whole file, and on
    Windows a reader holding it open makes that replace fail: measured with four
    readers and four writers over twelve seconds, 8,420 appends were refused and
    119 reads raised. Every timeline.list call and every monitor frame is one of
    those readers.

    The lock only covers this process, so the failure is still reported rather
    than raised: two processes can share an artifact root, and a caller asking
    for a diagnostic log should not get an internal error because the log was
    being trimmed as it asked.
    """
    limit = max(1, min(limit, 256))
    offset = max(0, offset)
    empty: JsonObject = {
        "events": [],
        "count": 0,
        "total": 0,
        "offset": offset,
        "limit": limit,
        "has_more": False,
    }
    with _timeline_lock(path):
        if not path.is_file():
            return empty
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except OSError as exc:
            return {**empty, "read_failed": f"{type(exc).__name__}: {exc}", "path": str(path)}
    total = len(lines)
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
