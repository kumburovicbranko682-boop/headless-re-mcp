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
    if not session_id or session_id in {".", ".."} or Path(session_id).name != session_id:
        raise ValueError("invalid session id for timeline path")
    base = (artifact_root.expanduser().resolve() / "sessions").resolve()
    candidate = (base / session_id / "timeline.jsonl").resolve()
    # A session id is a single opaque token (uuid hex). A client-supplied id
    # that escapes the sessions root -- ``..`` traversal, an absolute path,
    # embedded separators -- is hostile input, not a session.
    try:
        candidate.relative_to(base)
    except ValueError:
        raise ValueError(f"invalid session id: {session_id!r}") from None
    if candidate.parent.parent != base:
        raise ValueError("timeline path escaped the sessions directory")
    return candidate


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
    try:
        line = (json.dumps(entry, ensure_ascii=False) + "\n").encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        failure = f"{type(exc).__name__}: {exc}"
        return {
            "at": entry["at"],
            "event": "timeline.entry.write_failed",
            "message": "timeline entry could not be serialized",
            "details": {"error_type": type(exc).__name__},
            "write_failed": failure,
        }
    if len(line) > _MAX_BYTES:
        original_bytes = len(line)
        entry = {
            "at": entry["at"],
            "event": "timeline.entry.truncated",
            "message": "timeline entry exceeded the persistence limit",
            "details": {
                "original_event": str(event)[:128],
                "original_bytes": original_bytes,
                "max_bytes": _MAX_BYTES,
                "truncated": True,
            },
        }
        line = (json.dumps(entry, ensure_ascii=False) + "\n").encode("utf-8")
        if len(line) > _MAX_BYTES:
            entry["write_failed"] = "ValueError: timeline persistence limit is too small"
            return entry
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
    with path.open("rb") as stream:
        size = os.fstat(stream.fileno()).st_size
        start = max(0, size - _MAX_BYTES)
        stream.seek(start)
        tail = stream.read(_MAX_BYTES)
    if start:
        newline = tail.find(b"\n")
        tail = tail[newline + 1 :] if newline >= 0 else b""
    for raw in reversed(tail.splitlines(keepends=True)):
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


def _page(raw: bytes, offset: int, limit: int) -> tuple[int, list[str]]:
    """Total entries, and the requested window decoded.

    Entries are newline-terminated, so counting separators gives the total
    without building a list of every line in the file.
    """
    total = raw.count(b"\n") + (1 if raw and not raw.endswith(b"\n") else 0)
    start = 0
    for _ in range(offset):
        nxt = raw.find(b"\n", start)
        if nxt < 0:
            start = len(raw)
            break
        start = nxt + 1
    end = start
    for _ in range(limit):
        nxt = raw.find(b"\n", end)
        if nxt < 0:
            end = len(raw)
            break
        end = nxt + 1
    # Split only on the "\n" that terminates each JSONL record. str.splitlines()
    # additionally breaks on U+0085, U+2028 and U+2029, which are not control
    # characters below 0x20 and so json.dumps(ensure_ascii=False) writes them
    # literally inside a string value. A record carrying one of those (an
    # extracted string, a console line, a filename) was cut into fragments that
    # each failed to parse and vanished from the page, and the inflated line
    # count made has_more undercount. The terminator leaves a trailing "" that
    # is dropped so the returned count still equals the number of records.
    decoded = raw[start:end].decode("utf-8", errors="replace")
    lines = decoded.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    return total, lines


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
            # Creating a session writes its first entry, so no file at all means
            # no such session -- which is a different answer from a session that
            # has not done anything yet, and the caller has to be able to tell
            # them apart.
            return {**empty, "exists": False}
        try:
            with path.open("rb") as stream:
                raw = stream.read(_MAX_BYTES + 1)
        except OSError as exc:
            return {**empty, "read_failed": f"{type(exc).__name__}: {exc}", "path": str(path)}
        if len(raw) > _MAX_BYTES:
            return {
                **empty,
                "read_failed": f"timeline exceeds {_MAX_BYTES} bytes",
                "path": str(path),
            }
    # Counted and sliced as bytes, and only the requested page decoded. Holding
    # the lock across a full decode of the 8 MB cap cost 13ms, which every
    # append landing behind a reader waited out; this is 5.6ms for the same
    # answer, and the decode itself is now outside the lock entirely.
    total, chunk = _page(raw, offset, limit)
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
        "has_more": offset + len(chunk) < total,
        "path": str(path),
    }
