from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

JsonObject = dict[str, Any]
_MAX_LINES = 10_000
_MAX_BYTES = 8 * 1024 * 1024


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
    line = json.dumps(entry, ensure_ascii=False) + "\n"
    existing = path.read_bytes() if path.is_file() else b""
    if len(existing) + len(line.encode("utf-8")) > _MAX_BYTES:
        # drop from the front until under quota
        text = existing.decode("utf-8", errors="replace").splitlines(True)
        while text and len("".join(text).encode("utf-8")) + len(line.encode("utf-8")) > _MAX_BYTES:
            text.pop(0)
        existing = "".join(text).encode("utf-8")
    lines = existing.splitlines(True)
    if len(lines) >= _MAX_LINES:
        lines = lines[-( _MAX_LINES - 1) :]
        existing = b"".join(lines)
    partial = path.with_suffix(path.suffix + ".partial")
    partial.write_bytes(existing + line.encode("utf-8"))
    partial.replace(path)
    return entry


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
