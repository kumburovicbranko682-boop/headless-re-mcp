"""Bounded HAR serialization shared by the Web (CDP) and proxy (mitmproxy) lines.

Both capture surfaces export the same HAR 1.2 log, and both write it into the
session artifact tree where ``_register_capture`` reads the whole file back to
hash it. A capture ring holds thousands of flows, and a single export that is
not bounded fills the disk and then the hash reads all of it -- the same
unbounded-write-then-unbounded-read the count caps elsewhere were meant to
prevent. One serializer, imported by both, so the two cannot disagree about
the ceiling or about which end is dropped when they hit it.
"""

from __future__ import annotations

import json
from collections.abc import Iterable

JsonObject = dict[str, object]

_HAR_CREATOR = {"name": "headless-re-mcp"}


def build_bounded_har(
    entries: Iterable[JsonObject], *, max_bytes: int
) -> tuple[str, int, bool, int]:
    """Serialize HAR entries, dropping the oldest until the log fits ``max_bytes``.

    Entries arrive oldest-first (both capture rings evict from the front), so
    the oldest are dropped and the newest kept: an export is read for what just
    happened, and a capture that overflowed the cap is more useful ending at the
    last flow than at the first. Returns ``(text, kept_entry_count, truncated,
    size_bytes)``; an empty log is a few dozen bytes, so the loop always
    terminates at or below the cap.
    """
    kept = list(entries)
    truncated = False
    while True:
        log = {
            "log": {
                "version": "1.2",
                "creator": dict(_HAR_CREATOR),
                "entries": kept,
            }
        }
        text = json.dumps(log, ensure_ascii=False)
        size = len(text.encode("utf-8"))
        if size <= max_bytes or not kept:
            return text, len(kept), truncated, size
        # Drop a slice rather than one at a time so a log that is far over the
        # cap converges without re-serializing thousands of times.
        drop = max(1, len(kept) // 8)
        del kept[:drop]
        truncated = True
