"""Keep the artifact directory from growing until the volume fills.

Two separate problems live here. Registered artifacts have rows in the database
and can be collected oldest-first against a byte budget. Everything else --
screenshots, the undo records behind static writes, anything written straight to
disk -- has no row, so garbage collection cannot see it. Deleting unregistered
files by guesswork is how an analysis loses the evidence it was run to produce,
so those are measured and reported instead, and the operator decides.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from threading import Lock
from typing import Any, Protocol

JsonObject = dict[str, Any]

DEFAULT_MAX_TOTAL_BYTES = 512 * 1024 * 1024
DEFAULT_MIN_INTERVAL_S = 60.0
DEFAULT_USAGE_TTL_S = 30.0
# A walk of an artifact root with a runaway producer in it must not become the
# slowest part of a health probe.
USAGE_FILE_LIMIT = 50_000


class _Collector(Protocol):
    def gc_artifacts(self, *, max_total_bytes: int) -> JsonObject: ...


@dataclass(frozen=True, slots=True)
class DiskUsage:
    """What the artifact root currently holds."""

    bytes: int
    files: int
    truncated: bool

    def as_json(self) -> JsonObject:
        return {"bytes": self.bytes, "files": self.files, "truncated": self.truncated}


def measure_usage(root: Path, *, file_limit: int = USAGE_FILE_LIMIT) -> DiskUsage:
    """Total the artifact tree, giving up rather than stalling on a huge one.

    ``truncated`` says the answer is a floor, not the whole story, so a caller
    never reports a reassuring number that just means the walk stopped early.
    """
    total = 0
    files = 0
    try:
        for path in root.rglob("*"):
            if files >= file_limit:
                return DiskUsage(bytes=total, files=files, truncated=True)
            try:
                stat = path.stat()
            except OSError:
                continue
            if path.is_file():
                total += stat.st_size
                files += 1
    except OSError:
        return DiskUsage(bytes=total, files=files, truncated=True)
    return DiskUsage(bytes=total, files=files, truncated=False)


@dataclass(slots=True)
class ArtifactRetention:
    """Run artifact collection on a schedule instead of on request only.

    ``artifacts.gc`` existed but nothing ever called it, so retention depended on
    somebody remembering. Throttling matters because collection is invoked from
    ordinary paths such as closing a session, which can happen in a tight loop.
    """

    max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES
    min_interval_s: float = DEFAULT_MIN_INTERVAL_S
    _last_run: float = field(default=0.0)
    _lock: Lock = field(default_factory=Lock)

    @property
    def enabled(self) -> bool:
        return self.max_total_bytes > 0

    def maybe_collect(
        self, collector: _Collector, *, now: float | None = None
    ) -> JsonObject | None:
        """Collect if the budget is set and the throttle window has elapsed."""
        if not self.enabled:
            return None
        moment = time.monotonic() if now is None else now
        with self._lock:
            if moment - self._last_run < self.min_interval_s:
                return None
            self._last_run = moment
        try:
            return collector.gc_artifacts(max_total_bytes=self.max_total_bytes)
        except Exception:
            # Retention is maintenance. A failure here must never turn into a
            # failed session close for the caller that happened to trigger it.
            return None


@dataclass(slots=True)
class UsageCache:
    """Cache the directory walk so probes can ask often and cheaply."""

    ttl_s: float = DEFAULT_USAGE_TTL_S
    _value: DiskUsage | None = field(default=None)
    _at: float = field(default=0.0)
    _lock: Lock = field(default_factory=Lock)

    def get(self, root: Path, *, now: float | None = None) -> DiskUsage:
        moment = time.monotonic() if now is None else now
        with self._lock:
            if self._value is not None and moment - self._at < self.ttl_s:
                return self._value
        measured = measure_usage(root)
        with self._lock:
            self._value = measured
            self._at = moment
        return measured
