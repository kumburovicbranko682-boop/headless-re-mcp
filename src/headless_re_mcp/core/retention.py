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
from threading import Lock, Thread
from typing import Any, Protocol

from headless_re_mcp.telemetry import record_alert

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
    _pending_bytes: int = field(default=0)
    _failing: bool = field(default=False)
    _lock: Lock = field(default_factory=Lock)

    @property
    def enabled(self) -> bool:
        return self.max_total_bytes > 0

    @property
    def burst_bytes(self) -> int:
        """How much new material makes a collection worth doing immediately."""
        return max(1, self.max_total_bytes // 2)

    def maybe_collect(
        self, collector: _Collector, *, now: float | None = None, added_bytes: int = 0
    ) -> JsonObject | None:
        """Collect when the window has elapsed, or sooner if a burst demands it.

        Time alone is the wrong throttle for a producer that outruns it. A UI
        loop writing multi-megabyte bitmaps put 60 MB on disk against an 8 MB
        budget in under a second, all of it inside one throttle window, so the
        budget never applied. Registered volume is therefore a trigger of its
        own, which bounds the overshoot to the burst threshold instead of to
        whatever the producer manages in a minute.
        """
        if not self.enabled:
            return None
        moment = time.monotonic() if now is None else now
        with self._lock:
            self._pending_bytes += max(0, added_bytes)
            elapsed = moment - self._last_run >= self.min_interval_s
            if not elapsed and self._pending_bytes < self.burst_bytes:
                return None
            self._last_run = moment
            self._pending_bytes = 0
        try:
            collected = collector.gc_artifacts(max_total_bytes=self.max_total_bytes)
        except Exception as exc:
            # Retention is maintenance. A failure here must never turn into a
            # failed session close for the caller that happened to trigger it.
            # It must still be audible: a collector that has stopped working
            # stops enforcing the budget, and the only visible symptom is disk
            # use climbing past it with nothing to explain why. Once, because
            # this runs on every registration.
            if not self._failing:
                self._failing = True
                record_alert(
                    "artifact_collection_failing",
                    fields={
                        "detail": f"{type(exc).__name__}: {exc}",
                        "consequence": "the artifact byte budget is no longer being enforced",
                    },
                )
            return None
        if self._failing:
            self._failing = False
            # Recovery is a fact to record, not a page: reported at info like
            # every other *_recovered alert (backend_recovered,
            # artifact_usage_measurement_recovered, event_drain_recovered). The
            # failure above keeps the default warning; only the good news is
            # info, so an operator alerting on warnings is not woken when
            # collection starts working again.
            record_alert(
                "artifact_collection_recovered",
                severity="info",
                fields={"detail": "collection succeeded"},
            )
        return collected


@dataclass(slots=True)
class UsageCache:
    """Serve the last directory walk, and take the next one off the caller.

    The walk is bounded by a file count rather than by time: 938 files measured
    154ms here and 50,000 -- the cap -- took 5.9 seconds. Refreshing inside the
    caller made every probe that landed on an expiry pay that, which showed up
    as a readiness endpoint answering in 20ms and then 200ms once every TTL.

    The supervisor allows a probe five seconds before it counts a strike, so on
    a large tree an expiry answers late; and a tree slow enough that one walk
    outlasts the TTL leaves every probe refreshing, which is three late answers
    in a row and a restart of a healthy service. Disk use is reported and never
    gated, so none of that was deciding anything -- it was an informational
    field deciding whether the process looked alive.

    So the caller never walks. It gets whatever was measured last, and a stale
    value starts one background refresh for whoever asks next.
    """

    ttl_s: float = DEFAULT_USAGE_TTL_S
    _value: DiskUsage | None = field(default=None)
    _at: float = field(default=0.0)
    _lock: Lock = field(default_factory=Lock)
    _refreshing: bool = field(default=False)
    _failing: bool = field(default=False)

    def get(self, root: Path, *, now: float | None = None) -> DiskUsage:
        moment = time.monotonic() if now is None else now
        with self._lock:
            value = self._value
            stale = value is None or moment - self._at >= self.ttl_s
            claim = stale and not self._refreshing
            if claim:
                self._refreshing = True
        if claim:
            Thread(
                target=self._refresh,
                args=(root,),
                name="artifact-usage",
                daemon=True,
            ).start()
        if value is not None:
            return value
        # Never measured. Zero with truncated set is what this already means
        # elsewhere: a floor, not the whole story.
        return DiskUsage(bytes=0, files=0, truncated=True)

    def _refresh(self, root: Path) -> None:
        try:
            measured = measure_usage(root)
        except Exception as exc:  # noqa: BLE001 - background maintenance must stay bounded
            with self._lock:
                # An empty cache is always stale, so merely clearing the claim
                # starts another daemon thread on the next probe and bypasses
                # the TTL. Cache the same honest "unknown floor" returned on a
                # cold start (or retain the last measurement), and timestamp
                # the attempt so a broken walk is retried at the configured
                # cadence rather than at the readiness request rate.
                if self._value is None:
                    self._value = DiskUsage(bytes=0, files=0, truncated=True)
                self._at = time.monotonic()
                self._refreshing = False
                first_failure = not self._failing
                self._failing = True
            if first_failure:
                record_alert(
                    "artifact_usage_measurement_failing",
                    fields={
                        "detail": f"{type(exc).__name__}: {exc}",
                        "consequence": "artifact usage is stale until a later measurement succeeds",
                    },
                )
            return

        with self._lock:
            recovered = self._failing
            self._value = measured
            self._at = time.monotonic()
            self._refreshing = False
            self._failing = False
        if recovered:
            record_alert(
                "artifact_usage_measurement_recovered",
                severity="info",
                fields={"detail": "artifact usage measurement succeeded"},
            )
