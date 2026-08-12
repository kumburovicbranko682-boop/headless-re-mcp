"""Structured JSON telemetry for tool invocations.

Every tool call is timed and emitted as one JSON log line under the
``headless_re_mcp.telemetry`` logger, and a bounded in-memory ring keeps the most
recent calls so a metrics tool can answer without parsing log files. The ring is
capped so a long analysis session cannot grow memory without bound.

The ring answers "what is happening now" and dies with the process; the log file
answers "what happened last Tuesday". A long-lived deployment needs both, so
:func:`configure_telemetry_logging` must be called by every process entry point
that serves tools -- without it these records are formatted and then dropped,
because a logger with no handler has nowhere to put them.
"""

from __future__ import annotations

import inspect
import json
import logging
import os
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from functools import wraps
from pathlib import Path
from threading import RLock
from typing import Any

from headless_re_mcp.logging_setup import attach_rotating_handler, resolve_log_dir

JsonObject = dict[str, Any]

LOGGER_NAME = "headless_re_mcp.telemetry"
DEFAULT_CAPACITY = 512
_DISABLED_VALUES = frozenset({"0", "off", "false", "no"})

_LOGGER = logging.getLogger(LOGGER_NAME)
_LOG_LOCK = RLock()
_LOG_PATH: Path | None = None


def configure_telemetry_logging(log_dir: Path | None = None) -> Path | None:
    """Send tool-call records to a rotating JSONL file, exactly once.

    Returns ``None`` when ``HEADLESS_RE_TELEMETRY_LOG`` disables the sink. The
    logger does not propagate: on the stdio transport a root handler writing to
    stdout would interleave log text with JSON-RPC frames and break the session.
    """
    if os.environ.get("HEADLESS_RE_TELEMETRY_LOG", "").strip().lower() in _DISABLED_VALUES:
        return None
    global _LOG_PATH
    with _LOG_LOCK:
        if _LOG_PATH is not None:
            return _LOG_PATH
        path = (resolve_log_dir(log_dir) / "telemetry.jsonl").resolve()
        # The record is already JSON, so the formatter must add nothing at all
        # or the file stops being parseable line by line.
        _LOG_PATH = attach_rotating_handler(
            LOGGER_NAME,
            path,
            formatter=logging.Formatter("%(message)s"),
        )
        return _LOG_PATH


def telemetry_log_path() -> Path | None:
    """Return the active telemetry log file, or ``None`` when unconfigured."""
    with _LOG_LOCK:
        return _LOG_PATH


@dataclass(frozen=True, slots=True)
class ToolCallRecord:
    """One observed tool invocation."""

    tool: str
    ok: bool
    duration_ms: float
    at: str
    error_code: str | None = None
    session_id: str | None = None

    def to_dict(self) -> JsonObject:
        return {
            "tool": self.tool,
            "ok": self.ok,
            "duration_ms": self.duration_ms,
            "at": self.at,
            "error_code": self.error_code,
            "session_id": self.session_id,
        }


def _percentile(sorted_values: list[float], fraction: float) -> float:
    if not sorted_values:
        return 0.0
    index = int(round(fraction * (len(sorted_values) - 1)))
    return sorted_values[max(0, min(index, len(sorted_values) - 1))]


@dataclass(slots=True)
class ToolTotals:
    """Lifetime counts for one tool, kept outside the evicting window."""

    calls: int = 0
    failures: int = 0


class TelemetryRing:
    """Bounded store of recent records, plus unbounded-in-time call counters.

    The ring answers latency questions and forgets; the totals answer rate and
    error-budget questions and must not. Percentiles computed from an evicting
    window are honest about being a recent sample, but a call counter that falls
    when the window rolls would make every rate calculation wrong, so the two are
    tracked separately. Totals are bounded in memory by the number of registered
    tool names, not by traffic.
    """

    def __init__(self, capacity: int = DEFAULT_CAPACITY) -> None:
        self._records: deque[ToolCallRecord] = deque(maxlen=capacity)
        self._totals: dict[str, ToolTotals] = {}
        self._lock = RLock()

    @property
    def capacity(self) -> int:
        return self._records.maxlen or DEFAULT_CAPACITY

    def add(self, record: ToolCallRecord) -> None:
        with self._lock:
            self._records.append(record)
            totals = self._totals.get(record.tool)
            if totals is None:
                totals = ToolTotals()
                self._totals[record.tool] = totals
            totals.calls += 1
            if not record.ok:
                totals.failures += 1

    def totals(self) -> dict[str, ToolTotals]:
        with self._lock:
            return {
                name: ToolTotals(item.calls, item.failures)
                for name, item in self._totals.items()
            }

    def clear(self) -> None:
        """Drop the window and the counters. Intended for tests and resets."""
        with self._lock:
            self._records.clear()
            self._totals.clear()

    def recent(self, limit: int = 50) -> list[JsonObject]:
        with self._lock:
            items = list(self._records)
        newest_first = list(reversed(items))
        return [item.to_dict() for item in newest_first[: max(0, limit)]]

    def metrics(self) -> JsonObject:
        with self._lock:
            items = list(self._records)
            totals = {
                name: ToolTotals(item.calls, item.failures)
                for name, item in self._totals.items()
            }
        buckets: dict[str, list[ToolCallRecord]] = {}
        for item in items:
            buckets.setdefault(item.tool, []).append(item)
        tools: list[JsonObject] = []
        for name in sorted(set(buckets) | set(totals)):
            calls = buckets.get(name, [])
            durations = sorted(call.duration_ms for call in calls)
            failures = sum(1 for call in calls if not call.ok)
            lifetime = totals.get(name, ToolTotals())
            tools.append(
                {
                    "tool": name,
                    # "calls" stays the sampled count for compatibility; the
                    # *_total fields are the ones safe to build a rate on.
                    "calls": len(calls),
                    "failures": failures,
                    "calls_total": lifetime.calls,
                    "failures_total": lifetime.failures,
                    "p50_ms": round(_percentile(durations, 0.5), 3),
                    "p95_ms": round(_percentile(durations, 0.95), 3),
                    "max_ms": round(durations[-1], 3) if durations else 0.0,
                }
            )
        return {
            "tools": tools,
            "sampled_calls": len(items),
            "distinct_tools": len(buckets),
            "failures": sum(1 for item in items if not item.ok),
            "calls_total": sum(item.calls for item in totals.values()),
            "failures_total": sum(item.failures for item in totals.values()),
            "capacity": self.capacity,
        }


TELEMETRY = TelemetryRing()


def _envelope_ok(payload: object) -> bool:
    if isinstance(payload, dict) and "ok" in payload:
        return bool(payload.get("ok"))
    return True


def _envelope_error_code(payload: object) -> str | None:
    if not isinstance(payload, dict):
        return None
    error = payload.get("error")
    if isinstance(error, dict):
        code = error.get("code")
        if isinstance(code, str):
            return code
    return None


def record_tool_call(
    tool: str,
    *,
    ok: bool,
    duration_ms: float,
    error_code: str | None = None,
    session_id: str | None = None,
    ring: TelemetryRing | None = None,
) -> ToolCallRecord:
    """Log one structured record and retain it in the ring."""
    record = ToolCallRecord(
        tool=tool,
        ok=ok,
        duration_ms=round(duration_ms, 3),
        at=datetime.now(UTC).isoformat(),
        error_code=error_code,
        session_id=session_id,
    )
    (ring or TELEMETRY).add(record)
    _LOGGER.info(json.dumps({"event": "tool_call", **record.to_dict()}, ensure_ascii=False))
    return record


def _session_parameter_index(handler: Callable[..., Any]) -> int | None:
    """Locate ``session_id`` in the handler signature, once per registration.

    Resolved at wrap time because doing it per call would put signature
    introspection on the hot path of every tool invocation.
    """
    try:
        names = list(inspect.signature(handler).parameters)
    except (TypeError, ValueError):
        return None
    return names.index("session_id") if "session_id" in names else None


def instrument(
    handler: Callable[..., dict[str, Any]],
    *,
    name: str,
    ring: TelemetryRing | None = None,
) -> Callable[..., dict[str, Any]]:
    """Wrap a tool handler so each call emits duration and success telemetry.

    ``functools.wraps`` keeps ``__wrapped__``/``__annotations__`` intact so schema
    generation still sees the original typed signature.
    """
    session_index = _session_parameter_index(handler)

    def session_of(args: tuple[Any, ...], kwargs: dict[str, Any]) -> str | None:
        value = kwargs.get("session_id")
        if value is None and session_index is not None and len(args) > session_index:
            value = args[session_index]
        return value if isinstance(value, str) else None

    @wraps(handler)
    def observed(*args: Any, **kwargs: Any) -> dict[str, Any]:
        started = time.perf_counter()
        session_id = session_of(args, kwargs)
        try:
            payload = handler(*args, **kwargs)
        except BaseException as exc:
            record_tool_call(
                name,
                ok=False,
                duration_ms=(time.perf_counter() - started) * 1000.0,
                error_code=type(exc).__name__,
                session_id=session_id,
                ring=ring,
            )
            raise
        record_tool_call(
            name,
            ok=_envelope_ok(payload),
            duration_ms=(time.perf_counter() - started) * 1000.0,
            error_code=_envelope_error_code(payload),
            session_id=session_id,
            ring=ring,
        )
        return payload

    return observed
