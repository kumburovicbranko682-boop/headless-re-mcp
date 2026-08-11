"""Structured JSON telemetry for tool invocations.

Every tool call is timed and emitted as one JSON log line under the
``headless_re_mcp.telemetry`` logger, and a bounded in-memory ring keeps the most
recent calls so a metrics tool can answer without parsing log files. The ring is
capped so a long analysis session cannot grow memory without bound.
"""

from __future__ import annotations

import json
import logging
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from functools import wraps
from threading import RLock
from typing import Any

JsonObject = dict[str, Any]

LOGGER_NAME = "headless_re_mcp.telemetry"
DEFAULT_CAPACITY = 512

_LOGGER = logging.getLogger(LOGGER_NAME)


@dataclass(frozen=True, slots=True)
class ToolCallRecord:
    """One observed tool invocation."""

    tool: str
    ok: bool
    duration_ms: float
    at: str
    error_code: str | None = None

    def to_dict(self) -> JsonObject:
        return {
            "tool": self.tool,
            "ok": self.ok,
            "duration_ms": self.duration_ms,
            "at": self.at,
            "error_code": self.error_code,
        }


def _percentile(sorted_values: list[float], fraction: float) -> float:
    if not sorted_values:
        return 0.0
    index = int(round(fraction * (len(sorted_values) - 1)))
    return sorted_values[max(0, min(index, len(sorted_values) - 1))]


class TelemetryRing:
    """Bounded thread-safe store of recent tool-call records."""

    def __init__(self, capacity: int = DEFAULT_CAPACITY) -> None:
        self._records: deque[ToolCallRecord] = deque(maxlen=capacity)
        self._lock = RLock()

    @property
    def capacity(self) -> int:
        return self._records.maxlen or DEFAULT_CAPACITY

    def add(self, record: ToolCallRecord) -> None:
        with self._lock:
            self._records.append(record)

    def clear(self) -> None:
        with self._lock:
            self._records.clear()

    def recent(self, limit: int = 50) -> list[JsonObject]:
        with self._lock:
            items = list(self._records)
        newest_first = list(reversed(items))
        return [item.to_dict() for item in newest_first[: max(0, limit)]]

    def metrics(self) -> JsonObject:
        with self._lock:
            items = list(self._records)
        buckets: dict[str, list[ToolCallRecord]] = {}
        for item in items:
            buckets.setdefault(item.tool, []).append(item)
        tools: list[JsonObject] = []
        for name in sorted(buckets):
            calls = buckets[name]
            durations = sorted(call.duration_ms for call in calls)
            failures = sum(1 for call in calls if not call.ok)
            tools.append(
                {
                    "tool": name,
                    "calls": len(calls),
                    "failures": failures,
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
    ring: TelemetryRing | None = None,
) -> ToolCallRecord:
    """Log one structured record and retain it in the ring."""
    record = ToolCallRecord(
        tool=tool,
        ok=ok,
        duration_ms=round(duration_ms, 3),
        at=datetime.now(UTC).isoformat(),
        error_code=error_code,
    )
    (ring or TELEMETRY).add(record)
    _LOGGER.info(json.dumps({"event": "tool_call", **record.to_dict()}, ensure_ascii=False))
    return record


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

    @wraps(handler)
    def observed(*args: Any, **kwargs: Any) -> dict[str, Any]:
        started = time.perf_counter()
        try:
            payload = handler(*args, **kwargs)
        except BaseException as exc:
            record_tool_call(
                name,
                ok=False,
                duration_ms=(time.perf_counter() - started) * 1000.0,
                error_code=type(exc).__name__,
                ring=ring,
            )
            raise
        record_tool_call(
            name,
            ok=_envelope_ok(payload),
            duration_ms=(time.perf_counter() - started) * 1000.0,
            error_code=_envelope_error_code(payload),
            ring=ring,
        )
        return payload

    return observed
