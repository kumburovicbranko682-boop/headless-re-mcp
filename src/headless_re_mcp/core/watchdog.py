"""Notice and correct the failures nobody is watching for.

The service already reports plenty: health rows per backend, telemetry, a
readiness probe. All of it is pull-based and assumed a human would look. Under
24/7 operation nothing looks, so a dead worker sits dead and the missions that
need it fail one after another until the budget runs out.

The watchdog is the thing that looks. Correction is opt-in for the same reason
approvals are: a recovered dynamic backend comes back attached to nothing, and
deciding to relaunch a target is a real decision. Off by default, this reports
exactly what it would have done.
"""

from __future__ import annotations

import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Protocol

from headless_re_mcp.error_boundary import record_exception
from headless_re_mcp.telemetry import record_alert

JsonObject = dict[str, Any]

DEFAULT_ALERT_HISTORY = 128


class _HealthSource(Protocol):
    def session_health(self, session_id: str | None = None) -> Any: ...

    def session_recover(self, session_id: str, backends: list[str] | None = None) -> Any: ...


@dataclass(frozen=True, slots=True)
class WatchdogPolicy:
    """What the watchdog is allowed to do about what it finds."""

    # Off by design. A recovered dynamic backend is attached to nothing, so
    # relaunching the target is a decision the operator opts into.
    auto_recover_backends: bool = False
    interval_s: float = 30.0
    # Mirrors the supervisor's crash-loop limit. A backend that cannot come back
    # -- IDA uninstalled, the binary gone, a licence expired -- would otherwise
    # be relaunched every interval for as long as the process lives.
    max_recovery_attempts: int = 5

    @classmethod
    def from_settings(cls, settings: object) -> WatchdogPolicy:
        return cls(
            auto_recover_backends=bool(
                getattr(settings, "watchdog_auto_recover_backends", False)
            ),
            interval_s=float(getattr(settings, "watchdog_interval_s", 30.0) or 0.0),
        )

    @property
    def enabled(self) -> bool:
        return self.interval_s > 0


@dataclass(slots=True)
class Watchdog:
    """Sweep for dead backends, and either fix or report them."""

    health: _HealthSource
    policy: WatchdogPolicy = field(default_factory=WatchdogPolicy)
    clock: Callable[[], float] = time.time
    alerts: deque[JsonObject] = field(
        default_factory=lambda: deque(maxlen=DEFAULT_ALERT_HISTORY)
    )
    recovered: int = 0
    raised: int = 0
    # How many consecutive sweeps each (session, backend) has been found dead.
    # Pruned every sweep, so it holds one entry per currently-dead backend.
    _dead_streak: dict[tuple[str, str], int] = field(default_factory=dict)
    # Which (session, backend) pairs have already been reported disconnected.
    # Pruned the same way, so it holds one entry per currently-dropped pipe.
    _reported_disconnected: set[tuple[str, str]] = field(default_factory=set)

    def sweep(self) -> JsonObject:
        """One pass. Never raises: a watchdog that dies stops watching."""
        try:
            return self._sweep()
        except BaseException as exc:  # noqa: BLE001 - recorded, never fatal
            incident = record_exception(exc, context="watchdog")
            return self._alert(
                "watchdog_failed",
                detail=f"{type(exc).__name__}: {incident['message']}",
                incident_id=str(incident["incident_id"]),
            )

    def _sweep(self) -> JsonObject:
        result = self.health.session_health()
        rows = self._rows(result)
        dead = [row for row in rows if not row.get("worker_alive", True)]
        disconnected = [
            row
            for row in rows
            if row.get("worker_alive", True) and not row.get("connected", True)
        ]
        # Forget anything that is no longer dead, so a backend that comes back
        # and dies again is reported as a fresh failure rather than as a
        # continuation of the old one.
        still_dead = {self._key(row) for row in dead}
        for key in [key for key in self._dead_streak if key not in still_dead]:
            del self._dead_streak[key]
        still_disconnected = {self._key(row) for row in disconnected}
        self._reported_disconnected.intersection_update(still_disconnected)

        actions: list[JsonObject] = []
        for row in dead:
            actions.append(self._handle_dead(row))
        for row in disconnected:
            # Same once-per-outage rule as a dead worker. The health monitor
            # rebuilds connections itself; this is only worth saying out loud
            # the first time a pipe stays down, because a backend that keeps
            # dropping is a signal even when every reconnect succeeds.
            key = self._key(row)
            if key in self._reported_disconnected:
                continue
            self._reported_disconnected.add(key)
            self._alert(
                "backend_disconnected",
                session_id=str(row.get("session_id") or ""),
                backend=str(row.get("backend") or ""),
                detail=str(row.get("last_error") or "connection was rebuilt"),
            )
        return {
            "checked": len(rows),
            "dead": len(dead),
            "disconnected": len(disconnected),
            "actions": actions,
            "recovered_total": self.recovered,
            "alerts_total": self.raised,
        }

    @staticmethod
    def _key(row: JsonObject) -> tuple[str, str]:
        return (str(row.get("session_id") or ""), str(row.get("backend") or ""))

    def _handle_dead(self, row: JsonObject) -> JsonObject:
        """React to one dead backend, once, and stop trying if it will not come back.

        Both halves of this used to repeat on every sweep for as long as the
        backend stayed dead. At the default interval that is 2,880 identical
        alerts a day for one failure -- which buries the alerts that are not
        identical -- and, with recovery on, 2,880 attempts to relaunch a worker
        that has already refused to start.
        """
        session_id, backend = key = self._key(row)
        seen_before = self._dead_streak.get(key, 0)
        self._dead_streak[key] = seen_before + 1

        if not self.policy.auto_recover_backends:
            if seen_before == 0:
                self._alert(
                    "backend_dead",
                    session_id=session_id,
                    backend=backend,
                    detail="worker process is gone; session.recover was not attempted",
                )
                return {"session_id": session_id, "backend": backend, "action": "reported"}
            return {
                "session_id": session_id,
                "backend": backend,
                "action": "still_dead",
                "sweeps": seen_before + 1,
            }

        limit = max(1, self.policy.max_recovery_attempts)
        if seen_before >= limit:
            if seen_before == limit:
                self._alert(
                    "backend_recovery_abandoned",
                    session_id=session_id,
                    backend=backend,
                    detail=(
                        f"recovery failed {limit} times in a row; not trying again "
                        "until this backend comes back or the session is closed"
                    ),
                )
            return {"session_id": session_id, "backend": backend, "action": "abandoned"}

        outcome = self.health.session_recover(session_id, [backend] if backend else None)
        ok = bool(getattr(outcome, "ok", False))
        if ok:
            self.recovered += 1
            self._dead_streak.pop(key, None)
            self._alert(
                "backend_recovered",
                session_id=session_id,
                backend=backend,
                detail="worker was replaced; the target is not attached",
                severity="info",
            )
            return {"session_id": session_id, "backend": backend, "action": "recovered"}

        error = getattr(outcome, "error", None)
        self._alert(
            "backend_recovery_failed",
            session_id=session_id,
            backend=backend,
            detail=str(getattr(error, "message", error) or "recovery returned no error"),
            attempt=seen_before + 1,
            of=limit,
        )
        return {"session_id": session_id, "backend": backend, "action": "recovery_failed"}

    @staticmethod
    def _rows(result: Any) -> list[JsonObject]:
        data = getattr(result, "data", None)
        if not isinstance(data, dict):
            return []
        rows = data.get("backends")
        return [row for row in rows if isinstance(row, dict)] if isinstance(rows, list) else []

    def _alert(self, kind: str, *, severity: str = "warning", **fields: Any) -> JsonObject:
        alert: JsonObject = {
            "kind": kind,
            "severity": severity,
            "at": self.clock(),
            **fields,
        }
        self.alerts.append(alert)
        self.raised += 1
        # Emitted as a telemetry line so an external collector sees it without
        # polling this endpoint; the ring is only for asking after the fact.
        record_alert(kind, severity=severity, fields=fields)
        return alert

    def recent_alerts(self, limit: int = 50) -> list[JsonObject]:
        items = list(self.alerts)
        return list(reversed(items))[: max(0, limit)]