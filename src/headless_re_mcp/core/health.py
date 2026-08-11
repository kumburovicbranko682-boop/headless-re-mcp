"""Watch open backends and rebuild connections that dropped underneath them."""

from __future__ import annotations

import threading
import time
from contextlib import suppress
from dataclasses import dataclass, field
from typing import Any, Protocol

from headless_re_mcp.core.models import BackendKind

JsonObject = dict[str, Any]


class _Repairable(Protocol):
    """The part of a backend worker health monitoring relies on."""

    @property
    def exit_code(self) -> int | None: ...


@dataclass(slots=True)
class BackendHealth:
    """What the last check saw for one backend, and what it did about it."""

    session_id: str
    backend: str
    worker_alive: bool
    connected: bool
    checked_at: float
    reconnects: int = 0
    failures: int = 0
    last_error: str | None = None

    def as_json(self) -> JsonObject:
        return {
            "session_id": self.session_id,
            "backend": self.backend,
            "worker_alive": self.worker_alive,
            "connected": self.connected,
            "healthy": self.worker_alive and self.connected,
            "checked_at": self.checked_at,
            "reconnects": self.reconnects,
            "failures": self.failures,
            "last_error": self.last_error,
        }


class _RuntimeSource(Protocol):
    def snapshot(self) -> list[tuple[str, BackendKind, Any]]: ...


@dataclass(slots=True)
class BackendHealthMonitor:
    """Repair dropped connections without waiting for the caller to notice.

    Deliberately passive: it reads process and connection state and never issues
    an RPC of its own, so a healthy session never contends with it and a long
    running operation is never interrupted by a probe. It also never restarts a
    dead worker, because a restarted debugger comes back attached to nothing and
    only the caller can decide whether relaunching is acceptable; those are
    reported so that session.recover can be called deliberately.
    """

    runtimes: _RuntimeSource
    interval_s: float = 5.0
    _entries: dict[tuple[str, str], BackendHealth] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)
    _stop: threading.Event = field(default_factory=threading.Event)
    _thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread is not None:
            return
        self._stop.clear()
        thread = threading.Thread(target=self._run, name="backend-health", daemon=True)
        self._thread = thread
        thread.start()

    def stop(self, *, timeout: float = 2.0) -> None:
        self._stop.set()
        thread = self._thread
        self._thread = None
        if thread is not None:
            thread.join(timeout=timeout)

    def _run(self) -> None:
        while not self._stop.is_set():
            # A monitor that can raise would take down the session it exists to
            # protect; per-backend failures are already recorded in the report.
            with suppress(Exception):
                self.check_once()
            self._stop.wait(self.interval_s)

    def check_once(self) -> list[BackendHealth]:
        """Inspect every open backend once, repairing what can be repaired."""
        results: list[BackendHealth] = []
        for session_id, kind, runtime in self.runtimes.snapshot():
            worker = getattr(runtime, "worker", runtime)
            results.append(self._check_backend(session_id, kind, worker))
        return results

    def _check_backend(self, session_id: str, kind: BackendKind, worker: object) -> BackendHealth:
        key = (session_id, kind.value)
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                entry = BackendHealth(
                    session_id=session_id,
                    backend=kind.value,
                    worker_alive=True,
                    connected=True,
                    checked_at=time.time(),
                )
                self._entries[key] = entry

        # A worker that never reports an exit code cannot be judged dead, so
        # treat the unknown case as alive rather than inventing a failure.
        entry.worker_alive = getattr(worker, "exit_code", None) is None
        entry.connected = bool(getattr(worker, "transport_connected", True))
        entry.checked_at = time.time()
        reconnect = getattr(worker, "reconnect", None)
        if entry.worker_alive and not entry.connected and callable(reconnect):
            try:
                reconnect()
            except BaseException as exc:  # noqa: BLE001 - recorded, not raised
                entry.failures += 1
                entry.last_error = f"{type(exc).__name__}: {exc}"
            else:
                entry.reconnects += 1
                entry.last_error = None
                entry.connected = bool(getattr(worker, "transport_connected", True))
        return entry

    def forget(self, session_id: str) -> None:
        with self._lock:
            for key in [item for item in self._entries if item[0] == session_id]:
                del self._entries[key]

    def report(self, session_id: str | None = None) -> list[JsonObject]:
        with self._lock:
            entries = [
                entry
                for entry in self._entries.values()
                if session_id is None or entry.session_id == session_id
            ]
        return [entry.as_json() for entry in sorted(entries, key=lambda item: item.backend)]
