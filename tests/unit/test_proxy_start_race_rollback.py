"""proxy.start must not leak a bound port when the session races to terminal.

proxy_start re-checks the session state *after* the backend has bound its
port: a concurrent session.close landing during the start would otherwise
leave a mitmproxy listener bound to a port with no live session that could
ever stop it (the same leaked-listener failure the cross-session port-reserve
guard prevents from the other direction). The handler's answer is to stop the
just-started proxy and re-raise, so the port is released and the caller sees
invalid_request rather than a phantom "running" proxy.

That rollback branch (service_proxy lines 66-83) had no coverage -- neither
the happy path nor the race. A fake proxy backend stands in for mitmproxy so
no port is ever really bound: its start() optionally drives the session to a
terminal state as its side effect, reproducing the race deterministically,
and records whether stop() was called so the rollback is observable. A
regression that dropped the post-start re-check would pass the happy test and
fail the race test (ok=True, stop never called), which is exactly the leak.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from headless_re_mcp.config import Settings
from headless_re_mcp.core.models import SessionState
from headless_re_mcp.core.service import AnalysisService


class _FakeProxy:
    """Minimal ProxyBackend stand-in: records start/stop, binds no real port."""

    def __init__(self, *, on_start: Any = None) -> None:
        self.started: list[tuple[str, str, int]] = []
        self.stopped: list[str] = []
        self._on_start = on_start

    def start(self, session_id: str, host: str = "127.0.0.1", port: int = 8080) -> dict[str, Any]:
        self.started.append((session_id, host, port))
        if self._on_start is not None:
            self._on_start(session_id)
        return {
            "running": True,
            "host": host,
            "port": port,
            "endpoint": f"http://{host}:{port}",
        }

    def stop(self, session_id: str) -> dict[str, Any]:
        self.stopped.append(session_id)
        return {"stopped": True}

    def close_all(self) -> None:
        # AnalysisService.close_all() calls this on the owned proxy backend.
        return None


def _service(tmp_path: Path) -> AnalysisService:
    settings = Settings(
        ida_home=None,
        x64dbg_source=None,
        x64dbg_headless_x64=None,
        x64dbg_headless_x86=None,
        artifact_root=tmp_path / "artifacts",
    )
    return AnalysisService(settings)


def _web_session(service: AnalysisService, url: str = "https://example.com/app") -> str:
    created = service.create_session(url, target="web")
    assert created.ok and created.data is not None, created.error
    return str(created.data["session"]["id"])


def test_proxy_start_succeeds_and_does_not_roll_back_when_the_session_stays_live(
    tmp_path: Path,
) -> None:
    service = _service(tmp_path)
    try:
        session_id = _web_session(service)
        fake = _FakeProxy()
        service._proxy_backend = fake  # type: ignore[assignment]

        result = service.proxy_start(session_id)

        assert result.ok, result.error
        assert result.data is not None
        assert result.data["endpoint"] == "http://127.0.0.1:8080"
        assert fake.started == [(session_id, "127.0.0.1", 8080)]
        assert fake.stopped == [], "a live session must not trigger the rollback stop"
    finally:
        service.close_all()


def test_proxy_start_stops_the_proxy_when_the_session_races_to_terminal(
    tmp_path: Path,
) -> None:
    service = _service(tmp_path)
    try:
        session_id = _web_session(service)

        # The concurrent close, made deterministic: the backend's start() flips
        # the session to FAILED (allowed from created) as its side effect, so
        # the post-start re-check inside proxy_start sees a terminal session.
        def _fail_mid_start(sid: str) -> None:
            service.registry.transition(sid, SessionState.FAILED)

        fake = _FakeProxy(on_start=_fail_mid_start)
        service._proxy_backend = fake  # type: ignore[assignment]

        result = service.proxy_start(session_id)

        assert not result.ok, "a session that went terminal mid-start must not report running"
        assert result.error is not None
        assert result.error.code == "invalid_request"
        assert fake.started == [(session_id, "127.0.0.1", 8080)]
        assert fake.stopped == [session_id], (
            "the just-started proxy must be stopped so its bound port is released; "
            "leaving it up is the leak this guard exists to prevent"
        )
    finally:
        service.close_all()


def test_proxy_start_refuses_a_session_already_terminal_before_start(
    tmp_path: Path,
) -> None:
    """The pre-check half of the guard: a session already terminal must be
    refused before the backend is touched at all, so no port is bound."""
    service = _service(tmp_path)
    try:
        session_id = _web_session(service)
        service.registry.transition(session_id, SessionState.FAILED)

        fake = _FakeProxy()
        service._proxy_backend = fake  # type: ignore[assignment]

        result = service.proxy_start(session_id)

        assert not result.ok
        assert result.error is not None
        assert result.error.code == "invalid_request"
        assert fake.started == [], "a terminal session must never reach the backend start"
        assert fake.stopped == []
    finally:
        service.close_all()
