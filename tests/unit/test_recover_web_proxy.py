"""session.recover must rebuild web and proxy backends, not just PE workers.

Recovery used to be PE-only: the tool pattern rejected "web"/"proxy" outright
and the default path only considered ida/x64dbg, so the one deliberate
recovery verb answered "nothing to do" about a session whose browser was a
corpse. These tests pin the extension: a crashed browser reopens at the
session locator, a crashed proxy rebinds its old endpoint, healthy instances
are kept untouched, and unknown kinds are still rejected.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

from headless_re_mcp.backends.web import client as web_mod
from headless_re_mcp.backends.web.client import _WebSession
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService

_DEAD_PID = 666
_LIVE_PID = 4242


class _Dummy:
    def close(self) -> None:
        return None

    def stop(self) -> None:
        return None


def _service(tmp_path: Path) -> AnalysisService:
    return AnalysisService(
        Settings(
            ida_home=None,
            x64dbg_source=None,
            x64dbg_headless_x64=None,
            x64dbg_headless_x86=None,
            artifact_root=tmp_path / "artifacts",
        )
    )


def _web_session(service: AnalysisService) -> str:
    created = service.create_session("data:text/html,<title>t</title>x", target="web")
    assert created.ok and created.data is not None
    session = created.data["session"]
    assert isinstance(session, dict)
    return str(session["id"])


def _web_handle(*, driver_pid: int | None, wedged: bool = False) -> _WebSession:
    handle = _WebSession(_Dummy(), _Dummy(), _Dummy(), _Dummy(), _Dummy())
    handle.driver_pid = driver_pid
    handle.runner = SimpleNamespace(wedged=wedged)  # type: ignore[assignment]
    return handle


def _crashed_proxy(*, host: str = "127.0.0.1", port: int = 9099) -> Any:
    return SimpleNamespace(
        is_alive=lambda: False,
        crashed_after_start=lambda: True,
        exit_reason=lambda: "Event loop is closed",
        host=host,
        port=port,
        recorder=SimpleNamespace(count=lambda: 7),
    )


def _mark_dead_pid(monkeypatch: Any) -> None:
    monkeypatch.setattr(web_mod, "pid_still_running", lambda pid: pid != _DEAD_PID)


def test_default_recover_reopens_a_crashed_browser(
    tmp_path: Path, monkeypatch: Any
) -> None:
    _mark_dead_pid(monkeypatch)
    service = _service(tmp_path)
    session_id = _web_session(service)
    service._web_backend._sessions[session_id] = _web_handle(driver_pid=_DEAD_PID)

    calls: list[tuple[str, str]] = []
    service.web_close = lambda sid: (  # type: ignore[method-assign]
        calls.append(("close", sid)),
        SimpleNamespace(ok=True, error=None),
    )[1]
    service.web_open = lambda sid, url="": (  # type: ignore[method-assign]
        calls.append(("open", sid)),
        SimpleNamespace(ok=True, error=None),
    )[1]

    result = service.session_recover(session_id)

    assert result.ok and result.data is not None
    assert result.data["requested"] == ["web"]
    assert result.data["recovered"] == 1
    assert result.data["failed"] == 0
    entry = result.data["backends"][0]
    assert entry == {"backend": "web", "action": "reopened", "ok": True}
    assert calls == [("close", session_id), ("open", session_id)]


def test_recover_keeps_a_healthy_browser_untouched(
    tmp_path: Path, monkeypatch: Any
) -> None:
    _mark_dead_pid(monkeypatch)
    service = _service(tmp_path)
    session_id = _web_session(service)
    service._web_backend._sessions[session_id] = _web_handle(driver_pid=_LIVE_PID)

    touched: list[str] = []
    service.web_open = lambda sid, url="": (  # type: ignore[method-assign]
        touched.append(sid),
        SimpleNamespace(ok=True, error=None),
    )[1]

    result = service.session_recover(session_id, ["web"])

    assert result.ok and result.data is not None
    assert result.data["kept"] == 1
    assert result.data["recovered"] == 0
    assert touched == []


def test_a_wedged_browser_is_recovered_through_close_then_open(
    tmp_path: Path, monkeypatch: Any
) -> None:
    _mark_dead_pid(monkeypatch)
    service = _service(tmp_path)
    session_id = _web_session(service)
    service._web_backend._sessions[session_id] = _web_handle(
        driver_pid=_LIVE_PID, wedged=True
    )

    calls: list[str] = []
    service.web_close = lambda sid: (  # type: ignore[method-assign]
        calls.append("close"),
        SimpleNamespace(ok=True, error=None),
    )[1]
    service.web_open = lambda sid, url="": (  # type: ignore[method-assign]
        calls.append("open"),
        SimpleNamespace(ok=True, error=None),
    )[1]

    result = service.session_recover(session_id, ["web"])

    assert result.ok and result.data is not None
    assert result.data["recovered"] == 1
    assert calls == ["close", "open"]


def test_default_recover_restarts_a_crashed_proxy_on_its_old_endpoint(
    tmp_path: Path,
) -> None:
    service = _service(tmp_path)
    session_id = _web_session(service)
    service._proxy_backend._instances[session_id] = _crashed_proxy(port=9099)

    starts: list[dict[str, Any]] = []
    service.proxy_start = lambda sid, **kwargs: (  # type: ignore[method-assign]
        starts.append({"session_id": sid, **kwargs}),
        SimpleNamespace(ok=True, error=None),
    )[1]

    result = service.session_recover(session_id)

    assert result.ok and result.data is not None
    assert result.data["requested"] == ["proxy"]
    assert result.data["recovered"] == 1
    assert starts == [{"session_id": session_id, "host": "127.0.0.1", "port": 9099}]


def test_a_failed_web_reopen_fails_the_recovery_envelope(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """Recovery that did not recover must not answer ok: callers that only
    read the envelope used to keep issuing calls against a dead backend."""
    _mark_dead_pid(monkeypatch)
    service = _service(tmp_path)
    session_id = _web_session(service)
    service._web_backend._sessions[session_id] = _web_handle(driver_pid=_DEAD_PID)

    service.web_close = lambda sid: SimpleNamespace(ok=True, error=None)  # type: ignore[method-assign]
    error = SimpleNamespace(
        model_dump=lambda mode="json": {"code": "backend_error", "message": "no chromium"}
    )
    service.web_open = lambda sid, url="": SimpleNamespace(ok=False, error=error)  # type: ignore[method-assign]

    result = service.session_recover(session_id)

    assert not result.ok
    assert result.data is not None
    assert result.data["failed"] == 1
    entry = result.data["backends"][0]
    assert entry["ok"] is False
    assert entry["error"]["code"] == "backend_error"


def test_unknown_backend_names_are_still_rejected(tmp_path: Path) -> None:
    service = _service(tmp_path)
    session_id = _web_session(service)

    result = service.session_recover(session_id, ["frida"])

    assert not result.ok
    assert result.error is not None
    assert "web, proxy" in result.error.message


def test_a_session_with_no_web_or_proxy_requests_nothing_by_default(
    tmp_path: Path,
) -> None:
    """The liveness enumerations must not invent rows for other sessions."""
    service = _service(tmp_path)
    session_id = _web_session(service)
    service._proxy_backend._instances["someone-else"] = _crashed_proxy()

    result = service.session_recover(session_id)

    assert result.ok and result.data is not None
    assert result.data["requested"] == []
    assert result.data["backends"] == []
