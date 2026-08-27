"""session.health must see browser and proxy sessions, not just PE workers.

Web and proxy sessions never register a worker runtime, so the health report
was built only from the worker monitor and answered ``backends: []`` for them
no matter how dead the browser was. The one tool an unattended caller polls to
decide whether to intervene stayed blind to two whole target kinds while
web.status and proxy.status knew the truth. These tests pin the passive rows
that close that gap: a pid check and a thread flag, never an RPC into the
thing being reported on.
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


class _FakeRunner:
    def __init__(self, *, wedged: bool = False) -> None:
        self.wedged = wedged


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


def _web_handle(*, driver_pid: int | None, wedged: bool = False) -> _WebSession:
    handle = _WebSession(_Dummy(), _Dummy(), _Dummy(), _Dummy(), _Dummy())
    handle.driver_pid = driver_pid
    handle.runner = _FakeRunner(wedged=wedged)  # type: ignore[assignment]
    return handle


def _proxy_instance(*, alive: bool, crashed: bool, reason: str | None = None) -> Any:
    return SimpleNamespace(
        is_alive=lambda: alive,
        crashed_after_start=lambda: crashed,
        exit_reason=lambda: reason,
    )


def _rows_by_backend(result: Any) -> dict[str, dict[str, Any]]:
    assert result.ok and result.data is not None
    return {row["backend"]: row for row in result.data["backends"]}


def _mark_dead_pid(monkeypatch: Any) -> None:
    monkeypatch.setattr(web_mod, "pid_still_running", lambda pid: pid != _DEAD_PID)


def test_web_and_proxy_rows_join_the_health_report(
    tmp_path: Path, monkeypatch: Any
) -> None:
    _mark_dead_pid(monkeypatch)
    service = _service(tmp_path)
    service._web_backend._sessions["s-web"] = _web_handle(driver_pid=_LIVE_PID)
    service._proxy_backend._instances["s-proxy"] = _proxy_instance(
        alive=False, crashed=True, reason="Event loop is closed"
    )

    result = service.session_health()
    rows = _rows_by_backend(result)

    web_row = rows["web"]
    assert web_row["session_id"] == "s-web"
    assert web_row["worker_alive"] is True
    assert web_row["healthy"] is True
    assert web_row["last_error"] is None

    proxy_row = rows["proxy"]
    assert proxy_row["session_id"] == "s-proxy"
    assert proxy_row["worker_alive"] is False
    assert proxy_row["healthy"] is False
    assert proxy_row["last_error"] == "Event loop is closed"

    assert result.data is not None
    assert result.data["healthy"] is False


def test_a_dead_browser_flips_the_unified_verdict_and_names_the_fix(
    tmp_path: Path, monkeypatch: Any
) -> None:
    _mark_dead_pid(monkeypatch)
    service = _service(tmp_path)
    service._web_backend._sessions["s-web"] = _web_handle(driver_pid=_DEAD_PID)

    result = service.session_health()
    row = _rows_by_backend(result)["web"]

    assert row["worker_alive"] is False
    assert row["connected"] is False
    assert "web.open" in str(row["last_error"])
    assert result.data is not None
    assert result.data["healthy"] is False


def test_a_wedged_browser_reads_alive_but_disconnected(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A wedged runner is exactly a live worker with an unusable pipe, so it
    maps onto the monitor's existing vocabulary instead of inventing a new
    field the watchdog would not know how to read."""
    _mark_dead_pid(monkeypatch)
    service = _service(tmp_path)
    service._web_backend._sessions["s-web"] = _web_handle(
        driver_pid=_LIVE_PID, wedged=True
    )

    row = _rows_by_backend(service.session_health())["web"]

    assert row["worker_alive"] is True
    assert row["connected"] is False
    assert row["healthy"] is False
    assert "web.close" in str(row["last_error"])


def test_a_crashed_proxy_without_a_stored_reason_still_names_the_fix(
    tmp_path: Path,
) -> None:
    service = _service(tmp_path)
    service._proxy_backend._instances["s-proxy"] = _proxy_instance(
        alive=False, crashed=True, reason=None
    )

    row = _rows_by_backend(service.session_health())["proxy"]

    assert row["healthy"] is False
    assert "proxy.start" in str(row["last_error"])


def test_the_session_filter_excludes_other_sessions_rows(
    tmp_path: Path, monkeypatch: Any
) -> None:
    _mark_dead_pid(monkeypatch)
    service = _service(tmp_path)
    binary = tmp_path / "sample.exe"
    _write_minimal_pe(binary)
    created = service.create_session(str(binary))
    assert created.ok and created.data is not None
    session = created.data["session"]
    assert isinstance(session, dict)
    session_id = str(session["id"])

    service._web_backend._sessions[session_id] = _web_handle(driver_pid=_LIVE_PID)
    service._proxy_backend._instances["someone-else"] = _proxy_instance(
        alive=False, crashed=True, reason="boom"
    )

    result = service.session_health(session_id)
    rows = _rows_by_backend(result)

    assert set(rows) == {"web"}
    assert rows["web"]["session_id"] == session_id


def test_in_flight_registrations_are_not_health_subjects(
    tmp_path: Path,
) -> None:
    """An opening reservation and a proxy still inside start() belong to the
    call that is holding them; reporting them dead would page an operator
    about a launch that has not finished."""
    service = _service(tmp_path)
    service._web_backend._sessions["s-web"] = object()  # type: ignore[assignment]
    service._proxy_backend._instances["s-proxy"] = _proxy_instance(
        alive=False, crashed=False
    )

    result = service.session_health()

    assert result.ok and result.data is not None
    assert result.data["backends"] == []
    assert result.data["healthy"] is None


def _write_minimal_pe(path: Path, machine: int = 0x8664) -> None:
    image = bytearray(0x200)
    image[:2] = b"MZ"
    image[0x3C:0x40] = (0x80).to_bytes(4, "little")
    image[0x80:0x84] = b"PE\0\0"
    image[0x84:0x86] = machine.to_bytes(2, "little")
    path.write_bytes(image)
