"""Process-owned adb forwards are released the moment the last Android session goes.

``adb forward`` bindings live on the adb server, not in this process: closing a
session does not remove them, and the backend caps the process at
``_MAX_FORWARDS`` (32) so a long-lived agent that forwards frida or a debug port
every run eventually cannot bind another. ``_release_adb_forwards_if_idle`` is
the sweep that keeps that from happening -- it fires on every ``close_session``
-- but it is deliberately gated, and both sides of that gate matter:

* While *any* Android (APK) session is still live, it must NOT release. A running
  frida/gdb session reaches its target over exactly such a forward; tearing it
  down mid-analysis because a *different* session happened to close would break
  live instrumentation with no warning.
* Once the last live APK session is gone, it MUST release, or the forwards leak
  on the adb server until the process exits -- straight toward the 32-forward
  cap that then refuses new binds.

Only ``release_forwards`` itself and the ``close_all`` wiring were pinned before;
the idle gate that decides *whether* to call it was not. These tests pin it, so
a future change to the "what counts as a live Android session" predicate has to
make a deliberate decision rather than silently strand or leak forwards.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

from headless_re_mcp.config import Settings
from headless_re_mcp.core.models import Session, SessionState, TargetKind
from headless_re_mcp.core.service import AnalysisService


def _service(tmp_path: Path) -> tuple[AnalysisService, list[bool]]:
    """A service whose adb backend records each release request instead of running it."""
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    calls: list[bool] = []
    service._adb_backend.release_forwards = (  # type: ignore[method-assign]
        lambda: calls.append(True) or {"removed": [], "failed": [], "count": 0}
    )
    return service, calls


def _adopt(service: AnalysisService, target: TargetKind, state: SessionState) -> None:
    locator = "https://example.com/app" if target is TargetKind.WEB else "/tmp/app.bin"
    service.registry.adopt(Session(target=target, locator=locator, state=state))


def test_no_sessions_at_all_counts_as_idle_and_releases(tmp_path: Path) -> None:
    service, calls = _service(tmp_path)
    try:
        service._release_adb_forwards_if_idle()
        assert calls == [True]
    finally:
        service.close_all()


def test_a_live_apk_session_suppresses_the_release(tmp_path: Path) -> None:
    service, calls = _service(tmp_path)
    try:
        _adopt(service, TargetKind.APK, SessionState.READY)
        service._release_adb_forwards_if_idle()
        assert calls == [], "a live APK session must keep its forwards"
    finally:
        service.close_all()


def test_a_running_apk_session_also_suppresses_the_release(tmp_path: Path) -> None:
    service, calls = _service(tmp_path)
    try:
        _adopt(service, TargetKind.APK, SessionState.RUNNING)
        service._release_adb_forwards_if_idle()
        assert calls == []
    finally:
        service.close_all()


def test_only_terminal_apk_sessions_do_not_hold_forwards(tmp_path: Path) -> None:
    """A closed/failed/closing APK session no longer counts as live -> idle -> release."""
    for terminal in (SessionState.CLOSED, SessionState.FAILED, SessionState.CLOSING):
        service, calls = _service(tmp_path)
        try:
            _adopt(service, TargetKind.APK, terminal)
            service._release_adb_forwards_if_idle()
            assert calls == [True], f"a {terminal.value} APK session must not hold forwards"
        finally:
            service.close_all()


def test_a_live_web_session_does_not_hold_forwards(tmp_path: Path) -> None:
    """Only Android sessions bind adb forwards; a live web session is still idle."""
    service, calls = _service(tmp_path)
    try:
        _adopt(service, TargetKind.WEB, SessionState.READY)
        _adopt(service, TargetKind.PE, SessionState.READY)
        service._release_adb_forwards_if_idle()
        assert calls == [True]
    finally:
        service.close_all()


def test_a_live_apk_session_wins_over_closed_ones(tmp_path: Path) -> None:
    """One live APK session suppresses the release even beside already-closed peers."""
    service, calls = _service(tmp_path)
    try:
        _adopt(service, TargetKind.APK, SessionState.CLOSED)
        _adopt(service, TargetKind.APK, SessionState.READY)
        _adopt(service, TargetKind.WEB, SessionState.READY)
        service._release_adb_forwards_if_idle()
        assert calls == [], "a single live APK session must still hold the forwards"
    finally:
        service.close_all()


def test_a_missing_adb_backend_is_tolerated(tmp_path: Path) -> None:
    """No owned adb backend means nothing to release, and never a crash."""
    service, _calls = _service(tmp_path)
    try:
        service._adb_backend = None  # type: ignore[assignment]
        service._release_adb_forwards_if_idle()
    finally:
        service.close_all()
