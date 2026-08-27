"""A crashed browser must be reported honestly and failed fast, not after 60s.

Measured before the fix, with the driver tree SIGKILLed under an open session:
``status`` answered open=True with the stale url (page.url is served from the
driver-side mirror and _safe_title swallows the roundtrip error); the first
call that did touch the driver blocked for the full _CALL_TIMEOUT (60s),
came back as a generic ``timeout`` and wedged the runner; ``close`` then spent
its 20s bound dispatching teardown at a process that no longer existed. With
Chromium killed under a live driver the client-side flags never flip
(is_connected() still True 4s later) while a title roundtrip fails in ~1ms
with TargetClosedError. The driver pid and that roundtrip are the two health
signals that answer cheaply, so these tests pin the behavior built on them.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.web import client as web_mod
from headless_re_mcp.backends.web.client import WebBackend, WebError, _WebSession
from headless_re_mcp.core.process_tree import pid_still_running


class _RecordingRunner:
    """Runner double that counts dispatches and runs work inline."""

    def __init__(self, *, wedged: bool = False) -> None:
        self.wedged = wedged
        self.calls = 0
        self.shutdowns = 0

    def call(self, work: Any, *, timeout: float | None = None) -> Any:
        self.calls += 1
        return work()

    def shutdown(self) -> None:
        self.shutdowns += 1


class _TargetClosedError(Exception):
    """Same name as playwright's; _target_closed matches by class name."""


class _Page:
    url = "https://example.test/app"

    def __init__(self, *, alive: bool = True) -> None:
        self._alive = alive

    def title(self) -> str:
        if not self._alive:
            raise _TargetClosedError("Page.title: Target page, context or browser has been closed")
        return "example"


class _Dummy:
    def close(self) -> None:
        return None

    def stop(self) -> None:
        return None


def _session(
    backend: WebBackend,
    *,
    page_alive: bool = True,
    driver_pid: int | None = None,
    wedged: bool = False,
) -> tuple[_WebSession, _RecordingRunner]:
    handle = _WebSession(_Dummy(), _Dummy(), _Dummy(), _Page(alive=page_alive), _Dummy())
    handle.driver_pid = driver_pid
    runner = _RecordingRunner(wedged=wedged)
    handle.runner = runner  # type: ignore[assignment]
    backend._sessions["s"] = handle
    return handle, runner


class TestStatusStaysHonest:
    def test_a_dead_driver_reports_exited_without_dispatching(self, monkeypatch: Any) -> None:
        """The pid check must answer from this thread: dispatching would hang."""
        monkeypatch.setattr(web_mod, "pid_still_running", lambda pid: False)
        backend = WebBackend()
        _, runner = _session(backend, driver_pid=4242)
        assert backend.status("s") == {"open": True, "responsive": False, "exited": True}
        assert runner.calls == 0

    def test_a_wedged_runner_reports_unresponsive_instead_of_raising(self) -> None:
        """status is the health probe; it must not need the browser to answer."""
        backend = WebBackend()
        _, runner = _session(backend, wedged=True)
        assert backend.status("s") == {"open": True, "responsive": False, "wedged": True}
        assert runner.calls == 0

    def test_chromium_dying_under_a_live_driver_reports_exited(self) -> None:
        """The title roundtrip is the probe: client-side flags never flip."""
        backend = WebBackend()
        _session(backend, page_alive=False)
        assert backend.status("s") == {"open": True, "responsive": False, "exited": True}

    def test_a_healthy_session_reports_responsive_with_identity(self) -> None:
        backend = WebBackend()
        _session(backend)
        payload = backend.status("s")
        assert payload["open"] is True
        assert payload["responsive"] is True
        assert payload["url"] == "https://example.test/app"
        assert payload["title"] == "example"

    def test_an_ordinary_title_failure_still_reads_as_responsive(self) -> None:
        """Only a closed target flips the flag; a flaky title() must not."""
        backend = WebBackend()
        handle, _ = _session(backend)
        handle.page.title = lambda: (_ for _ in ()).throw(RuntimeError("layout not settled"))  # type: ignore[method-assign]
        payload = backend.status("s")
        assert payload["responsive"] is True
        assert payload["title"] == ""


class TestCallsFailFastAfterACrash:
    @pytest.fixture()
    def dead_driver_backend(self, monkeypatch: Any) -> tuple[WebBackend, _RecordingRunner]:
        monkeypatch.setattr(web_mod, "pid_still_running", lambda pid: False)
        backend = WebBackend()
        _, runner = _session(backend, driver_pid=4242)
        return backend, runner

    def test_dom_snapshot_refuses_immediately_with_invalid_state(
        self, dead_driver_backend: tuple[WebBackend, _RecordingRunner]
    ) -> None:
        backend, runner = dead_driver_backend
        with pytest.raises(WebError) as info:
            backend.dom_snapshot("s")
        assert info.value.code == "invalid_state"
        assert "exited" in info.value.message
        assert runner.calls == 0

    def test_navigate_refuses_immediately_with_invalid_state(
        self, dead_driver_backend: tuple[WebBackend, _RecordingRunner]
    ) -> None:
        backend, runner = dead_driver_backend
        with pytest.raises(WebError) as info:
            backend.navigate("s", "https://example.test/next")
        assert info.value.code == "invalid_state"
        assert runner.calls == 0

    def test_buffered_telemetry_stays_readable_after_the_crash(
        self, dead_driver_backend: tuple[WebBackend, _RecordingRunner]
    ) -> None:
        """Captured requests/console/scripts are this session's evidence; a
        dead browser must not take the already-collected data with it."""
        backend, _ = dead_driver_backend
        handle = backend._sessions["s"]
        with handle.lock:
            handle.requests["1"] = {"requestId": "1", "url": "https://example.test/x"}
        assert backend.network_list("s")["total"] == 1
        assert backend.console("s")["count"] == 0
        assert backend.scripts("s")["total"] == 0


class TestCloseRecoversFastAfterACrash:
    def test_close_skips_the_dead_driver_and_reaps_instead(self, monkeypatch: Any) -> None:
        """Dispatching teardown at a dead driver costs the 20s bound for nothing."""
        monkeypatch.setattr(web_mod, "pid_still_running", lambda pid: False)
        reaped: list[int | None] = []
        monkeypatch.setattr(
            web_mod, "_reap_web_session", lambda handle: reaped.append(handle.driver_pid)
        )
        backend = WebBackend()
        _, runner = _session(backend, driver_pid=4242)
        payload = backend.close("s")
        assert payload == {"closed": True, "clean": False}
        assert runner.calls == 0
        assert reaped == [4242]
        assert runner.shutdowns == 1

    def test_close_of_a_healthy_session_still_tears_down_on_the_runner(self) -> None:
        backend = WebBackend()
        _, runner = _session(backend)
        payload = backend.close("s")
        assert payload == {"closed": True, "clean": True}
        assert runner.calls == 1


class TestOpenReplacesACrashedSession:
    """proxy.start replaces a crashed proxy; web.open owed the same recovery.

    Before this, a session whose driver died answered "web session already
    open" to the one call that could bring it back, while status said exited
    -- two tools contradicting each other about the same corpse. Only an
    unambiguously dead driver is replaced: a wedged-but-alive browser still
    holds real processes that close() knows how to reap first.
    """

    @staticmethod
    def _stub_playwright(monkeypatch: Any) -> None:
        import types

        pkg = types.ModuleType("playwright")
        api = types.ModuleType("playwright.sync_api")
        api.sync_playwright = lambda: None  # type: ignore[attr-defined]
        pkg.sync_api = api  # type: ignore[attr-defined]
        monkeypatch.setitem(sys.modules, "playwright", pkg)
        monkeypatch.setitem(sys.modules, "playwright.sync_api", api)

    def test_open_reaps_and_replaces_a_dead_driver_session(self, monkeypatch: Any) -> None:
        monkeypatch.setattr(web_mod, "pid_still_running", lambda pid: False)
        reaped: list[int | None] = []
        monkeypatch.setattr(
            web_mod, "_reap_web_session", lambda handle: reaped.append(handle.driver_pid)
        )
        self._stub_playwright(monkeypatch)
        backend = WebBackend()
        backend._available = True
        _, stale_runner = _session(backend, driver_pid=4242)

        new_handle = _WebSession(_Dummy(), _Dummy(), _Dummy(), _Page(), _Dummy())

        class _FakeRunner:
            def __init__(self, name: str) -> None:
                self.wedged = False

            def call(self, work: Any, *, timeout: float | None = None) -> Any:
                return new_handle, {"opened": True, "url": _Page.url, "headless": True}

            def shutdown(self) -> None:
                return None

        monkeypatch.setattr(web_mod, "_Runner", _FakeRunner)

        payload = backend.open("s", "https://example.test/app")
        assert payload["opened"] is True
        assert backend._sessions["s"] is new_handle
        assert stale_runner.shutdowns == 1
        assert reaped == [4242]

    def test_open_still_refuses_a_live_session(self) -> None:
        backend = WebBackend()
        backend._available = True
        _session(backend)
        with pytest.raises(WebError) as info:
            backend.open("s", "https://example.test/app")
        assert info.value.code == "invalid_state"
        assert "already open" in info.value.message

    def test_open_still_refuses_a_wedged_but_alive_session(self) -> None:
        backend = WebBackend()
        backend._available = True
        _session(backend, wedged=True)
        with pytest.raises(WebError) as info:
            backend.open("s", "https://example.test/app")
        assert info.value.code == "invalid_state"


@pytest.mark.skipif(os.name == "nt", reason="pins the POSIX branch; NT had one already")
class TestImageGatedReapWorksOnPosix:
    """process_image_path returned None on POSIX, so _reap_driver_pid matched no
    marker and a wedged web session leaked its node driver plus the Chromium
    tree -- the exact leak the reap was built to stop. The existing wedged-close
    test monkeypatched a Windows image path, which is how this stayed green."""

    def test_process_image_path_answers_for_an_own_child(self) -> None:
        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
        try:
            image = web_mod.process_image_path(child.pid)
            assert image is not None
            assert Path(image).name == Path(os.readlink(f"/proc/{child.pid}/exe")).name
        finally:
            child.kill()
            child.wait()
        assert web_mod.process_image_path(child.pid) is None

    def test_reap_driver_pid_kills_a_marker_matching_tree(self, tmp_path: Path) -> None:
        """A binary whose name carries a driver marker must actually be swept."""
        fake_node = tmp_path / "node-helper"
        shutil.copy2(sys.executable, fake_node)
        child = subprocess.Popen([str(fake_node), "-c", "import time; time.sleep(30)"])
        try:
            web_mod._reap_driver_pid(child.pid)
            deadline = time.monotonic() + 5.0
            while pid_still_running(child.pid) and time.monotonic() < deadline:
                time.sleep(0.02)
            assert pid_still_running(child.pid) is False
        finally:
            child.kill()
            child.wait()

    def test_reap_driver_pid_refuses_an_unrecognized_image(self) -> None:
        """Identity-gated kills stay fail-closed: a pid whose image carries no
        driver marker (here: plain python) must be left alone."""
        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
        try:
            web_mod._reap_driver_pid(child.pid)
            time.sleep(0.2)
            assert pid_still_running(child.pid) is True
        finally:
            child.kill()
            child.wait()


class TestPidStillRunning:
    def test_an_exited_process_reads_as_gone_and_a_live_one_does_not(self) -> None:
        live = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(30)"],
        )
        try:
            assert pid_still_running(live.pid) is True
        finally:
            live.kill()
            live.wait()
        done = subprocess.Popen([sys.executable, "-c", "pass"])
        done.wait()
        deadline = time.monotonic() + 5.0
        while pid_still_running(done.pid) and time.monotonic() < deadline:
            time.sleep(0.02)
        assert pid_still_running(done.pid) is False
