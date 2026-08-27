"""Properties that decide whether an unattended run survives the night.

Everything here is about time, not about features: buffers that grow with the
capture, state written from one thread and read from another, and success
reported before the thing actually works. These only fail after hours of real
use, so they are asserted directly instead of being left to a soak test.
"""

from __future__ import annotations

import os
import threading
from collections import OrderedDict
from typing import Any

import pytest

from headless_re_mcp.backends.proxy.client import _FlowRecorder, _port_accepts
from headless_re_mcp.backends.web.client import _MAX_SCRIPTS, _WebSession
from headless_re_mcp.core.service_frida import _MAX_AUTHORIZED, _append_recent


class _FakeHeaders(dict):  # type: ignore[type-arg]
    def get(self, key: str, default: str = "") -> str:
        return dict.get(self, key, default)


class _FakeFlow:
    """Stands in for a mitmproxy flow, including a body worth evicting."""

    def __init__(self, index: int, body_bytes: int = 1024) -> None:
        self.id = f"flow-{index}"
        self.request = type(
            "Req",
            (),
            {
                "method": "GET",
                "pretty_url": f"https://example.com/{index}",
                "host": "example.com",
            },
        )()
        self.response = type(
            "Resp",
            (),
            {"status_code": 200, "headers": _FakeHeaders({"content-type": "text/plain"})},
        )()
        self.payload = b"x" * body_bytes


class TestProxyCaptureIsBounded:
    def test_raw_flows_are_evicted_in_lockstep_with_summaries(self) -> None:
        """The raw ring holds whole flows; unbounded, it is an overnight OOM."""
        recorder = _FlowRecorder(capacity=10)
        for index in range(500):
            recorder.response(_FakeFlow(index))

        assert recorder.count() == 10
        assert len(recorder._raw) == 10

        # The two views must agree: every summarised flow is still retrievable,
        # and nothing outside the window is retained.
        summarised = {item["id"] for item in recorder.snapshot()}
        assert set(recorder._raw) == summarised
        assert recorder.raw("flow-499") is not None
        assert recorder.raw("flow-0") is None

    def test_a_huge_body_is_not_kept_in_the_raw_ring(self, monkeypatch: Any) -> None:
        from headless_re_mcp.backends.proxy import client as mod

        monkeypatch.setattr(mod, "_MAX_STORED_BODY", 8)

        class Huge:
            def __init__(self) -> None:
                self.id = "huge"
                self.request = type(
                    "Req",
                    (),
                    {"method": "GET", "pretty_url": "http://x", "host": "x"},
                )()
                self.response = type(
                    "Resp",
                    (),
                    {
                        "status_code": 200,
                        "headers": _FakeHeaders(
                            {"content-type": "application/octet-stream"}
                        ),
                        "raw_content": b"x" * 9,
                    },
                )()

        recorder = mod._FlowRecorder(capacity=4)
        recorder.response(Huge())
        assert recorder.raw("huge") is mod._OMITTED_BODY
        row = recorder.snapshot()[0]
        assert row["body_omitted"] is True
        assert recorder.count() == 1

    def test_total_raw_flow_bytes_evict_old_bodies_before_memory_grows(
        self, monkeypatch: Any
    ) -> None:
        from headless_re_mcp.backends.proxy import client as mod

        monkeypatch.setattr(mod, "_MAX_STORED_BODY", 2000)
        monkeypatch.setattr(mod, "_MAX_RETAINED_BYTES", 1000)
        recorder = mod._FlowRecorder(capacity=10)
        first = _FakeFlow(1)
        second = _FakeFlow(2)
        first.response.raw_content = b"x" * 600
        second.response.raw_content = b"y" * 600

        recorder.response(first)
        recorder.response(second)

        assert recorder.raw("flow-1") is mod._OMITTED_BODY
        assert recorder.raw("flow-2") is second
        assert recorder.retained_bytes() <= 1000
        assert recorder.snapshot()[0]["body_omitted"] is True

    def test_proxy_summary_metadata_is_byte_bounded(self) -> None:
        from headless_re_mcp.backends.proxy import client as mod

        flow = _FakeFlow(1)
        flow.request.pretty_url = "é" * mod._MAX_URL_BYTES
        flow.request.method = "é" * mod._MAX_METADATA_BYTES
        flow.request.host = "é" * mod._MAX_METADATA_BYTES
        flow.response.headers["content-type"] = "é" * mod._MAX_METADATA_BYTES
        recorder = mod._FlowRecorder(capacity=2)

        recorder.response(flow)

        row = recorder.snapshot()[0]
        assert len(str(row["url"]).encode()) <= mod._MAX_URL_BYTES
        assert len(str(row["method"]).encode()) <= mod._MAX_METADATA_BYTES
        assert len(str(row["host"]).encode()) <= mod._MAX_METADATA_BYTES
        assert len(str(row["content_type"]).encode()) <= mod._MAX_METADATA_BYTES
        assert row["metadata_truncated"] is True

    def test_sequence_numbers_keep_counting_past_the_window(self) -> None:
        recorder = _FlowRecorder(capacity=5)
        for index in range(20):
            recorder.response(_FakeFlow(index))
        assert [item["seq"] for item in recorder.snapshot()] == [16, 17, 18, 19, 20]

    def test_evicted_flows_are_disclosed_on_the_list(self) -> None:
        from headless_re_mcp.backends.proxy.client import ProxyBackend, _ProxyInstance

        inst = _ProxyInstance("127.0.0.1", 1)
        inst.recorder = _FlowRecorder(capacity=5)
        for index in range(20):
            inst.recorder.response(_FakeFlow(index))
        backend = ProxyBackend()
        backend._instances["s"] = inst
        result = backend.flows("s", offset=0, limit=100)
        assert result["total"] == 5
        assert result["dropped"] == 15
        assert result["has_more"] is False

    def test_a_wrapped_ring_reports_how_many_flows_were_dropped(self) -> None:
        from headless_re_mcp.backends.proxy.client import ProxyBackend, _ProxyInstance

        recorder = _FlowRecorder(capacity=5)
        for index in range(20):
            recorder.response(_FakeFlow(index))
        backend = ProxyBackend()
        inst = _ProxyInstance("127.0.0.1", 1)
        inst.recorder = recorder
        backend._instances["s"] = inst
        result = backend.flows("s", offset=0, limit=2)
        assert result["dropped"] == 15
        assert result["total"] == 5
        assert result["count"] == 2
        assert result["has_more"] is True

    def test_concurrent_writers_and_readers_stay_consistent(self) -> None:
        """mitmproxy writes from its loop thread while tools read from workers."""
        recorder = _FlowRecorder(capacity=50)
        errors: list[BaseException] = []
        stop = threading.Event()

        def writer(base: int) -> None:
            try:
                for index in range(300):
                    recorder.response(_FakeFlow(base + index))
            except BaseException as exc:  # noqa: BLE001 - recorded, then asserted
                errors.append(exc)

        def reader() -> None:
            try:
                while not stop.is_set():
                    for item in recorder.snapshot():
                        recorder.raw(str(item["id"]))
            except BaseException as exc:  # noqa: BLE001
                errors.append(exc)

        writers = [threading.Thread(target=writer, args=(i * 1000,)) for i in range(4)]
        readers = [threading.Thread(target=reader) for _ in range(2)]
        for thread in readers:
            thread.start()
        for thread in writers:
            thread.start()
        for thread in writers:
            thread.join()
        stop.set()
        for thread in readers:
            thread.join()

        assert errors == []
        assert recorder.count() == 50
        assert len(recorder._raw) == 50
        # Every write incremented the sequence exactly once.
        assert recorder._seq == 4 * 300


class TestProxyStartHonesty:
    def test_port_probe_reports_false_for_a_closed_port(self) -> None:
        # Port 1 on loopback is not something this test suite ever binds.
        assert _port_accepts("127.0.0.1", 1, timeout=0.1) is False

    def test_port_probe_reports_true_for_a_listening_socket(self) -> None:
        import socket

        server = socket.socket()
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        try:
            assert _port_accepts("127.0.0.1", server.getsockname()[1], timeout=1.0) is True
        finally:
            server.close()

    def test_a_holder_that_never_accepts_is_still_a_taken_port(self) -> None:
        """The connect probe answers "is anyone serving", not "is it free".

        A socket bound without ``listen``, or a listener whose backlog is full,
        reads as free. Starting mitmproxy there costs the whole readiness
        timeout and leaves a half-built proxy behind, for an answer that was
        available before the thread was ever created.
        """
        import socket
        import time

        from headless_re_mcp.backends.proxy.client import (
            ProxyError,
            _port_bindable,
            _ProxyInstance,
        )

        holder = socket.socket()
        holder.bind(("127.0.0.1", 0))
        port = holder.getsockname()[1]
        try:
            assert _port_accepts("127.0.0.1", port, timeout=0.2) is False
            assert _port_bindable("127.0.0.1", port) is False

            instance = _ProxyInstance("127.0.0.1", port)
            started = time.monotonic()
            with pytest.raises(ProxyError) as caught:
                instance.start()
            assert caught.value.code == "invalid_state"
            assert time.monotonic() - started < 2.0
            # Refused before anything was built, so there is nothing to reclaim.
            assert instance._thread is None
            assert instance._master is None
        finally:
            holder.close()

    def test_a_free_port_is_reported_bindable(self) -> None:
        import socket

        from headless_re_mcp.backends.proxy.client import _port_bindable

        probe = socket.socket()
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
        probe.close()
        assert _port_bindable("127.0.0.1", port) is True

    def test_startup_only_catches_signature_mismatches_at_construction(self) -> None:
        """A TypeError from a running proxy must not start a second master."""
        import inspect

        from headless_re_mcp.backends.proxy import client as proxy_client

        source = inspect.getsource(proxy_client._ProxyInstance._run)
        # The narrow retry wraps the constructor only; run() is outside it.
        assert "except TypeError:" in source
        constructor_retry = source.index("except TypeError:")
        run_call = source.index("master.run()")
        assert run_call > constructor_retry
        assert not hasattr(proxy_client._ProxyInstance, "_run_fallback")


class TestFailedProxyStartLeavesNothingBehind:
    """mitmproxy installs a root-logger handler in ``Master.__init__``.

    It is removed in ``Master.done()``, which only a normal shutdown reaches. A
    startup that fails leaves the handler on the root logger holding the master,
    its addons and every captured flow -- and from then on every log record
    anywhere in the process is dispatched into a closed event loop.
    """

    def _fake_master(self, loop: Any) -> tuple[Any, Any]:
        import logging

        class _Handler(logging.Handler):
            def __init__(self, master: Any) -> None:
                super().__init__()
                self.master = master

            def emit(self, record: logging.LogRecord) -> None:
                raise RuntimeError("Event loop is closed")

            def uninstall(self) -> None:
                logging.getLogger().removeHandler(self)

        class _Master:
            def __init__(self) -> None:
                self.event_loop = loop

        master = _Master()
        handler = _Handler(master)
        master._legacy_log_events = handler  # type: ignore[attr-defined]
        return master, handler

    def test_the_handler_is_removed_by_master_identity(self) -> None:
        import logging

        from headless_re_mcp.backends.proxy.client import _uninstall_master_logging

        master, handler = self._fake_master(object())
        logging.getLogger().addHandler(handler)
        try:
            _uninstall_master_logging(master)
            assert handler not in logging.getLogger().handlers
        finally:
            logging.getLogger().removeHandler(handler)

    def test_a_master_nothing_can_reach_is_still_removed_by_loop(self) -> None:
        """The constructor installs before it can fail, so the caller may never
        get a reference to the master it has to clean up."""
        import logging

        from headless_re_mcp.backends.proxy.client import _uninstall_master_logging

        loop = object()
        _, handler = self._fake_master(loop)
        logging.getLogger().addHandler(handler)
        try:
            _uninstall_master_logging(None, loop)
            assert handler not in logging.getLogger().handlers
        finally:
            logging.getLogger().removeHandler(handler)

    def test_unrelated_handlers_are_left_alone(self) -> None:
        import logging

        from headless_re_mcp.backends.proxy.client import _uninstall_master_logging

        mine, _ = self._fake_master(object())
        other = logging.NullHandler()
        logging.getLogger().addHandler(other)
        try:
            _uninstall_master_logging(mine, object())
            assert other in logging.getLogger().handlers
        finally:
            logging.getLogger().removeHandler(other)


class TestProxyStopReleasesTheListeningSocket:
    """mitmproxy has no Done hook that closes the proxy server, and closing the
    event loop does not close the socket it opened. Run in process, stop() has
    to reconfigure the server set to empty (mitmproxy's own teardown path) or
    the port stays bound until the whole process exits and the next capture can
    never rebind it. The live gate proves the port frees; these pin the contract
    without a real mitmproxy so a refactor cannot quietly drop the teardown.
    """

    @staticmethod
    def _running_loop() -> tuple[Any, Any]:
        import asyncio
        import threading

        loop = asyncio.new_event_loop()
        ready = threading.Event()

        def run() -> None:
            asyncio.set_event_loop(loop)
            loop.call_soon(ready.set)
            loop.run_forever()

        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        assert ready.wait(2.0)
        return loop, thread

    @staticmethod
    def _stop_loop(loop: Any, thread: Any) -> None:
        loop.call_soon_threadsafe(loop.stop)
        thread.join(2.0)
        loop.close()

    def _proxyserver_master(self, calls: list[list[Any]]) -> Any:
        from types import SimpleNamespace

        async def update(modes: Any) -> None:
            calls.append(list(modes))

        servers = SimpleNamespace(update=update)
        proxyserver = SimpleNamespace(servers=servers)
        return SimpleNamespace(
            addons=SimpleNamespace(
                get=lambda name: proxyserver if name == "proxyserver" else None
            )
        )

    def test_close_servers_reconfigures_the_server_set_to_empty(self) -> None:
        from headless_re_mcp.backends.proxy.client import _close_proxy_servers

        calls: list[list[Any]] = []
        loop, thread = self._running_loop()
        try:
            _close_proxy_servers(self._proxyserver_master(calls), loop, timeout=5.0)
        finally:
            self._stop_loop(loop, thread)
        assert calls == [[]], "stop must tell mitmproxy to drop every server"

    def test_close_servers_is_a_noop_without_the_addon(self) -> None:
        from types import SimpleNamespace

        from headless_re_mcp.backends.proxy.client import _close_proxy_servers

        loop, thread = self._running_loop()
        try:
            foreign = SimpleNamespace(addons=SimpleNamespace(get=lambda name: None))
            # A shape this does not recognise must fall through, not raise.
            _close_proxy_servers(foreign, loop, timeout=1.0)
        finally:
            self._stop_loop(loop, thread)

    def test_close_servers_skips_a_loop_that_is_not_running(self) -> None:
        import asyncio

        from headless_re_mcp.backends.proxy.client import _close_proxy_servers

        calls: list[list[Any]] = []
        loop = asyncio.new_event_loop()
        try:
            # A stopped loop can never run the coroutine; returning at once beats
            # blocking out the whole timeout for an answer already available.
            _close_proxy_servers(self._proxyserver_master(calls), loop, timeout=5.0)
        finally:
            loop.close()
        assert calls == []

    def test_stop_closes_servers_before_it_shuts_the_master_down(self) -> None:
        """Order matters: once should_exit is set the loop unwinds and closes,
        so the server teardown has to run while the loop is still alive."""
        import inspect

        from headless_re_mcp.backends.proxy import client as proxy_client

        source = inspect.getsource(proxy_client._ProxyInstance.stop)
        assert "_close_proxy_servers(" in source
        assert source.index("_close_proxy_servers(") < source.index("master.shutdown")


class TestProxyMasterSurvivesLifeAsAnEmbeddedProxy:
    """DumpMaster ships mitmdump's CLI addons, and each of them can kill a
    healthy in-process capture: keepserving/readfilestdin read the shared
    ``ctx.options.rfile`` in their running() hook (which crashes when another
    master is mid-construction and ctx points at its half-built Options), and
    errorcheck installs a process-wide ERROR-level root handler that
    ``sys.exit(1)``s the master when *anything* in the process logs an error
    during its startup window. These pin that the client strips all three and
    serializes the hazardous construction-to-running window across masters.
    """

    def _dump_master(self, removed: list[str], finished: list[str]) -> Any:
        from types import SimpleNamespace

        class _ErrorCheck:
            def finish(self) -> None:
                finished.append("errorcheck")

        addons = {
            "keepserving": SimpleNamespace(),
            "readfilestdin": SimpleNamespace(),
            "errorcheck": _ErrorCheck(),
            "proxyserver": SimpleNamespace(),
        }

        def remove(addon: Any) -> None:
            for name, known in list(addons.items()):
                if known is addon:
                    removed.append(name)
                    del addons[name]

        return SimpleNamespace(
            addons=SimpleNamespace(get=addons.get, remove=remove)
        )

    def test_strip_removes_every_cli_addon_and_detaches_errorchecks_handler(
        self,
    ) -> None:
        from headless_re_mcp.backends.proxy.client import _strip_dump_cli_addons

        removed: list[str] = []
        finished: list[str] = []
        master = self._dump_master(removed, finished)
        _strip_dump_cli_addons(master)
        assert sorted(removed) == ["errorcheck", "keepserving", "readfilestdin"]
        # errorcheck's root-logger handler is installed in its constructor and
        # only Master.run() would detach it; once the addon is removed, the
        # strip has to do that or the handler leaks for the process lifetime.
        assert finished == ["errorcheck"]

    def test_strip_leaves_the_proxyserver_alone(self) -> None:
        from headless_re_mcp.backends.proxy.client import _strip_dump_cli_addons

        removed: list[str] = []
        master = self._dump_master(removed, [])
        _strip_dump_cli_addons(master)
        assert "proxyserver" not in removed

    def test_strip_tolerates_a_master_without_the_cli_addons(self) -> None:
        from types import SimpleNamespace

        from headless_re_mcp.backends.proxy.client import _strip_dump_cli_addons

        # A future mitmproxy that no longer bundles these addons must not make
        # startup raise; the strip is defense, not a requirement.
        lean = SimpleNamespace(addons=SimpleNamespace(get=lambda name: None))
        _strip_dump_cli_addons(lean)

    def test_run_strips_cli_addons_before_registering_our_own(self) -> None:
        """The window between construction and strip must not widen: the strip
        has to happen inside _run, right after the master exists and before the
        recorder/signal go in."""
        import inspect

        from headless_re_mcp.backends.proxy import client as proxy_client

        source = inspect.getsource(proxy_client._ProxyInstance._run)
        assert "_strip_dump_cli_addons(" in source
        assert source.index("_strip_dump_cli_addons(") < source.index("addons.add")

    def test_start_serializes_the_construction_to_running_window(self) -> None:
        """Master.__init__ resets the process-global ctx before options are
        registered, and setup_servers reads the *shared* ctx.options.mode: two
        unserialized starts can crash each other's hooks or bind each other's
        port."""
        import inspect

        from headless_re_mcp.backends.proxy import client as proxy_client

        source = inspect.getsource(proxy_client._ProxyInstance.start)
        assert "with _START_SERIALIZER" in source

    def test_readiness_waits_for_the_running_hook_chain_not_just_the_port(
        self,
    ) -> None:
        """The socket accepts as soon as setup_servers finishes, but the hooks
        that read the shared ctx run after that; releasing the start lock on
        port-accept alone would reopen the race the lock exists to close."""
        import inspect

        from headless_re_mcp.backends.proxy import client as proxy_client

        source = inspect.getsource(proxy_client._ProxyInstance._locked_start)
        assert "_running_signal.reached.is_set()" in source

    def test_running_signal_reports_the_hook(self) -> None:
        from headless_re_mcp.backends.proxy.client import _RunningSignal

        signal = _RunningSignal()
        assert not signal.reached.is_set()
        signal.running()
        assert signal.reached.is_set()


class TestConcurrentStartDoesNotLeakABackend:
    def test_two_proxy_starts_for_one_session_only_keep_one_instance(
        self, monkeypatch: Any
    ) -> None:
        from headless_re_mcp.backends.proxy.client import (
            ProxyBackend,
            ProxyError,
            _ProxyInstance,
        )

        created: list[object] = []
        first_entered = threading.Event()
        release = threading.Event()

        def slow_start(self: Any, timeout: float = 15.0) -> None:
            del timeout
            created.append(self)
            first_entered.set()
            release.wait(2.0)

        monkeypatch.setattr(_ProxyInstance, "start", slow_start)
        backend = ProxyBackend()
        backend._check_available = lambda: None  # type: ignore[method-assign]

        def first() -> None:
            backend.start("s", port=18080)

        thread = threading.Thread(target=first)
        thread.start()
        try:
            assert first_entered.wait(2.0)
            with pytest.raises(ProxyError) as caught:
                backend.start("s", port=18081)
            assert caught.value.code == "invalid_state"
            assert len(created) == 1
        finally:
            release.set()
            thread.join(2.0)
        assert list(backend._instances) == ["s"]
        backend.stop("s")

    def test_a_failed_proxy_start_releases_the_reservation(
        self, monkeypatch: Any
    ) -> None:
        from headless_re_mcp.backends.proxy.client import (
            ProxyBackend,
            ProxyError,
            _ProxyInstance,
        )

        def boom(self: Any, timeout: float = 15.0) -> None:
            del timeout
            raise ProxyError("timeout", "did not listen")

        monkeypatch.setattr(_ProxyInstance, "start", boom)
        monkeypatch.setattr(_ProxyInstance, "stop", lambda self: None)
        backend = ProxyBackend()
        backend._check_available = lambda: None  # type: ignore[method-assign]
        with pytest.raises(ProxyError):
            backend.start("s", port=18080)
        assert backend._instances == {}

    def test_a_second_web_open_is_refused_while_the_first_is_reserved(self) -> None:
        from headless_re_mcp.backends.web.client import _OPENING, WebBackend, WebError

        backend = WebBackend()
        backend._check_available = lambda: None  # type: ignore[method-assign]
        backend._sessions["s"] = _OPENING  # type: ignore[assignment]
        with pytest.raises(WebError) as caught:
            backend.open("s", "http://example.com")
        assert caught.value.code == "invalid_state"
        assert backend._sessions["s"] is _OPENING

    def test_a_closed_open_does_not_install_over_a_later_reservation(
        self, monkeypatch: Any
    ) -> None:
        import sys
        import types
        from threading import Event, Thread

        from headless_re_mcp.backends.web.client import WebBackend, WebError

        fake_pw = types.ModuleType("playwright")
        fake_sync = types.ModuleType("playwright.sync_api")
        fake_sync.sync_playwright = lambda: None  # type: ignore[method-assign]
        monkeypatch.setitem(sys.modules, "playwright", fake_pw)
        monkeypatch.setitem(sys.modules, "playwright.sync_api", fake_sync)

        first_blocked = Event()
        release_first = Event()

        class FakeRunner:
            def __init__(self, name: str) -> None:
                del name
                self.wedged = False

            def call(self, work: Any, *, timeout: float = 60.0) -> Any:
                del work, timeout
                if not first_blocked.is_set():
                    first_blocked.set()
                    assert release_first.wait(5)
                handle = types.SimpleNamespace(runner=None, driver_pid=None)
                return handle, {
                    "opened": True,
                    "url": "http://example.com",
                    "title": "",
                    "headless": True,
                }

            def shutdown(self) -> None:
                return None

        monkeypatch.setattr(
            "headless_re_mcp.backends.web.client._Runner", FakeRunner
        )
        monkeypatch.setattr(
            "headless_re_mcp.backends.web.client._reap_web_session", lambda handle: None
        )

        backend = WebBackend()
        backend._check_available = lambda: None  # type: ignore[method-assign]
        errors: list[WebError] = []

        def first_open() -> None:
            try:
                backend.open("s", "http://example.com")
            except WebError as exc:
                errors.append(exc)

        thread = Thread(target=first_open)
        thread.start()
        assert first_blocked.wait(5)
        backend.close("s")
        later = object()
        backend._sessions["s"] = later  # type: ignore[assignment]
        release_first.set()
        thread.join(5)
        assert errors and errors[0].code == "invalid_state"
        assert backend._sessions["s"] is later

    def test_repeated_refused_starts_leave_no_residue(self) -> None:
        """Twenty failed captures in a row must cost the process nothing.

        Measured on this machine before the fix: forty refused starts against a
        held port cost 45 MB, 75 OS handles and two stale root handlers, and
        took ten minutes because each one waited out the readiness timeout.
        """
        import logging
        import socket
        import threading
        import time

        from headless_re_mcp.backends.proxy.client import ProxyBackend, ProxyError

        handlers_before = len(logging.getLogger().handlers)
        threads_before = threading.active_count()
        holder = socket.socket()
        holder.bind(("127.0.0.1", 0))
        port = holder.getsockname()[1]
        backend = ProxyBackend()
        started = time.monotonic()
        try:
            # Eight is enough to show nothing accumulates per refusal; each one
            # spends the port probe's timeout, so more only costs suite time.
            for _ in range(8):
                with pytest.raises(ProxyError):
                    backend.start("session", port=port)
            assert len(logging.getLogger().handlers) == handlers_before
            assert threading.active_count() == threads_before
            assert time.monotonic() - started < 8.0
        finally:
            holder.close()
            backend.close_all()


class TestBrowserCallsAreThreadConfinedAndBounded:
    """Playwright's sync API is greenlet-based and thread-affine.

    Tool calls are served by a shared worker pool, so the thread that opened a
    browser is not the thread that will run the next call against it. Touching
    the objects from anywhere else raises "Cannot switch to a different thread"
    from inside playwright -- and because a pool reuses idle workers, it happens
    only once calls start spreading out, which is the worst way to find out.
    """

    def test_every_call_lands_on_the_same_dedicated_thread(self) -> None:
        import threading
        from concurrent.futures import ThreadPoolExecutor

        from headless_re_mcp.backends.web.client import _Runner

        runner = _Runner("test-runner")
        try:
            caller = threading.current_thread().name
            seen = {runner.call(lambda: threading.current_thread().name)}
            with ThreadPoolExecutor(max_workers=4) as pool:
                for name in pool.map(
                    lambda _: runner.call(lambda: threading.current_thread().name), range(8)
                ):
                    seen.add(name)
            assert len(seen) == 1
            assert caller not in seen
        finally:
            runner.shutdown()

    def test_a_call_that_never_returns_times_out_instead_of_parking_the_caller(self) -> None:
        """Playwright's own timeouts live in the driver process and die with it."""
        import threading
        import time

        from headless_re_mcp.backends.web.client import WebError, _Runner

        release = threading.Event()
        runner = _Runner("test-wedge")
        try:
            started = time.monotonic()
            with pytest.raises(WebError) as caught:
                runner.call(lambda: release.wait(30.0), timeout=0.5)
            assert caught.value.code == "timeout"
            assert time.monotonic() - started < 5.0
            assert runner.wedged is True

            # The thread is stuck in a call nothing can interrupt, so the next
            # call must be refused rather than queued behind it forever.
            started = time.monotonic()
            with pytest.raises(WebError) as second:
                runner.call(lambda: "unreachable", timeout=10.0)
            assert second.value.code == "backend_error"
            assert time.monotonic() - started < 1.0
        finally:
            release.set()
            runner.shutdown()

    def test_a_shut_down_runner_refuses_work(self) -> None:
        from headless_re_mcp.backends.web.client import WebError, _Runner

        runner = _Runner("test-shutdown")
        assert runner.call(lambda: 7) == 7
        runner.shutdown()
        with pytest.raises(WebError) as caught:
            runner.call(lambda: 7)
        assert caught.value.code == "invalid_state"

    def test_exceptions_travel_back_to_the_caller(self) -> None:
        from headless_re_mcp.backends.web.client import WebError, _Runner

        runner = _Runner("test-raise")

        def boom() -> None:
            raise WebError("backend_error", "navigation failed: target closed")

        try:
            with pytest.raises(WebError) as caught:
                runner.call(boom)
            assert caught.value.message.startswith("navigation failed")
            # A failed call is not a wedged runner; the session stays usable.
            assert runner.wedged is False
            assert runner.call(lambda: "still works") == "still works"
        finally:
            runner.shutdown()

    def test_the_runner_thread_does_not_outlive_shutdown(self) -> None:
        import threading
        import time

        from headless_re_mcp.backends.web.client import _Runner

        before = threading.active_count()
        runner = _Runner("test-exit")
        runner.call(lambda: None)
        assert threading.active_count() == before + 1
        runner.shutdown()
        deadline = time.monotonic() + 5.0
        while threading.active_count() > before and time.monotonic() < deadline:
            time.sleep(0.02)
        assert threading.active_count() == before

    def test_closing_a_wedged_session_kills_the_driver_tree(self, monkeypatch: Any) -> None:
        """Playwright objects cannot be closed from this thread once it is stuck.

        The node driver is what still holds Chromium. Leaving it running is a
        process leak per hung navigation, for the rest of the service's life.
        """
        import subprocess
        import sys
        import time
        from types import SimpleNamespace

        from headless_re_mcp.backends.web import client as web_mod
        from headless_re_mcp.backends.web.client import WebBackend, _Runner
        from headless_re_mcp.core.process_tree import terminate_pid_tree

        monkeypatch.setattr(web_mod, "process_image_path", lambda pid: r"C:\node.exe")

        process = subprocess.Popen(
            [sys.executable, "-c", _LAUNCHER],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        assert process.stdout is not None
        child = int(process.stdout.readline().strip())
        runner = _Runner("test-reap")
        runner._wedged = True
        backend = WebBackend()
        backend._sessions["s"] = SimpleNamespace(  # type: ignore[assignment]
            runner=runner,
            driver_pid=process.pid,
            close=lambda: None,
        )
        try:
            result = backend.close("s")
            assert result["closed"] is True
            assert result["clean"] is False
            deadline = time.monotonic() + 5.0
            while time.monotonic() < deadline:
                if not _pid_is_alive(process.pid) and not _pid_is_alive(child):
                    break
                time.sleep(0.05)
            assert not _pid_is_alive(process.pid)
            assert not _pid_is_alive(child)
        finally:
            terminate_pid_tree(process.pid)
            runner.shutdown()


class TestWebScriptBufferIsBounded:
    def test_parsed_scripts_do_not_grow_without_bound(self) -> None:
        handle = _WebSession(object(), object(), object(), object(), object())
        for index in range(_MAX_SCRIPTS + 500):
            with handle.lock:
                handle.scripts[str(index)] = {"scriptId": str(index)}
                while len(handle.scripts) > _MAX_SCRIPTS:
                    handle.scripts.popitem(last=False)
        assert len(handle.scripts) == _MAX_SCRIPTS
        assert isinstance(handle.scripts, OrderedDict)
        # The window keeps the newest scripts, which are the ones worth fetching.
        assert str(_MAX_SCRIPTS + 499) in handle.scripts
        assert "0" not in handle.scripts

    def test_a_full_script_buffer_says_older_scripts_were_dropped(self) -> None:
        from headless_re_mcp.backends.web.client import WebBackend

        backend = WebBackend()
        handle = _WebSession(object(), object(), object(), object(), object())
        for index in range(_MAX_SCRIPTS + 10):
            handle.scripts[str(index)] = {"scriptId": str(index)}
            while len(handle.scripts) > _MAX_SCRIPTS:
                handle.scripts.popitem(last=False)
                handle.scripts_dropped += 1
        backend._sessions["s"] = handle
        result = backend.scripts("s", offset=0, limit=1000)
        assert result["count"] == 1000
        assert result["total"] == _MAX_SCRIPTS
        assert result["has_more"] is True
        assert result["dropped"] == 10
        tail = backend.scripts("s", offset=1000, limit=1000)
        assert tail["count"] == 1000
        assert tail["has_more"] is False
        assert tail["dropped"] == 10

    def test_a_full_script_buffer_says_older_wasm_modules_were_dropped(self) -> None:
        from headless_re_mcp.backends.web.client import WebBackend

        backend = WebBackend()
        handle = _WebSession(object(), object(), object(), object(), object())
        for index in range(_MAX_SCRIPTS + 10):
            handle.scripts[str(index)] = {
                "scriptId": str(index),
                "language": "WebAssembly" if index % 2 else "JavaScript",
            }
            while len(handle.scripts) > _MAX_SCRIPTS:
                handle.scripts.popitem(last=False)
                handle.scripts_dropped += 1
        backend._sessions["s"] = handle
        result = backend.scripts("s", wasm_only=True, limit=_MAX_SCRIPTS)
        assert result["count"] == _MAX_SCRIPTS // 2
        assert result["dropped"] == 10

    def test_a_script_buffer_that_never_evicted_is_not_labelled_truncated(self) -> None:
        from headless_re_mcp.backends.web.client import WebBackend

        backend = WebBackend()
        handle = _WebSession(object(), object(), object(), object(), object())
        handle.scripts["1"] = {"scriptId": "1"}
        backend._sessions["s"] = handle
        result = backend.scripts("s")
        assert result["count"] == 1
        assert result["has_more"] is False
        assert result["dropped"] == 0

    def test_evicted_requests_are_counted_as_dropped(self) -> None:
        from headless_re_mcp.backends.web.client import WebBackend

        backend = WebBackend()
        handle = _WebSession(object(), object(), object(), object(), object())
        handle.requests["a"] = {"requestId": "a"}
        handle.requests_dropped = 7
        backend._sessions["s"] = handle
        result = backend.network_list("s")
        assert result["dropped"] == 7
        assert result["has_more"] is False

    def test_the_script_list_is_paged(self) -> None:
        """2000 typical URLs encoded to 441 KiB; a page of 100 is 22 KiB."""
        from headless_re_mcp.backends.web.client import WebBackend

        handle = _WebSession(object(), object(), object(), object(), object())
        for index in range(250):
            handle.scripts[str(index)] = {
                "scriptId": str(index),
                "url": f"https://cdn.example.com/{index}.js",
                "language": "JavaScript",
            }
        backend = WebBackend()
        backend._sessions["s"] = handle
        page = backend.scripts("s", offset=0, limit=10)
        assert page["count"] == 10
        assert page["total"] == 250
        assert page["has_more"] is True
        tail = backend.scripts("s", offset=240, limit=20)
        assert tail["count"] == 10
        assert tail["has_more"] is False
        assert {item["scriptId"] for item in page["scripts"]} & {
            item["scriptId"] for item in tail["scripts"]
        } == set()

    def test_request_and_console_buffers_are_bounded_types(self) -> None:
        handle = _WebSession(object(), object(), object(), object(), object())
        assert handle.console.maxlen is not None
        assert isinstance(handle.requests, OrderedDict)

    def test_a_console_page_says_when_older_lines_remain(self) -> None:
        from headless_re_mcp.backends.web.client import WebBackend

        backend = WebBackend()
        handle = _WebSession(object(), object(), object(), object(), object())
        handle.console.extend({"text": str(index)} for index in range(10))
        backend._sessions["s"] = handle
        result = backend.console("s", limit=4)
        assert result["count"] == 4
        assert result["has_more"] is True
        assert result["console"][0]["text"] == "6"

    def test_a_console_page_that_fits_is_not_labelled_truncated(self) -> None:
        from headless_re_mcp.backends.web.client import WebBackend

        backend = WebBackend()
        handle = _WebSession(object(), object(), object(), object(), object())
        handle.console.extend({"text": str(index)} for index in range(3))
        backend._sessions["s"] = handle
        result = backend.console("s", limit=10)
        assert result["count"] == 3
        assert result["has_more"] is False
        assert result["dropped"] == 0

    def test_a_huge_console_line_is_cut_in_the_ring(self) -> None:
        from headless_re_mcp.backends.web.client import _MAX_CONSOLE_TEXT, WebBackend

        class Cdp:
            def __init__(self) -> None:
                self.handlers: dict[str, Any] = {}

            def send(self, method: str, params: Any = None) -> None:
                del method, params

            def on(self, event: str, callback: Any) -> None:
                self.handlers[event] = callback

        cdp = Cdp()
        handle = _WebSession(object(), object(), object(), object(), cdp)
        WebBackend()._wire_events(handle)
        cdp.handlers["Runtime.consoleAPICalled"](
            {"type": "log", "args": [{"value": "x" * (_MAX_CONSOLE_TEXT + 40)}]}
        )
        row = handle.console[0]
        assert len(row["text"]) == _MAX_CONSOLE_TEXT
        assert row["text_truncated"] is True

    def test_a_response_body_over_the_capture_cap_is_not_written(
        self, tmp_path: Any, monkeypatch: Any
    ) -> None:
        from headless_re_mcp.backends.web import client as mod

        monkeypatch.setattr(mod, "UNREGISTERED_CAPTURE_MAX_BYTES", 50)

        class Immediate:
            def call(self, work: Any, timeout: float | None = None) -> Any:
                del timeout
                return work()

        class Cdp:
            def send(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
                del method, params
                return {"body": "z" * 60, "base64Encoded": False}

        class Handle:
            lock = threading.Lock()
            requests = {"r1": {"requestId": "r1", "url": "https://x"}}
            cdp = Cdp()

        backend = mod.WebBackend()
        backend._get = lambda session_id: Handle()  # type: ignore[method-assign]
        backend._runner = lambda handle: Immediate()  # type: ignore[method-assign]
        with pytest.raises(mod.WebError) as caught:
            backend.network_get("s", "r1", tmp_path)
        assert caught.value.code == "too_large"
        assert list(tmp_path.iterdir()) == []

    def test_a_script_source_over_the_capture_cap_is_not_written(
        self, tmp_path: Any, monkeypatch: Any
    ) -> None:
        from types import SimpleNamespace

        from headless_re_mcp.backends.web import client as mod

        monkeypatch.setattr(mod, "UNREGISTERED_CAPTURE_MAX_BYTES", 50)

        class Immediate:
            def call(self, work: Any, timeout: float | None = None) -> Any:
                del timeout
                return work()

        class Cdp:
            def send(self, method: str, params: dict[str, Any]) -> dict[str, str]:
                del method, params
                return {"scriptSource": "y" * 60}

        backend = mod.WebBackend()
        backend._get = lambda session_id: SimpleNamespace(cdp=Cdp())  # type: ignore[method-assign]
        backend._runner = lambda handle: Immediate()  # type: ignore[method-assign]
        with pytest.raises(mod.WebError) as caught:
            backend.script_source("s", "42", tmp_path)
        assert caught.value.code == "too_large"
        assert list(tmp_path.iterdir()) == []


class TestFridaAuthorizationWindow:
    def test_most_recent_pid_wins_even_when_it_is_numerically_smaller(self) -> None:
        """Sorting would silently target the highest pid, not the new app."""
        pids: Any = []
        pids = _append_recent(pids, 5000)
        pids = _append_recent(pids, 3000)
        assert pids[-1] == 3000

    def test_repeated_spawns_do_not_grow_the_authorization_list(self) -> None:
        pids: Any = []
        for pid in range(_MAX_AUTHORIZED * 3):
            pids = _append_recent(pids, pid)
        assert len(pids) == _MAX_AUTHORIZED
        assert pids[-1] == _MAX_AUTHORIZED * 3 - 1

    def test_respawning_the_same_target_does_not_duplicate_it(self) -> None:
        pids: Any = []
        for _ in range(10):
            pids = _append_recent(pids, 777)
        assert pids == [777]

    def test_packages_follow_the_same_recency_rule(self) -> None:
        packages: Any = []
        packages = _append_recent(packages, "com.b")
        packages = _append_recent(packages, "com.a")
        assert packages[-1] == "com.a"


class TestLongLivedBackendsAreSingletons:
    def test_concurrent_first_use_never_builds_two_backends(self) -> None:
        """Two workers racing to first-use must not each get their own backend.

        The loser's browser or bound port would be untracked, so nothing could
        ever close it.
        """
        from headless_re_mcp.core.service import AnalysisService

        service = AnalysisService()
        try:
            seen_web: list[int] = []
            seen_proxy: list[int] = []
            seen_adb: list[int] = []
            barrier = threading.Barrier(8)

            def touch() -> None:
                barrier.wait()
                seen_web.append(id(service._web))
                seen_proxy.append(id(service._proxy))
                seen_adb.append(id(service._backend()))

            threads = [threading.Thread(target=touch) for _ in range(8)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()

            assert len(set(seen_web)) == 1
            assert len(set(seen_proxy)) == 1
            assert len(set(seen_adb)) == 1
        finally:
            service.close_all()

    def test_backends_exist_before_any_tool_call(self) -> None:
        from headless_re_mcp.core.service import AnalysisService

        service = AnalysisService()
        try:
            assert service._web is service._web_backend
            assert service._proxy is service._proxy_backend
            assert service._backend() is service._adb_backend
        finally:
            service.close_all()


class TestApkCacheIsReclaimed:
    def test_release_drops_every_cached_parse_for_one_path(self, tmp_path: Any) -> None:
        from headless_re_mcp.backends.apk.client import ApkClient

        target = tmp_path / "app.apk"
        target.write_bytes(b"PK\x03\x04")
        resolved = str(target.resolve())
        ApkClient._light_cache[(resolved, 1)] = object()
        ApkClient._full_cache[(resolved, 1)] = object()  # type: ignore[assignment]
        other = tmp_path / "other.apk"
        other.write_bytes(b"PK\x03\x04")
        ApkClient._light_cache[(str(other.resolve()), 1)] = object()
        try:
            assert ApkClient.release(target) is True
            assert not any(key[0] == resolved for key in ApkClient._light_cache)
            assert not any(key[0] == resolved for key in ApkClient._full_cache)
            # Releasing one APK must not evict another session's work.
            assert any(key[0] == str(other.resolve()) for key in ApkClient._light_cache)
        finally:
            ApkClient._light_cache.clear()
            ApkClient._full_cache.clear()

    def test_release_of_an_uncached_path_is_harmless(self, tmp_path: Any) -> None:
        from headless_re_mcp.backends.apk.client import ApkClient

        target = tmp_path / "never-parsed.apk"
        target.write_bytes(b"PK\x03\x04")
        assert ApkClient.release(target) is False

    def test_closing_an_apk_session_reclaims_its_parse(self, tmp_path: Any) -> None:
        import zipfile

        from headless_re_mcp.backends.apk.client import ApkClient
        from headless_re_mcp.core.service import AnalysisService

        apk = tmp_path / "app.apk"
        with zipfile.ZipFile(apk, "w") as archive:
            archive.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00m")
            archive.writestr("classes.dex", b"dex\n035\x00")

        service = AnalysisService()
        try:
            created = service.create_session(str(apk))
            session_id = created.data["session"]["id"]
            # Stand in for a real parse so the test does not depend on androguard.
            ApkClient._light_cache[(str(apk.resolve()), 1)] = object()

            service.close_session(session_id)
            assert not any(
                key[0] == str(apk.resolve()) for key in ApkClient._light_cache
            )
        finally:
            ApkClient._light_cache.clear()
            ApkClient._full_cache.clear()
            service.close_all()


class TestArtifactBudgetAppliesToAnOpenSession:
    """A session that never closes used to never collect.

    Retention ran on session close only, so the shape that actually fills a disk
    -- one session held open for days while a loop dumps modules and traces --
    was the one shape the byte budget did not cover.
    """

    def _service(self, tmp_path: Any, budget: int) -> Any:
        from dataclasses import replace

        from headless_re_mcp.config import Settings
        from headless_re_mcp.core.service import AnalysisService

        settings = replace(
            Settings.load(),
            artifact_root=tmp_path / "artifacts",
            artifact_max_total_bytes=budget,
        )
        service = AnalysisService(settings)
        # The throttle is verified separately; here it would hide the behaviour.
        service._retention.min_interval_s = 0.0
        return service

    def _write(self, tmp_path: Any, name: str, size: int) -> Any:
        blob = tmp_path / name
        blob.write_bytes(b"\x00" * size)
        return blob

    def test_registering_over_budget_collects_without_closing_the_session(
        self, tmp_path: Any
    ) -> None:
        service = self._service(tmp_path, budget=4096)
        try:
            blobs = [
                self._write(tmp_path / "artifacts", f"dump-{index}.bin", 1024)
                for index in range(12)
            ]
            for index, blob in enumerate(blobs):
                service.record_artifact(
                    session_id="open-session",
                    kind="module_dump",
                    path=blob,
                    sha256=f"{index:064d}",
                    source="test",
                    size=1024,
                )

            listed = service.repository.list_artifacts()
            assert listed["total"] <= 4
            # Oldest go first, newest survive: the loop keeps what it just made.
            assert not blobs[0].exists()
            assert blobs[-1].exists()
        finally:
            service.close_all()

    def test_a_dump_larger_than_the_whole_budget_is_still_returned(
        self, tmp_path: Any
    ) -> None:
        """Collecting the file whose path is about to be returned is worse than
        being over budget for a while."""
        service = self._service(tmp_path, budget=1024)
        try:
            huge = self._write(tmp_path / "artifacts", "huge.bin", 8192)
            artifact = service.record_artifact(
                session_id="open-session",
                kind="module_dump",
                path=huge,
                sha256="f" * 64,
                source="test",
                size=8192,
            )
            assert huge.is_file()
            assert service.repository.describe_artifact(str(artifact["id"])) is not None
        finally:
            service.close_all()

    def test_a_burst_does_not_wait_out_the_throttle(self) -> None:
        """Time alone is the wrong throttle for a producer that outruns it.

        Measured before this: an 8 MB budget with 1 MB captures reached 60 MB on
        disk in under a second, every one of them inside a single throttle
        window, so the budget never applied once.
        """
        from headless_re_mcp.core.retention import ArtifactRetention

        calls: list[int] = []

        class _Collector:
            def gc_artifacts(self, *, max_total_bytes: int) -> dict[str, Any]:
                calls.append(max_total_bytes)
                return {"removed": [], "count": 0}

        collector = _Collector()
        retention = ArtifactRetention(max_total_bytes=8_000_000, min_interval_s=60.0)
        assert retention.maybe_collect(collector, now=1000.0) is not None

        # Well inside the window, and small change is still not worth a walk.
        assert retention.maybe_collect(collector, now=1001.0, added_bytes=1_000_000) is None
        assert retention.maybe_collect(collector, now=1002.0, added_bytes=1_000_000) is None
        # Half the budget of new material is, though.
        assert retention.maybe_collect(collector, now=1003.0, added_bytes=2_000_000) is not None
        assert len(calls) == 2

        # The counter starts over, so the next burst has to earn its own run.
        assert retention.maybe_collect(collector, now=1004.0, added_bytes=1_000_000) is None

    def test_a_fast_producer_stays_near_its_budget(self, tmp_path: Any) -> None:
        from headless_re_mcp.core.retention import measure_usage

        service = self._service(tmp_path, budget=1_000_000)
        # The burst trigger has to carry this on its own, not the timer.
        service._retention.min_interval_s = 3600.0
        root = (tmp_path / "artifacts").resolve()
        try:
            written = 0
            for index in range(20):
                blob = self._write(root, f"capture-{index}.bin", 256 * 1024)
                written += 256 * 1024
                service.record_artifact(
                    session_id="fast",
                    kind="ui_screenshot",
                    path=blob,
                    sha256=f"{index:064d}",
                    source="test",
                    size=256 * 1024,
                )
            usage = measure_usage(root)
            assert written == 20 * 256 * 1024
            # Not "under budget" -- the newest is never collected and the store
            # itself takes room -- but within sight of it rather than 5 MB.
            assert usage.bytes < 2_000_000
        finally:
            service.close_all()

    def test_concurrent_registrations_neither_lose_bytes_nor_double_collect(self) -> None:
        """Registration is now a hot path shared by the whole worker pool."""
        from headless_re_mcp.core.retention import ArtifactRetention

        collected = threading.Semaphore(0)
        runs = []

        class _Collector:
            def gc_artifacts(self, *, max_total_bytes: int) -> dict[str, Any]:
                runs.append(max_total_bytes)
                collected.release()
                return {"removed": [], "count": 0}

        collector = _Collector()
        retention = ArtifactRetention(max_total_bytes=1000, min_interval_s=3600.0)
        barrier = threading.Barrier(8)
        errors: list[BaseException] = []

        def register() -> None:
            try:
                barrier.wait()
                for _ in range(50):
                    retention.maybe_collect(collector, now=1.0, added_bytes=10)
            except BaseException as exc:  # noqa: BLE001 - recorded, then asserted
                errors.append(exc)

        threads = [threading.Thread(target=register) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert errors == []
        # 8 x 50 x 10 = 4000 bytes of new material, 500 per collection: no
        # update may be lost, and none may be counted twice.
        assert len(runs) == 8
        assert retention._pending_bytes == 0

    def test_collection_is_throttled_so_a_burst_costs_one_walk(self) -> None:
        from headless_re_mcp.core.retention import ArtifactRetention

        calls: list[int] = []

        class _Collector:
            def gc_artifacts(self, *, max_total_bytes: int) -> dict[str, Any]:
                calls.append(max_total_bytes)
                return {"removed": [], "count": 0}

        collector = _Collector()
        retention = ArtifactRetention(max_total_bytes=4096, min_interval_s=60.0)
        assert retention.maybe_collect(collector, now=1000.0) is not None
        for tick in range(1001, 1060):
            assert retention.maybe_collect(collector, now=float(tick)) is None
        assert retention.maybe_collect(collector, now=1061.0) is not None
        assert calls == [4096, 4096]


class TestUiCapturesAreRegistered:
    """UI bitmaps were the largest thing nothing could account for.

    ``ui.screenshot`` and ``ui.ocr`` write an uncompressed BMP per call -- a
    full window is megabytes -- under a fresh uuid. Unregistered, retention
    cannot reclaim them and no tool can read them back, so a UI-driving loop
    left gigabytes on disk that the artifact budget never even counted.
    """

    def _service(self, tmp_path: Any) -> Any:
        from dataclasses import replace

        from headless_re_mcp.config import Settings
        from headless_re_mcp.core.service import AnalysisService

        settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
        return AnalysisService(settings)

    def _ok(self, payload: dict[str, Any]) -> Any:
        from headless_re_mcp.core.results import _success

        return _success(payload, session_id="s")

    def test_a_captured_bitmap_becomes_a_readable_reclaimable_artifact(
        self, tmp_path: Any
    ) -> None:
        service = self._service(tmp_path)
        try:
            # The real layout: captures live under the artifact root, which is
            # also what lets artifacts.read serve them at all.
            shot = tmp_path / "artifacts" / "ui" / "s" / "screenshot-abc.bmp"
            shot.parent.mkdir(parents=True, exist_ok=True)
            shot.write_bytes(b"BM" + b"\x00" * 4096)
            result = service._register_ui_capture(
                self._ok({"width": 100, "height": 50}),
                "s",
                shot,
                kind="ui_screenshot",
                source="ui.screenshot",
            )

            assert result.ok and result.data is not None
            # The original payload is untouched; the id is added beside it.
            assert result.data["width"] == 100
            artifact_id = str(result.data["artifact_id"])
            described = service.repository.describe_artifact(artifact_id)
            assert described is not None
            assert described["kind"] == "ui_screenshot"
            assert described["size"] == 4098

            read = service.artifacts_read(artifact_id, offset=0, limit=2)
            assert read.ok and read.data is not None
            assert read.data["data"] == "424d"
        finally:
            service.close_all()

    def test_a_failed_capture_registers_nothing(self, tmp_path: Any) -> None:
        from headless_re_mcp.core.results import _failure

        service = self._service(tmp_path)
        try:
            missing = tmp_path / "never-written.bmp"
            failed = _failure(RuntimeError("capture refused"), session_id="s")
            assert service._register_ui_capture(
                failed, "s", missing, kind="ui_screenshot", source="ui.screenshot"
            ) is failed
            assert service.repository.list_artifacts("s")["total"] == 0
        finally:
            service.close_all()

    def test_both_ui_capture_tools_route_through_the_registration(self) -> None:
        """Neither path may quietly go back to returning a bare file path."""
        import inspect

        from headless_re_mcp.core import service_ui

        mixin = service_ui.UiAutomationMixin
        for method in (mixin.ui_screenshot, mixin.ui_ocr):
            assert "_register_ui_capture" in inspect.getsource(method)


def _minimal_pe(path: Any) -> Any:
    image = bytearray(0x200)
    image[:2] = b"MZ"
    image[0x3C:0x40] = (0x80).to_bytes(4, "little")
    image[0x80:0x84] = b"PE\0\0"
    image[0x84:0x86] = (0x8664).to_bytes(2, "little")
    path.write_bytes(image)
    return path


class TestGeneratedReportsAreRegistered:
    def test_every_report_is_an_artifact_rather_than_a_loose_file(
        self, tmp_path: Any
    ) -> None:
        """Each call writes a new timestamped file under the artifact root.

        An unattended loop that reports per run would otherwise leave one behind
        every time, with nothing able to collect them.
        """
        from dataclasses import replace

        from headless_re_mcp.config import Settings
        from headless_re_mcp.core.service import AnalysisService

        settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
        service = AnalysisService(settings)
        try:
            created = service.create_session(str(_minimal_pe(tmp_path / "target.exe")))
            session_id = str(created.data["session"]["id"])

            report = service.report_generate(session_id, title="soak")
            assert report.ok, report.error
            assert report.data is not None
            # The report text still comes back inline; the id is added beside it.
            assert report.data["markdown"].startswith("#")
            described = service.repository.describe_artifact(str(report.data["artifact_id"]))
            assert described is not None
            assert described["kind"] == "report_markdown"
            assert described["path"] == report.data["path"]
        finally:
            service.close_all()


class TestPerSessionStateDiesWithTheSession:
    """Nothing keyed by session id may outlive the session that made it.

    A server that opens and closes sessions all day is the target shape, so a
    single dictionary entry left behind per session is a leak with a slow fuse.
    """

    def test_closing_a_session_forgets_its_backend_phases(self) -> None:
        from headless_re_mcp.core.models import BackendKind
        from headless_re_mcp.core.runtime_state import (
            BackendRuntimeOwner,
            BackendRuntimePhase,
        )

        owner: BackendRuntimeOwner[object] = BackendRuntimeOwner()
        for index in range(200):
            session_id = f"s{index}"
            owner.begin_open(session_id, BackendKind.X64DBG)
            owner.put(session_id, BackendKind.X64DBG, object())
            assert owner.pop_session(session_id)

        assert owner.items == {}
        assert owner.phases == {}
        assert owner.phase("s0", BackendKind.X64DBG) is BackendRuntimePhase.ABSENT

    def test_a_failed_backend_is_forgotten_once_its_session_closes(self) -> None:
        from headless_re_mcp.core.models import BackendKind
        from headless_re_mcp.core.runtime_state import BackendRuntimeOwner

        owner: BackendRuntimeOwner[object] = BackendRuntimeOwner()
        owner.begin_open("s", BackendKind.IDA)
        owner.put("s", BackendKind.IDA, object())
        owner.fail("s", BackendKind.IDA)
        owner.begin_open("s", BackendKind.X64DBG)
        owner.put("s", BackendKind.X64DBG, object())

        owner.pop_session("s")
        # The FAILED marker is what session_recover reads; a closed session must
        # not keep offering itself up for recovery.
        assert owner.phases == {}

    def test_closing_a_session_releases_its_trace_state(self, tmp_path: Any) -> None:
        from dataclasses import replace

        from headless_re_mcp.config import Settings
        from headless_re_mcp.core.service import AnalysisService

        settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
        service = AnalysisService(settings)
        try:
            import zipfile

            apk = tmp_path / "app.apk"
            with zipfile.ZipFile(apk, "w") as archive:
                archive.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00m")
            created = service.create_session(str(apk), target="apk")
            session_id = created.data["session"]["id"]
            service._trace_owner.put(session_id, object())

            service.close_session(session_id)
            assert service._trace_owner.get(session_id) is None
            assert service._trace_owner.sessions == {}
        finally:
            service.close_all()

    def test_closing_a_session_removes_its_work_dirs_not_a_siblings(self, tmp_path: Any) -> None:
        from dataclasses import replace

        from headless_re_mcp.config import Settings
        from headless_re_mcp.core.service import AnalysisService

        settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
        service = AnalysisService(settings)
        try:
            import zipfile

            apk = tmp_path / "app.apk"
            with zipfile.ZipFile(apk, "w") as archive:
                archive.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00m")
            created = service.create_session(str(apk), target="apk")
            session_id = str(created.data["session"]["id"])
            own = tmp_path / "artifacts" / "jadx" / session_id
            sibling = tmp_path / "artifacts" / "jadx" / "other-session"
            own.mkdir(parents=True)
            (own / "Main.java").write_text("class Main {}", encoding="utf-8")
            sibling.mkdir(parents=True)
            (sibling / "Other.java").write_text("class Other {}", encoding="utf-8")

            closed = service.close_session(session_id)
            assert closed.ok, closed.error
            assert not own.exists()
            assert sibling.is_dir(), "pruning the shared jadx parent deleted another session"
        finally:
            service.close_all()

    def test_closing_a_session_keeps_registered_ghidra_exports(self, tmp_path: Any) -> None:
        from dataclasses import replace

        from headless_re_mcp.config import Settings
        from headless_re_mcp.core.service import AnalysisService

        settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
        service = AnalysisService(settings)
        try:
            import zipfile

            apk = tmp_path / "app.apk"
            with zipfile.ZipFile(apk, "w") as archive:
                archive.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00m")
            created = service.create_session(str(apk), target="apk")
            session_id = str(created.data["session"]["id"])
            project = tmp_path / "artifacts" / "ghidra" / session_id
            project.mkdir(parents=True)
            export = project / "export_functions.json"
            export.write_text("[]", encoding="utf-8")
            remnant = project / "session.gpr"
            remnant.write_text("project", encoding="utf-8")
            (project / "session.rep").mkdir()
            service.record_artifact(
                session_id=session_id,
                kind="ghidra_functions",
                path=export,
                sha256="a" * 64,
                source="ghidra.functions",
                size=export.stat().st_size,
            )

            closed = service.close_session(session_id)
            assert closed.ok, closed.error
            assert export.is_file(), "registered ghidra export was deleted with the work dir"
            assert not remnant.exists()
            assert not (project / "session.rep").exists()
        finally:
            service.close_all()

    def test_closing_a_session_removes_its_debug_event_log(self, tmp_path: Any) -> None:
        from dataclasses import replace

        from headless_re_mcp.config import Settings
        from headless_re_mcp.core.service import AnalysisService

        settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
        service = AnalysisService(settings)
        try:
            import zipfile

            apk = tmp_path / "app.apk"
            with zipfile.ZipFile(apk, "w") as archive:
                archive.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00m")
            created = service.create_session(str(apk), target="apk")
            session_id = str(created.data["session"]["id"])
            log_dir = tmp_path / "artifacts" / "debug-events" / session_id
            log_dir.mkdir(parents=True)
            (log_dir / "events.sqlite3").write_bytes(b"sqlite")

            closed = service.close_session(session_id)
            assert closed.ok, closed.error
            assert not log_dir.exists()
        finally:
            service.close_all()

    def test_a_web_close_that_throws_still_closes_the_debugger_worker(
        self, tmp_path: Any
    ) -> None:
        from dataclasses import replace

        from headless_re_mcp.config import Settings
        from headless_re_mcp.core.models import BackendKind
        from headless_re_mcp.core.service import AnalysisService, _BackendRuntime

        settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
        service = AnalysisService(settings)

        class _Worker:
            def __init__(self) -> None:
                self.closed = False

            def close(self, *, timeout: float = 15.0) -> None:
                del timeout
                self.closed = True

            def terminate(self) -> None:
                return None

        class _ExplodingWeb:
            def close(self, session_id: str) -> None:
                del session_id
                raise RuntimeError("browser thread wedged")

            def close_all(self) -> None:
                return None

        worker = _Worker()
        try:
            created = service.create_session(str(_minimal_pe(tmp_path / "target.exe")))
            session_id = str(created.data["session"]["id"])
            service._runtime_owner.begin_open(session_id, BackendKind.X64DBG)
            service._runtime_owner.put(
                session_id,
                BackendKind.X64DBG,
                _BackendRuntime(worker=worker),  # type: ignore[arg-type]
            )
            service._web_backend = _ExplodingWeb()  # type: ignore[assignment]

            closed = service.close_session(session_id)
            assert closed.ok, closed.error
            assert worker.closed is True
        finally:
            service.close_all()


class TestTheArtifactRootCanDisappearUnderTheService:
    """Operators clean disks, scanners quarantine, volumes come back unmounted.

    Before this the store could never be opened again: every later call failed
    for the life of the process, and the bookkeeping that runs after a close
    threw its failure out of ``close_session`` -- so a session that really had
    closed answered with a traceback and stayed CLOSING for good.
    """

    def _service(self, tmp_path: Any) -> Any:
        from dataclasses import replace

        from headless_re_mcp.config import Settings
        from headless_re_mcp.core.service import AnalysisService

        settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
        return AnalysisService(settings)

    def _cycle(self, service: Any, target: Any) -> None:
        created = service.create_session(str(target))
        assert created.ok, created.error
        assert created.data is not None
        session_id = str(created.data["session"]["id"])
        assert service.timeline_list(session_id).ok
        assert service.artifacts_list(session_id).ok
        closed = service.close_session(session_id)
        assert closed.ok, closed.error

    def test_work_continues_and_the_root_comes_back(self, tmp_path: Any) -> None:
        import shutil

        service = self._service(tmp_path)
        target = _minimal_pe(tmp_path / "target.exe")
        root = tmp_path / "artifacts"
        try:
            self._cycle(service, target)
            shutil.rmtree(root)
            assert not root.exists()

            self._cycle(service, target)
            assert root.exists()
            # And again, to prove the recovery is not a one-off.
            self._cycle(service, target)
        finally:
            service.close_all()

    def test_close_returns_an_envelope_even_if_the_bookkeeping_throws(
        self, tmp_path: Any
    ) -> None:
        service = self._service(tmp_path)
        target = _minimal_pe(tmp_path / "target.exe")
        try:
            created = service.create_session(str(target))
            session_id = str(created.data["session"]["id"])

            def explode(*_: object, **__: object) -> None:
                raise OSError("unable to open database file")

            service.repository.note_session_closed = explode  # type: ignore[method-assign]
            closed = service.close_session(session_id)

            # The session did close; failing to write that down must not undo it.
            assert closed.ok, closed.error
            assert service.registry.get(session_id).state.value == "closed"
            # Nor may it be hidden: a caller working against an audit trail that
            # quietly stopped is the other way this goes wrong.
            assert closed.meta["persisted"] is False
            assert "unable to open database file" in str(closed.meta["persist_error"])
        finally:
            service.close_all()


class TestAStoreThatCanBeReadButNotWritten:
    """Reading proves less than it looks.

    A database file that has gone read-only -- a scanner quarantine, a
    permissions change, a volume remounted without write access -- answers every
    query exactly as before while accepting no session, artifact or audit row
    again. The readiness probe called that healthy.
    """

    def test_the_store_probe_fails_when_a_write_would_fail(self) -> None:
        from headless_re_mcp.core.readiness import probe_store

        class _ReadableOnly:
            def list_unclean_sessions(self, **_: object) -> tuple[list[dict[str, Any]], int]:
                return [], 0

            def check_writable(self) -> None:
                raise OSError("attempt to write a readonly database")

        check = probe_store(_ReadableOnly())
        assert check.ok is False
        assert "readonly" in check.detail

    def test_a_writable_store_says_so(self) -> None:
        from headless_re_mcp.core.readiness import probe_store

        class _Writable:
            def list_unclean_sessions(self, **_: object) -> tuple[list[dict[str, Any]], int]:
                return [], 0

            def check_writable(self) -> None:
                return None

        assert probe_store(_Writable()) == probe_store(_Writable())
        assert probe_store(_Writable()).detail == "readable and writable"

    def test_the_real_probe_detects_a_read_only_file(self, tmp_path: Any) -> None:
        """The obvious probe does not: BEGIN IMMEDIATE succeeds on a read-only
        database, because SQLite defers the refusal until a page is dirtied."""
        import os
        import stat

        from headless_re_mcp.core.store.sqlite_store import SessionStore

        store = SessionStore(tmp_path / "meta" / "sessions.db")
        store.check_writable()

        database = tmp_path / "meta" / "sessions.db"
        os.chmod(database, stat.S_IREAD)
        try:
            if os.access(database, os.W_OK):
                pytest.skip("this filesystem ignores the read-only bit (skip != pass)")
            with pytest.raises(Exception, match="readonly"):
                store.check_writable()
        finally:
            os.chmod(database, stat.S_IWRITE | stat.S_IREAD)

        # Recovers, and the rolled-back probe left the schema untouched.
        store.check_writable()
        assert store.list_unclean_sessions() == ([], 0)


class TestTheUncleanListIsPaged:
    """Nothing clears these rows, and the list is longest exactly when it is read.

    A hard kill with sessions open adds one row per session and no path removes
    them. Measured at 3000 of them, the unpaged reply was 993 KiB from the very
    tool a caller reaches for right after a crash.
    """

    def _service(self, tmp_path: Any) -> Any:
        from dataclasses import replace

        from headless_re_mcp.config import Settings
        from headless_re_mcp.core.service import AnalysisService

        settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
        return AnalysisService(settings)

    def test_a_page_says_how_much_it_left_behind(self, tmp_path: Any) -> None:
        import zipfile

        service = self._service(tmp_path)
        try:
            apk = tmp_path / "app.apk"
            with zipfile.ZipFile(apk, "w") as archive:
                archive.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00m")
            for _ in range(25):
                service.create_session(str(apk), target="apk")

            page = service.sessions_unclean(limit=10)
            assert page.ok and page.data is not None
            assert page.data["count"] == 10
            assert page.data["total"] == 25
            assert page.data["has_more"] is True

            tail = service.sessions_unclean(offset=20, limit=10)
            assert tail.data is not None
            assert tail.data["count"] == 5
            assert tail.data["has_more"] is False
            # The two pages must not overlap.
            first_ids = {item["id"] for item in page.data["sessions"]}
            tail_ids = {item["id"] for item in tail.data["sessions"]}
            assert first_ids & tail_ids == set()
        finally:
            service.close_all()

    def test_the_readiness_probe_asks_for_one_row_not_all_of_them(self) -> None:
        import inspect

        from headless_re_mcp.core import readiness

        source = inspect.getsource(readiness.probe_store)
        assert "limit=1" in source


class TestACorruptStoreIsAnsweredNotThrown:
    """The read paths assumed the store could not fail.

    A metadata database that has been truncated by a crash, quarantined or
    replaced answers nothing -- and these are exactly the tools a caller reaches
    for when trying to find out what went wrong, so raising through them is the
    worst possible moment to break the envelope contract.
    """

    def _service(self, tmp_path: Any) -> Any:
        from dataclasses import replace

        from headless_re_mcp.config import Settings
        from headless_re_mcp.core.service import AnalysisService

        settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
        return AnalysisService(settings)

    def test_every_read_tool_answers_with_an_envelope(self, tmp_path: Any) -> None:
        service = self._service(tmp_path)
        target = _minimal_pe(tmp_path / "target.exe")
        try:
            created = service.create_session(str(target))
            session_id = str(created.data["session"]["id"])
            service.close_session(session_id)

            database = tmp_path / "artifacts" / "meta" / "sessions.db"
            database.write_bytes(b"not a database" * 100)

            for label, call in (
                ("artifacts_list", lambda: service.artifacts_list(session_id)),
                ("audit_list", lambda: service.audit_list(session_id)),
                ("sessions_unclean", lambda: service.sessions_unclean()),
                ("artifacts_describe", lambda: service.artifacts_describe("nope")),
                ("artifacts_gc", lambda: service.artifacts_gc(max_total_bytes=1)),
                ("artifacts_read", lambda: service.artifacts_read("nope")),
            ):
                result = call()
                assert result.ok is False, label
                assert result.error is not None, label
                # Named, because "internal_error" tells a caller nothing about
                # whether to retry or to stop asking.
                assert result.error.code == "storage_unavailable", (label, result.error.code)
        finally:
            service.close_all()

    def test_a_locked_store_is_marked_retryable_and_a_corrupt_one_is_not(self) -> None:
        import sqlite3

        from headless_re_mcp.core.results import _failure

        locked = _failure(sqlite3.OperationalError("database is locked"))
        corrupt = _failure(sqlite3.DatabaseError("file is not a database"))

        assert locked.error is not None and corrupt.error is not None
        assert locked.error.code == corrupt.error.code == "storage_unavailable"
        assert locked.error.retryable is True
        assert corrupt.error.retryable is False


def _pe_with_stub(path: Any, *, pe_offset: int, x64: bool = True) -> Any:
    """A PE whose header sits at an arbitrary distance into the file."""
    optional_size = 0xF0 if x64 else 0xE0
    end = pe_offset + 24 + optional_size
    image = bytearray(end + 0x40)
    image[:2] = b"MZ"
    image[0x3C:0x40] = pe_offset.to_bytes(4, "little")
    image[pe_offset : pe_offset + 4] = b"PE\0\0"
    image[pe_offset + 20 : pe_offset + 22] = optional_size.to_bytes(2, "little")
    optional = pe_offset + 24
    if x64:
        image[optional : optional + 2] = (0x20B).to_bytes(2, "little")
        image[optional + 24 : optional + 32] = (0x140000000).to_bytes(8, "little")
    else:
        image[optional : optional + 2] = (0x10B).to_bytes(2, "little")
        image[optional + 28 : optional + 32] = (0x400000).to_bytes(4, "little")
    path.write_bytes(bytes(image))
    return path


_LAUNCHER = (
    "import subprocess, sys, time\n"
    "child = subprocess.Popen([sys.executable, '-c', "
    "'import time\\nwhile True: time.sleep(0.2)'])\n"
    "print(child.pid, flush=True)\n"
    "while True: time.sleep(0.2)\n"
)

_EXIT0_LAUNCHER = (
    "import subprocess, sys\n"
    "child = subprocess.Popen(\n"
    "    [sys.executable, '-c', 'import time\\nwhile True: time.sleep(0.2)'],\n"
    "    stdin=subprocess.DEVNULL,\n"
    "    stdout=subprocess.DEVNULL,\n"
    "    stderr=subprocess.DEVNULL,\n"
    "    close_fds=True,\n"
    ")\n"
    "print(child.pid, flush=True)\n"
    "raise SystemExit(0)\n"
)


def _pid_is_alive(pid: int) -> bool:
    import ctypes
    import os
    from pathlib import Path

    if os.name != "nt":
        # ``os.kill(pid, 0)`` succeeds on a zombie, so it reports a process that
        # has already been killed but not yet reaped as still alive. These tests
        # kill a launcher this test process parents and never wait() on it, and in
        # a container whose pid 1 does not reap orphans that launcher lingers as a
        # zombie -- an os.kill probe would call the successful kill a failure. The
        # process state in ``/proc/<pid>/stat`` distinguishes a live process
        # ('R'/'S'/'D'...) from one already killed and only awaiting reaping
        # ('Z'/'X').
        try:
            stat = Path(f"/proc/{pid}/stat").read_text(encoding="ascii", errors="replace")
        except OSError:
            return False
        close = stat.rfind(")")
        if close < 0:
            return False
        fields = stat[close + 2 :].split()
        if not fields:
            return False
        return fields[0] not in {"Z", "X", "x"}
    handle = ctypes.windll.kernel32.OpenProcess(0x1000, False, pid)
    if not handle:
        return False
    try:
        code = ctypes.c_ulong()
        ctypes.windll.kernel32.GetExitCodeProcess(handle, ctypes.byref(code))
        return code.value == 259
    finally:
        ctypes.windll.kernel32.CloseHandle(handle)


class TestStuckToolCallsStopPilingUp:
    """A cancelled tool call does not stop running, it stops being waited for.

    Cancelling returns the limiter token while the thread carries on, so the
    next call starts at once. Measured against a backend that never answers:
    sixty timed-out calls left sixty live threads, one per call, with nothing to
    stop the next sixty -- and a mission loop retrying a wedged backend is
    exactly that shape.
    """

    def _orchestrator(self, tmp_path: Any) -> Any:
        from headless_re_mcp.agent.config import ProviderConfigStore
        from headless_re_mcp.agent.orchestrator import AgentOrchestrator
        from headless_re_mcp.agent.store import AgentStore
        from headless_re_mcp.tools.catalog import COMMAND_CATALOG

        return AgentOrchestrator(
            AgentStore(tmp_path / "agent.db"),
            COMMAND_CATALOG,
            ProviderConfigStore(tmp_path / "providers.json"),
        )

    def test_the_count_follows_the_thread_not_the_caller(self, tmp_path: Any) -> None:
        import threading

        orchestrator = self._orchestrator(tmp_path)
        release = threading.Event()
        entered = threading.Event()

        def slow(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
            del name, arguments
            entered.set()
            release.wait(10.0)
            return {"ok": True}

        from types import SimpleNamespace

        orchestrator.catalog = SimpleNamespace(invoke=slow)  # type: ignore[assignment]
        assert orchestrator.stuck_tool_threads == 0

        worker = threading.Thread(
            target=lambda: orchestrator._invoke_counted("x", {}), daemon=True
        )
        worker.start()
        assert entered.wait(5.0)
        assert orchestrator.stuck_tool_threads == 1

        release.set()
        worker.join(5.0)
        assert orchestrator.stuck_tool_threads == 0

    def test_past_the_bound_it_says_so_instead_of_adding_another(
        self, tmp_path: Any
    ) -> None:
        import asyncio

        from headless_re_mcp.agent.models import RunStatus
        from headless_re_mcp.agent.orchestrator import _MAX_STUCK_TOOL_THREADS

        orchestrator = self._orchestrator(tmp_path)
        thread = orchestrator.store.create_thread(title="stuck")
        run = orchestrator.store.create_run(
            thread.id, provider_profile="p", model="m", deadline_seconds=60.0
        )
        orchestrator.store.transition(run.id, RunStatus.STREAMING)
        orchestrator._inflight_tools = _MAX_STUCK_TOOL_THREADS

        with pytest.raises(RuntimeError, match="stuck"):
            asyncio.run(
                orchestrator._handle_tool_call(run.id, "call-1", "capabilities.search", {})
            )

        events = orchestrator.store.list_events(run.id, after=0)
        completed = [item for item in events if item.type == "tool.completed"]
        assert completed, "the refusal has to be visible in the run, not just raised"
        assert completed[-1].data["error"] == "tool_workers_stuck"


class TestATimeoutBindsWhatTheToolStarted:
    """jadx, apktool and Ghidra are scripts that start a JVM; webcrack starts node.

    ``subprocess.run(timeout=...)`` kills the process it spawned and nothing
    else. Measured here: kill a launcher and the process it started keeps
    running -- so a timed-out analysis returned its answer while an orphaned
    JVM held a core and a lock on the sample for the rest of the service's life.
    """

    def _launcher(self) -> tuple[Any, int]:
        import subprocess
        import sys

        process = subprocess.Popen(
            [sys.executable, "-c", _LAUNCHER],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        assert process.stdout is not None
        return process, int(process.stdout.readline().strip())

    def _alive(self, pid: int) -> bool:
        # Same zombie-vs-live distinction as the module-level probe: a killed but
        # unreaped process must read as dead, or a successful tree kill looks like
        # a leak in a container without a reaping init.
        return _pid_is_alive(pid)

    def test_the_process_the_launcher_started_is_killed_too(self) -> None:
        import time

        from headless_re_mcp.core.process_tree import terminate_process_tree

        process, grandchild = self._launcher()
        try:
            assert self._alive(grandchild) is True
            killed = terminate_process_tree(process)

            deadline = time.monotonic() + 5.0
            while self._alive(grandchild) and time.monotonic() < deadline:
                time.sleep(0.05)
            assert self._alive(grandchild) is False, "the launcher's child outlived the kill"
            assert grandchild in killed
        finally:
            from contextlib import suppress

            with suppress(Exception):
                process.kill()

    def test_a_pid_without_a_popen_handle_is_still_bound(self) -> None:
        import time

        from headless_re_mcp.core.process_tree import terminate_pid_tree

        process, grandchild = self._launcher()
        try:
            assert self._alive(grandchild) is True
            terminate_pid_tree(int(process.pid))
            deadline = time.monotonic() + 5.0
            while (
                self._alive(process.pid) or self._alive(grandchild)
            ) and time.monotonic() < deadline:
                time.sleep(0.05)
            assert self._alive(process.pid) is False
            assert self._alive(grandchild) is False
        finally:
            from contextlib import suppress

            with suppress(Exception):
                process.kill()

    def test_a_tool_that_overruns_is_reported_with_what_was_killed(self) -> None:
        import sys
        import time

        from headless_re_mcp.backends.common.bounded_run import TimedOut, run_bounded

        started = time.monotonic()
        with pytest.raises(TimedOut) as caught:
            run_bounded([sys.executable, "-c", _LAUNCHER], timeout=0.8)
        elapsed = time.monotonic() - started

        # Returning at all is half the point. The launcher's child inherits the
        # pipes, so killing only the launcher leaves the drain waiting for an
        # EOF that never comes -- and subprocess.run's own post-kill drain on
        # Windows has no timeout, so that wait is unbounded.
        assert elapsed < 10.0
        # The launcher and the process it started, not just the launcher.
        assert len(caught.value.killed) >= 2
        for pid in caught.value.killed:
            assert self._alive(pid) is False

    def test_a_cancel_kills_the_tool_before_the_deadline(self) -> None:
        import sys
        import time
        from threading import Event, Thread

        from headless_re_mcp.backends.common.bounded_run import (
            BoundedCancelled,
            bound_cancel_scope,
            run_bounded,
        )

        cancel = Event()

        def fire() -> None:
            time.sleep(0.2)
            cancel.set()

        Thread(target=fire, daemon=True).start()
        started = time.monotonic()
        with pytest.raises(BoundedCancelled) as caught, bound_cancel_scope(cancel):
            run_bounded([sys.executable, "-c", _LAUNCHER], timeout=20.0)
        elapsed = time.monotonic() - started
        assert elapsed < 8.0
        assert caught.value.killed
        for pid in caught.value.killed:
            assert self._alive(pid) is False

    def test_capture_process_honors_a_bound_cancel(self) -> None:
        import sys
        import time
        from threading import Event, Thread

        from headless_re_mcp.backends.common.bounded_run import (
            BoundedCancelled,
            bound_cancel_scope,
        )
        from headless_re_mcp.dotnet.de4dot import _capture_process

        cancel = Event()

        def fire() -> None:
            time.sleep(0.2)
            cancel.set()

        Thread(target=fire, daemon=True).start()
        started = time.monotonic()
        with pytest.raises(BoundedCancelled), bound_cancel_scope(cancel):
            _capture_process(
                [sys.executable, "-c", _LAUNCHER],
                timeout=20.0,
                max_output_size=4096,
            )
        assert time.monotonic() - started < 8.0

    def test_a_tool_that_finishes_in_time_is_untouched(self) -> None:
        import sys

        from headless_re_mcp.backends.common.bounded_run import run_bounded

        completed = run_bounded(
            [sys.executable, "-c", "import sys; print('done'); sys.exit(3)"], timeout=30.0
        )
        assert completed.returncode == 3
        assert completed.stdout.strip() == b"done"

    def test_a_chatty_tool_does_not_keep_an_unbounded_stdout(self) -> None:
        import sys

        from headless_re_mcp.backends.common.bounded_run import run_bounded

        completed = run_bounded(
            [
                sys.executable,
                "-c",
                "import sys; sys.stdout.buffer.write(b'x' * 2_000_000)",
            ],
            timeout=30.0,
            max_output=1000,
        )
        assert completed.returncode == 0
        assert completed.stdout == b"x" * 1000
        assert completed.stdout_truncated is True
        assert len(completed.stderr) == 0

    def test_a_launcher_that_exits_zero_does_not_kill_its_helper(self) -> None:
        import sys
        from contextlib import suppress

        from headless_re_mcp.backends.common.bounded_run import run_bounded
        from headless_re_mcp.core.process_tree import terminate_pid_tree

        completed = run_bounded(
            [sys.executable, "-c", _EXIT0_LAUNCHER],
            timeout=3.0,
            drain_s=0.4,
        )
        assert completed.returncode == 0
        child = int(completed.stdout.strip().split()[0])
        try:
            assert self._alive(child) is True
        finally:
            with suppress(Exception):
                terminate_pid_tree(child)

    def test_capture_process_kills_leftover_children(self) -> None:
        import sys
        import time
        from contextlib import suppress

        from headless_re_mcp.core.process_tree import terminate_pid_tree
        from headless_re_mcp.dotnet.de4dot import _capture_process

        capture = _capture_process(
            [sys.executable, "-c", _EXIT0_LAUNCHER],
            timeout=3.0,
            max_output_size=4096,
        )
        child = int(capture.stdout.strip().split()[0])
        try:
            deadline = time.monotonic() + 5.0
            while self._alive(child) and time.monotonic() < deadline:
                time.sleep(0.05)
            assert self._alive(child) is False
        finally:
            with suppress(Exception):
                terminate_pid_tree(child)

    @pytest.mark.parametrize(
        "module_name",
        (
            "headless_re_mcp.detection.die",
            "headless_re_mcp.detection.exeinfope",
            "headless_re_mcp.unpack.upx",
        ),
        ids=("die", "exeinfope", "upx"),
    )
    def test_successful_cli_adapters_reap_detached_helpers(self, module_name: str) -> None:
        import importlib
        import sys
        from contextlib import suppress

        from headless_re_mcp.core.process_tree import terminate_pid_tree

        module = importlib.import_module(module_name)
        capture = module._capture_process(  # type: ignore[attr-defined]
            [sys.executable, "-c", _EXIT0_LAUNCHER],
            timeout=3.0,
            max_output_size=4096,
        )
        child = int(capture.stdout.strip().split()[0])
        try:
            assert self._alive(child) is False
        finally:
            with suppress(Exception):
                terminate_pid_tree(child)


def test_kill_walk_is_not_clamped_to_the_ui_page_size() -> None:
    from headless_re_mcp.core.process_tree import (
        _MAX_CHILD_PIDS,
        _MAX_KILL_DESCENDANTS,
        _child_enum_limit,
    )

    assert _MAX_KILL_DESCENDANTS > _MAX_CHILD_PIDS
    assert _child_enum_limit(_MAX_CHILD_PIDS) == _MAX_CHILD_PIDS
    assert _child_enum_limit(_MAX_KILL_DESCENDANTS) == _MAX_KILL_DESCENDANTS
    assert _child_enum_limit(_MAX_KILL_DESCENDANTS + 10) == _MAX_KILL_DESCENDANTS


class TestOnlyAMissingSessionSaysSessionNotFound:
    """Any KeyError used to be reported as a missing session.

    A missing key while reading a backend reply, or a cache eviction race,
    therefore told an unattended caller that its session had disappeared -- and
    the reasonable response to that, recreating the session and starting the
    analysis again, is the wrong answer to a transient internal fault.
    """

    def test_a_real_missing_session_still_reports_itself(self, tmp_path: Any) -> None:
        from dataclasses import replace

        from headless_re_mcp.config import Settings
        from headless_re_mcp.core.service import AnalysisService

        settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
        service = AnalysisService(settings)
        try:
            result = service.get_session("0123456789abcdef0123456789abcdef")
            assert result.ok is False
            assert result.error is not None
            assert result.error.code == "session_not_found"
        finally:
            service.close_all()

    def test_an_ordinary_key_error_is_not_dressed_up_as_one(self) -> None:
        from headless_re_mcp.core.results import _failure

        result = _failure(KeyError("exports"))

        assert result.error is not None
        assert result.error.code == "internal_error"
        assert "KeyError" in result.error.message

    def test_the_marker_is_still_a_key_error_for_existing_handlers(self) -> None:
        """Callers all over the codebase catch KeyError for this."""
        from headless_re_mcp.core.session import SessionNotFound

        assert issubclass(SessionNotFound, KeyError)
        try:
            raise SessionNotFound("session not found: abc")
        except KeyError as exc:
            assert "session not found" in str(exc.args[0])


class TestTheApkCacheSurvivesConcurrentUse:
    """The parse cache is process-wide and reached from several threads.

    Tool calls run on a worker pool while session close calls release() on the
    same dictionaries. With the interpreter's switch interval forced low, that
    raised "OrderedDict mutated during iteration" from release and KeyError from
    the eviction path -- and KeyError is mapped to session_not_found, so the
    caller was told the wrong thing about a cache race.
    """

    def test_lookup_insert_and_release_do_not_collide(self, tmp_path: Any) -> None:
        import sys
        import threading

        from headless_re_mcp.backends.apk.client import ApkClient

        targets = []
        for index in range(6):
            target = tmp_path / f"app{index}.apk"
            target.write_bytes(b"PK\x03\x04" + bytes([index]))
            targets.append(target)

        ApkClient._light_cache.clear()
        ApkClient._full_cache.clear()
        errors: list[BaseException] = []
        barrier = threading.Barrier(6)
        previous = sys.getswitchinterval()
        sys.setswitchinterval(1e-9)

        def churn(worker: int) -> None:
            client = ApkClient()
            try:
                barrier.wait()
                for round_index in range(250):
                    target = targets[(worker + round_index) % len(targets)]
                    key = (str(target.resolve()), int(target.stat().st_mtime_ns))
                    with client._cache_lock:
                        cached = client._light_cache.get(key)
                        if cached is None:
                            client._light_cache[key] = object()
                            while len(client._light_cache) > 4:
                                client._light_cache.popitem(last=False)
                        else:
                            client._light_cache.move_to_end(key)
                    if round_index % 3 == 0:
                        ApkClient.release(targets[round_index % len(targets)])
            except BaseException as exc:  # noqa: BLE001 - recorded, then asserted
                errors.append(exc)

        threads = [threading.Thread(target=churn, args=(index,)) for index in range(6)]
        try:
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
        finally:
            sys.setswitchinterval(previous)
            ApkClient._light_cache.clear()
            ApkClient._full_cache.clear()

        assert errors == []

    def test_release_takes_the_same_lock_as_the_cache_paths(self) -> None:
        """A snapshot would hide the defect; the iteration must be inside it."""
        import inspect

        from headless_re_mcp.backends.apk.client import ApkClient

        source = inspect.getsource(ApkClient.release)
        assert "_cache_lock" in source
        for method in (ApkClient._apk, ApkClient._parsed):
            assert "_cache_lock" in inspect.getsource(method)


class TestATruncatedListSaysSo:
    """A list that stopped at the cap looks like a list that ended.

    The r2 payload keeps at most 4096 items. Nothing said when more existed, so
    an agent concluding "these are all the xrefs to this function" concluded it
    from a slice. The raw-output cut beside it already discloses itself.
    """

    def test_a_capped_item_list_reports_what_was_dropped(self, tmp_path: Any) -> None:
        import json

        from headless_re_mcp.backends.r2.mapping import _MAX_ITEMS, enrich_r2_payload

        entries = [{"offset": 0x140001000 + index} for index in range(_MAX_ITEMS + 250)]
        payload = enrich_r2_payload(
            {"raw": json.dumps(entries), "commands": ["axtj"]},
            binary=_pe_with_stub(tmp_path / "t.exe", pe_offset=0x80),
        )

        assert payload["count"] == _MAX_ITEMS
        assert payload["items_truncated"] is True
        assert payload["items_total"] == _MAX_ITEMS + 250
        assert payload["items_limit"] == _MAX_ITEMS

    def test_a_list_that_fits_is_not_labelled_truncated(self, tmp_path: Any) -> None:
        import json

        from headless_re_mcp.backends.r2.mapping import enrich_r2_payload

        entries = [{"offset": 0x140001000 + index} for index in range(12)]
        payload = enrich_r2_payload(
            {"raw": json.dumps(entries), "commands": ["axtj"]},
            binary=_pe_with_stub(tmp_path / "t.exe", pe_offset=0x80),
        )

        assert payload["count"] == 12
        assert "items_truncated" not in payload
        assert "items_total" not in payload


class TestAFindingIsEitherRecordedOrRefused:
    """Findings are what an unattended run remembers between sessions.

    The value is stored as JSON text and was cut at 8000 chars, which stops it
    being JSON: the call answered ok, and reading it back returned a string
    fragment instead of the object that was written. A later decision then
    rested on something the caller had no way to know was not what it wrote.
    """

    def _service(self, tmp_path: Any) -> Any:
        from dataclasses import replace

        from headless_re_mcp.config import Settings
        from headless_re_mcp.core.service import AnalysisService

        settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
        return AnalysisService(settings)

    def test_what_is_recorded_reads_back_identical(self, tmp_path: Any) -> None:
        service = self._service(tmp_path)
        try:
            created = service.create_session(str(_minimal_pe(tmp_path / "t.exe")))
            session_id = str(created.data["session"]["id"])
            value = {"note": "serial is H3adl3ss", "confidence": 0.9, "at": [1, 2, 3]}

            assert service.knowledge_record(session_id, "finding", "serial", value).ok
            read = service.knowledge_query(session_id, kind="finding")
            assert read.ok and read.data is not None
            entry = next(item for item in read.data["entries"] if item["key"] == "serial")
            assert entry["value"] == value
        finally:
            service.close_all()

    def test_a_finding_too_large_to_store_is_refused_not_silently_cut(
        self, tmp_path: Any
    ) -> None:
        from headless_re_mcp.core.store.sqlite_store import KNOWLEDGE_VALUE_MAX_CHARS

        service = self._service(tmp_path)
        try:
            created = service.create_session(str(_minimal_pe(tmp_path / "t.exe")))
            session_id = str(created.data["session"]["id"])
            oversized = {"decompilation": "int main(void) { return 0; }\n" * 1000}

            result = service.knowledge_record(session_id, "finding", "big", oversized)

            assert result.ok is False
            assert result.error is not None
            assert result.error.code == "invalid_request"
            assert str(KNOWLEDGE_VALUE_MAX_CHARS) in result.error.message
            # And nothing half-written was left behind to be read back later.
            read = service.knowledge_query(session_id, kind="finding")
            assert read.data is not None
            assert [item for item in read.data["entries"] if item["key"] == "big"] == []
        finally:
            service.close_all()


class TestARebuildThatWouldNotFitIsRefused:
    """Rebuilding a dump allocates several times its size.

    Measured on this code: a 64 MB dump peaked at 3.0x and a 256 MB one at 4.0x.
    A few gigabytes of dump therefore does not fail the call, it takes the
    process down, and an unattended run loses every open session with it.
    """

    def test_the_estimate_is_compared_against_memory_that_is_actually_free(self) -> None:
        from headless_re_mcp.core.limits import (
            PE_REBUILD_MEMORY_FACTOR,
            available_memory_bytes,
            rebuild_would_exhaust_memory,
        )

        free = available_memory_bytes()
        assert free is None or free > 0

        modest = 8 * 1024 * 1024
        too_big, estimate, reported = rebuild_would_exhaust_memory(modest)
        assert estimate == modest * PE_REBUILD_MEMORY_FACTOR
        assert too_big is False, "a small dump must never be refused"
        # Not compared for equality with the reading above: free memory moves
        # between two calls on any live machine.
        assert (reported is None) == (free is None)
        assert reported is None or reported > 0

        if free is None:
            pytest.skip("this platform does not report free memory (skip != pass)")
        absurd = free * 100
        verdict, _, _ = rebuild_would_exhaust_memory(absurd)
        assert verdict is True

    def test_an_unknown_memory_figure_allows_the_work(self, monkeypatch: Any) -> None:
        """Refusing on an unknown turns a limit into an outage."""
        from headless_re_mcp.core import limits

        monkeypatch.setattr(limits, "available_memory_bytes", lambda: None)
        too_big, estimate, reported = limits.rebuild_would_exhaust_memory(1 << 40)
        assert too_big is False
        assert reported is None
        assert estimate == (1 << 40) * limits.PE_REBUILD_MEMORY_FACTOR

    def test_the_rebuild_refuses_before_it_allocates(self, tmp_path: Any, monkeypatch: Any) -> None:
        from pathlib import Path

        from headless_re_mcp.core import service_unpack

        dump = tmp_path / "huge.bin"
        dump.write_bytes(b"MZ" + b"\x00" * 1024)
        monkeypatch.setattr(
            service_unpack,
            "rebuild_would_exhaust_memory",
            lambda size: (True, size * 4, 1024),
        )

        def refuse(self: Any, *args: Any, **kwargs: Any) -> bytes:
            raise AssertionError("the dump must not be read once the rebuild is refused")

        monkeypatch.setattr(Path, "read_bytes", refuse)
        result = service_unpack._refuse_rebuild_that_will_not_fit(dump)

        assert result is not None
        assert result.error is not None
        assert result.error.code == "dump_too_large"
        assert result.error.details["dump_bytes"] == 1026


class TestReadingAHeaderDoesNotReadTheTarget:
    """Every r2 tool call enriches its payload with the PE image base.

    Reading the whole target for one header field cost, measured on a 200 MB
    sample, 200 MB of RSS per call and 0.41s for the six calls one tool sweep
    makes. Targets are routinely bigger than that.
    """

    def test_the_base_is_still_parsed_for_both_architectures(self, tmp_path: Any) -> None:
        from headless_re_mcp.backends.r2.mapping import pe_preferred_base
        from headless_re_mcp.core.models import Architecture

        x64 = _pe_with_stub(tmp_path / "a.exe", pe_offset=0x80, x64=True)
        x86 = _pe_with_stub(tmp_path / "b.exe", pe_offset=0x80, x64=False)

        assert pe_preferred_base(x64) == (Architecture.X64, 0x140000000)
        assert pe_preferred_base(x86) == (Architecture.X86, 0x400000)

    def test_it_does_not_read_the_whole_file(self, tmp_path: Any, monkeypatch: Any) -> None:
        from pathlib import Path

        from headless_re_mcp.backends.r2.mapping import pe_preferred_base
        from headless_re_mcp.core.models import Architecture

        target = _pe_with_stub(tmp_path / "big.exe", pe_offset=0x80)
        with target.open("ab") as stream:
            stream.write(b"\x00" * (2 * 1024 * 1024))

        def refuse(self: Any, *args: Any, **kwargs: Any) -> bytes:
            raise AssertionError("the header must be read as a prefix, not the file")

        monkeypatch.setattr(Path, "read_bytes", refuse)
        assert pe_preferred_base(target) == (Architecture.X64, 0x140000000)

    def test_a_stub_longer_than_the_window_still_parses(self, tmp_path: Any) -> None:
        """The prefix is a window, not a limit: an unusual DOS stub re-reads."""
        from headless_re_mcp.backends.r2.mapping import _HEADER_WINDOW, pe_preferred_base
        from headless_re_mcp.core.models import Architecture

        target = _pe_with_stub(tmp_path / "stub.exe", pe_offset=_HEADER_WINDOW + 0x2000)
        assert pe_preferred_base(target) == (Architecture.X64, 0x140000000)

    def test_a_file_that_is_not_a_pe_is_answered_not_guessed(self, tmp_path: Any) -> None:
        from headless_re_mcp.backends.r2.mapping import pe_preferred_base

        plain = tmp_path / "notes.txt"
        plain.write_bytes(b"not an executable at all")
        assert pe_preferred_base(plain) == (None, None)
        assert pe_preferred_base(tmp_path / "missing.exe") == (None, None)


class TestReadingASliceDoesNotLoadTheWholeArtifact:
    """Artifacts here are process dumps and traces, not documents.

    Measured on a 200 MB dump before this: twenty paginated 256 KiB reads took
    1.44s, spiked RSS to 243 MB against a 42 MB baseline, and touched 4 GB to
    serve 5 MB, because every page re-read the file from the start. A 2 GB dump
    would not have fitted at all. After: 0.03s and under 1 MB of growth.
    """

    def _service(self, tmp_path: Any) -> Any:
        from dataclasses import replace

        from headless_re_mcp.config import Settings
        from headless_re_mcp.core.service import AnalysisService

        settings = replace(
            Settings.load(), artifact_root=tmp_path / "artifacts", artifact_max_total_bytes=0
        )
        return AnalysisService(settings)

    def test_the_slice_is_correct_and_the_file_is_not_slurped(
        self, tmp_path: Any, monkeypatch: Any
    ) -> None:
        from pathlib import Path

        service = self._service(tmp_path)
        try:
            directory = tmp_path / "artifacts" / "dump" / "big"
            directory.mkdir(parents=True, exist_ok=True)
            blob = directory / "module.bin"
            blob.write_bytes(bytes(range(256)) * 4096)
            artifact = service.record_artifact(
                session_id="big",
                kind="module_dump",
                path=blob,
                sha256="0" * 64,
                source="test",
                size=blob.stat().st_size,
            )

            def refuse(self: Any, *args: Any, **kwargs: Any) -> bytes:
                raise AssertionError("artifacts.read must not read the whole file")

            monkeypatch.setattr(Path, "read_bytes", refuse)
            result = service.artifacts_read(str(artifact["id"]), offset=300, limit=8)
            monkeypatch.undo()

            assert result.ok, result.error
            assert result.data is not None
            expected = (bytes(range(256)) * 4096)[300:308]
            assert result.data["data"] == expected.hex()
            assert result.data["size"] == 256 * 4096
        finally:
            service.close_all()

    def test_reading_past_the_end_is_an_empty_slice_not_an_error(
        self, tmp_path: Any
    ) -> None:
        service = self._service(tmp_path)
        try:
            directory = tmp_path / "artifacts" / "dump" / "small"
            directory.mkdir(parents=True, exist_ok=True)
            blob = directory / "tiny.bin"
            blob.write_bytes(b"1234")
            artifact = service.record_artifact(
                session_id="small",
                kind="module_dump",
                path=blob,
                sha256="1" * 64,
                source="test",
                size=4,
            )
            result = service.artifacts_read(str(artifact["id"]), offset=99, limit=16)
            assert result.ok, result.error
            assert result.data is not None
            assert result.data["data"] == ""
        finally:
            service.close_all()


class TestCollectionSurvivesAFileItCannotDelete:
    """On Windows an open handle makes a file undeletable, which is routine.

    A trace the debugger is still writing, a dump being copied, a scanner
    holding a screenshot. Collection always starts at the oldest artifact, so
    letting that error out of the loop meant one stuck file stopped every later
    one from ever being collected -- and because ``maybe_collect`` swallows the
    failure, the budget simply stopped being enforced with nothing said.
    """

    def _store(self, tmp_path: Any) -> Any:
        from headless_re_mcp.core.store.sqlite_store import SessionStore

        return SessionStore(tmp_path / "meta" / "sessions.db")

    def _artifact(self, store: Any, tmp_path: Any, index: int) -> Any:
        directory = tmp_path / "trace" / f"s{index}"
        directory.mkdir(parents=True, exist_ok=True)
        blob = directory / f"run-{index}.bin"
        blob.write_bytes(b"T" * 4096)
        store.register_artifact(
            session_id=f"s{index}",
            kind="run_trace",
            path=blob,
            sha256=f"{index:064d}",
            source="test",
        )
        return blob

    def test_a_locked_file_is_skipped_and_the_rest_are_still_collected(
        self, tmp_path: Any, monkeypatch: Any
    ) -> None:
        from pathlib import Path

        store = self._store(tmp_path)
        blobs = [self._artifact(store, tmp_path, index) for index in range(4)]
        stuck = blobs[0]
        real_unlink = Path.unlink

        def refuse(self: Any, *args: Any, **kwargs: Any) -> None:
            if self == stuck:
                raise PermissionError(32, "The process cannot access the file")
            real_unlink(self, *args, **kwargs)

        monkeypatch.setattr(Path, "unlink", refuse)
        result = store.gc_artifacts(max_total_bytes=1)

        assert result["skipped_count"] == 1
        assert "PermissionError" in result["skipped"][0]["reason"]
        # The oldest being stuck must not stop the ones behind it.
        assert result["count"] == 2
        assert stuck.is_file()
        assert not blobs[1].exists()
        assert not blobs[2].exists()
        # Newest is never collected.
        assert blobs[3].is_file()

    def test_rows_and_files_never_disagree_after_a_failure(
        self, tmp_path: Any, monkeypatch: Any
    ) -> None:
        """The rollback used to take back rows whose files were already gone."""
        from pathlib import Path

        store = self._store(tmp_path)
        blobs = [self._artifact(store, tmp_path, index) for index in range(4)]
        real_unlink = Path.unlink

        def refuse(self: Any, *args: Any, **kwargs: Any) -> None:
            # The *second* candidate fails, so one deletion has already happened.
            if self == blobs[1]:
                raise PermissionError(32, "The process cannot access the file")
            real_unlink(self, *args, **kwargs)

        monkeypatch.setattr(Path, "unlink", refuse)
        store.gc_artifacts(max_total_bytes=1)
        monkeypatch.undo()

        listed = store.list_artifacts(None, offset=0, limit=100)
        for item in listed["artifacts"]:
            assert Path(str(item["path"])).is_file(), item["path"]
        surviving = {Path(str(item["path"])) for item in listed["artifacts"]}
        for blob in blobs:
            if blob.exists():
                assert blob in surviving, f"{blob} has no row and nothing will reclaim it"


class TestCollectionLeavesNoEmptyDirectories:
    """Reclaiming the file is not reclaiming the tree.

    Measured over 150 sessions with one capture each: collection freed the
    files and left 142 empty per-session directories behind, one per session,
    which every disk-usage walk then visits forever. At a few hundred sessions
    a day that is tens of thousands of directory entries standing in for
    nothing.
    """

    def test_the_directory_of_a_collected_artifact_goes_with_it(
        self, tmp_path: Any
    ) -> None:
        from pathlib import Path

        from headless_re_mcp.core.store.sqlite_store import SessionStore

        root = tmp_path / "artifacts"
        store = SessionStore(root / "meta" / "sessions.db")
        kept: Any = None
        directories = []
        for index in range(3):
            directory = root / "ui" / f"session-{index}"
            directory.mkdir(parents=True, exist_ok=True)
            directories.append(directory)
            blob = directory / "screenshot.bmp"
            blob.write_bytes(b"BM" + b"\x00" * 4096)
            kept = store.register_artifact(
                session_id=f"session-{index}",
                kind="ui_screenshot",
                path=blob,
                sha256=f"{index:064d}",
                source="test",
            )

        store.gc_artifacts(max_total_bytes=1)

        # The newest survives by design, and so does the directory holding it.
        assert Path(str(kept["path"])).is_file()
        assert directories[-1].is_dir()
        assert not directories[0].exists()
        assert not directories[1].exists()
        # Never the root or the database's own directory.
        assert root.is_dir()
        assert (root / "meta").is_dir()

    def test_a_directory_that_still_holds_something_is_left_alone(
        self, tmp_path: Any
    ) -> None:
        from headless_re_mcp.core.store.sqlite_store import SessionStore

        root = tmp_path / "artifacts"
        store = SessionStore(root / "meta" / "sessions.db")
        directory = root / "ui" / "shared"
        directory.mkdir(parents=True, exist_ok=True)
        collected = directory / "old.bmp"
        collected.write_bytes(b"BM" + b"\x00" * 4096)
        neighbour = directory / "not-an-artifact.txt"
        neighbour.write_text("evidence nobody registered", encoding="utf-8")

        store.register_artifact(
            session_id="shared",
            kind="ui_screenshot",
            path=collected,
            sha256="0" * 64,
            source="test",
        )
        newest = root / "ui" / "newest"
        newest.mkdir(parents=True, exist_ok=True)
        latest = newest / "new.bmp"
        latest.write_bytes(b"BM")
        store.register_artifact(
            session_id="newest", kind="ui_screenshot", path=latest, sha256="1" * 64, source="test"
        )

        store.gc_artifacts(max_total_bytes=1)

        assert not collected.exists()
        assert neighbour.is_file(), "an unregistered file must not be swept up with its neighbour"
        assert directory.is_dir()


class TestSessionChurnStaysBounded:
    """The shape of an unattended run: sessions open and close all day.

    Everything here was verified once by hand with a soak harness -- 600 cycles
    cost 1 MB of RSS and no threads or handles -- and this is the cheap standing
    version of that, so the property is checked on every run rather than the day
    someone remembers to soak it again.
    """

    def test_repeated_cycles_leave_no_threads_and_a_bounded_artifact_root(
        self, tmp_path: Any
    ) -> None:
        import threading
        import zipfile
        from dataclasses import replace

        from headless_re_mcp.config import Settings
        from headless_re_mcp.core.retention import measure_usage
        from headless_re_mcp.core.service import AnalysisService

        budget = 1_000_000
        settings = replace(
            Settings.load(),
            artifact_root=tmp_path / "artifacts",
            artifact_max_total_bytes=budget,
        )
        service = AnalysisService(settings)
        root = (tmp_path / "artifacts").resolve()
        apk = tmp_path / "app.apk"
        with zipfile.ZipFile(apk, "w") as archive:
            archive.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00m")

        threads_before = threading.active_count()
        blob = tmp_path / "capture.bin"
        blob.write_bytes(b"\x00" * (64 * 1024))
        try:
            for index in range(120):
                created = service.create_session(str(apk), target="apk")
                assert created.data is not None
                session_id = str(created.data["session"]["id"])
                copy = root / "ui" / session_id / "screenshot.bmp"
                copy.parent.mkdir(parents=True, exist_ok=True)
                copy.write_bytes(blob.read_bytes())
                service.record_artifact(
                    session_id=session_id,
                    kind="ui_screenshot",
                    path=copy,
                    sha256=f"{index:064d}",
                    source="soak",
                    size=copy.stat().st_size,
                )
                service.timeline_list(session_id)
                closed = service.close_session(session_id)
                assert closed.ok, closed.error

            assert threading.active_count() == threads_before
            usage = measure_usage(root)
            # 7.7 MB written against a 1 MB budget.
            assert usage.bytes < 3 * budget
        finally:
            service.close_all()


class TestUnregisteredCaptureDirsStayCapped:
    def test_oldest_files_go_when_the_count_is_passed(self, tmp_path: Any) -> None:
        from headless_re_mcp.core.limits import prune_capped_dir

        root = tmp_path / "device"
        root.mkdir()
        for index in range(10):
            path = root / f"{index}.png"
            path.write_bytes(b"x" * 10)
            os.utime(path, (index + 1, index + 1))
        removed = prune_capped_dir(root, max_entries=4, max_bytes=10_000)
        assert removed == 6
        assert sorted(path.name for path in root.iterdir()) == ["6.png", "7.png", "8.png", "9.png"]

    def test_the_newest_file_is_kept_even_when_it_alone_exceeds_the_budget(
        self, tmp_path: Any
    ) -> None:
        from headless_re_mcp.core.limits import prune_capped_dir

        root = tmp_path / "device"
        root.mkdir()
        huge = root / "huge.bin"
        huge.write_bytes(b"x" * 1000)
        prune_capped_dir(root, max_entries=8, max_bytes=100)
        assert huge.is_file(), "deleting the file just written is the bug this exists to prevent"

    def test_oldest_directories_go_the_same_way(self, tmp_path: Any) -> None:
        from headless_re_mcp.core.limits import prune_capped_dir

        root = tmp_path / "jsre"
        root.mkdir()
        for index in range(6):
            folder = root / f"unpack-{index}"
            folder.mkdir()
            (folder / "out.js").write_text("x", encoding="utf-8")
            os.utime(folder, (index + 1, index + 1))
        prune_capped_dir(root, max_entries=2, max_bytes=10_000)
        left = sorted(path.name for path in root.iterdir())
        assert left == ["unpack-4", "unpack-5"]


class TestAdbForwardsAreReleased:
    def test_a_successful_forward_is_remembered(self) -> None:
        from headless_re_mcp.backends.adb.client import AdbBackend

        backend = AdbBackend()

        class Dev:
            def forward(self, local: str, remote: str) -> None:
                del local, remote

        backend._device = lambda serial: Dev()  # type: ignore[method-assign]
        result = backend.forward("emulator-5554", "tcp:27042", "tcp:27042")
        assert result["local"] == "tcp:27042"
        assert backend._forwards == [("emulator-5554", "tcp:27042")]

    def test_new_forwards_are_refused_once_the_table_is_full(
        self, monkeypatch: Any
    ) -> None:
        from headless_re_mcp.backends.adb import client as mod

        monkeypatch.setattr(mod, "_MAX_FORWARDS", 2)

        class Dev:
            def forward(self, local: str, remote: str) -> None:
                del local, remote

        backend = mod.AdbBackend()
        backend._device = lambda serial: Dev()  # type: ignore[method-assign]
        backend.forward("emulator-5554", "tcp:1", "tcp:1")
        backend.forward("emulator-5554", "tcp:2", "tcp:2")
        with pytest.raises(mod.AdbError) as caught:
            backend.forward("emulator-5554", "tcp:3", "tcp:3")
        assert caught.value.code == "invalid_state"
        assert backend._forwards == [
            ("emulator-5554", "tcp:1"),
            ("emulator-5554", "tcp:2"),
        ]

    def test_a_failed_forward_is_not_kept_in_the_table(self) -> None:
        from headless_re_mcp.backends.adb.client import AdbBackend, AdbError

        class Dev:
            def forward(self, local: str, remote: str) -> None:
                raise RuntimeError("adb refused")

        backend = AdbBackend()
        backend._device = lambda serial: Dev()  # type: ignore[method-assign]
        with pytest.raises(AdbError) as caught:
            backend.forward("emulator-5554", "tcp:1", "tcp:1")
        assert caught.value.code == "backend_error"
        assert backend._forwards == []

    def test_a_device_lookup_failure_does_not_consume_a_forward_slot(self) -> None:
        from headless_re_mcp.backends.adb.client import AdbBackend, AdbError

        backend = AdbBackend()

        def boom(serial: str) -> Any:
            del serial
            raise AdbError("capability_unavailable", "adbutils is not installed")

        backend._device = boom  # type: ignore[method-assign]
        with pytest.raises(AdbError) as caught:
            backend.forward("emulator-5554", "tcp:1", "tcp:1")
        assert caught.value.code == "capability_unavailable"
        assert backend._forwards == []

    def test_release_removes_every_forward_this_process_created(self) -> None:
        from headless_re_mcp.backends.adb.client import AdbBackend

        backend = AdbBackend()
        removed: list[str] = []

        class Dev:
            def forward_remove(self, local: str) -> None:
                removed.append(local)

        backend._device = lambda serial: Dev()  # type: ignore[method-assign]
        backend._forwards = [("emu", "tcp:1"), ("emu", "tcp:2")]
        result = backend.release_forwards()
        assert result["count"] == 2
        assert removed == ["tcp:1", "tcp:2"]
        assert backend._forwards == []

    def test_a_failed_release_is_remembered_for_the_next_attempt(self) -> None:
        from headless_re_mcp.backends.adb.client import AdbBackend

        class Dev:
            def forward_remove(self, local: str) -> None:
                raise RuntimeError(f"device offline ({local})")

        backend = AdbBackend()
        backend._device = lambda serial: Dev()  # type: ignore[method-assign]
        backend._forwards = [("emu", "tcp:1"), ("emu", "tcp:2")]
        result = backend.release_forwards()
        assert result["count"] == 0
        assert len(result["failed"]) == 2
        assert backend._forwards == [("emu", "tcp:1"), ("emu", "tcp:2")]

    def test_close_all_asks_the_owned_backend_to_release(self) -> None:
        from headless_re_mcp.core.service import AnalysisService

        service = AnalysisService()
        called: list[bool] = []
        service._adb_backend.release_forwards = lambda: called.append(True) or {  # type: ignore[method-assign]
            "removed": [],
            "failed": [],
            "count": 0,
        }
        try:
            service.close_all()
            assert called == [True]
        finally:
            pass

    def test_ca_install_and_frida_ensure_use_the_owned_backend(self, tmp_path: Any) -> None:
        from dataclasses import replace

        from headless_re_mcp.config import Settings
        from headless_re_mcp.core.service import AnalysisService

        settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
        service = AnalysisService(settings)
        try:
            created = service.create_session("https://example.com", target="web")
            assert created.data is not None
            session_id = str(created.data["session"]["id"])
            pushed: list[tuple[str, str]] = []
            ensured: list[str] = []
            cert = tmp_path / "mitmproxy-ca-cert.pem"
            cert.write_text("x", encoding="utf-8")
            service._adb_backend.push = (  # type: ignore[method-assign]
                lambda serial, local_path, remote_path: pushed.append((serial, remote_path))
                or {"local": local_path, "remote": remote_path}
            )
            service._proxy_backend.ca_cert_path = lambda: cert  # type: ignore[method-assign]
            result = service.proxy_ca_install_android(session_id, "emulator-5554")
            assert result.ok
            assert pushed == [("emulator-5554", "/data/local/tmp/mitmproxy-ca-cert.pem")]

            service._adb_backend.ensure_frida_server = (  # type: ignore[method-assign]
                lambda serial, server_binary=None, port=27042: ensured.append(serial)
                or {"running": True, "pushed": False, "port": port}
            )
            result = service.frida_server_ensure(session_id, "emulator-5554")
            assert result.ok
            assert ensured == ["emulator-5554"]
        finally:
            service.close_all()


class TestUnpackProbesKillWhatTheyStart:
    def test_scylla_timeout_is_not_availability_after_the_tree_is_dead(
        self, tmp_path: Any, monkeypatch: Any
    ) -> None:
        from headless_re_mcp.backends.common.bounded_run import TimedOut
        from headless_re_mcp.unpack import scylla as mod

        seen: list[list[str]] = []

        def fake_run(cmd: list[str], **kwargs: Any) -> Any:
            del kwargs
            seen.append(cmd)
            raise TimedOut(0.5, [11, 22])

        monkeypatch.setattr(mod, "run_bounded", fake_run)
        exe = tmp_path / "Scylla.exe"
        exe.write_bytes(b"MZ")
        ok, output = mod.probe_scylla(exe, timeout=0.5)
        assert ok is False
        assert output == "timeout_after_start"
        assert seen == [[str(exe)]]

    def test_xvlkc_timeout_is_not_availability(self, tmp_path: Any, monkeypatch: Any) -> None:
        from headless_re_mcp.backends.common.bounded_run import TimedOut
        from headless_re_mcp.unpack import xvlkc as mod

        def fake_run(cmd: list[str], **kwargs: Any) -> Any:
            del cmd, kwargs
            raise TimedOut(0.5, [])

        monkeypatch.setattr(mod, "run_bounded", fake_run)
        exe = tmp_path / "xvlkc.exe"
        exe.write_bytes(b"MZ")
        ok, output = mod.probe_xvlkc(exe, timeout=0.5)
        assert ok is False
        assert output == ""

    def test_de4dot_timeout_does_not_count_as_a_hanging_probe(
        self, tmp_path: Any, monkeypatch: Any
    ) -> None:
        from headless_re_mcp.backends.common.bounded_run import TimedOut
        from headless_re_mcp.dotnet import de4dot as mod

        def fake_run(cmd: list[str], **kwargs: Any) -> Any:
            del cmd, kwargs
            raise TimedOut(0.5, [])

        monkeypatch.setattr(mod, "run_bounded", fake_run)
        exe = tmp_path / "de4dot.exe"
        exe.write_bytes(b"MZ")
        ok, output = mod.probe_de4dot_version(exe, timeout=0.5)
        assert ok is False
        assert output == ""


class TestDeviceListsDiscloseTruncation:
    """pm list / getprop used to return everything they found, or cut silently.

    A busy emulator easily has more packages than an agent should ingest in one
    reply, and a cap with no has_more is the same lie as the r2/frida lists:
    the caller concludes "that is all of them".
    """

    def _backend(self, raw: str) -> Any:
        from headless_re_mcp.backends.adb.client import AdbBackend

        class Dev:
            def shell(self, args: Any, timeout: float | None = None) -> str:
                del args, timeout
                return raw

        backend = AdbBackend()
        backend._device = lambda serial: Dev()  # type: ignore[method-assign]
        return backend

    def test_a_package_list_past_the_cap_says_so(self) -> None:
        raw = "\n".join(f"package:com.app{index}" for index in range(20))
        result = self._backend(raw).packages("emulator-5554", limit=5)
        assert result["count"] == 5
        assert result["has_more"] is True
        assert len(result["packages"]) == 5

    def test_a_package_list_that_fits_is_not_labelled_truncated(self) -> None:
        raw = "\n".join(f"package:com.app{index}" for index in range(5))
        result = self._backend(raw).packages("emulator-5554", limit=5)
        assert result["count"] == 5
        assert result["has_more"] is False

    def test_properties_past_the_cap_say_so(self) -> None:
        raw = "\n".join(f"[ro.item{index}]: [{index}]" for index in range(12))
        result = self._backend(raw).properties("emulator-5554", limit=4)
        assert result["count"] == 4
        assert result["has_more"] is True
        assert "ro.item4" not in result["properties"]

    def test_frida_application_list_past_the_cap_says_so(self) -> None:
        from headless_re_mcp.backends.frida.client import FridaClient

        class App:
            def __init__(self, index: int) -> None:
                self.identifier = f"com.app{index}"
                self.name = str(index)
                self.pid = 0

        class Dev:
            def enumerate_applications(self) -> list[App]:
                return [App(index) for index in range(10)]

        client = FridaClient()
        client._resolve_device = lambda device_id: Dev()  # type: ignore[method-assign]
        result = client.applications("usb", limit=3)
        assert result["count"] == 3
        assert result["total"] == 10
        assert result["has_more"] is True

    def test_a_failed_resume_kills_the_spawned_pid(self) -> None:
        from headless_re_mcp.backends.frida.client import FridaClient, FridaError

        killed: list[int] = []

        class Dev:
            def spawn(self, argv: list[str]) -> int:
                del argv
                return 4242

            def resume(self, pid: int) -> None:
                del pid
                raise RuntimeError("not permitted")

            def kill(self, pid: int) -> None:
                killed.append(pid)

        client = FridaClient()
        client._resolve_device = lambda device_id: Dev()  # type: ignore[method-assign]
        with pytest.raises(FridaError) as caught:
            client.spawn("usb", "com.example.app")
        assert caught.value.details["pid"] == 4242
        assert killed == [4242]
        assert "resume failed" in caught.value.message

    def test_native_libs_past_the_cap_say_so(self, tmp_path: Any) -> None:
        from headless_re_mcp.backends.apk.client import _MAX_NATIVE_LIBS, ApkClient

        class FakeApk:
            def get_files(self) -> list[str]:
                return [f"lib/arm64-v8a/lib{index}.so" for index in range(_MAX_NATIVE_LIBS + 40)]

        client = ApkClient()
        client._apk = lambda path: FakeApk()  # type: ignore[method-assign]
        result = client.native_libs(tmp_path / "app.apk")
        assert result["count"] == _MAX_NATIVE_LIBS
        assert result["has_more"] is True
        assert len(result["native_libs"]) == _MAX_NATIVE_LIBS

    def test_apk_strings_do_not_materialise_an_unbounded_set(
        self, tmp_path: Any, monkeypatch: Any
    ) -> None:
        from headless_re_mcp.backends.apk import client as mod

        monkeypatch.setattr(mod, "_MAX_STRINGS_COLLECT", 8)

        class Item:
            def __init__(self, value: str) -> None:
                self._value = value

            def get_value(self) -> str:
                return self._value

        class Analysis:
            def get_strings(self) -> list[Item]:
                return [Item(f"s{index:04d}") for index in range(40)]

        class Parsed:
            analysis = Analysis()

        client = mod.ApkClient()
        client._parsed = lambda path: Parsed()  # type: ignore[method-assign]
        result = client.strings(tmp_path / "app.apk", offset=0, limit=3)
        assert result["count"] == 3
        assert result["total"] == 8
        assert result["has_more"] is True
        assert result["scan_capped"] is True
        exhausted = client.strings(tmp_path / "app.apk", offset=8, limit=3)
        assert exhausted["count"] == 0
        assert exhausted["has_more"] is False
        assert exhausted["scan_capped"] is True

    def test_apk_classes_do_not_materialise_an_unbounded_name_list(
        self, tmp_path: Any, monkeypatch: Any
    ) -> None:
        from headless_re_mcp.backends.apk import client as mod

        monkeypatch.setattr(mod, "_MAX_CLASSES_COLLECT", 6)

        class Klass:
            def __init__(self, name: str) -> None:
                self.name = name

            def is_external(self) -> bool:
                return False

        class Analysis:
            def get_classes(self) -> list[Klass]:
                return [Klass(f"Lfoo/C{index};") for index in range(20)]

        class Parsed:
            analysis = Analysis()

        client = mod.ApkClient()
        client._parsed = lambda path: Parsed()  # type: ignore[method-assign]
        result = client.classes(tmp_path / "app.apk", offset=0, limit=2)
        assert result["count"] == 2
        assert result["total"] == 6
        assert result["has_more"] is True
        assert result["scan_capped"] is True
        exhausted = client.classes(tmp_path / "app.apk", offset=6, limit=2)
        assert exhausted["count"] == 0
        assert exhausted["has_more"] is False
        assert exhausted["scan_capped"] is True

    def test_apk_methods_stop_collecting_at_the_cap(
        self, tmp_path: Any, monkeypatch: Any
    ) -> None:
        from headless_re_mcp.backends.apk import client as mod

        monkeypatch.setattr(mod, "_MAX_METHODS_COLLECT", 5)

        class Method:
            def __init__(self, name: str) -> None:
                self.name = name
                self.descriptor = "()V"
                self.access = "public"

        class Klass:
            name = "Lfoo/C;"

            def get_methods(self) -> list[Method]:
                return [Method(f"m{index}") for index in range(20)]

        class Analysis:
            def get_classes(self) -> list[Klass]:
                return [Klass()]

        class Parsed:
            analysis = Analysis()

        client = mod.ApkClient()
        client._parsed = lambda path: Parsed()  # type: ignore[method-assign]
        result = client.methods(tmp_path / "app.apk", "Lfoo/C;", offset=0, limit=3)
        assert result["count"] == 3
        assert result["total"] == 5
        assert result["has_more"] is True
        assert result["scan_capped"] is True
        exhausted = client.methods(tmp_path / "app.apk", "Lfoo/C;", offset=5, limit=3)
        assert exhausted["count"] == 0
        assert exhausted["has_more"] is False
        assert exhausted["scan_capped"] is True

    def test_components_past_the_cap_say_so(self, tmp_path: Any) -> None:
        from headless_re_mcp.backends.apk.client import _MAX_COMPONENT_NAMES, ApkClient

        class FakeApk:
            def get_activities(self) -> list[str]:
                return [f"A{index}" for index in range(_MAX_COMPONENT_NAMES + 10)]

            def get_services(self) -> list[str]:
                return ["S"]

            def get_receivers(self) -> list[str]:
                return []

            def get_providers(self) -> list[str]:
                return []

            def get_main_activity(self) -> str:
                return "A0"

        client = ApkClient()
        client._apk = lambda path: FakeApk()  # type: ignore[method-assign]
        result = client.components(tmp_path / "app.apk")
        assert len(result["activities"]) == _MAX_COMPONENT_NAMES
        assert result["has_more"] is True
        assert result["main_activity"] == "A0"

    def test_a_cut_manifest_says_it_was_cut(self, tmp_path: Any) -> None:
        from headless_re_mcp.backends.apk.client import _MAX_MANIFEST_CHARS, ApkClient

        class Body:
            def get_xml(self) -> bytes:
                return b"<manifest/>" * ((_MAX_MANIFEST_CHARS // 10) + 20)

        class FakeApk:
            def get_android_manifest_axml(self) -> Body:
                return Body()

            def get_package(self) -> str:
                return "com.example.app"

        client = ApkClient()
        client._apk = lambda path: FakeApk()  # type: ignore[method-assign]
        result = client.manifest(tmp_path / "app.apk")
        assert result["truncated"] is True
        assert len(result["manifest_xml"]) == _MAX_MANIFEST_CHARS
        assert result["package"] == "com.example.app"


class TestExportedFileListsDiscloseTruncation:
    def test_jadx_source_list_past_the_cap_says_so(
        self, tmp_path: Any, monkeypatch: Any
    ) -> None:
        from headless_re_mcp.backends.jadx import client as mod

        monkeypatch.setattr(mod, "_MAX_LISTED_FILES", 4)
        out = tmp_path / "out"
        sources = out / "sources"
        sources.mkdir(parents=True)
        for index in range(6):
            (sources / f"C{index}.java").write_text("class C {}", encoding="utf-8")
        client = mod.JadxClient(tmp_path / "jadx.bat")
        (tmp_path / "jadx.bat").write_text("x", encoding="utf-8")
        client._run = lambda *args, **kwargs: ("", "", 0)  # type: ignore[method-assign]
        result = client.export_sources(tmp_path / "app.apk", out)
        assert result["java_file_count"] == 6
        assert len(result["java_files"]) == 4
        assert result["has_more"] is True

    def test_jadx_decompile_does_not_return_a_homonym_class(self, tmp_path: Any) -> None:
        from headless_re_mcp.backends.jadx import client as mod
        from headless_re_mcp.backends.jadx.client import JadxError

        out = tmp_path / "out"
        foo = out / "sources" / "com" / "foo"
        bar = out / "sources" / "com" / "bar"
        foo.mkdir(parents=True)
        bar.mkdir(parents=True)
        (foo / "Main.java").write_text("package com.foo; class Main {}", encoding="utf-8")
        (bar / "Main.java").write_text("package com.bar; class Main {}", encoding="utf-8")
        client = mod.JadxClient(tmp_path / "jadx.bat")
        (tmp_path / "jadx.bat").write_text("x", encoding="utf-8")
        client._run = lambda *args, **kwargs: ("", "", 0)  # type: ignore[method-assign]
        found = client.decompile(tmp_path / "app.apk", out, "com.foo.Main")
        assert found["path"].replace("\\", "/").endswith("sources/com/foo/Main.java")
        with pytest.raises(JadxError) as caught:
            client.decompile(tmp_path / "app.apk", out, "com.missing.Main")
        assert caught.value.code == "not_found"

    def test_webcrack_unpack_list_past_the_cap_says_so(
        self, tmp_path: Any, monkeypatch: Any
    ) -> None:
        from headless_re_mcp.backends.jsre import client as mod

        monkeypatch.setattr(mod, "_MAX_LISTED_FILES", 3)
        monkeypatch.setattr(
            mod.JsClient,
            "_require_input",
            lambda self, path: path,
        )
        monkeypatch.setattr(mod, "_run", lambda cmd, timeout: ("", "", 0))
        out = tmp_path / "unpacked"
        out.mkdir()
        for index in range(5):
            (out / f"{index}.js").write_text("x", encoding="utf-8")
        result = mod.JsClient(tmp_path / "webcrack").unpack_bundle(
            tmp_path / "app.js", out, offset=0, limit=3
        )
        assert result["file_count"] == 5
        assert result["total"] == 5
        assert result["count"] == 3
        assert len(result["files"]) == 3
        assert result["has_more"] is True


class TestGhidraExportDisclosesTruncation:
    def test_the_headless_script_marks_cut_lists_and_cut_decompilation(self) -> None:
        from pathlib import Path

        from headless_re_mcp.backends.ghidra import client as ghidra

        script = Path(ghidra.__file__).resolve().parent / "scripts" / "ExportJson.py"
        text = script.read_text(encoding="utf-8")
        assert 'payload["has_more"] = True' in text
        assert 'payload["truncated"] = len(text) > 200000' in text


class TestAdbShellCallsAreBounded:
    def test_a_stalled_shell_is_a_timeout_not_a_hung_worker(self) -> None:
        from headless_re_mcp.backends.adb.client import AdbBackend, AdbError

        seen: list[float | None] = []

        class Dev:
            def shell(self, args: Any, timeout: float | None = None) -> str:
                del args
                seen.append(timeout)
                raise TimeoutError("device stalled")

        backend = AdbBackend()
        backend._device = lambda serial: Dev()  # type: ignore[method-assign]
        with pytest.raises(AdbError) as caught:
            backend.packages("emulator-5554")
        assert caught.value.code == "timeout"
        assert seen == [30.0]

    def test_older_adbutils_without_a_timeout_argument_still_runs(self) -> None:
        from headless_re_mcp.backends.adb.client import AdbBackend

        class Dev:
            def shell(self, args: Any) -> str:
                del args
                return "package:com.example.app"

        backend = AdbBackend()
        backend._device = lambda serial: Dev()  # type: ignore[method-assign]
        result = backend.packages("emulator-5554")
        assert result["packages"] == ["com.example.app"]
        assert result["has_more"] is False

    def test_a_type_error_from_shell_is_not_retried_without_a_deadline(self) -> None:
        from headless_re_mcp.backends.adb.client import AdbBackend, AdbError

        seen: list[float | None] = []

        class Dev:
            def shell(self, args: Any, timeout: float | None = None) -> str:
                del args
                seen.append(timeout)
                raise TypeError("internal")

        backend = AdbBackend()
        backend._device = lambda serial: Dev()  # type: ignore[method-assign]
        with pytest.raises(AdbError) as caught:
            backend.packages("emulator-5554")
        assert caught.value.code == "backend_error"
        assert seen == [30.0]


class TestFridaServerEnsureIsHonest:
    def test_a_launch_that_does_not_show_in_ps_is_not_reported_running(self) -> None:
        from headless_re_mcp.backends.adb.client import AdbBackend

        class Dev:
            def shell(self, args: Any, timeout: float | None = None) -> str:
                del timeout
                if isinstance(args, str) and args.startswith("su"):
                    return ""
                return "root 1 init"

        backend = AdbBackend()
        backend._device = lambda serial: Dev()  # type: ignore[method-assign]
        result = backend.ensure_frida_server("emulator-5554")
        assert result["running"] is False
        assert "not visible" in str(result.get("note", ""))

    def test_an_already_running_server_is_left_alone(self) -> None:
        from headless_re_mcp.backends.adb.client import AdbBackend

        class Dev:
            def shell(self, args: Any, timeout: float | None = None) -> str:
                del timeout
                return "root 99 /data/local/tmp/frida-server"

        backend = AdbBackend()
        backend._device = lambda serial: Dev()  # type: ignore[method-assign]
        result = backend.ensure_frida_server("emulator-5554")
        assert result == {"running": True, "pushed": False, "port": 27042}


class TestDeviceLaunchIsHonest:
    def test_monkey_without_the_app_in_foreground_is_not_reported_launched(self) -> None:
        from headless_re_mcp.backends.adb.client import AdbBackend

        class Current:
            package = "com.other.app"
            activity = "Other"

        class Dev:
            def shell(self, args: Any, timeout: float | None = None) -> str:
                del args, timeout
                return ""

            def app_current(self, timeout: float | None = None) -> Current:
                del timeout
                return Current()

        backend = AdbBackend()
        backend._device = lambda serial: Dev()  # type: ignore[method-assign]
        result = backend.launch("emulator-5554", "com.example.app")
        assert result["launched"] is False
        assert result["foreground"] == "com.other.app"

    def test_the_foreground_package_matching_is_reported_launched(self) -> None:
        from headless_re_mcp.backends.adb.client import AdbBackend

        class Current:
            package = "com.example.app"
            activity = "Main"

        class Dev:
            def shell(self, args: Any, timeout: float | None = None) -> str:
                del args, timeout
                return ""

            def app_current(self, timeout: float | None = None) -> Current:
                del timeout
                return Current()

        backend = AdbBackend()
        backend._device = lambda serial: Dev()  # type: ignore[method-assign]
        result = backend.launch("emulator-5554", "com.example.app")
        assert result["launched"] is True
        assert result["foreground"] == "com.example.app"


class TestAdbHostCallsAreBounded:
    def test_list_devices_passes_a_socket_timeout_to_the_client(self) -> None:
        from headless_re_mcp.backends.adb.client import _ADB_PROBE_TIMEOUT_S, AdbBackend

        seen: dict[str, float | None] = {}

        class FakeAdb:
            class AdbClient:
                def __init__(
                    self,
                    host: str = "127.0.0.1",
                    port: int = 5037,
                    socket_timeout: float | None = None,
                ) -> None:
                    del host, port
                    seen["socket_timeout"] = socket_timeout

                def list(self) -> list[Any]:
                    return []

        backend = AdbBackend()
        backend._available = True
        backend._adbutils = FakeAdb
        result = backend.list_devices()
        assert seen["socket_timeout"] == _ADB_PROBE_TIMEOUT_S
        assert result == {"devices": [], "count": 0, "has_more": False}

    def test_list_includes_offline_devices_and_does_not_probe_get_state(self) -> None:
        from headless_re_mcp.backends.adb.client import AdbBackend

        class Info:
            def __init__(self, serial: str, state: str) -> None:
                self.serial = serial
                self.state = state

        class FakeAdb:
            class AdbClient:
                def __init__(self, **kwargs: Any) -> None:
                    del kwargs

                def list(self) -> list[Info]:
                    return [Info("emulator-5554", "offline"), Info("ZY223KDTM7", "device")]

                def device(self, serial: str | None = None) -> None:
                    del serial
                    raise AssertionError("list must not fall back to per-device get_state")

        backend = AdbBackend()
        backend._available = True
        backend._adbutils = FakeAdb
        result = backend.list_devices()
        assert result["count"] == 2
        assert result["devices"][0]["state"] == "offline"
        assert result["has_more"] is False

    def test_open_transport_default_is_not_ten_minutes(self) -> None:
        from headless_re_mcp.backends.adb.client import (
            _ADB_TRANSPORT_TIMEOUT_S,
            _bind_open_transport,
        )

        seen: list[float | None] = []

        class Dev:
            def open_transport(self, command: Any = None, timeout: float = 600.0) -> str:
                del command
                seen.append(timeout)
                return "ok"

        bound = _bind_open_transport(Dev(), _ADB_TRANSPORT_TIMEOUT_S)
        bound.open_transport()
        assert seen == [_ADB_TRANSPORT_TIMEOUT_S]


class TestDeviceInstallUninstallAreHonest:
    def test_install_that_does_not_show_in_pm_path_is_not_success(
        self, tmp_path: Any, monkeypatch: Any
    ) -> None:
        from headless_re_mcp.backends.adb import client as mod

        apk = tmp_path / "app.apk"
        apk.write_bytes(b"PK\x03\x04")
        monkeypatch.setattr(mod, "_apk_package_name", lambda path: "com.example.app")

        class Sync:
            def push(self, *args: Any, **kwargs: Any) -> None:
                del args, kwargs

        class Dev:
            sync = Sync()

            def install(self, path: str, **kwargs: Any) -> None:
                del path, kwargs

            def shell(self, args: Any, timeout: float | None = None) -> str:
                del args, timeout
                return ""

        backend = mod.AdbBackend()
        backend._device = lambda serial: Dev()  # type: ignore[method-assign]
        result = backend.install("emulator-5554", str(apk))
        assert result["installed"] is False
        assert result["package"] == "com.example.app"
        assert "not visible" in str(result.get("note", ""))

    def test_install_visible_to_pm_path_is_success(
        self, tmp_path: Any, monkeypatch: Any
    ) -> None:
        from headless_re_mcp.backends.adb import client as mod

        apk = tmp_path / "app.apk"
        apk.write_bytes(b"PK\x03\x04")
        monkeypatch.setattr(mod, "_apk_package_name", lambda path: "com.example.app")

        class Dev:
            def install(self, path: str, **kwargs: Any) -> None:
                del path, kwargs

            def shell(self, args: Any, timeout: float | None = None) -> str:
                del timeout
                if args == ["pm", "path", "com.example.app"]:
                    return "package:/data/app/com.example.app/base.apk"
                return ""

        backend = mod.AdbBackend()
        backend._device = lambda serial: Dev()  # type: ignore[method-assign]
        result = backend.install("emulator-5554", str(apk))
        assert result["installed"] is True
        assert result["package"] == "com.example.app"

    def test_uninstall_that_leaves_pm_path_is_not_success(self) -> None:
        from headless_re_mcp.backends.adb.client import AdbBackend

        class Dev:
            def uninstall(self, package: str, timeout: float | None = None) -> None:
                del package, timeout

            def shell(self, args: Any, timeout: float | None = None) -> str:
                del timeout
                if isinstance(args, list) and args[:2] == ["pm", "path"]:
                    return "package:/data/app/still/base.apk"
                return ""

        backend = AdbBackend()
        backend._device = lambda serial: Dev()  # type: ignore[method-assign]
        result = backend.uninstall("emulator-5554", "com.example.app")
        assert result["uninstalled"] is False
        assert "still visible" in str(result.get("note", ""))


class TestDeviceForceStopIsHonest:
    def test_a_process_still_in_pidof_is_not_reported_stopped(self) -> None:
        from headless_re_mcp.backends.adb.client import AdbBackend

        class Dev:
            def shell(self, args: Any, timeout: float | None = None) -> str:
                del timeout
                if isinstance(args, list) and args[:1] == ["pidof"]:
                    return "4242"
                return ""

        backend = AdbBackend()
        backend._device = lambda serial: Dev()  # type: ignore[method-assign]
        result = backend.force_stop("emulator-5554", "com.example.app")
        assert result["stopped"] is False
        assert result["remaining_pids"] == [4242]

    def test_empty_pidof_is_reported_stopped(self) -> None:
        from headless_re_mcp.backends.adb.client import AdbBackend

        class Dev:
            def shell(self, args: Any, timeout: float | None = None) -> str:
                del args, timeout
                return ""

        backend = AdbBackend()
        backend._device = lambda serial: Dev()  # type: ignore[method-assign]
        result = backend.force_stop("emulator-5554", "com.example.app")
        assert result["stopped"] is True
        assert result["remaining_pids"] == []


class TestDevicePullRefusesTreesAndHugeFiles:
    def test_a_directory_is_refused_before_copy(self, tmp_path: Any) -> None:
        from headless_re_mcp.backends.adb.client import AdbBackend, AdbError

        class Info:
            mode = 0o040755
            size = 0

        pulled: list[str] = []

        class Sync:
            def stat(self, remote: str, timeout: float | None = None) -> Info:
                del remote, timeout
                return Info()

            def pull(self, remote: str, local: str, timeout: float | None = None) -> None:
                del local, timeout
                pulled.append(remote)
                raise AssertionError("must not copy a remote directory")

        class Dev:
            sync = Sync()

        backend = AdbBackend()
        backend._device = lambda serial: Dev()  # type: ignore[method-assign]
        with pytest.raises(AdbError) as caught:
            backend.pull("emulator-5554", "/sdcard", tmp_path / "out")
        assert caught.value.code == "invalid_params"
        assert pulled == []

    def test_a_file_over_the_capture_cap_is_refused(self, tmp_path: Any) -> None:
        from headless_re_mcp.backends.adb.client import AdbBackend, AdbError
        from headless_re_mcp.core.limits import UNREGISTERED_CAPTURE_MAX_BYTES

        class Info:
            mode = 0o100644
            size = UNREGISTERED_CAPTURE_MAX_BYTES + 1

        class Sync:
            def stat(self, remote: str, timeout: float | None = None) -> Info:
                del remote, timeout
                return Info()

            def pull(self, *args: Any, **kwargs: Any) -> None:
                raise AssertionError("must not copy an oversized remote file")

        class Dev:
            sync = Sync()

        backend = AdbBackend()
        backend._device = lambda serial: Dev()  # type: ignore[method-assign]
        with pytest.raises(AdbError) as caught:
            backend.pull("emulator-5554", "/sdcard/huge.bin", tmp_path / "huge.bin")
        assert caught.value.code == "too_large"

    def test_a_local_file_over_the_capture_cap_is_not_pushed(
        self, tmp_path: Any, monkeypatch: Any
    ) -> None:
        from headless_re_mcp.backends.adb import client as mod

        monkeypatch.setattr(mod, "UNREGISTERED_CAPTURE_MAX_BYTES", 4)
        huge = tmp_path / "huge.bin"
        huge.write_bytes(b"12345")

        class Sync:
            def push(self, *args: Any, **kwargs: Any) -> None:
                raise AssertionError("must not push an oversized local file")

        class Dev:
            sync = Sync()

        backend = mod.AdbBackend()
        backend._device = lambda serial: Dev()  # type: ignore[method-assign]
        with pytest.raises(mod.AdbError) as caught:
            backend.push("emulator-5554", str(huge), "/data/local/tmp/huge.bin")
        assert caught.value.code == "too_large"

    def test_a_huge_screenshot_is_deleted_not_kept(
        self, tmp_path: Any, monkeypatch: Any
    ) -> None:
        from pathlib import Path

        from headless_re_mcp.backends.adb import client as mod

        monkeypatch.setattr(mod, "UNREGISTERED_CAPTURE_MAX_BYTES", 4)
        out = tmp_path / "shot.png"

        class Image:
            def save(self, path: str) -> None:
                Path(path).write_bytes(b"12345")

        class Dev:
            def screenshot(self, timeout: float | None = None) -> Image:
                del timeout
                return Image()

        backend = mod.AdbBackend()
        backend._device = lambda serial: Dev()  # type: ignore[method-assign]
        with pytest.raises(mod.AdbError) as caught:
            backend.screenshot("emulator-5554", out)
        assert caught.value.code == "too_large"
        assert out.exists() is False


class TestProxyReplayWaitsForTheCommand:
    def test_a_failed_replay_command_is_not_reported_replayed(self) -> None:
        from types import SimpleNamespace

        from headless_re_mcp.backends.proxy.client import ProxyBackend, ProxyError

        class Loop:
            def call_soon_threadsafe(self, callback: Any, *args: Any) -> None:
                callback(*args)

        class Commands:
            def call(self, name: str, args: Any) -> None:
                del name, args
                raise RuntimeError("no such flow")

        flow = SimpleNamespace(copy=lambda: SimpleNamespace())
        inst = SimpleNamespace(
            recorder=SimpleNamespace(raw=lambda flow_id: flow),
            _master=SimpleNamespace(commands=Commands()),
            _loop=Loop(),
        )
        backend = ProxyBackend()
        backend._get = lambda session_id: inst  # type: ignore[method-assign]
        with pytest.raises(ProxyError) as caught:
            backend.replay("s", "flow-1")
        assert caught.value.code == "backend_error"

    def test_a_queued_replay_that_never_runs_is_a_timeout(
        self, monkeypatch: Any
    ) -> None:
        from types import SimpleNamespace

        from headless_re_mcp.backends.proxy import client as mod

        monkeypatch.setattr(mod, "_REPLAY_WAIT_S", 0.2)

        class Loop:
            def call_soon_threadsafe(self, callback: Any, *args: Any) -> None:
                del callback, args

        flow = SimpleNamespace(copy=lambda: SimpleNamespace())
        inst = SimpleNamespace(
            recorder=SimpleNamespace(raw=lambda flow_id: flow),
            _master=SimpleNamespace(commands=SimpleNamespace(call=lambda *a, **k: None)),
            _loop=Loop(),
        )
        backend = mod.ProxyBackend()
        backend._get = lambda session_id: inst  # type: ignore[method-assign]
        with pytest.raises(mod.ProxyError) as caught:
            backend.replay("s", "flow-1")
        assert caught.value.code == "timeout"


class TestFridaJavaEnumerationStopsEarly:
    def test_class_enumeration_script_stops_at_the_cap(self) -> None:
        from headless_re_mcp.backends.frida.client import _JAVA_SCRIPT

        assert "enumerateLoadedClassesSync" not in _JAVA_SCRIPT
        assert "headless-re-mcp:class-cap" in _JAVA_SCRIPT
        assert "enumerateLoadedClasses" in _JAVA_SCRIPT


class TestFridaModuleEnumerationCapsRpc:
    def test_module_script_does_not_serialize_the_whole_table(self) -> None:
        from headless_re_mcp.backends.frida.client import _ENUM_SCRIPT

        assert "return {modules: items, total: all.length}" in _ENUM_SCRIPT
        assert ".map(function (m)" not in _ENUM_SCRIPT


class TestIsolationKillsWhatItStarted:
    """The isolation command is the step between samples on an unattended box.

    It is typically a script that starts a hypervisor tool. subprocess.run's
    timeout kills the script and then drains with no deadline, so a child that
    inherited the pipes holds the worker forever -- and the VM is left dirty.
    """

    def test_production_path_uses_the_bounded_runner(self, monkeypatch: Any) -> None:
        from headless_re_mcp.backends.common.bounded_run import Completed
        from headless_re_mcp.core.isolation import IsolationPolicy, IsolationRunner

        seen: list[tuple[list[str], float]] = []

        def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
            seen.append((cmd, float(kwargs["timeout"])))
            return Completed(0, b"", b"")

        monkeypatch.setattr("headless_re_mcp.core.isolation.run_bounded", fake_run)
        outcome = IsolationRunner(
            IsolationPolicy(command=("revert.ps1",), timeout_s=7.0)
        ).rotate()
        assert outcome["ok"] is True and outcome["performed"] is True
        assert seen == [(["revert.ps1"], 7.0)]

    def test_a_snapshot_script_that_starts_a_child_is_reaped(self) -> None:
        import ast
        import re
        import sys
        import time

        from headless_re_mcp.core.isolation import IsolationPolicy, IsolationRunner

        started = time.monotonic()
        outcome = IsolationRunner(
            IsolationPolicy(
                command=(sys.executable, "-c", _LAUNCHER),
                timeout_s=0.8,
                required=False,
            )
        ).rotate()
        elapsed = time.monotonic() - started
        assert elapsed < 10.0
        assert outcome["ok"] is False
        assert "TimedOut" in str(outcome["detail"])
        match = re.search(r"killed (\[.*\])", str(outcome["detail"]))
        assert match is not None
        killed = ast.literal_eval(match.group(1))
        assert len(killed) >= 2
        for pid in killed:
            assert _pid_is_alive(int(pid)) is False


def _session_keyed_dicts(root: Any) -> list[tuple[str, dict[Any, Any]]]:
    """Every dict on the service, or one attribute below it, keyed by anything."""

    def attributes(obj: Any) -> list[tuple[str, Any]]:
        names: list[str] = list(getattr(type(obj), "__slots__", ()) or ())
        if hasattr(obj, "__dict__"):
            names.extend(vars(obj).keys())
        items: list[tuple[str, Any]] = []
        for name in names:
            if name.startswith("__"):
                continue
            try:
                items.append((name, getattr(obj, name)))
            except AttributeError:
                continue
        return items

    found: list[tuple[str, dict[Any, Any]]] = []
    for name, value in attributes(root):
        # The registry deliberately retains a bounded window of closed sessions
        # so a caller can still ask what happened to one.
        if name == "registry":
            continue
        if isinstance(value, dict):
            found.append((name, value))
            continue
        if hasattr(value, "__dict__") or getattr(type(value), "__slots__", None):
            found.extend(
                (f"{name}.{sub_name}", sub_value)
                for sub_name, sub_value in attributes(value)
                if isinstance(sub_value, dict)
            )
    return found


def _seed_per_session_state(service: Any, session_id: str) -> None:
    """Leave behind what a real run leaves behind, without a real backend.

    A session that only ever existed writes to none of these, so a guard run
    against a bare create/close pair would pass by having nothing to find.
    """
    from headless_re_mcp.core.models import BackendKind

    # A backend that opened and then died: the phase outlives the runtime.
    service._runtime_owner.begin_open(session_id, BackendKind.X64DBG)
    service._runtime_owner.fail(session_id, BackendKind.X64DBG)
    service._trace_owner.put(session_id, object())
    service._workflow_owner.put(session_id, object())
    service._unpack_owner.sessions[session_id] = object()
    service._unpack_owner.protection_snapshots[session_id] = []


def test_no_service_state_remembers_a_closed_session(tmp_path: Any) -> None:
    """A generic guard, so the next session-keyed dict is caught when it lands.

    Two of these were found by hand -- trace state and backend phases -- which
    is a poor way to find the third.
    """
    import zipfile
    from dataclasses import replace

    from headless_re_mcp.config import Settings
    from headless_re_mcp.core.service import AnalysisService

    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    try:
        apk = tmp_path / "app.apk"
        with zipfile.ZipFile(apk, "w") as archive:
            archive.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00m")

        session_ids = []
        for _ in range(3):
            created = service.create_session(str(apk), target="apk")
            assert created.data is not None
            session_id = str(created.data["session"]["id"])
            session_ids.append(session_id)
            _seed_per_session_state(service, session_id)
            service.close_session(session_id)

        scanned = _session_keyed_dicts(service)
        # Without this the guard passes by simply not looking anywhere.
        assert {
            "_runtime_owner.items",
            "_runtime_owner.phases",
            "_trace_owner.sessions",
            "_workflow_owner.terminal",
        } <= {name for name, _ in scanned}

        leaked = {
            name: [key for key in mapping if any(sid in str(key) for sid in session_ids)]
            for name, mapping in scanned
        }
        assert {name: keys for name, keys in leaked.items() if keys} == {}
    finally:
        service.close_all()


@pytest.mark.parametrize(
    "module_name",
    [
        "headless_re_mcp.backends.proxy.client",
        "headless_re_mcp.backends.web.client",
    ],
)
def test_long_lived_buffers_declare_an_explicit_cap(module_name: str) -> None:
    """Every retained-in-memory collection in these backends must have a cap."""
    import importlib

    module = importlib.import_module(module_name)
    caps = [
        value
        for name, value in vars(module).items()
        if name.startswith("_MAX_") and isinstance(value, int)
    ]
    assert caps, f"{module_name} retains state but declares no _MAX_* bound"
    assert all(cap > 0 for cap in caps)
