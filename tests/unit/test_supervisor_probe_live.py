"""The readiness probe and spawn/terminate arcs that need a real socket or process."""

from __future__ import annotations

import subprocess
import sys
import threading
import time
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from headless_re_mcp import supervisor as supervisor_module
from headless_re_mcp.backends.common.subprocess_rpc import no_window_popen_kwargs
from headless_re_mcp.supervisor import Supervisor, probe_ready


def _serve(handler: type[BaseHTTPRequestHandler]) -> Iterator[int]:
    httpd = HTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield int(httpd.server_address[1])
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=2.0)


class _Ok(BaseHTTPRequestHandler):
    def log_message(self, *args: object) -> None:
        return

    def do_GET(self) -> None:
        body = b'{"ok":true}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class _ServiceUnavailable(BaseHTTPRequestHandler):
    def log_message(self, *args: object) -> None:
        return

    def do_GET(self) -> None:
        self.send_response(503)
        self.send_header("Content-Length", "0")
        self.end_headers()


class _Wedged(BaseHTTPRequestHandler):
    def log_message(self, *args: object) -> None:
        return

    def do_GET(self) -> None:
        # Accept the request, then hold the response past the probe's bound so
        # the worker thread is still blocked when the join deadline passes.
        time.sleep(3.0)
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()


def test_probe_reports_ready_for_a_two_hundred() -> None:
    for port in _serve(_Ok):
        ready, detail = probe_ready(f"http://127.0.0.1:{port}/readyz", timeout=1.0)
        assert ready is True
        assert detail == "http 200"


def test_probe_reports_a_non_2xx_as_a_definite_not_ready() -> None:
    for port in _serve(_ServiceUnavailable):
        ready, detail = probe_ready(f"http://127.0.0.1:{port}/readyz", timeout=1.0)
        assert ready is False
        assert detail == "http 503"


def test_a_wedged_child_is_torn_off_the_socket_and_reported_unreachable() -> None:
    """A child that accepts then stalls must not keep the probe thread forever.

    The join deadline passes with an empty verdict box, so the probe shuts the
    socket down from outside the worker; the blocked read then raises and the
    short second join collects an unreachable verdict instead of leaking the
    thread and its file descriptor.
    """
    for port in _serve(_Wedged):
        started = time.perf_counter()
        ready, detail = probe_ready(f"http://127.0.0.1:{port}/readyz", timeout=0.3)
        elapsed = time.perf_counter() - started

        assert ready is False
        assert detail.startswith("unreachable:")
        assert elapsed < 2.5, f"probe against a wedged child ran {elapsed:.2f}s"


def test_spawn_notes_when_a_real_child_cannot_be_grouped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """On Windows a Popen that will not join the job object is logged, not fatal."""
    logged: list[dict[str, object]] = []
    monkeypatch.setattr(supervisor_module, "is_windows_host", lambda: True)
    monkeypatch.setattr(supervisor_module, "assign_to_process_group", lambda pid: False)

    child = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(30)"],
        **no_window_popen_kwargs(),
    )
    supervisor = Supervisor(["x"], spawn=lambda argv: child, log=logged.append)
    try:
        returned = supervisor._spawn_child()
        assert returned is child
    finally:
        child.kill()
        child.wait(timeout=10)

    assert any(record["event"] == "child.not_grouped" for record in logged)


def test_terminate_stops_a_real_child_process() -> None:
    """The Popen arm of _terminate goes through terminate_process_tree."""
    child = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(30)"],
        **no_window_popen_kwargs(),
    )
    supervisor = Supervisor(["x"])

    started = time.monotonic()
    supervisor._terminate(child)
    elapsed = time.monotonic() - started

    assert elapsed < 15.0
    assert child.poll() is not None, "the child process is still running"
