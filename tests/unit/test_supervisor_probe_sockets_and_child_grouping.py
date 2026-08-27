"""Readiness probe against live sockets, and Windows child-grouping fallbacks."""

from __future__ import annotations

import http.client
import http.server
import socket
import subprocess
import sys
import threading
import time
from collections.abc import Iterator
from typing import Any

import pytest

from headless_re_mcp import supervisor as supervisor_module
from headless_re_mcp.supervisor import Supervisor, probe_ready


class _Healthy(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - stdlib handler naming
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: Any) -> None:
        return


@pytest.fixture
def healthy_server() -> Iterator[str]:
    server = http.server.HTTPServer(("127.0.0.1", 0), _Healthy)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/healthz"
    finally:
        server.shutdown()
        thread.join(5.0)
        server.server_close()


def test_a_healthy_child_answers_the_probe_with_its_status(healthy_server: str) -> None:
    # The everyday success path over a real socket: a 2xx answer within the
    # budget is ready, and the detail carries the code an operator would want
    # in the log. The URL has no query string, so none is appended.
    assert probe_ready(healthy_server, timeout=5.0) == (True, "http 200")


def test_a_child_that_accepts_but_never_answers_is_shut_down_from_outside() -> None:
    # A wedged child: the connect succeeds via the listen backlog, the request
    # is swallowed, and no response line ever comes. The probe must reclaim
    # its worker by shutting the socket down -- close() alone leaves the
    # blocked recv holding the descriptor -- and report unreachable.
    with socket.socket() as silent:
        silent.bind(("127.0.0.1", 0))
        silent.listen(1)
        port = silent.getsockname()[1]

        verdict, detail = probe_ready(f"http://127.0.0.1:{port}/", timeout=0.3)

    assert verdict is False
    assert detail.startswith("unreachable:")


def test_a_worker_wedged_past_the_grace_join_reports_a_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # If the worker never even establishes a socket there is nothing to shut
    # down, and a worker that stays wedged through the collection join must
    # not hang the probe: the caller gets a timeout verdict and the daemon
    # thread is abandoned.
    class _WedgedConnection:
        def __init__(self, host: str, port: int | None, timeout: float = 0.0) -> None:
            self.sock = None

        def request(self, method: str, path: str) -> None:
            time.sleep(2.5)

        def close(self) -> None:
            return

    monkeypatch.setattr(http.client, "HTTPConnection", _WedgedConnection)

    assert probe_ready("http://127.0.0.1:1/", timeout=0.1) == (
        False,
        "unreachable: TimeoutError",
    )


def _sleeper() -> list[str]:
    return [sys.executable, "-c", "import time; time.sleep(30)"]


def test_a_child_that_cannot_join_the_process_group_is_logged(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # On Windows the group is what lets the supervisor take the child down
    # with itself. Failing to join is worth an operator-visible note, but not
    # worth refusing the child that just started.
    records: list[dict[str, Any]] = []
    monkeypatch.setattr(supervisor_module, "is_windows_host", lambda: True)
    monkeypatch.setattr(supervisor_module, "assign_to_process_group", lambda pid: False)
    sup = Supervisor(argv=_sleeper(), log=records.append)

    child = sup._spawn_child()

    try:
        assert isinstance(child, subprocess.Popen)
        events = [record["event"] for record in records]
        assert "child.not_grouped" in events
    finally:
        assert child is not None
        child.kill()
        child.wait(timeout=10.0)


def test_terminating_a_real_child_goes_through_the_process_tree(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A bare terminate() stops the serve process and nothing else; the tree
    # walk is what takes down the debuggers and debuggees the child started.
    # Only a real Popen earns that path -- an injected fake falls back to its
    # own terminate so it cannot name someone else's pid for killing.
    reaped: list[Any] = []
    monkeypatch.setattr(
        supervisor_module,
        "terminate_process_tree",
        lambda child, wait_s: reaped.append((child, wait_s)),
    )
    sup = Supervisor(argv=_sleeper(), log=lambda record: None)
    child = subprocess.Popen(_sleeper())

    try:
        sup._terminate(child)
        assert reaped == [(child, 15.0)]
    finally:
        child.kill()
        child.wait(timeout=10.0)
