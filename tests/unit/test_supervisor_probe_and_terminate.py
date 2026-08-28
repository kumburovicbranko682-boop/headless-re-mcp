"""The supervisor arms that need a real socket or a real process.

test_supervisor.py drives the restart state machine entirely through injected
fakes, so probe_ready never touches a socket there and _terminate never sees a
subprocess.Popen. That leaves unexecuted exactly the paths whose failure modes
were measured in production: the probe against a live listener (including the
query-string rebuild), the wedged child that dribbles header bytes forever and
used to leak one thread and one descriptor per probe, the worker that never
reports at all, the Windows child that could not be tied to the job object,
and the process-tree termination of a real child. This file exercises each
against real sockets and real processes, bounded tightly enough for CI.
"""

from __future__ import annotations

import socket
import subprocess
import sys
import threading
import time
from collections.abc import Iterator, Sequence
from contextlib import suppress
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import pytest

from headless_re_mcp import supervisor as supervisor_module
from headless_re_mcp.backends.common.subprocess_rpc import no_window_popen_kwargs
from headless_re_mcp.supervisor import Supervisor, probe_ready


# --------------------------------------------------------------------------- #
# probe_ready against a live HTTP listener                                    #
# --------------------------------------------------------------------------- #
@pytest.fixture
def ready_server() -> Iterator[tuple[str, list[str]]]:
    """A real listener: /readyz answers 200, anything else answers 503."""
    seen_paths: list[str] = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler's name
            seen_paths.append(self.path)
            code = 200 if self.path.startswith("/readyz") else 503
            body = b"ok" if code == 200 else b"no"
            self.send_response(code)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
            pass  # keep the test output clean

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, name="ready-server", daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", seen_paths
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def test_a_live_child_answers_ready_and_keeps_its_query_string(
    ready_server: tuple[str, list[str]],
) -> None:
    """The probe must rebuild path?query; dropping the query changed the answer."""
    base, seen_paths = ready_server

    verdict = probe_ready(f"{base}/readyz?deep=1", timeout=5.0)

    assert verdict == (True, "http 200")
    assert seen_paths == ["/readyz?deep=1"]


def test_a_non_2xx_answer_is_a_definite_not_ready(
    ready_server: tuple[str, list[str]],
) -> None:
    """503 is an answer, not unreachability: the child is alive but declining."""
    base, _ = ready_server

    ready, detail = probe_ready(f"{base}/other", timeout=5.0)

    assert ready is False
    assert detail == "http 503"


# --------------------------------------------------------------------------- #
# the wedged child: accepts, dribbles header bytes, never finishes            #
# --------------------------------------------------------------------------- #
def test_a_child_that_dribbles_bytes_is_declared_unreachable_promptly() -> None:
    """One header byte per poll resets the socket timeout, so only the outer
    join bounds the probe; the shutdown must then collect the worker's socket
    instead of leaking a blocked thread and descriptor per probe."""
    listener = socket.socket()
    listener.settimeout(10.0)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    stop = threading.Event()

    def dribble() -> None:
        with suppress(OSError, TimeoutError):
            connection, _ = listener.accept()
            with suppress(OSError):
                while not stop.wait(0.05):
                    connection.send(b"H")  # never a complete status line
            with suppress(OSError):
                connection.close()

    server = threading.Thread(target=dribble, name="dribbler", daemon=True)
    server.start()
    port = listener.getsockname()[1]
    try:
        began = time.monotonic()
        ready, detail = probe_ready(f"http://127.0.0.1:{port}/readyz", timeout=0.4)
        elapsed = time.monotonic() - began

        assert ready is False
        assert detail.startswith("unreachable:"), detail
        # 0.4s deadline plus the 1s post-shutdown join, with slack for CI: far
        # below the 4s the measured dribbler held the old implementation.
        assert elapsed < 3.0, f"the probe must not wait out the dribbler ({elapsed:.2f}s)"
    finally:
        stop.set()
        server.join(timeout=5)
        listener.close()


def test_a_worker_that_never_reports_is_a_timeout_verdict(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No socket to shut down and no answer even after the grace join: the
    probe must still return its own verdict rather than block or crash."""
    never = threading.Event()

    class BlockedConnection:
        sock = None  # nothing to shut down, so the grace join is the only exit

        def __init__(self, host: str | None, port: int | None, timeout: float) -> None:
            pass

        def request(self, method: str, path: str) -> None:
            never.wait(5.0)  # outlives bound + the 1s grace join

        def close(self) -> None:
            pass

    monkeypatch.setattr("http.client.HTTPConnection", BlockedConnection)

    verdict = probe_ready("http://127.0.0.1:1/readyz", timeout=0.1)

    assert verdict == (False, "unreachable: TimeoutError")
    never.set()  # release the daemon worker before the test returns


# --------------------------------------------------------------------------- #
# a real child: the not-grouped log arm and process-tree termination          #
# --------------------------------------------------------------------------- #
def _supervisor_with(spawn: Any, records: list[dict[str, Any]]) -> Supervisor:
    return Supervisor(
        ["unused"],
        spawn=spawn,
        log=records.append,
    )


def test_an_ungroupable_windows_child_is_logged_but_still_supervised(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Failing to join the job object is worth a log line, not a dead start."""
    records: list[dict[str, Any]] = []
    spawned: list[subprocess.Popen[bytes]] = []

    def spawn(argv: Sequence[str]) -> subprocess.Popen[bytes]:
        child = subprocess.Popen([sys.executable, "-c", "pass"], **no_window_popen_kwargs())
        spawned.append(child)
        return child

    monkeypatch.setattr(supervisor_module, "is_windows_host", lambda: True)
    monkeypatch.setattr(supervisor_module, "assign_to_process_group", lambda pid: False)
    supervisor = _supervisor_with(spawn, records)

    child = supervisor._spawn_child()
    try:
        assert child is spawned[0], "the child is still used despite the failed grouping"
        not_grouped = [r for r in records if r["event"] == "child.not_grouped"]
        assert len(not_grouped) == 1
        assert not_grouped[0]["pid"] == spawned[0].pid
    finally:
        spawned[0].kill()
        spawned[0].wait(timeout=10)


def test_terminating_a_real_child_takes_down_its_process(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A real Popen goes through process-tree termination, not bare terminate().

    Measured before the tree kill: the launcher died in 0.002s while the
    sleeper it started stayed alive, so an unhealthy restart fought the old
    child over the debugger and the debuggee.
    """
    records: list[dict[str, Any]] = []
    child = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(30)"],
        **no_window_popen_kwargs(),
    )
    supervisor = _supervisor_with(lambda argv: child, records)
    assert child.poll() is None, "the child must be alive before termination"

    supervisor._terminate(child)

    assert child.poll() is not None, "the supervised process must be gone"
