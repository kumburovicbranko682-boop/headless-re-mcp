"""The probe's three verdicts, and the restart plumbing around a real child.

``probe_ready`` distinguishes an answer from silence: a served status code --
any code -- means the child is alive enough to speak, and only a 2xx means
ready. A child that accepts the connection and then trickles bytes forever is
the case the probe was rebuilt for (the docstring's measured wedge): the join
deadline must close the socket out from under the worker and report
unreachable instead of hanging a probe thread and a descriptor per check. And
a connection object the deadline cannot even unblock still returns the
timeout verdict rather than waiting on the worker.

The supervisor pieces around it: ``_terminate`` must reap a real Popen through
the process-tree kill on POSIX too (the Windows test pins descendants), and a
spawn that cannot join the process group on Windows is logged, not fatal.
"""

from __future__ import annotations

import socket
import subprocess
import sys
import threading
from typing import Any

import pytest

import headless_re_mcp.supervisor as supervisor_module
from headless_re_mcp.supervisor import Supervisor, probe_ready


def _serve_once(response: bytes) -> tuple[socket.socket, int]:
    """A listener that answers one request with ``response`` and hangs up."""
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]

    def _answer() -> None:
        conn, _ = listener.accept()
        with conn:
            conn.recv(65536)
            conn.sendall(response)

    threading.Thread(target=_answer, name="probe-listener", daemon=True).start()
    return listener, port


# ---------------------------------------------------------------------------
# A child that answers is reported by its status code.
# ---------------------------------------------------------------------------
def test_a_2xx_answer_reports_ready_with_the_code() -> None:
    listener, port = _serve_once(
        b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n"
    )
    try:
        ok, detail = probe_ready(f"http://127.0.0.1:{port}/readyz?verbose=1", timeout=5.0)
    finally:
        listener.close()
    assert ok is True
    assert detail == "http 204"


def test_a_non_2xx_answer_is_a_definite_no_not_unreachable() -> None:
    # A 500 means the process is alive and serving; only the verdict is
    # negative. Conflating it with unreachable would hide which failure the
    # operator has.
    listener, port = _serve_once(
        b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n"
    )
    try:
        ok, detail = probe_ready(f"http://127.0.0.1:{port}/readyz", timeout=5.0)
    finally:
        listener.close()
    assert ok is False
    assert detail == "http 500"


# ---------------------------------------------------------------------------
# The measured wedge: accepted connection, bytes trickling, never a response.
# ---------------------------------------------------------------------------
def test_a_wedged_child_is_unreachable_within_the_join_deadline() -> None:
    """One header byte per tick resets the socket timeout; the join must not.

    The probe closes the connection out from under its worker when the overall
    deadline passes, so the blocked read raises and the thread exits with its
    socket -- instead of each probe leaking a thread and a descriptor until
    spawn fails (the failure mode measured in the module docstring).
    """
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    stop = threading.Event()

    def _trickle() -> None:
        conn, _ = listener.accept()
        with conn:
            conn.recv(65536)
            while not stop.is_set():
                try:
                    conn.sendall(b"H")
                except OSError:
                    return
                stop.wait(0.05)

    thread = threading.Thread(target=_trickle, name="wedged-child", daemon=True)
    thread.start()
    try:
        ok, detail = probe_ready(f"http://127.0.0.1:{port}/readyz", timeout=0.5)
    finally:
        stop.set()
        listener.close()
        thread.join(5.0)
    assert ok is False
    assert detail.startswith("unreachable:")


def test_a_worker_the_shutdown_cannot_unblock_still_reports_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # No socket to shut down (sock is None) and a request that ignores the
    # close: the probe must still return the timeout verdict on its own
    # deadline rather than wait for the worker.
    release = threading.Event()

    class _StuckConnection:
        sock = None

        def __init__(self, host: Any, port: Any, timeout: float) -> None:
            pass

        def request(self, method: str, path: str) -> None:
            release.wait(30.0)
            raise OSError("released")

        def close(self) -> None:
            pass

    monkeypatch.setattr(
        supervisor_module.http.client, "HTTPConnection", _StuckConnection
    )
    try:
        ok, detail = probe_ready("http://127.0.0.1:1/readyz", timeout=0.1)
    finally:
        release.set()
    assert ok is False
    assert detail == "unreachable: TimeoutError"


# ---------------------------------------------------------------------------
# Supervisor plumbing around a real child.
# ---------------------------------------------------------------------------
def test_terminate_reaps_a_real_popen_child() -> None:
    process = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    Supervisor(["x"])._terminate(process)
    assert process.poll() is not None


def test_a_child_that_cannot_join_the_group_is_logged_not_dropped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Windows-only guard: the group attach failing means a force-kill of the
    # supervisor could leak the child, which is worth a log line -- but the
    # child did start, so the spawn must still hand it back.
    monkeypatch.setattr(supervisor_module, "is_windows_host", lambda: True)
    monkeypatch.setattr(supervisor_module, "assign_to_process_group", lambda pid: False)
    records: list[dict[str, Any]] = []
    supervisor = Supervisor(
        ["x"],
        spawn=lambda argv: subprocess.Popen([sys.executable, "-c", "pass"]),
        log=records.append,
    )
    child = supervisor._spawn_child()
    assert child is not None
    child.wait(timeout=30)
    events = [record.get("event") for record in records]
    assert "child.not_grouped" in events
