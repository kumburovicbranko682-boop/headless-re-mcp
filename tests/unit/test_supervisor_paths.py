"""Coverage for the readiness probe and child teardown in supervisor.py.

probe_ready owns a socket it can close from outside its worker thread so a
wedged child cannot pin a descriptor; that success reply, the shutdown-on-
timeout path, and the real-subprocess teardown never ran on a hosted runner.
These drive them against a local socket and a throwaway child process.
"""

from __future__ import annotations

import socket
import subprocess
import threading
import time
from collections.abc import Callable

from headless_re_mcp.supervisor import Supervisor, probe_ready


def _serve_once(
    handler: Callable[[socket.socket], None], ready: threading.Event
) -> tuple[socket.socket, int]:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]

    def _run() -> None:
        ready.set()
        try:
            conn, _addr = server.accept()
        except OSError:
            return
        handler(conn)

    threading.Thread(target=_run, name="probe-fake-server", daemon=True).start()
    return server, port


def test_probe_ready_reports_a_healthy_child() -> None:
    ready = threading.Event()

    def _respond(conn: socket.socket) -> None:
        with conn:
            conn.recv(4096)
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")

    server, port = _serve_once(_respond, ready)
    try:
        ready.wait(2)
        ok, detail = probe_ready(f"http://127.0.0.1:{port}/readyz", timeout=2.0)
        assert ok is True
        assert detail == "http 200"
    finally:
        server.close()


def test_probe_ready_gives_up_on_a_wedged_child() -> None:
    ready = threading.Event()
    hold: list[socket.socket] = []

    def _wedge(conn: socket.socket) -> None:
        # Accept but never answer, holding the connection open so the probe's
        # worker blocks in getresponse and the shutdown/close path runs.
        hold.append(conn)
        time.sleep(2)

    server, port = _serve_once(_wedge, ready)
    try:
        ready.wait(2)
        ok, detail = probe_ready(f"http://127.0.0.1:{port}/readyz", timeout=0.1)
        assert ok is False
        assert detail.startswith("unreachable")
    finally:
        server.close()
        for conn in hold:
            conn.close()


def test_probe_ready_rejects_a_non_http_url() -> None:
    ok, detail = probe_ready("ftp://example/health", timeout=1.0)
    assert ok is False
    assert "unreachable" in detail


def test_terminate_kills_a_real_child_process() -> None:
    supervisor = Supervisor(argv=["true"])
    child = subprocess.Popen(["sleep", "30"])
    try:
        supervisor._terminate(child)
        child.wait(timeout=10)
        assert child.poll() is not None
    finally:
        if child.poll() is None:
            child.kill()
            child.wait(timeout=5)
