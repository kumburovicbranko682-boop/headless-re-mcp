from __future__ import annotations

import socket
import threading
import time
from collections.abc import Iterator
from contextlib import suppress
from http.server import BaseHTTPRequestHandler, HTTPServer

from headless_re_mcp.supervisor import probe_ready


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


def test_probe_ready_returns_within_timeout_when_headers_trickle() -> None:
    """urlopen's timeout is per recv, so a slow status line reset it forever.

    Measured: timeout 0.5s, one header byte every 250ms, returned after 4.016s
    when the listener hung up (BadStatusLine). The supervisor was stuck in
    that probe and could not count an unhealthy strike or restart the child.
    """
    port_box: list[int] = []
    hold_s = 4.0

    def trickle() -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("127.0.0.1", 0))
        sock.listen(1)
        port_box.append(int(sock.getsockname()[1]))
        conn = None
        try:
            sock.settimeout(hold_s + 1.0)
            conn, _ = sock.accept()
            conn.settimeout(1.0)
            with suppress(OSError):
                conn.recv(4096)
            deadline = time.monotonic() + hold_s
            while time.monotonic() < deadline:
                conn.sendall(b"H")
                time.sleep(0.25)
        except OSError:
            pass
        finally:
            if conn is not None:
                with suppress(OSError):
                    conn.close()
            with suppress(OSError):
                sock.close()

    thread = threading.Thread(target=trickle, daemon=True)
    thread.start()
    for _ in range(50):
        if port_box:
            break
        time.sleep(0.02)
    started = time.perf_counter()
    ok, detail = probe_ready(f"http://127.0.0.1:{port_box[0]}/readyz", timeout=0.5)
    elapsed = time.perf_counter() - started
    assert ok is False
    assert detail.startswith("unreachable:")
    assert elapsed < 1.5, f"readiness probe ran {elapsed:.3f}s against a 0.5s timeout"
    thread.join(timeout=2.0)


def test_an_abandoned_probe_releases_its_thread_and_socket() -> None:
    """Giving up on a probe must reclaim the worker, not just stop waiting.

    The join is the overall deadline, but the worker used to stay blocked in
    recv for as long as the wedged child kept dribbling header bytes, holding
    one thread and one file descriptor per probe. Probes repeat every
    check_interval_s (10s by default), so an unattended weekend against
    exactly the child a readiness check exists to catch leaked thousands of
    both: the supervisor hits the descriptor limit, spawn fails, and the
    crash-loop bound stops the one process whose job was keeping the service
    alive. Closing the connection when the deadline passes makes the blocked
    read raise, so the worker exits and takes its socket with it.
    """
    port_box: list[int] = []
    hold_s = 8.0

    def dribble() -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("127.0.0.1", 0))
        sock.listen(1)
        port_box.append(int(sock.getsockname()[1]))
        conn = None
        try:
            sock.settimeout(hold_s + 1.0)
            conn, _ = sock.accept()
            conn.settimeout(1.0)
            with suppress(OSError):
                conn.recv(4096)
            deadline = time.monotonic() + hold_s
            while time.monotonic() < deadline:
                # sendall raises as soon as the probe closes its end, which
                # is what lets this thread finish long before hold_s.
                conn.sendall(b"H")
                time.sleep(0.25)
        except OSError:
            pass
        finally:
            if conn is not None:
                with suppress(OSError):
                    conn.close()
            with suppress(OSError):
                sock.close()

    server = threading.Thread(target=dribble, daemon=True)
    server.start()
    for _ in range(50):
        if port_box:
            break
        time.sleep(0.02)
    ok, detail = probe_ready(f"http://127.0.0.1:{port_box[0]}/readyz", timeout=0.5)
    assert ok is False
    assert detail.startswith("unreachable:")
    # The dribbler keeps sending for hold_s, so on the old code the worker is
    # provably still blocked in recv when this window closes.
    deadline = time.monotonic() + 2.0
    while time.monotonic() < deadline and any(
        worker.name == "ready-probe" and worker.is_alive()
        for worker in threading.enumerate()
    ):
        time.sleep(0.05)
    leaked = [
        worker
        for worker in threading.enumerate()
        if worker.name == "ready-probe" and worker.is_alive()
    ]
    assert not leaked, "the probe worker outlived the deadline it missed"
    server.join(timeout=3.0)
    assert not server.is_alive(), "closing the probe socket should unblock the server"


def test_probe_ready_still_reports_a_live_child() -> None:
    class Ready(BaseHTTPRequestHandler):
        def log_message(self, *args: object) -> None:
            return

        def do_GET(self) -> None:
            body = b'{"ok":true}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    for port in _serve(Ready):
        ok, detail = probe_ready(f"http://127.0.0.1:{port}/readyz", timeout=0.5)
        assert ok is True
        assert detail == "http 200"


def test_probe_ready_refuses_a_url_that_is_not_http() -> None:
    ok, detail = probe_ready("ftp://127.0.0.1/readyz", timeout=0.2)

    assert ok is False
    assert detail == "unreachable: ValueError"


def test_probe_ready_reports_unreachable_for_a_refused_port() -> None:
    # Nothing listens on port 1; the probe must build the query path and report
    # unreachable rather than hang or raise.
    ok, detail = probe_ready("http://127.0.0.1:1/readyz?verbose=1", timeout=0.3)
    assert ok is False
    assert detail.startswith("unreachable:")


def test_probe_ready_preserves_the_query_string() -> None:
    seen: list[str] = []

    class Echo(BaseHTTPRequestHandler):
        def log_message(self, *args: object) -> None:
            return

        def do_GET(self) -> None:
            seen.append(self.path)
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()

    for port in _serve(Echo):
        ok, _detail = probe_ready(
            f"http://127.0.0.1:{port}/readyz?deep=1", timeout=0.5
        )
        assert ok is True
        assert seen == ["/readyz?deep=1"]


def test_probe_ready_gives_up_on_a_connection_that_never_forms(
    monkeypatch,  # type: ignore[no-untyped-def]
) -> None:
    """No socket yet means nothing to shut down; the deadline still holds."""
    import http.client

    class Wedged:
        def __init__(self, host: object, port: object, timeout: float) -> None:
            self.sock = None

        def request(self, method: str, path: str) -> None:
            time.sleep(1.4)
            raise OSError("late")

        def close(self) -> None:
            return None

    monkeypatch.setattr(http.client, "HTTPConnection", Wedged)
    started = time.perf_counter()
    ok, detail = probe_ready("http://127.0.0.1:1/readyz", timeout=0.2)
    elapsed = time.perf_counter() - started

    assert ok is False
    assert detail == "unreachable: TimeoutError"
    assert elapsed < 1.5


def test_probe_ready_names_a_non_200() -> None:
    class Sick(BaseHTTPRequestHandler):
        def log_message(self, *args: object) -> None:
            return

        def do_GET(self) -> None:
            self.send_response(503)
            self.send_header("Content-Length", "0")
            self.end_headers()

    for port in _serve(Sick):
        ok, detail = probe_ready(f"http://127.0.0.1:{port}/readyz", timeout=0.5)
        assert ok is False
        assert detail == "http 503"
