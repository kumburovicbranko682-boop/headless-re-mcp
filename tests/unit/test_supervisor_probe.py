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
