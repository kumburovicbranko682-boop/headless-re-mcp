from __future__ import annotations

import socket
import threading
import time
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from headless_re_mcp.web.launch_util import choose_bind_port, port_is_free, probe_our_healthz


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


def test_port_is_free_and_choose_fallback() -> None:
    # Bind an ephemeral port to force it busy, then ask chooser to skip it.
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    busy_port = sock.getsockname()[1]
    try:
        assert port_is_free("127.0.0.1", busy_port) is False
        chosen, reason = choose_bind_port("127.0.0.1", busy_port, span=20, auto=True)
        assert reason == "fallback"
        assert chosen != busy_port
        assert port_is_free("127.0.0.1", chosen) is True
        busy_only, reason2 = choose_bind_port("127.0.0.1", busy_port, span=1, auto=False)
        assert busy_only == busy_port
        assert reason2 == "busy"
    finally:
        sock.close()


def test_choose_preferred_when_free() -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    probe = sock.getsockname()[1]
    sock.close()
    # After close, port should be choosable as preferred.
    chosen, reason = choose_bind_port("127.0.0.1", probe, span=5, auto=True)
    assert chosen == probe
    assert reason == "preferred"


def test_probe_our_healthz_none_on_closed_port() -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    assert probe_our_healthz("127.0.0.1", port, timeout=0.2) is None


def test_probe_our_healthz_short_body_is_not_our_console() -> None:
    """A listener that closes early used to raise IncompleteRead.

    Measured: Content-Length 10000 and 11 bytes on the wire raised
    IncompleteRead in 16ms. That exception is not URLError or OSError, so
    start_web.py died instead of treating the port as occupied-by-something-else
    and binding the next one. The supervised restart then hit the same port.
    """

    class ShortBody(BaseHTTPRequestHandler):
        def log_message(self, *args: object) -> None:
            return

        def do_GET(self) -> None:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", "10000")
            self.end_headers()
            self.wfile.write(b'{"ok":true}')

    for port in _serve(ShortBody):
        assert probe_our_healthz("127.0.0.1", port, timeout=0.4) is None


def test_probe_our_healthz_returns_within_timeout_when_the_body_trickles() -> None:
    """urlopen's timeout is per recv, so a slow body reset it forever.

    Measured: 80 bytes at 50ms each, no Content-Length, timeout 0.4s, returned
    after 4.045s. start_web probes /healthz before binding and again while
    waiting to open the browser; a leftover listener that dribbles kept the
    launcher -- and the supervisor that started it -- parked.
    """

    class Trickle(BaseHTTPRequestHandler):
        def log_message(self, *args: object) -> None:
            return

        def do_GET(self) -> None:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            for _ in range(80):
                self.wfile.write(b"x")
                self.wfile.flush()
                time.sleep(0.05)

    for port in _serve(Trickle):
        started = time.perf_counter()
        assert probe_our_healthz("127.0.0.1", port, timeout=0.4) is None
        elapsed = time.perf_counter() - started
        assert elapsed < 1.5, f"healthz probe ran {elapsed:.3f}s against a 0.4s timeout"


def test_probe_our_healthz_still_recognises_this_console() -> None:
    class Ours(BaseHTTPRequestHandler):
        def log_message(self, *args: object) -> None:
            return

        def do_GET(self) -> None:
            body = b'{"ok":true,"service":"headless-re-mcp-web","build":{"version":"test"}}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    for port in _serve(Ours):
        data = probe_our_healthz("127.0.0.1", port, timeout=0.4)
        assert data is not None
        assert data["service"] == "headless-re-mcp-web"


def test_run_web_chinese_refuse_non_loopback(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    from headless_re_mcp.config import Settings
    from headless_re_mcp.web.app import run_web

    settings = Settings(
        ida_home=None,
        x64dbg_source=None,
        x64dbg_headless_x64=None,
        x64dbg_headless_x86=None,
        artifact_root=tmp_path / "artifacts",
        http_host="127.0.0.1",
        http_port=8765,
    )
    code = run_web(settings, host="0.0.0.0", port=8765)
    assert code == 2
    out = capsys.readouterr().out
    assert "拒绝绑定" in out


def test_serve_web_releases_its_analysis_sessions_when_it_stops(tmp_path: Path) -> None:
    """The stdio transport always did this; the web one never did.

    A session owns a real IDA or x64dbg process, and the debuggee under it.
    None of them exit because the server did, so every shutdown left them
    running -- and the supervised deployment restarts this process on purpose,
    on a schedule, whenever readiness fails. An IDA instance is measured in
    gigabytes, so a handful of restarts is a machine that needs rebooting.
    """
    from dataclasses import replace
    from unittest.mock import patch

    import uvicorn

    from headless_re_mcp.config import Settings
    from headless_re_mcp.web import app as web_app

    settings = replace(
        Settings.load(),
        artifact_root=tmp_path / "artifacts",
        http_host="127.0.0.1",
        http_port=0,
    )
    closed: list[bool] = []

    class TrackingService(web_app.AnalysisService):  # type: ignore[name-defined, misc]
        def close_all(self):  # type: ignore[no-untyped-def]
            closed.append(True)
            return super().close_all()

    with (
        patch.object(web_app, "AnalysisService", TrackingService),
        patch.object(uvicorn, "run", lambda *args, **kwargs: None),
    ):
        code = web_app.run_web(settings, host="127.0.0.1", port=0, quiet_banner=True)

    assert code == 0
    assert closed, "the server exited without releasing its sessions"