"""An IPv6 loopback child must be probeable, or the supervisor kills it forever.

``run_web`` accepts any ``is_loopback`` address, so ``supervise --target
serve-web --host ::1`` starts a child that binds and serves normally. But the
readiness URL was built as ``f"http://{host}:{port}/readyz"``, and
``urlsplit("http://::1:8765/readyz")`` reads an empty hostname -- an IPv6
authority needs brackets -- so ``probe_ready`` reported that healthy child
unreachable on every check. Three strikes later the supervisor terminated and
restarted it, and because "unhealthy" restarts never count toward the
crash-loop bound, it kept doing so indefinitely. These pin the bracketed URL,
prove the probe reaches a real ::1 listener through it, and keep the old
unbracketed form on record as the failure it was.
"""

from __future__ import annotations

import json
import socket
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

import pytest

import headless_re_mcp.cli as cli_module
from headless_re_mcp.config import Settings
from headless_re_mcp.supervisor import probe_ready, readyz_url


def test_readyz_url_brackets_an_ipv6_literal_and_leaves_ipv4_alone() -> None:
    assert readyz_url("::1", 8765) == "http://[::1]:8765/readyz"
    assert readyz_url("127.0.0.1", 8765) == "http://127.0.0.1:8765/readyz"


class _V6Server(HTTPServer):
    address_family = socket.AF_INET6


class _Ready(BaseHTTPRequestHandler):
    def log_message(self, *args: object) -> None:
        return

    def do_GET(self) -> None:
        body = b'{"ok":true}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _serve_v6() -> Iterator[int]:
    try:
        httpd = _V6Server(("::1", 0), _Ready)
    except OSError:
        pytest.skip("IPv6 loopback is unavailable on this host")
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield int(httpd.server_address[1])
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=2.0)


def test_probe_ready_reaches_a_live_ipv6_loopback_child_through_readyz_url() -> None:
    for port in _serve_v6():
        ok, detail = probe_ready(readyz_url("::1", port), timeout=2.0)
        assert ok is True
        assert detail == "http 200"


def test_the_unbracketed_form_reported_that_same_live_child_unreachable() -> None:
    """The pre-fix URL, kept as evidence: the server answers, the probe cannot ask."""
    for port in _serve_v6():
        ok, detail = probe_ready(f"http://::1:{port}/readyz", timeout=2.0)
        assert ok is False
        assert detail.startswith("unreachable:")


def test_supervise_ipv6_loopback_host_builds_a_bracketed_ready_url(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    settings = Settings(
        ida_home=None,
        x64dbg_source=None,
        x64dbg_headless_x64=None,
        x64dbg_headless_x86=None,
        artifact_root=tmp_path / "artifacts",
        http_host="127.0.0.1",
        http_port=8765,
    )
    monkeypatch.setattr(Settings, "load", staticmethod(lambda _path=None: settings))
    seen: dict[str, Any] = {}

    class _FakeReport:
        stopped_reason = "child_exited_cleanly"

        def as_json(self) -> dict[str, Any]:
            return {"stopped_reason": self.stopped_reason}

    class _FakeSupervisor:
        def __init__(self, argv: Any, **kwargs: Any) -> None:
            seen["argv"] = argv
            seen.update(kwargs)

        def run_forever(self) -> _FakeReport:
            return _FakeReport()

    monkeypatch.setattr("headless_re_mcp.supervisor.Supervisor", _FakeSupervisor)
    code = cli_module._main(
        ["supervise", "--target", "serve-web", "--host", "::1", "--port", "9106"]
    )
    assert code == 0
    assert seen["ready_url"] == "http://[::1]:9106/readyz"
    # The child still receives the bare literal: brackets belong to URLs, not
    # to the --host argument run_web validates with ipaddress.ip_address.
    assert "--host" in seen["argv"] and "::1" in seen["argv"]
    assert json.loads(capsys.readouterr().out)["ok"] is True
