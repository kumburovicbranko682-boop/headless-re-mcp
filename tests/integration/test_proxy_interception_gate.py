"""Live mitmproxy interception gate: real traffic in, faithful capture out.

The lifecycle gate proves start/stop honesty, but every assertion it makes is
about an empty capture (``flow_count == 0``). This gate proves the reason the
proxy exists: a request routed through the capture port reaches its origin,
and the flow ring, flow.get bodies, replay, and the HAR export all describe
the traffic that actually happened.
"""

from __future__ import annotations

import contextlib
import json
import socket
import threading
import time
import urllib.request
from collections.abc import Callable, Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import cast

import pytest

from headless_re_mcp.backends.proxy import ProxyBackend, ProxyError

_TOKEN_BODY = b'{"token": "headless-re-gate"}'
_LOGIN_REQUEST_BODY = b'{"user": "headless"}'


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def _mitmproxy_available() -> bool:
    try:
        ProxyBackend()._check_available()
    except ProxyError:
        return False
    return True


def _wait_until(predicate: Callable[[], bool], what: str, timeout: float = 15.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.05)
    pytest.fail(f"timed out waiting for {what}")


class _Origin(ThreadingHTTPServer):
    """Local HTTP origin that remembers every request the proxy forwards."""

    def __init__(self) -> None:
        self.requests: list[tuple[str, str, bytes]] = []
        self.lock = threading.Lock()
        super().__init__(("127.0.0.1", 0), _OriginHandler)

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.server_address[1]}"

    def seen(self) -> list[tuple[str, str, bytes]]:
        with self.lock:
            return list(self.requests)


class _OriginHandler(BaseHTTPRequestHandler):
    def _origin(self) -> _Origin:
        return cast(_Origin, self.server)

    def _reply(self, status: int, content_type: str, payload: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler's contract
        origin = self._origin()
        with origin.lock:
            origin.requests.append(("GET", self.path, b""))
        self._reply(200, "application/json", _TOKEN_BODY)

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler's contract
        origin = self._origin()
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        with origin.lock:
            origin.requests.append(("POST", self.path, body))
        self._reply(201, "text/plain", b"created:" + body)

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        """Silence the default stderr access log; the test reads self.requests."""


@contextlib.contextmanager
def _live_capture(
    session_id: str,
) -> Iterator[tuple[ProxyBackend, _Origin, urllib.request.OpenerDirector]]:
    backend = ProxyBackend()
    proxy_port = _free_port()
    backend.start(session_id, host="127.0.0.1", port=proxy_port)
    origin = _Origin()
    serving = threading.Thread(target=origin.serve_forever, name="origin-http", daemon=True)
    serving.start()
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({"http": f"http://127.0.0.1:{proxy_port}"})
    )
    try:
        yield backend, origin, opener
    finally:
        with contextlib.suppress(Exception):
            backend.close_all()
        origin.shutdown()
        origin.server_close()


@pytest.mark.integration
def test_capture_describes_the_traffic_that_really_happened(tmp_path: Path) -> None:
    if not _mitmproxy_available():
        pytest.skip("mitmproxy not installed — proxy interception Gate not run (skip != pass)")
    with _live_capture("gate-intercept") as (backend, origin, opener):
        # The client must get real origin responses through the proxy...
        with opener.open(f"{origin.base_url}/token", timeout=10) as got:
            assert got.status == 200
            assert got.read() == _TOKEN_BODY
        login = urllib.request.Request(
            f"{origin.base_url}/login",
            data=_LOGIN_REQUEST_BODY,
            headers={"Content-Type": "application/json"},
        )
        with opener.open(login, timeout=10) as got:
            assert got.status == 201
            assert got.read() == b"created:" + _LOGIN_REQUEST_BODY

        # ...and the origin must have seen exactly those two requests.
        assert origin.seen() == [
            ("GET", "/token", b""),
            ("POST", "/login", _LOGIN_REQUEST_BODY),
        ]

        session = "gate-intercept"
        _wait_until(
            lambda: backend.status(session).get("flow_count") == 2,
            "both flows to land in the capture ring",
        )
        listing = backend.flows(session)
        assert listing["total"] == 2
        assert listing["dropped"] == 0
        rows = cast(list[dict[str, object]], listing["flows"])
        # Sequential requests must be captured in the order they happened.
        assert [(row["method"], row["url"], row["status"]) for row in rows] == [
            ("GET", f"{origin.base_url}/token", 200),
            ("POST", f"{origin.base_url}/login", 201),
        ]
        assert rows[0]["content_type"] == "application/json"
        assert rows[0]["response_size"] == len(_TOKEN_BODY)

        # flow.get must hand back the actual bytes on the wire, both directions.
        detail = backend.flow_get(session, str(rows[1]["id"]), tmp_path)
        request = cast(dict[str, object], detail["request"])
        response = cast(dict[str, object], detail["response"])
        assert request["method"] == "POST"
        assert request["body"] == _LOGIN_REQUEST_BODY.decode()
        headers = {
            key.lower(): value for key, value in cast(dict[str, str], request["headers"]).items()
        }
        assert headers["content-type"] == "application/json"
        assert response["status"] == 201
        assert response["body"] == "created:" + _LOGIN_REQUEST_BODY.decode()

        # The HAR export must carry the same two exchanges.
        out_path = tmp_path / "capture.har"
        exported = backend.export_har(session, out_path)
        assert exported["entry_count"] == 2
        assert exported["truncated"] is False
        entries = json.loads(out_path.read_text(encoding="utf-8"))["log"]["entries"]
        assert [(e["request"]["method"], e["request"]["url"]) for e in entries] == [
            ("GET", f"{origin.base_url}/token"),
            ("POST", f"{origin.base_url}/login"),
        ]
        assert [e["response"]["status"] for e in entries] == [200, 201]


@pytest.mark.integration
def test_replay_reissues_the_recorded_request_to_the_origin() -> None:
    if not _mitmproxy_available():
        pytest.skip("mitmproxy not installed — proxy interception Gate not run (skip != pass)")
    with _live_capture("gate-replay") as (backend, origin, opener):
        with opener.open(f"{origin.base_url}/token", timeout=10) as got:
            assert got.read() == _TOKEN_BODY
        _wait_until(
            lambda: backend.status("gate-replay").get("flow_count") == 1,
            "the first flow to land in the capture ring",
        )
        rows = cast(list[dict[str, object]], backend.flows("gate-replay")["flows"])
        flow_id = str(rows[0]["id"])

        replayed = backend.replay("gate-replay", flow_id)
        assert replayed == {"replayed": True, "flow_id": flow_id}

        # Replay is only real if the origin serves the request a second time
        # and the new exchange lands in the ring as its own flow.
        _wait_until(
            lambda: len(origin.seen()) == 2,
            "the origin to serve the replayed request",
        )
        assert origin.seen() == [("GET", "/token", b"")] * 2
        _wait_until(
            lambda: backend.status("gate-replay").get("flow_count") == 2,
            "the replayed flow to land in the capture ring",
        )
        replay_rows = cast(list[dict[str, object]], backend.flows("gate-replay")["flows"])
        assert [(row["method"], row["url"], row["status"]) for row in replay_rows] == [
            ("GET", f"{origin.base_url}/token", 200)
        ] * 2
        assert replay_rows[1]["id"] != flow_id
