"""Live mitmproxy capture gate: real traffic in, flows / bodies / HAR out.

The lifecycle gate proves the port contract (start listens, stop releases). This
gate proves the thing the proxy exists for: that traffic sent through it is
actually recorded and readable. It stands up a local origin server, routes a GET
and a POST through the running proxy, and asserts the flow ring, per-flow body
retrieval and the HAR export all reflect the real request/response -- plus that a
request to an unreachable upstream is captured as an errored flow rather than
silently dropped. Everything is unit-mocked elsewhere; nothing else drives the
mitmproxy DumpMaster end to end.

mitmproxy is optional, so the gate skips loudly when it is absent (skip != pass).
Only plain HTTP is exercised, so no CA trust setup is needed on the runner.
"""

from __future__ import annotations

import json
import socket
import threading
import urllib.error
import urllib.request
from collections.abc import Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from headless_re_mcp.backends.proxy import ProxyBackend, ProxyError

_GET_BODY = b'{"hello":"gate","n":42}'
_MANDATORY_HAR_ENTRY_KEYS = {
    "startedDateTime",
    "time",
    "request",
    "response",
    "cache",
    "timings",
}


def _mitmproxy_available() -> bool:
    try:
        ProxyBackend()._check_available()
    except ProxyError:
        return False
    return True


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


class _OriginHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(_GET_BODY)))
        self.end_headers()
        self.wfile.write(_GET_BODY)

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(length)
        body = b"created"
        self.send_response(201)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args: object) -> None:  # keep test output quiet
        return


@contextmanager
def _origin_server() -> Iterator[str]:
    server = HTTPServer(("127.0.0.1", _free_port()), _OriginHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        thread.join(timeout=5.0)


@contextmanager
def _running_proxy(session: str) -> Iterator[tuple[ProxyBackend, str]]:
    backend = ProxyBackend()
    port = _free_port()
    backend.start(session, host="127.0.0.1", port=port)
    try:
        yield backend, f"http://127.0.0.1:{port}"
    finally:
        backend.stop(session)


def _proxied_opener(proxy_url: str) -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(urllib.request.ProxyHandler({"http": proxy_url}))


def _wait_for_flows(backend: ProxyBackend, session: str, want: int) -> list[dict]:
    # The recorder is written from the proxy's own loop thread, so poll briefly
    # for the flow to land rather than racing it.
    import time

    deadline = time.monotonic() + 10.0
    while time.monotonic() < deadline:
        flows = backend.flows(session)["flows"]
        if len(flows) >= want:
            return flows
        time.sleep(0.05)
    return backend.flows(session)["flows"]


@pytest.mark.integration
def test_proxy_records_get_and_post_flows_with_bodies(tmp_path: Path) -> None:
    if not _mitmproxy_available():
        pytest.skip("mitmproxy not installed — proxy capture Gate not run (skip != pass)")

    with _origin_server() as origin, _running_proxy("capture") as (backend, proxy_url):
        opener = _proxied_opener(proxy_url)
        got = opener.open(origin + "/api/thing?q=1&x=two", timeout=10)
        assert got.status == 200
        assert got.read() == _GET_BODY
        posted = opener.open(
            urllib.request.Request(
                origin + "/submit",
                data=b'{"a":1}',
                method="POST",
                headers={"Content-Type": "application/json"},
            ),
            timeout=10,
        )
        assert posted.status == 201

        flows = _wait_for_flows(backend, "capture", want=2)
        assert len(flows) == 2, flows
        by_method = {f["method"]: f for f in flows}
        assert set(by_method) == {"GET", "POST"}, flows

        get_flow = by_method["GET"]
        assert get_flow["status"] == 200
        assert get_flow["url"].endswith("/api/thing?q=1&x=two")
        assert get_flow["content_type"] == "application/json"
        assert get_flow["response_size"] == len(_GET_BODY)

        post_flow = by_method["POST"]
        assert post_flow["status"] == 201

        # flow.get must return the real bodies: the GET response, and -- what an
        # API reverse-engineer most wants -- the POST *request* body.
        get_detail = backend.flow_get("capture", get_flow["id"], tmp_path / "get")
        assert get_detail["response"]["body"] == _GET_BODY.decode()

        post_detail = backend.flow_get("capture", post_flow["id"], tmp_path / "post")
        assert post_detail["request"]["body"] == '{"a":1}'
        assert post_detail["response"]["body"] == "created"


@pytest.mark.integration
def test_proxy_exports_a_spec_valid_har_of_captured_flows(tmp_path: Path) -> None:
    if not _mitmproxy_available():
        pytest.skip("mitmproxy not installed — proxy capture Gate not run (skip != pass)")

    with _origin_server() as origin, _running_proxy("har") as (backend, proxy_url):
        opener = _proxied_opener(proxy_url)
        opener.open(origin + "/page?q=1&x=two", timeout=10).read()
        _wait_for_flows(backend, "har", want=1)

        out = tmp_path / "capture.har"
        result = backend.export_har("har", out)
        assert result["entry_count"] >= 1, result
        assert out.is_file()

        har = json.loads(out.read_text(encoding="utf-8"))
        assert har["log"]["version"] == "1.2"
        entries = har["log"]["entries"]
        assert entries, har
        entry = entries[0]
        # Every mandatory 1.2 member is present, or a strict consumer (Chrome
        # DevTools "Import HAR", har-validator) rejects the whole file.
        assert set(entry) >= _MANDATORY_HAR_ENTRY_KEYS, sorted(entry)
        assert entry["request"]["queryString"] == [
            {"name": "q", "value": "1"},
            {"name": "x", "value": "two"},
        ]
        assert entry["response"]["status"] == 200
        assert entry["response"]["content"]["mimeType"] == "application/json"
        assert entry["response"]["content"]["size"] == len(_GET_BODY)


@pytest.mark.integration
def test_proxy_records_an_unreachable_upstream_as_an_errored_flow() -> None:
    if not _mitmproxy_available():
        pytest.skip("mitmproxy not installed — proxy capture Gate not run (skip != pass)")

    # A port nothing listens on: the proxy's upstream connect must fail.
    dead_port = _free_port()
    with _running_proxy("errored") as (backend, proxy_url):
        opener = _proxied_opener(proxy_url)
        with pytest.raises(urllib.error.HTTPError) as caught:
            opener.open(f"http://127.0.0.1:{dead_port}/gone", timeout=10)
        # mitmproxy answers the client with a gateway error it could not fulfil.
        assert caught.value.code >= 500

        flows = _wait_for_flows(backend, "errored", want=1)
        assert len(flows) == 1, flows
        errored = flows[0]
        # A failed request is captured, not dropped, and stays distinguishable
        # from a completed one: no numeric status, an error flag and a message.
        assert errored["status"] is None, errored
        assert errored["error"] is True, errored
        assert errored["error_msg"], errored
