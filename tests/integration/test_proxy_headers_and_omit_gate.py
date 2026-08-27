"""Live gate: proxy captures both header directions and drops oversized bodies.

The proxy gates cover capture, HTTPS, replay and the 200KB->disk body spill, but
two contracts of an interception proxy are still unproven. First, an analyst
relies on seeing *both* header directions -- what the client sent (auth tokens,
custom headers) and what the origin returned (set-cookie, content types) -- and
nothing asserts flow_get exposes them faithfully. Second, the recorder omits any
flow whose stored bytes exceed 2 MiB: the summary is kept but the body is
dropped and flow_get must answer a structured ``too_large`` rather than hand back
a truncated blob. That omission path is distinct from the 200KB->2MB spill and is
ungated.

Both are driven with a plain urllib client pointed at the proxy (no browser, so
the checks are deterministic): one request carries a custom header to an origin
that returns a custom header, and a second requests a >2 MiB body. skip != pass
when mitmproxy is missing.
"""

from __future__ import annotations

import socket
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from headless_re_mcp.backends.proxy import ProxyBackend, ProxyError

_REQ_HEADER = ("X-Gate-Token", "gate-req-7c1e")
_RESP_HEADER = ("X-Gate-Origin", "gate-resp-9a4d")
_SMALL_BODY = b"small-body-marker-11a2"
# Just over the recorder's 2 MiB _MAX_STORED_BODY so retention is refused.
_BIG_BODY = b"B" * (2 * 1024 * 1024 + 4096)


class _Origin(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract
        body = _BIG_BODY if self.path.startswith("/big") else _SMALL_BODY
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header(_RESP_HEADER[0], _RESP_HEADER[1])
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: object) -> None:  # keep pytest output clean
        return


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


def _fetch_through_proxy(url: str, proxy_url: str) -> tuple[int, bytes]:
    handler = urllib.request.ProxyHandler({"http": proxy_url})
    opener = urllib.request.build_opener(handler)
    request = urllib.request.Request(url, headers={_REQ_HEADER[0]: _REQ_HEADER[1]})
    with opener.open(request, timeout=15) as response:
        return int(response.status), response.read()


def _ci_lookup(headers: dict[str, str], name: str) -> str | None:
    for key, value in headers.items():
        if key.lower() == name.lower():
            return value
    return None


def _wait_flows(proxy: ProxyBackend, session: str, want: int, timeout: float = 6.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if proxy.status(session)["flow_count"] >= want:
            return
        time.sleep(0.1)


@pytest.mark.integration
def test_proxy_captures_request_and_response_headers(tmp_path: Path) -> None:
    if not _mitmproxy_available():
        pytest.skip("mitmproxy not installed — proxy headers Gate not run (skip != pass)")

    origin_port = _free_port()
    origin = ThreadingHTTPServer(("127.0.0.1", origin_port), _Origin)
    threading.Thread(target=origin.serve_forever, daemon=True).start()

    proxy = ProxyBackend()
    proxy_port = _free_port()
    try:
        proxy.start("px", host="127.0.0.1", port=proxy_port)
        time.sleep(0.3)

        status, body = _fetch_through_proxy(
            f"http://127.0.0.1:{origin_port}/small", f"http://127.0.0.1:{proxy_port}"
        )
        assert status == 200
        assert body == _SMALL_BODY

        _wait_flows(proxy, "px", 1)
        flow = next(
            f for f in proxy.flows("px")["flows"] if str(f["url"]).endswith("/small")
        )
        detail = proxy.flow_get("px", flow["id"], tmp_path / "artifacts")

        # Request direction: the custom header the client sent survived into the
        # captured request, with its value intact.
        assert detail["request"]["method"] == "GET", detail["request"]
        assert str(detail["request"]["url"]).endswith("/small"), detail["request"]
        assert _ci_lookup(detail["request"]["headers"], _REQ_HEADER[0]) == _REQ_HEADER[1], detail[
            "request"
        ]["headers"]

        # Response direction: the origin's custom header and content type are
        # both exposed, and the body is inline for a small flow.
        assert detail["response"]["status"] == 200, detail["response"]
        assert _ci_lookup(detail["response"]["headers"], _RESP_HEADER[0]) == _RESP_HEADER[1], (
            detail["response"]["headers"]
        )
        assert (
            _ci_lookup(detail["response"]["headers"], "Content-Type")
            == "application/octet-stream"
        ), detail["response"]["headers"]
        assert detail["response"]["body"] == _SMALL_BODY.decode(), detail["response"]
    finally:
        proxy.close_all()
        origin.shutdown()
        origin.server_close()


@pytest.mark.integration
def test_proxy_omits_oversized_body_but_keeps_the_summary(tmp_path: Path) -> None:
    if not _mitmproxy_available():
        pytest.skip("mitmproxy not installed — proxy omit Gate not run (skip != pass)")

    origin_port = _free_port()
    origin = ThreadingHTTPServer(("127.0.0.1", origin_port), _Origin)
    threading.Thread(target=origin.serve_forever, daemon=True).start()

    proxy = ProxyBackend()
    proxy_port = _free_port()
    try:
        proxy.start("px", host="127.0.0.1", port=proxy_port)
        time.sleep(0.3)

        status, body = _fetch_through_proxy(
            f"http://127.0.0.1:{origin_port}/big", f"http://127.0.0.1:{proxy_port}"
        )
        assert status == 200
        assert len(body) == len(_BIG_BODY)  # the client still got the whole body

        _wait_flows(proxy, "px", 1)
        flow = next(
            f for f in proxy.flows("px")["flows"] if str(f["url"]).endswith("/big")
        )
        # The summary is retained -- method, url and status are still queryable --
        # but the recorder marks the body as omitted for exceeding 2 MiB.
        assert flow["method"] == "GET", flow
        assert flow["status"] == 200, flow
        assert flow.get("body_omitted") is True, flow

        # flow_get refuses with a structured too_large rather than a partial body.
        with pytest.raises(ProxyError) as excinfo:
            proxy.flow_get("px", flow["id"], tmp_path / "artifacts")
        assert excinfo.value.code == "too_large", excinfo.value.code
    finally:
        proxy.close_all()
        origin.shutdown()
        origin.server_close()
