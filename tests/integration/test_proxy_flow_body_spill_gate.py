"""Live proxy gate: flow_get spills a large body to disk, inlines a small one.

The capture gate only ever retrieves a tiny response, so it exercises one side
of flow_get's size boundary -- the inline ``body`` string -- and never the other.
Above 200 KB flow_get must not inline the body into the JSON envelope; it writes
the raw bytes to an artifact file and returns ``body_path`` instead. That branch
is the memory-safety valve for multi-megabyte responses, and it is also the only
path that preserves a binary body intact (the inline path is utf-8 decoded with
replacement, which would corrupt non-text bytes).

This gate routes one small text response and one large binary response through
mitmproxy and asserts flow_get inlines the first and spills the second to a real
file whose bytes match exactly. skip != pass when mitmproxy is missing.
"""

from __future__ import annotations

import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from headless_re_mcp.backends.proxy import ProxyBackend, ProxyError

_SMALL = b"proxy-spill-gate-small-inline-8c17"
# ~300 KB, above the 200 KB inline threshold, and full of bytes that are not
# valid utf-8 so a regression that inlined + decoded it would be caught as
# corruption, not just as a wrong field name.
_BIG = bytes((i * 7 + 3) % 256 for i in range(300_000))


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


class _Origin(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract
        if self.path.startswith("/big"):
            body, ctype = _BIG, "application/octet-stream"
        else:
            body, ctype = _SMALL, "text/plain; charset=utf-8"
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: object) -> None:  # keep pytest output clean
        return


def _http_get_via_proxy(
    proxy_host: str, proxy_port: int, url: str, host_header: str, timeout: float = 15.0
) -> None:
    """Drive a request through the forward proxy; the response body is ignored.

    A raw socket with an absolute-form request line avoids urllib's localhost
    proxy-bypass, guaranteeing the request traverses mitmproxy so the flow is
    recorded.
    """
    with socket.create_connection((proxy_host, proxy_port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        request = (
            f"GET {url} HTTP/1.1\r\n"
            f"Host: {host_header}\r\n"
            "Connection: close\r\n\r\n"
        ).encode("ascii")
        sock.sendall(request)
        while True:
            if not sock.recv(65536):
                break


@pytest.mark.integration
def test_proxy_flow_get_spills_large_body_and_inlines_small(tmp_path: Path) -> None:
    if not _mitmproxy_available():
        pytest.skip("mitmproxy not installed — proxy spill Gate not run (skip != pass)")

    origin_port = _free_port()
    origin = ThreadingHTTPServer(("127.0.0.1", origin_port), _Origin)
    threading.Thread(target=origin.serve_forever, daemon=True).start()

    backend = ProxyBackend()
    proxy_port = _free_port()
    assert backend.start("spill", host="127.0.0.1", port=proxy_port)["running"] is True
    try:
        host_header = f"127.0.0.1:{origin_port}"
        for leaf in ("small", "big"):
            _http_get_via_proxy(
                "127.0.0.1", proxy_port, f"http://127.0.0.1:{origin_port}/{leaf}", host_header
            )

        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline and backend.status("spill")["flow_count"] < 2:
            time.sleep(0.05)
        assert backend.status("spill")["flow_count"] >= 2

        flows = backend.flows("spill")["flows"]
        id_by_leaf = {leaf: None for leaf in ("small", "big")}
        for flow in flows:
            for leaf in id_by_leaf:
                if str(flow["url"]).endswith(f"/{leaf}"):
                    id_by_leaf[leaf] = flow["id"]
        assert id_by_leaf["small"] and id_by_leaf["big"], flows

        artifacts = tmp_path / "artifacts"

        # Small response: inlined into the envelope, no file spilled.
        small = backend.flow_get("spill", id_by_leaf["small"], artifacts)
        assert small["response"]["status"] == 200
        assert small["response"]["size"] == len(_SMALL)
        assert "body_path" not in small["response"], small
        assert _SMALL.decode() in small["response"]["body"], small

        # Large response: spilled to a real file under the artifact dir, not
        # inlined, and byte-for-byte identical to what the origin served.
        big = backend.flow_get("spill", id_by_leaf["big"], artifacts)
        assert big["response"]["status"] == 200
        assert big["response"]["size"] == len(_BIG)
        assert "body" not in big["response"], big
        spilled = big["response"].get("body_path")
        assert isinstance(spilled, str) and spilled, big
        spilled_path = Path(spilled)
        assert artifacts in spilled_path.parents, spilled
        assert spilled_path.is_file(), spilled
        assert spilled_path.read_bytes() == _BIG
    finally:
        backend.stop("spill")
        origin.shutdown()
        origin.server_close()
