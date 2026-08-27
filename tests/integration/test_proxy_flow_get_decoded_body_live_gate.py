"""proxy.flow.get live gate: a real gzip response comes back decompressed.

mitmproxy keeps two views of a body: ``raw_content`` is the bytes exactly as
they crossed the wire, and ``content`` is those bytes with any Content-Encoding
undone. Modern responses are almost always gzip- or brotli-compressed, so
``raw_content`` is opaque compressed bytes. flow.get read ``raw_content``, so
``_emit_body`` could only spill it as an unreadable ``.bin`` (spill_reason
"binary") -- hiding the very JSON an analyst opened flow.get to read. It now
reads ``content``, so a compressed body comes back as its real text.

Every unit test fakes the content/raw_content split, so only a real mitmproxy
proves that its own capture of a genuinely gzip-encoded response is decoded by
the backend. This gate stands up a throwaway localhost origin that always
gzip-encodes its JSON, drives a client through a real mitmproxy in regular proxy
mode, then fetches the captured flow and asserts the returned body is the
readable JSON -- and that its decoded size exceeds the on-wire (compressed)
response_size, proving compression really happened rather than the fix being a
no-op.

Skip != pass: the gate skips with a reason only when mitmproxy is absent. CI
installs it, so a skip there is a genuine regression rather than a bare machine.
"""

from __future__ import annotations

import gzip
import http.server
import json
import socket
import threading
import time
import urllib.request
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest

from headless_re_mcp.backends.proxy import ProxyBackend, ProxyError

# A repetitive JSON body so gzip is meaningfully smaller than the decoded text;
# the gate asserts the compression is real, not a wash.
_PAYLOAD = {"marker": "decoded-json-body-visible", "rows": ["repeat"] * 400}
_DECODED = json.dumps(_PAYLOAD).encode("utf-8")
_GZIPPED = gzip.compress(_DECODED)


class _GzipHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args: object) -> None:  # keep pytest output clean
        pass

    def do_GET(self) -> None:
        # Always gzip, regardless of Accept-Encoding, so the captured flow is
        # guaranteed to carry a Content-Encoding the backend must decode.
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Encoding", "gzip")
        self.send_header("Content-Length", str(len(_GZIPPED)))
        self.end_headers()
        self.wfile.write(_GZIPPED)


@contextmanager
def _gzip_origin() -> Iterator[str]:
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _GzipHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


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


def _get_through_proxy(url: str, proxy_endpoint: str) -> None:
    """Drive one HTTP GET through the proxy so mitmproxy captures the flow.

    urllib never auto-decompresses gzip, so what the client does with the body
    does not matter -- the gate only needs mitmproxy to record the exchange.
    """
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({"http": proxy_endpoint})
    )
    with opener.open(url, timeout=10) as resp:
        resp.read()


@pytest.mark.integration
def test_flow_get_returns_the_decompressed_body_of_a_real_gzip_response(
    tmp_path: Path,
) -> None:
    if not _mitmproxy_available():
        pytest.skip("mitmproxy not installed — decoded-body Gate not run (skip != pass)")

    # Guard the guard: the gzip really is smaller, so a pass means the body was
    # decoded, not that compressed and decoded happened to coincide.
    assert len(_GZIPPED) < len(_DECODED)

    backend = ProxyBackend()
    port = _free_port()
    started = backend.start("decoded-gate", host="127.0.0.1", port=port)
    assert started["running"] is True
    try:
        with _gzip_origin() as origin:
            _get_through_proxy(f"{origin}/api", f"http://127.0.0.1:{port}")

            # The response arrives on mitmproxy's loop thread; wait for it.
            flow_id = None
            wire_size = None
            deadline = time.monotonic() + 15.0
            while time.monotonic() < deadline:
                listing = backend.flows("decoded-gate", offset=0, limit=100)
                for row in listing["flows"]:
                    if str(row.get("url", "")).endswith("/api"):
                        flow_id = str(row["id"])
                        wire_size = int(row["response_size"])
                        break
                if flow_id is not None:
                    break
                time.sleep(0.2)

            assert flow_id is not None, "mitmproxy never captured the /api flow"
            # proxy.flows reports the on-wire (compressed) length.
            assert wire_size == len(_GZIPPED)

            payload = backend.flow_get("decoded-gate", flow_id, tmp_path)
            resp = payload["response"]

            # The fix: the body is the readable JSON, inline, sized by its
            # decompressed length -- never spilled as an opaque gzip .bin.
            assert "body_path" not in resp, resp.get("spill_reason")
            assert "spill_reason" not in resp
            assert resp["body"] == _DECODED.decode("utf-8")
            assert json.loads(resp["body"]) == _PAYLOAD
            assert resp["size"] == len(_DECODED)
            # Decoded size exceeds the on-wire size: compression was real.
            assert resp["size"] > wire_size
    finally:
        backend.stop("decoded-gate")
