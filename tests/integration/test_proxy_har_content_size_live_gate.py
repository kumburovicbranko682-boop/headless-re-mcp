"""proxy.export_har live gate: HAR bodySize is on-wire, content.size is decoded.

The bug: the proxy fed one number -- the received (on-wire) body length,
measured from mitmproxy's ``raw_content`` -- into both ``response.bodySize`` and
``response.content.size`` of every HAR entry. HAR 1.2 draws them apart:
``bodySize`` is the bytes received on the wire (compressed as transferred),
``content.size`` is the decoded length after ``Content-Encoding`` is undone, and
the two are equal only when there was no compression. So a gzip'd response got a
``content.size`` equal to its compressed length -- which a HAR consumer reads as
"no compression" and an understated content size.

This gate drives one gzip'd and one identity response through a real mitmproxy,
then exports the HAR and asserts: the gzip entry's ``bodySize`` is the compressed
on-wire length while its ``content.size`` is the -1 "unknown" sentinel (the
export never decompresses), and the identity entry carries the same value in
both. It guards the guard -- the gzip payload really is smaller compressed -- so
a pass means the two sizes were told apart, not that they coincided. skip != pass:
it skips only when mitmproxy is genuinely absent.
"""

from __future__ import annotations

import gzip
import json
import socket
import threading
import time
import urllib.request
from collections.abc import Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from headless_re_mcp.backends.proxy.client import ProxyBackend

# A highly compressible JSON body: gzip'd it is far smaller than decoded, so the
# on-wire length and the decoded length are unmistakably different numbers.
_PAYLOAD = {"token": "A" * 6000, "n": 1}
_DECODED = json.dumps(_PAYLOAD).encode("utf-8")
_GZIPPED = gzip.compress(_DECODED)
# An identity body served with no Content-Encoding: on-wire == decoded.
_PLAIN = json.dumps({"plain": "B" * 300}).encode("utf-8")


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args: object) -> None:  # silence the access log
        pass

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        if self.path.endswith("/gz"):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Encoding", "gzip")
            self.send_header("Content-Length", str(len(_GZIPPED)))
            self.end_headers()
            self.wfile.write(_GZIPPED)
        elif self.path.endswith("/plain"):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(_PLAIN)))
            self.end_headers()
            self.wfile.write(_PLAIN)
        else:
            self.send_response(404)
            self.end_headers()


@contextmanager
def _origin() -> Iterator[str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = server.server_address[:2]
        yield f"http://127.0.0.1:{port}"
    finally:
        server.shutdown()
        server.server_close()


def _free_port() -> int:
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind(("127.0.0.1", 0))
    port = int(probe.getsockname()[1])
    probe.close()
    return port


def _mitmproxy_available() -> bool:
    try:
        import mitmproxy.version  # noqa: F401
    except Exception:  # noqa: BLE001 - absence is the only thing we ask
        return False
    return True


def _get_through_proxy(url: str, proxy: str) -> None:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({"http": proxy}))
    with opener.open(url, timeout=15.0) as response:
        response.read()


@pytest.mark.integration
def test_export_har_separates_wire_size_from_decoded_size(tmp_path: Path) -> None:
    if not _mitmproxy_available():
        pytest.skip("mitmproxy not installed — HAR size Gate not run (skip != pass)")

    # Guard the guard: the compressed body really is smaller, so telling the two
    # sizes apart is meaningful rather than a coincidence.
    assert len(_GZIPPED) < len(_DECODED)

    backend = ProxyBackend()
    proxy_port = _free_port()
    started = backend.start("har-size-gate", host="127.0.0.1", port=proxy_port)
    assert started["running"] is True
    try:
        with _origin() as origin:
            _get_through_proxy(f"{origin}/gz", f"http://127.0.0.1:{proxy_port}")
            _get_through_proxy(f"{origin}/plain", f"http://127.0.0.1:{proxy_port}")

            # Both responses arrive on mitmproxy's loop thread; wait for them.
            rows: dict[str, dict] = {}
            deadline = time.monotonic() + 15.0
            while time.monotonic() < deadline:
                rows = {}
                for row in backend.flows("har-size-gate", offset=0, limit=100)["flows"]:
                    url = str(row.get("url", ""))
                    if url.endswith("/gz"):
                        rows["gz"] = row
                    elif url.endswith("/plain"):
                        rows["plain"] = row
                if "gz" in rows and "plain" in rows:
                    break
                time.sleep(0.2)

            assert "gz" in rows and "plain" in rows, rows

            # The summary reports the on-wire (compressed) length and marks the
            # gzip flow encoded; the identity flow is not marked.
            assert rows["gz"]["response_size"] == len(_GZIPPED)
            assert rows["gz"].get("response_encoded") is True
            assert rows["plain"]["response_size"] == len(_PLAIN)
            assert rows["plain"].get("response_encoded") is not True

            out = tmp_path / "capture.har"
            backend.export_har("har-size-gate", out)
            doc = json.loads(out.read_text(encoding="utf-8"))
            entries: dict[str, dict] = {}
            for entry in doc["log"]["entries"]:
                url = str(entry["request"]["url"])
                if url.endswith("/gz"):
                    entries["gz"] = entry
                elif url.endswith("/plain"):
                    entries["plain"] = entry

            assert "gz" in entries and "plain" in entries, list(entries)

            gz_resp = entries["gz"]["response"]
            plain_resp = entries["plain"]["response"]

            # The fix: for the gzip flow, bodySize is the compressed on-wire
            # length and content.size is the -1 "unknown" sentinel -- not the
            # compressed length restated as the decoded size.
            assert gz_resp["bodySize"] == len(_GZIPPED)
            assert gz_resp["content"]["size"] == -1
            assert gz_resp["content"]["size"] != gz_resp["bodySize"]

            # The identity flow was not encoded, so on-wire == decoded and both
            # fields carry the same real length.
            assert plain_resp["bodySize"] == len(_PLAIN)
            assert plain_resp["content"]["size"] == len(_PLAIN)
    finally:
        backend.stop("har-size-gate")
