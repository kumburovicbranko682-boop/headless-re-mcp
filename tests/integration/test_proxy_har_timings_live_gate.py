"""proxy.export_har live gate: HAR carries the flow's real time, not export time.

The bug: ``proxy.export_har`` fed no timing to ``har_entry``, so every entry's
``startedDateTime`` fell back to *export* time -- the instant the HAR file was
written -- and all of ``timings`` stayed the -1 "not measured" sentinel with
``time`` 0. A HAR consumer (Chrome DevTools "Import HAR", Firefox) then draws
the whole capture as flows that all started at one moment with flat, zero-width
waterfall bars: the timeline is destroyed. mitmproxy already stamps
``timestamp_start`` / ``timestamp_end`` on each end of the exchange, so the fix
derives each flow's real start and its send/wait/receive phases (the same
mapping mitmproxy's own HAR addon uses) and hands them to the export.

This gate drives one request through a real mitmproxy to an origin that delays
its response by a known amount, then -- crucially -- waits a further, larger
gap before exporting, so the request instant and the export instant are far
apart. It asserts the entry's ``startedDateTime`` is the request instant (at or
before the pre-export marker), not the much-later export instant; that the
measured ``wait`` phase reflects the origin's real delay (guarding the guard:
the delay budget really exceeds the threshold, so a pass means a measurement,
not a coincidence); and that ``time`` is the non-negative sum of the phases.
skip != pass: it skips only when mitmproxy is genuinely absent.
"""

from __future__ import annotations

import json
import socket
import threading
import time
import urllib.request
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from headless_re_mcp.backends.proxy.client import ProxyBackend

# The origin holds each response back by this long before replying. It is far
# larger than the sub-millisecond measurement noise of a loopback exchange, so a
# measured ``wait`` at least a good fraction of it proves the phase was timed.
_SERVER_DELAY_S = 0.30
_WAIT_FLOOR_MS = 150.0
# The gap between the request completing and the export running. Making it large
# means an export-time ``startedDateTime`` (the old behaviour) lands far after
# the request instant, so the two are impossible to confuse.
_EXPORT_DELAY_S = 3.0


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args: object) -> None:  # silence the access log
        pass

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        time.sleep(_SERVER_DELAY_S)
        body = b'{"ok": true}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


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
    with opener.open(url, timeout=20.0) as response:
        response.read()


@pytest.mark.integration
def test_export_har_stamps_the_request_instant_and_measures_the_phases(
    tmp_path: Path,
) -> None:
    if not _mitmproxy_available():
        pytest.skip("mitmproxy not installed — HAR timings Gate not run (skip != pass)")

    # Guard the guard: the origin's delay budget really exceeds the wait floor,
    # so a measured wait clearing the floor is a real timing, not a fluke.
    assert _SERVER_DELAY_S * 1000.0 > _WAIT_FLOOR_MS

    backend = ProxyBackend()
    proxy_port = _free_port()
    started = backend.start("har-timings-gate", host="127.0.0.1", port=proxy_port)
    assert started["running"] is True
    try:
        with _origin() as origin:
            _get_through_proxy(f"{origin}/slow", f"http://127.0.0.1:{proxy_port}")

            # Wait for the response to land on mitmproxy's loop thread.
            row: dict | None = None
            deadline = time.monotonic() + 20.0
            while time.monotonic() < deadline:
                for candidate in backend.flows("har-timings-gate", offset=0, limit=50)["flows"]:
                    if str(candidate.get("url", "")).endswith("/slow"):
                        row = candidate
                        break
                if row is not None:
                    break
                time.sleep(0.2)
            assert row is not None, "the /slow flow never appeared"

            # The summary row carries the real start and the measured phases.
            assert "started_at" in row, row
            assert row["timings"]["wait"] >= _WAIT_FLOOR_MS, row["timings"]

            # Mark the moment the request is known-complete, then wait a large
            # gap. An export-time startedDateTime would now be far past this
            # marker; a request-time one stays at or before it.
            pre_export = datetime.now(UTC)
            time.sleep(_EXPORT_DELAY_S)

            out = tmp_path / "capture.har"
            backend.export_har("har-timings-gate", out)
            doc = json.loads(out.read_text(encoding="utf-8"))
            entry = next(
                e for e in doc["log"]["entries"] if str(e["request"]["url"]).endswith("/slow")
            )

            # The fix: startedDateTime is the request instant, not export time.
            started_at = datetime.fromisoformat(entry["startedDateTime"])
            gap_s = (pre_export - started_at).total_seconds()
            # Positive gap: the request started before the pre-export marker. The
            # old behaviour stamped export time, ~_EXPORT_DELAY_S *after* it, which
            # would make this gap sharply negative. A hair of tolerance for skew.
            assert gap_s >= -0.25, (
                f"startedDateTime {started_at} looks like export time, not the "
                f"request instant (marker {pre_export}, gap {gap_s:.3f}s)"
            )
            # And it is a recent, sane instant -- the actual request, not epoch 0.
            assert gap_s <= 60.0, gap_s

            # The phases were measured: wait reflects the origin's real delay, and
            # time is the non-negative sum of the phases (> 0, unlike the old
            # flat-zero waterfall).
            timings = entry["timings"]
            assert timings["wait"] >= _WAIT_FLOOR_MS, timings
            assert timings["send"] >= 0, timings
            assert timings["receive"] >= 0, timings
            measured = [v for v in (timings["send"], timings["wait"], timings["receive"]) if v >= 0]
            assert entry["time"] == pytest.approx(round(sum(measured), 3), abs=0.01)
            assert entry["time"] >= timings["wait"]
    finally:
        backend.stop("har-timings-gate")
