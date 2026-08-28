"""Live mitmproxy lifecycle gate: honest start, real bind, clean release.

The unit tests bound the buffers; this gate proves the process-level contract
that an unattended run depends on -- start means listening, stop means the port
is free again, and a port that is already taken is refused instead of being
reported as a running capture.
"""

from __future__ import annotations

import contextlib
import http.server
import json
import socket
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from headless_re_mcp.backends.proxy import ProxyBackend, ProxyError
from headless_re_mcp.backends.proxy.client import _port_accepts


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


class _HelloHandler(http.server.BaseHTTPRequestHandler):
    """A one-route upstream so the proxy has a real flow to record."""

    # Class-level: how many requests actually reached the upstream. The replay
    # gate resets it and uses it as ground truth that replay touched the
    # network rather than only re-appending a row to the capture ring.
    hits = 0

    def do_GET(self) -> None:
        type(self).hits += 1
        body = b"hello-through-proxy"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: object) -> None:  # keep the test output clean
        return


def _mitmproxy_available() -> bool:
    try:
        ProxyBackend()._check_available()
    except ProxyError:
        return False
    return True


@pytest.mark.integration
def test_proxy_start_means_listening_and_stop_releases_the_port() -> None:
    if not _mitmproxy_available():
        pytest.skip("mitmproxy not installed — proxy lifecycle Gate not run (skip != pass)")
    backend = ProxyBackend()
    port = _free_port()
    started = backend.start("gate-session", host="127.0.0.1", port=port)
    try:
        assert started["running"] is True
        assert started["port"] == port
        # start() must not return before the socket actually accepts.
        assert _port_accepts("127.0.0.1", port, timeout=1.0) is True

        status = backend.status("gate-session")
        assert status["running"] is True
        assert status["flow_count"] == 0
        assert status["retained_max"] > 0
    finally:
        stopped = backend.stop("gate-session")

    assert stopped["stopped"] is True
    assert backend.status("gate-session") == {"running": False}

    # The listener must actually go away, or the next run cannot rebind.
    deadline = time.monotonic() + 10.0
    while time.monotonic() < deadline:
        if not _port_accepts("127.0.0.1", port, timeout=0.25):
            break
        time.sleep(0.1)
    else:
        pytest.fail("proxy port was still accepting connections after stop")


@pytest.mark.integration
def test_start_on_an_occupied_port_fails_instead_of_reporting_success() -> None:
    """A leftover listener must not be mistaken for our own healthy capture."""
    if not _mitmproxy_available():
        pytest.skip("mitmproxy not installed — proxy lifecycle Gate not run (skip != pass)")
    backend = ProxyBackend()
    squatter = socket.socket()
    squatter.bind(("127.0.0.1", 0))
    squatter.listen(1)
    port = int(squatter.getsockname()[1])
    try:
        with pytest.raises(ProxyError) as info:
            backend.start("gate-occupied", host="127.0.0.1", port=port)
        assert info.value.code == "invalid_state"
        # A refused start must leave no half-registered session behind.
        assert backend.status("gate-occupied") == {"running": False}
    finally:
        squatter.close()
        backend.stop("gate-occupied")


@pytest.mark.integration
def test_two_sessions_cannot_silently_share_one_port() -> None:
    if not _mitmproxy_available():
        pytest.skip("mitmproxy not installed — proxy lifecycle Gate not run (skip != pass)")
    backend = ProxyBackend()
    port = _free_port()
    backend.start("first", host="127.0.0.1", port=port)
    try:
        with pytest.raises(ProxyError):
            backend.start("second", host="127.0.0.1", port=port)
        assert backend.status("first")["running"] is True
        assert backend.status("second") == {"running": False}
    finally:
        backend.close_all()


@pytest.mark.integration
def test_close_all_releases_every_running_capture() -> None:
    if not _mitmproxy_available():
        pytest.skip("mitmproxy not installed — proxy lifecycle Gate not run (skip != pass)")
    backend = ProxyBackend()
    ports = [_free_port(), _free_port()]
    for index, port in enumerate(ports):
        backend.start(f"session-{index}", host="127.0.0.1", port=port)
    backend.close_all()
    for index, port in enumerate(ports):
        assert backend.status(f"session-{index}") == {"running": False}
        deadline = time.monotonic() + 10.0
        while time.monotonic() < deadline:
            if not _port_accepts("127.0.0.1", port, timeout=0.25):
                break
            time.sleep(0.1)
        else:
            pytest.fail(f"port {port} still accepting after close_all")


@pytest.mark.integration
def test_repeated_start_stop_cycles_do_not_leak_threads_or_ports() -> None:
    """Ten start/stop cycles must strand neither a serving thread nor a port.

    The single-cycle gate proves one stop frees its port, but a capture that is
    reclaimed everywhere except its own mitmproxy thread -- stop() reports
    stopped, the port even comes back, yet the DumpMaster thread lives on -- is
    the leak that only shows after a long unattended run turns into a hundred
    stranded event loops. mitmproxy serves each capture on its own thread and
    stop() joins it, so threading.active_count() is a deterministic, dependency
    -free signal here: a running capture is worth exactly one thread and a clean
    stop hands it back. That is what makes this soak load-bearing rather than a
    check that always reads zero.

    The bound is self-calibrating: one running capture is priced first, and the
    whole soak is allowed to drift by less than that. A stop that failed to join
    would grow by a thread per cycle -- ten over the soak -- tripping this long
    before the budget, and every cycle's port is proven free besides.
    """
    if not _mitmproxy_available():
        pytest.skip("mitmproxy not installed — proxy lifecycle Gate not run (skip != pass)")
    backend = ProxyBackend()
    try:
        baseline = threading.active_count()
        probe_port = _free_port()
        backend.start("proxy-leak-probe", host="127.0.0.1", port=probe_port)
        running = threading.active_count()
        assert backend.stop("proxy-leak-probe")["stopped"] is True
        per_session = running - baseline
        if per_session < 1:
            pytest.skip("a running capture adds no countable thread here (skip != pass)")

        # stop() above joined the probe's thread, so this settles deterministically.
        settled = threading.active_count()
        ports: list[int] = []
        for index in range(10):
            port = _free_port()
            ports.append(port)
            backend.start(f"proxy-leak-{index}", host="127.0.0.1", port=port)
            assert backend.stop(f"proxy-leak-{index}")["stopped"] is True
        after = threading.active_count()

        # A stop that stranded the listener would fail here even if the thread
        # count happened to look right, so the two signals cover each other.
        for port in ports:
            deadline = time.monotonic() + 10.0
            while time.monotonic() < deadline:
                if not _port_accepts("127.0.0.1", port, timeout=0.25):
                    break
                time.sleep(0.1)
            else:
                pytest.fail(f"port {port} still accepting after its stop")

        drift = after - settled
        assert drift <= per_session, (
            f"start/stop leaked ~{drift} threads over 10 cycles; a running capture "
            f"is ~{per_session} thread(s), so a thread-per-cycle is a leak"
        )
    finally:
        backend.close_all()


@pytest.mark.integration
def test_proxy_records_a_real_request_and_exports_it_to_har(tmp_path: Path) -> None:
    """Route a real request through the proxy; it must be captured and exported.

    The other gates prove the lifecycle (start/stop/port); this proves the
    capability they exist for -- that traffic through the proxy is recorded and
    reaches a spec-valid HAR entry. A loopback HTTP server is the upstream (plain
    HTTP, so no CA/TLS setup), and a urllib client is pointed at the proxy via an
    explicit opener so no ambient http_proxy env leaks in. Without this, a break
    that left the recorder wired to nothing -- start still "running", stop still
    freeing the port -- would pass every lifecycle assertion while capturing
    zero flows. skip != pass: skips only when mitmproxy is unavailable.
    """
    if not _mitmproxy_available():
        pytest.skip("mitmproxy not installed — proxy capture Gate not run (skip != pass)")

    server = http.server.HTTPServer(("127.0.0.1", 0), _HelloHandler)
    upstream_port = server.server_address[1]
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()

    backend = ProxyBackend()
    proxy_port = _free_port()
    backend.start("capture", host="127.0.0.1", port=proxy_port)
    try:
        target = f"http://127.0.0.1:{upstream_port}/probe"
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({"http": f"http://127.0.0.1:{proxy_port}"})
        )
        with opener.open(target, timeout=10.0) as response:
            assert response.status == 200
            assert response.read() == b"hello-through-proxy"

        # The flow is recorded on mitmproxy's response hook, which fires slightly
        # after the client's own read returns; poll rather than assume ordering.
        deadline = time.monotonic() + 10.0
        while time.monotonic() < deadline:
            if backend.status("capture")["flow_count"] >= 1:
                break
            time.sleep(0.1)
        else:
            pytest.fail("proxy captured no flow for a request routed through it")

        flows = backend.flows("capture")
        assert flows["total"] >= 1
        recorded = [f for f in flows["flows"] if f.get("url") == target]
        assert recorded, f"the captured flow list does not contain {target}: {flows['flows']}"
        assert recorded[0]["method"] == "GET"
        assert recorded[0]["status"] == 200
        # The recorder computes each flow's decoded response body length up front
        # so the summary keeps it even for a flow whose body was later dropped
        # from the retain ring. The upstream serves a fixed 19-byte body with an
        # explicit Content-Length and no content-encoding, so raw_content is
        # exactly those bytes -- the same length flow.get reports below. Pin it:
        # a regression that stopped recording response_size would otherwise pass
        # every url/status assertion while silently feeding the HAR nothing.
        body_size = len(b"hello-through-proxy")
        assert recorded[0]["response_size"] == body_size

        exported = backend.export_har("capture", tmp_path / "capture.har")
        assert exported["entry_count"] >= 1
        assert exported["size"] == (tmp_path / "capture.har").stat().st_size

        document = json.loads((tmp_path / "capture.har").read_text(encoding="utf-8"))
        entries = document["log"]["entries"]
        assert any(entry["request"]["url"] == target for entry in entries)
        matched = next(entry for entry in entries if entry["request"]["url"] == target)
        assert matched["response"]["status"] == 200
        # response_size threads through to the HAR: content.size and bodySize must
        # carry the real 19 bytes, not the spec's -1 "not available" placeholder a
        # flow with no recorded length falls back to. This is the only coverage of
        # the recorder -> har_entry size pipeline against real traffic, so without
        # it a break anywhere along response_size -> response_body_size ->
        # content.size would revert HAR sizes to -1 unnoticed.
        assert matched["response"]["content"]["size"] == body_size
        assert matched["response"]["bodySize"] == body_size
        # Real phase timings, measured from mitmproxy's own flow timestamps (the
        # source its HAR export uses too): a live roundtrip must produce all
        # three phases with a positive total, not the -1 "not measured"
        # sentinels a summary without timestamps falls back to. Only asserted
        # loosely (non-negative phases, sane total) because localhost phase
        # durations are tiny; the exact arithmetic is pinned by unit tests.
        timings = matched["timings"]
        assert all(timings[phase] >= 0 for phase in ("send", "wait", "receive")), timings
        assert 0 < matched["time"] <= 60_000, matched["time"]
        assert matched["time"] == round(sum(timings.values()), 3), (matched["time"], timings)
        row_timings = recorded[0].get("timings")
        assert row_timings and all(value >= 0 for value in row_timings.values()), recorded[0]

        # A flow mitmproxy cannot complete must be captured as an errored flow
        # and reach the HAR as an _error entry -- the symmetric proof to the web
        # gate's loadingFailed check. Route the client at a closed upstream port
        # through the proxy: mitmproxy's connect fails, firing its error hook.
        dead_port = _free_port()
        dead_target = f"http://127.0.0.1:{dead_port}/unreachable"
        with contextlib.suppress(urllib.error.URLError):
            opener.open(dead_target, timeout=10.0)
        deadline = time.monotonic() + 10.0
        while time.monotonic() < deadline:
            errored = [f for f in backend.flows("capture")["flows"] if f.get("error")]
            if errored:
                break
            time.sleep(0.1)
        else:
            pytest.fail("proxy captured no errored flow for a refused upstream")
        assert errored[0]["status"] is None, errored[0]
        assert isinstance(errored[0]["error_msg"], str) and errored[0]["error_msg"], errored[0]

        backend.export_har("capture", tmp_path / "capture-failed.har")
        failed_doc = json.loads((tmp_path / "capture-failed.har").read_text(encoding="utf-8"))
        failed_entries = {
            e["request"]["url"]: e for e in failed_doc["log"]["entries"]
        }
        failed_entry = failed_entries.get(dead_target)
        assert failed_entry is not None, failed_entries.keys()
        assert failed_entry["_error"] == errored[0]["error_msg"], failed_entry
        assert failed_entry["response"]["status"] == 0, failed_entry
    finally:
        backend.close_all()
        server.shutdown()
        server_thread.join(timeout=5.0)


@pytest.mark.integration
def test_flow_detail_and_replay_reach_the_upstream_again(tmp_path: Path) -> None:
    """flow.get must return the recorded exchange; replay must re-send it.

    The capture gate proves traffic is recorded; these are the two surfaces
    built on that recording, and neither had executable coverage. The detail is
    asserted against ground truth -- the body the upstream actually served --
    and the replay against the upstream's own hit counter: a replay that only
    re-appended a ring entry without touching the network would satisfy any
    flow-count assertion, but cannot increment the server's counter.
    skip != pass: skips only when mitmproxy is unavailable.
    """
    if not _mitmproxy_available():
        pytest.skip("mitmproxy not installed — proxy replay Gate not run (skip != pass)")

    _HelloHandler.hits = 0
    server = http.server.HTTPServer(("127.0.0.1", 0), _HelloHandler)
    upstream_port = server.server_address[1]
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()

    backend = ProxyBackend()
    proxy_port = _free_port()
    backend.start("replay", host="127.0.0.1", port=proxy_port)
    try:
        target = f"http://127.0.0.1:{upstream_port}/probe"
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({"http": f"http://127.0.0.1:{proxy_port}"})
        )
        with opener.open(target, timeout=10.0) as response:
            assert response.read() == b"hello-through-proxy"

        deadline = time.monotonic() + 10.0
        while time.monotonic() < deadline:
            if backend.status("replay")["flow_count"] >= 1:
                break
            time.sleep(0.1)
        else:
            pytest.fail("proxy captured no flow for a request routed through it")

        rows = [f for f in backend.flows("replay")["flows"] if f.get("url") == target]
        assert rows, backend.flows("replay")["flows"]
        flow_id = rows[0]["id"]

        detail = backend.flow_get("replay", flow_id, tmp_path)
        assert detail["id"] == flow_id
        assert detail["request"]["method"] == "GET"
        assert detail["request"]["url"] == target
        assert detail["response"]["status"] == 200
        # The recorded body must be the bytes the upstream served, inline
        # (19 bytes of UTF-8 is far under the spill threshold).
        assert detail["response"]["body"] == "hello-through-proxy"
        assert detail["response"]["size"] == len(b"hello-through-proxy")

        assert _HelloHandler.hits == 1
        replayed = backend.replay("replay", flow_id)
        assert replayed == {"replayed": True, "flow_id": flow_id}

        # replay.client is asynchronous: the command returns once scheduled,
        # the new exchange completes on the proxy loop. Both effects must
        # materialise -- the upstream serves a second request, and the
        # recorder captures it as a new flow.
        deadline = time.monotonic() + 10.0
        while time.monotonic() < deadline:
            if _HelloHandler.hits >= 2 and backend.status("replay")["flow_count"] >= 2:
                break
            time.sleep(0.1)
        else:
            pytest.fail(
                f"replay did not reach the upstream: hits={_HelloHandler.hits}, "
                f"flows={backend.status('replay')['flow_count']}"
            )
        replay_rows = [f for f in backend.flows("replay")["flows"] if f.get("url") == target]
        assert len(replay_rows) >= 2
        assert all(row["status"] == 200 for row in replay_rows)
    finally:
        backend.close_all()
        server.shutdown()
        server_thread.join(timeout=5.0)
