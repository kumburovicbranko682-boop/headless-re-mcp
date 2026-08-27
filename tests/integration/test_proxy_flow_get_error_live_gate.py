"""proxy.flow.get live gate: a real errored flow reports its reason.

The error hook captures a flow mitmproxy could not complete (TLS refused,
upstream unreachable, connection reset) and proxy.flows marks it error /
error_msg with a null status. But such a flow has no response, so flow.get
produced status null and an empty body and nothing else -- indistinguishable,
on flow.get alone, from a request that answered with nothing. flow.get now
surfaces the flow's own error the same way the summary does.

Every unit test drives flow_get with a hand-built errored flow, so only a real
mitmproxy proves that a genuine upstream failure produces an error the backend
surfaces through flow.get. The gate drives a client through a real mitmproxy in
regular proxy mode toward a 127.0.0.1 port with nothing listening, so the
upstream connect is refused for real and offline; mitmproxy records the errored
flow, and the gate asserts flow.get returns error true with a non-empty
error_msg and a null status.

Skip != pass: the gate skips with a reason only when mitmproxy is absent. CI
installs it, so a skip there is a genuine regression rather than a bare machine.
"""

from __future__ import annotations

import socket
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from headless_re_mcp.backends.proxy import ProxyBackend, ProxyError


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


def _drive_failing_request(url: str, proxy_endpoint: str) -> None:
    """GET through the proxy toward a refused upstream; the failure is expected.

    mitmproxy answers the client 502 for an upstream it cannot reach, so urllib
    raises; either outcome is fine -- the gate only needs mitmproxy to record
    the errored flow on its side.
    """
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({"http": proxy_endpoint})
    )
    try:
        with opener.open(url, timeout=10) as resp:
            resp.read()
    except (urllib.error.URLError, OSError):
        pass


@pytest.mark.integration
def test_flow_get_reports_the_error_of_a_refused_upstream(tmp_path: Path) -> None:
    if not _mitmproxy_available():
        pytest.skip("mitmproxy not installed — flow.get error Gate not run (skip != pass)")

    # A 127.0.0.1 port with nothing listening: the upstream connect is refused
    # immediately and offline, with no external network.
    dead_upstream = _free_port()
    proxy_port = _free_port()

    backend = ProxyBackend()
    started = backend.start("flow-error-gate", host="127.0.0.1", port=proxy_port)
    assert started["running"] is True
    try:
        _drive_failing_request(
            f"http://127.0.0.1:{dead_upstream}/beacon", f"http://127.0.0.1:{proxy_port}"
        )

        # The errored flow arrives on mitmproxy's loop thread; wait for it.
        flow_id = None
        deadline = time.monotonic() + 15.0
        while time.monotonic() < deadline:
            listing = backend.flows("flow-error-gate", offset=0, limit=100)
            for row in listing["flows"]:
                if row.get("error") and str(row.get("url", "")).endswith("/beacon"):
                    flow_id = str(row["id"])
                    break
            if flow_id is not None:
                break
            time.sleep(0.2)

        assert flow_id is not None, "mitmproxy never captured the errored flow"

        payload = backend.flow_get("flow-error-gate", flow_id, tmp_path)

        # The fix: flow.get says the flow errored and why, and its status is null
        # -- not read as a real empty response.
        assert payload["error"] is True
        assert isinstance(payload["error_msg"], str) and payload["error_msg"], payload
        assert payload["response"]["status"] is None
    finally:
        backend.stop("flow-error-gate")
