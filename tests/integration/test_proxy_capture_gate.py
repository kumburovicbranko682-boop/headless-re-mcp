"""Live mitmproxy capture gate: proof that traffic is recorded, not just bound.

The lifecycle gate proves the process contract (start binds, stop frees the
port). It never sends a byte through the proxy, so ``flow_count`` stays zero and
the thing the proxy exists for -- recording an exchange and handing it back --
is unproven. This gate drives the real tool surface (``proxy.start`` ->
``proxy.flows`` -> ``proxy.flow.get`` -> ``proxy.export_har`` -> ``proxy.replay``)
against a throwaway local origin and asserts the capture actually holds the
request that went out and the response that came back:

  * the summary lists the flow with its method, full URL, upstream status and
    content-type;
  * ``flow.get`` returns the exact request body that was POSTed and the exact
    response body the origin sent -- proof it captured the whole exchange, not a
    header sketch;
  * the HAR export carries that flow as a real entry;
  * ``replay`` re-issues the captured request and the origin sees it a second
    time, byte-for-byte;
  * an exchange whose upstream refuses the connection is still recorded, marked
    as an error with a null status, because "this host would not answer" is
    itself a finding.
  * starting the proxy mints the mitmproxy root CA on disk -- the precondition
    for HTTPS interception and for ``proxy.ca.install_android``, both dead
    without it -- and it is a real, usable CA certificate.

Plain HTTP keeps the capture path free of any CA-trust setup: mitmproxy sees the
whole request and response without intercepting TLS. skip != pass -- with
mitmproxy absent the gate skips loudly rather than reporting a hollow success.
"""

from __future__ import annotations

import contextlib
import socket
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from headless_re_mcp.backends.proxy import ProxyBackend, ProxyError
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService

# A token stitched into the URL so this flow is unmistakable among any other
# traffic the browserless session might generate.
_TOKEN = "proxy-capture-gate-7f3a"
_REQUEST_BODY = b"secret=gate-payload&token=" + _TOKEN.encode("ascii")
_RESPONSE_BODY = b"origin says: capture me whole"
_DATA_URL = "data:text/html,<html><body>proxy-capture-gate</body></html>"


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        ida_home=None,
        x64dbg_source=None,
        x64dbg_headless_x64=None,
        x64dbg_headless_x86=None,
        artifact_root=tmp_path / "artifacts",
    )


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


class _Origin:
    """A tiny local HTTP origin that echoes a fixed body and counts POST hits.

    The hit list is what proves replay reached the wire rather than merely being
    accepted by mitmproxy: a genuine replay makes the origin see the same
    request a second time.
    """

    def __init__(self) -> None:
        self.hits: list[bytes] = []
        self._lock = threading.Lock()
        origin = self

        class _Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:  # noqa: N802 - stdlib naming
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length)
                with origin._lock:
                    origin.hits.append(body)
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Content-Length", str(len(_RESPONSE_BODY)))
                self.end_headers()
                self.wfile.write(_RESPONSE_BODY)

            def log_message(self, *args: object) -> None:  # silence stderr spam
                pass

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.port = int(self._server.server_address[1])
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    def __enter__(self) -> _Origin:
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self._server.shutdown()
        self._server.server_close()

    def hit_count(self) -> int:
        with self._lock:
            return len(self.hits)

    def wait_for_hits(self, target: int, timeout: float = 15.0) -> int:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.hit_count() >= target:
                break
            time.sleep(0.05)
        return self.hit_count()


def _through_proxy(proxy_port: int) -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(
        urllib.request.ProxyHandler({"http": f"http://127.0.0.1:{proxy_port}"})
    )


def _find_flow(service: AnalysisService, session_id: str, needle: str, timeout: float = 10.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        listed = service.proxy_flows(session_id)
        assert listed.ok, listed.error
        for flow in listed.data["flows"]:
            if needle in flow.get("url", ""):
                return flow
        time.sleep(0.05)
    return None


@pytest.mark.integration
def test_proxy_records_replays_and_exports_a_real_exchange(tmp_path: Path) -> None:
    if not _mitmproxy_available():
        pytest.skip("mitmproxy not installed — proxy capture Gate not run (skip != pass)")

    service = AnalysisService(_settings(tmp_path))
    with _Origin() as origin:
        try:
            created = service.create_session(_DATA_URL, target="web")
            assert created.ok, created.error
            session_id = created.data["session"]["id"]

            proxy_port = _free_port()
            started = service.proxy_start(session_id, host="127.0.0.1", port=proxy_port)
            assert started.ok, started.error
            assert started.data["running"] is True

            url = f"http://127.0.0.1:{origin.port}/gate/echo?token={_TOKEN}"
            request = urllib.request.Request(url, data=_REQUEST_BODY, method="POST")
            with _through_proxy(proxy_port).open(request, timeout=10.0) as response:
                assert response.status == 200
                assert response.read() == _RESPONSE_BODY
            assert origin.hit_count() == 1

            # The capture is what an agent reads back; it must list our exchange
            # with the real method, URL, upstream status and content type.
            flow = _find_flow(service, session_id, _TOKEN)
            assert flow is not None, "proxy never recorded the request that went through it"
            assert flow["method"] == "POST"
            assert flow["url"] == url
            assert flow["status"] == 200
            assert flow["content_type"].startswith("text/plain")

            status = service.proxy_status(session_id)
            assert status.ok, status.error
            assert status.data["flow_count"] >= 1

            # flow.get must return the whole exchange -- the body that was POSTed
            # and the body the origin returned -- not merely a header summary.
            got = service.proxy_flow_get(session_id, flow["id"])
            assert got.ok, got.error
            req = got.data["request"]
            resp = got.data["response"]
            assert req["method"] == "POST"
            assert req["url"] == url
            assert req["body"].encode("utf-8") == _REQUEST_BODY
            assert resp["status"] == 200
            assert resp["body"].encode("utf-8") == _RESPONSE_BODY

            # The HAR export must carry this flow as a real, addressable entry.
            exported = service.proxy_export_har(session_id)
            assert exported.ok, exported.error
            assert exported.data["entry_count"] >= 1
            assert exported.data.get("artifact_id")
            har_text = Path(exported.data["path"]).read_text(encoding="utf-8")
            assert _TOKEN in har_text
            assert '"status": 200' in har_text

            # Replay must actually reach the wire: the origin sees the identical
            # request a second time, which is the whole point of a capture you
            # can re-issue.
            replayed = service.proxy_replay(session_id, flow["id"])
            assert replayed.ok, replayed.error
            assert replayed.data["replayed"] is True
            assert origin.wait_for_hits(2) == 2
            assert origin.hits[0] == origin.hits[1] == _REQUEST_BODY
        finally:
            service.close_all()


@pytest.mark.integration
def test_proxy_records_an_upstream_that_refuses_the_connection(tmp_path: Path) -> None:
    """A refused upstream is a finding, so the errored flow must be captured too."""
    if not _mitmproxy_available():
        pytest.skip("mitmproxy not installed — proxy capture Gate not run (skip != pass)")

    service = AnalysisService(_settings(tmp_path))
    try:
        created = service.create_session(_DATA_URL, target="web")
        assert created.ok, created.error
        session_id = created.data["session"]["id"]

        proxy_port = _free_port()
        # Reserve a port and never listen on it, so the proxy's upstream connect
        # is refused and the flow errors before any response.
        dead_port = _free_port()
        started = service.proxy_start(session_id, host="127.0.0.1", port=proxy_port)
        assert started.ok, started.error

        url = f"http://127.0.0.1:{dead_port}/unreachable-{_TOKEN}"
        # mitmproxy answers a refused upstream with a 502 to the client, so
        # urllib raises rather than returning; the client-side failure is
        # expected and irrelevant -- what matters is the proxy recorded the
        # errored flow.
        with contextlib.suppress(urllib.error.URLError, urllib.error.HTTPError, OSError):
            _through_proxy(proxy_port).open(url, timeout=10.0)

        flow = _find_flow(service, session_id, "unreachable")
        assert flow is not None, "proxy dropped a failed request instead of recording it"
        assert flow.get("error") is True
        # A completed flow always carries a numeric status; an errored one must
        # stay distinguishable with a null status and a message.
        assert flow.get("status") is None
        assert isinstance(flow.get("error_msg"), str) and flow["error_msg"]
    finally:
        service.close_all()


@pytest.mark.integration
def test_proxy_start_materializes_a_usable_ca_certificate(tmp_path: Path) -> None:
    """Starting the proxy mints the CA that HTTPS interception depends on.

    To read TLS, mitmproxy signs a per-host leaf with its root CA, and
    ``proxy.ca.install_android`` pushes that root onto a device so the device
    trusts the interception. Both are dead without the CA on disk, and mitmproxy
    generates it lazily -- only when the proxy actually starts. The capture path
    above runs over plain HTTP and never forces it, so prove here that a start
    materialises a *real, usable* CA (an X.509 certificate whose basic
    constraints mark it a CA, so it can sign those leaves), not merely that a
    ``~/.mitmproxy`` directory exists.
    """
    if not _mitmproxy_available():
        pytest.skip("mitmproxy not installed — proxy CA Gate not run (skip != pass)")
    from cryptography import x509  # mitmproxy pulls cryptography in as a dependency

    service = AnalysisService(_settings(tmp_path))
    try:
        created = service.create_session(_DATA_URL, target="web")
        assert created.ok, created.error
        session_id = created.data["session"]["id"]

        started = service.proxy_start(session_id, host="127.0.0.1", port=_free_port())
        assert started.ok, started.error

        # The CA mitmproxy would present -- and that proxy.ca.install_android
        # would push -- is generated on startup. ca_cert_path reads ~/.mitmproxy,
        # so a fresh backend resolves the same file; poll, as the TLS addon writes
        # it just after run() begins.
        ca_path = None
        deadline = time.monotonic() + 10.0
        while time.monotonic() < deadline:
            ca_path = ProxyBackend().ca_cert_path()
            if ca_path is not None:
                break
            time.sleep(0.05)
        assert ca_path is not None, "proxy.start did not generate the mitmproxy CA"
        assert ca_path.is_file(), ca_path

        pem = ca_path.read_bytes()
        assert pem.startswith(b"-----BEGIN CERTIFICATE-----"), pem[:40]
        cert = x509.load_pem_x509_certificate(pem)
        # A real CA: it can sign the per-host leaves interception needs.
        basic = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        assert basic.ca is True, "generated cert is not a CA — cannot sign interception leaves"
        assert cert.not_valid_after_utc > cert.not_valid_before_utc, cert
        # ...and it is mitmproxy's own CA, not some unrelated cert on the box.
        subject = cert.subject.rfc4514_string().lower()
        assert "mitmproxy" in subject, subject
    finally:
        service.close_all()
