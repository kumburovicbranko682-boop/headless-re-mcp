"""Live mitmproxy HTTPS interception gate: TLS traffic is actually decrypted.

The capture gate proves a plain-HTTP round trip is recorded. This one proves
the part that makes an intercepting proxy worth anything for reverse
engineering -- that HTTPS is man-in-the-middled and its *decrypted* request and
response show up in ``flows``/``flow.get``/``export_har``.

It is fully hermetic: it mints a throwaway CA-less self-signed cert with
``cryptography`` (which mitmproxy already depends on), serves it from a local
TLS origin, routes a real ``CONNECT`` tunnel through the proxy, and trusts the
proxy's own generated CA on the client side. Because the origin is self-signed,
this only works when the proxy is told to skip upstream verification -- so the
gate also pins that ``ssl_insecure`` is load-bearing: with it off, the same
request is rejected with a gateway error and nothing is decrypted. Skips
honestly when mitmproxy (hence cryptography) is absent (skip != pass).
"""

from __future__ import annotations

import datetime
import ipaddress
import socket
import ssl
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from headless_re_mcp.backends.proxy import ProxyBackend, ProxyError

_MARKER = "HEADLESS_RE_HTTPS_DECRYPT_MARKER"
_PATH = "/probe/secret.json"


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


def _make_origin_cert(dirpath: Path) -> tuple[Path, Path]:
    """A self-signed leaf for 127.0.0.1 -- no issuing CA, so it is untrusted."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    key_path = dirpath / "origin-key.pem"
    cert_path = dirpath / "origin-cert.pem"
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return key_path, cert_path


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - name mandated by BaseHTTPRequestHandler
        body = _MARKER.encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args: object) -> None:
        """Silence the default stderr access log during the gate."""


@pytest.fixture(scope="module")
def _https_origin(tmp_path_factory: pytest.TempPathFactory) -> Iterator[str]:
    """A throwaway HTTPS origin presenting the self-signed leaf."""
    cert_dir = tmp_path_factory.mktemp("origin")
    key_path, cert_path = _make_origin_cert(cert_dir)
    server = HTTPServer(("127.0.0.1", 0), _Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(cert_path), str(key_path))
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"https://127.0.0.1:{server.server_address[1]}{_PATH}"
    finally:
        server.shutdown()
        thread.join(timeout=5.0)


def _wait_for_ca(backend: ProxyBackend) -> Path:
    """mitmproxy writes its CA a moment after the listener binds; wait for it."""
    deadline = time.monotonic() + 10.0
    while time.monotonic() < deadline:
        ca = backend.ca_cert_path()
        if ca is not None:
            return ca
        time.sleep(0.05)
    raise AssertionError("mitmproxy did not generate its CA within the timeout")


def _get_https_through_proxy(url: str, proxy_port: int, ca_path: Path) -> tuple[int, str]:
    """Real CONNECT tunnel: trust the proxy CA, verify the presented cert/host."""
    ctx = ssl.create_default_context(cafile=str(ca_path))
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({"https": f"http://127.0.0.1:{proxy_port}"}),
        urllib.request.HTTPSHandler(context=ctx),
    )
    with opener.open(url, timeout=15.0) as response:
        return int(response.status), response.read().decode("utf-8", "replace")


def _wait_for_flow(backend: ProxyBackend, session_id: str) -> dict:
    deadline = time.monotonic() + 10.0
    while time.monotonic() < deadline:
        matches = [
            flow
            for flow in backend.flows(session_id)["flows"]
            if _PATH in str(flow.get("url", ""))
        ]
        if matches:
            return matches[0]
        time.sleep(0.1)
    raise AssertionError("proxy did not record the HTTPS flow within the timeout")


@pytest.mark.integration
def test_https_traffic_is_decrypted_and_captured(_https_origin: str, tmp_path: Path) -> None:
    if not _mitmproxy_available():
        pytest.skip("mitmproxy not installed — HTTPS interception Gate not run (skip != pass)")
    backend = ProxyBackend()
    port = _free_port()
    info = backend.start("https-ok", host="127.0.0.1", port=port, ssl_insecure=True)
    assert info["ssl_insecure"] is True
    try:
        ca = _wait_for_ca(backend)

        status, body = _get_https_through_proxy(_https_origin, port, ca)
        # The client saw a 200 over TLS it trusts, so the proxy successfully
        # impersonated the origin: the man-in-the-middle chain held end to end.
        assert status == 200
        assert body == _MARKER

        flow = _wait_for_flow(backend, "https-ok")
        assert flow["method"] == "GET"
        assert flow["status"] == 200
        assert str(flow["url"]).startswith("https://")

        detail = backend.flow_get("https-ok", str(flow["id"]), tmp_path)
        assert detail["request"]["url"].startswith("https://")
        assert detail["response"]["status"] == 200
        # The decrypted plaintext body -- the whole point of TLS interception.
        assert _MARKER in detail["response"]["body"]

        har_path = tmp_path / "https.har"
        exported = backend.export_har("https-ok", har_path)
        assert exported["entry_count"] >= 1
        assert _PATH in har_path.read_text(encoding="utf-8")
    finally:
        backend.close_all()


@pytest.mark.integration
def test_without_ssl_insecure_the_self_signed_upstream_is_rejected(_https_origin: str) -> None:
    if not _mitmproxy_available():
        pytest.skip("mitmproxy not installed — HTTPS interception Gate not run (skip != pass)")
    backend = ProxyBackend()
    port = _free_port()
    info = backend.start("https-strict", host="127.0.0.1", port=port)
    # Default posture verifies the upstream cert, so ssl_insecure stays off.
    assert info["ssl_insecure"] is False
    try:
        ca = _wait_for_ca(backend)
        # The tunnel and client-side TLS still succeed (the proxy CA is trusted),
        # but the upstream leg fails verification, so mitmproxy answers a gateway
        # error instead of the decrypted 200 -- proof ssl_insecure is what turns
        # interception of an untrusted origin on, not an incidental default.
        with pytest.raises(urllib.error.HTTPError) as excinfo:
            _get_https_through_proxy(_https_origin, port, ca)
        assert excinfo.value.code == 502
    finally:
        backend.close_all()
