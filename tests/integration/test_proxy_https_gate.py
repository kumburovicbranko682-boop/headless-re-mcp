"""Live HTTPS interception gate: mitmproxy terminates TLS and records the flow.

The capture gate proves a plain-HTTP request is recorded, but the backend's
whole reason for existing -- ``HTTP(S)`` interception -- means decrypting TLS,
and nothing exercised that. This gate stands up a self-signed HTTPS origin,
routes a CONNECT-tunnelled request through mitmproxy with the client trusting
mitmproxy's own CA, and asserts the decrypted flow is recorded with its body.

It also pins why ``ssl_insecure`` exists: against an untrusted origin the
default (verifying) proxy returns 502 and records nothing, so the origin body
never reaches the client. Only the opt-in insecure proxy completes the MITM.
skip != pass when mitmproxy (or cryptography) is missing.
"""

from __future__ import annotations

import contextlib
import datetime
import ipaddress
import json
import socket
import ssl
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from headless_re_mcp.backends.proxy import ProxyBackend, ProxyError

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    _CRYPTO = True
except Exception:  # noqa: BLE001 - optional dependency
    _CRYPTO = False

_BODY = b"HTTPS-GATE-BODY-a71c"


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


def _self_signed(dirpath: Path) -> tuple[Path, Path]:
    """A throwaway localhost cert so the origin speaks TLS the proxy must MITM."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=2))
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                ]
            ),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    certfile = dirpath / "origin-cert.pem"
    keyfile = dirpath / "origin-key.pem"
    certfile.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    keyfile.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    return certfile, keyfile


class _Origin(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(_BODY)))
        self.end_headers()
        self.wfile.write(_BODY)

    def log_message(self, *args: object) -> None:  # keep pytest output clean
        return


def _https_get_via_proxy(
    proxy_port: int, origin_port: int, ca_pem: Path, timeout: float = 10.0
) -> tuple[bytes, bytes]:
    """CONNECT-tunnel to the origin through the proxy, then TLS + GET over it.

    The client trusts only mitmproxy's CA, so a completed handshake means the
    proxy really minted a leaf for the origin and is terminating TLS in the
    middle. Returns the status line and the full response bytes.
    """
    raw = socket.create_connection(("127.0.0.1", proxy_port), timeout=timeout)
    try:
        raw.settimeout(timeout)
        raw.sendall(
            f"CONNECT localhost:{origin_port} HTTP/1.1\r\n"
            f"Host: localhost:{origin_port}\r\n\r\n".encode("ascii")
        )
        connect = raw.recv(4096)
        assert b"200" in connect.split(b"\r\n", 1)[0], connect[:200]

        ctx = ssl.create_default_context(cafile=str(ca_pem))
        tls = ctx.wrap_socket(raw, server_hostname="localhost")
        try:
            tls.sendall(
                f"GET /probe HTTP/1.1\r\nHost: localhost:{origin_port}\r\n"
                "Connection: close\r\n\r\n".encode("ascii")
            )
            data = b""
            while True:
                chunk = tls.recv(65536)
                if not chunk:
                    break
                data += chunk
        finally:
            with contextlib.suppress(Exception):
                tls.close()
    finally:
        with contextlib.suppress(Exception):
            raw.close()
    return data.split(b"\r\n", 1)[0], data


@pytest.mark.integration
def test_proxy_intercepts_https_only_when_ssl_insecure(tmp_path: Path) -> None:
    if not _mitmproxy_available():
        pytest.skip("mitmproxy not installed — HTTPS gate not run (skip != pass)")
    if not _CRYPTO:
        pytest.skip("cryptography not installed — cannot mint an origin cert (skip != pass)")

    certfile, keyfile = _self_signed(tmp_path)
    origin_port = _free_port()
    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ctx.load_cert_chain(str(certfile), str(keyfile))
    origin = ThreadingHTTPServer(("127.0.0.1", origin_port), _Origin)
    origin.socket = server_ctx.wrap_socket(origin.socket, server_side=True)
    origin_thread = threading.Thread(target=origin.serve_forever, daemon=True)
    origin_thread.start()

    backend = ProxyBackend()
    try:
        # First start also generates the CA, so wait for the PEM the client
        # must trust. Using the .pem explicitly: ca_cert_path() may hand back
        # the DER .cer copy, which is not a usable verify file.
        secure_port = _free_port()
        backend.start("secure", host="127.0.0.1", port=secure_port)
        ca_pem = Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.pem"
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline and not ca_pem.is_file():
            time.sleep(0.05)
        assert ca_pem.is_file(), "mitmproxy CA PEM never appeared"
        assert backend.ca_cert_path() is not None

        # Negative control: verifying proxy vs an untrusted origin. The tunnel
        # is established, but mitmproxy refuses the upstream and answers 502, so
        # the origin body never reaches the client and no 200 flow is recorded.
        status_line, response = _https_get_via_proxy(secure_port, origin_port, ca_pem)
        assert _BODY not in response, response[:200]
        assert b"200" not in status_line, status_line
        time.sleep(0.5)
        secure_flows = backend.flows("secure")["flows"]
        assert all(f.get("status") != 200 for f in secure_flows), secure_flows
        backend.stop("secure")

        # Opt-in insecure proxy: the MITM completes, the client gets the real
        # 200 and body, and the decrypted flow is recorded and retrievable.
        insecure_port = _free_port()
        backend.start("insecure", host="127.0.0.1", port=insecure_port, ssl_insecure=True)
        status_line, response = _https_get_via_proxy(insecure_port, origin_port, ca_pem)
        assert b"200" in status_line, status_line
        assert _BODY in response, response[:200]

        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline and backend.status("insecure")["flow_count"] < 1:
            time.sleep(0.05)
        assert backend.status("insecure")["flow_count"] >= 1

        listed = backend.flows("insecure")["flows"]
        flow = next(f for f in listed if f.get("status") == 200)
        assert flow["method"] == "GET"
        # The recorded URL is the decrypted https target, not the CONNECT host.
        assert flow["url"] == f"https://localhost:{origin_port}/probe", flow

        detail = backend.flow_get("insecure", flow["id"], tmp_path / "artifacts")
        assert detail["response"]["status"] == 200
        assert _BODY.decode() in detail["response"]["body"], detail

        har_path = tmp_path / "https.har"
        backend.export_har("insecure", har_path)
        har = json.loads(har_path.read_text(encoding="utf-8"))
        urls = [entry["request"]["url"] for entry in har["log"]["entries"]]
        assert any(url == f"https://localhost:{origin_port}/probe" for url in urls), urls
    finally:
        backend.close_all()
        origin.shutdown()
        origin.server_close()
