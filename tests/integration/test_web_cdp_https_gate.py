"""Live web CDP gate over HTTPS: the browser hands back decrypted TLS content.

The plain CDP gate drives an http:// origin, so the (S) in the backend's
HTTP(S) inspection -- a page fetched over TLS and its response bodies read back
through CDP getResponseBody -- was never exercised on the browser side. This
gate serves a self-signed HTTPS origin, opens it in Chromium (which the backend
already lets ignore cert errors), and asserts the document and script requests
are recorded as https with status, the script's decrypted body is retrievable,
the console line is captured, and the HAR carries the https url.
skip != pass when playwright/chromium or cryptography is missing.
"""

from __future__ import annotations

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

from headless_re_mcp.backends.web import WebBackend, WebError

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    _CRYPTO = True
except Exception:  # noqa: BLE001 - optional dependency
    _CRYPTO = False

_MARKER = "w3b-https-marker-5c2d"
_PAGE = (
    "<!doctype html><html><head><title>cdp-https</title>"
    '<script src="/app.js"></script></head>'
    "<body><h1>cdp https body</h1></body></html>"
)
_APP_JS = f"console.log('{_MARKER}'); window.__m = '{_MARKER}';"


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def _playwright_available() -> bool:
    try:
        WebBackend()._check_available()
    except WebError:
        return False
    return True


def _self_signed(dirpath: Path) -> tuple[Path, Path]:
    """A throwaway localhost cert so the origin serves TLS the browser must ignore."""
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
        if self.path.startswith("/app.js"):
            text, ctype = _APP_JS, "application/javascript; charset=utf-8"
        else:
            text, ctype = _PAGE, "text/html; charset=utf-8"
        body = text.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: object) -> None:  # keep pytest output clean
        return


@pytest.mark.integration
def test_web_cdp_reads_decrypted_https_bodies(tmp_path: Path) -> None:
    if not _playwright_available():
        pytest.skip("playwright not installed — web CDP HTTPS Gate not run (skip != pass)")
    if not _CRYPTO:
        pytest.skip("cryptography not installed — cannot mint an origin cert (skip != pass)")

    certfile, keyfile = _self_signed(tmp_path)
    port = _free_port()
    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ctx.load_cert_chain(str(certfile), str(keyfile))
    origin = ThreadingHTTPServer(("127.0.0.1", port), _Origin)
    origin.socket = server_ctx.wrap_socket(origin.socket, server_side=True)
    threading.Thread(target=origin.serve_forever, daemon=True).start()

    backend = WebBackend()
    url = f"https://127.0.0.1:{port}/page"
    try:
        try:
            opened = backend.open("cdps", url, headless=True, timeout=45.0)
        except WebError as exc:
            pytest.skip(f"chromium could not launch ({exc.code}) — Gate not run (skip != pass)")
        assert opened["opened"] is True
        assert opened["title"] == "cdp-https"
        assert str(opened["url"]).startswith("https://"), opened

        # The document lands during open; the script response may follow a beat
        # later, so wait for it before asserting.
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            requests = backend.network_list("cdps")["requests"]
            if any(str(r["url"]).endswith("/app.js") and r["status"] for r in requests):
                break
            time.sleep(0.1)

        listed = backend.network_list("cdps")
        assert listed["total"] >= 2, listed
        by_url = {str(r["url"]): r for r in listed["requests"]}

        doc = next(r for u, r in by_url.items() if u.endswith("/page"))
        assert str(doc["url"]).startswith("https://"), doc
        assert doc["status"] == 200
        assert str(doc["mimeType"] or "").startswith("text/html"), doc
        assert str(doc["resourceType"]).lower() == "document", doc

        js = next(r for u, r in by_url.items() if u.endswith("/app.js"))
        assert str(js["url"]).startswith("https://"), js
        assert js["status"] == 200
        assert str(js["resourceType"]).lower() == "script", js

        # The decrypted script body comes back through CDP getResponseBody: the
        # marker proves the browser handed back TLS-terminated content, not that
        # a request merely appeared in the list.
        detail = backend.network_get("cdps", str(js["requestId"]), tmp_path / "artifacts")
        assert _MARKER in str(detail.get("body", "")), detail

        # The console line the script logged is captured over CDP.
        console = backend.console("cdps", limit=200)
        assert any(_MARKER in str(item.get("text")) for item in console["console"]), console

        # HAR export carries the https request through to a file.
        har_path = tmp_path / "web-https.har"
        exported = backend.har_export("cdps", har_path)
        assert exported["entry_count"] >= 2
        har = json.loads(har_path.read_text(encoding="utf-8"))
        har_urls = [entry["request"]["url"] for entry in har["log"]["entries"]]
        assert any(
            str(u).startswith("https://") and str(u).endswith("/app.js") for u in har_urls
        ), har_urls
    finally:
        backend.close_all()
        origin.shutdown()
        origin.server_close()
