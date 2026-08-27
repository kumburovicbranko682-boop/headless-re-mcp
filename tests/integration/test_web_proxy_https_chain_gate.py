"""Live gate: the browser driven through mitmproxy, both lines see one HTTPS hit.

The web and proxy lines each capture traffic on their own, but nothing wired
them together the way an analyst actually works -- a browser pointed at an
intercepting proxy so the proxy decrypts what the page loads. web.open gained an
upstream ``proxy`` option for exactly this; this gate exercises it end to end.

A self-signed HTTPS origin is driven by Chromium through an ssl_insecure
mitmproxy. It asserts the browser loaded the TLS page (its CDP capture has the
document and script at 200 with the decrypted marker), that the *same*
transaction was intercepted by mitmproxy (a recorded https flow for the script),
and that the response body both lines hand back is byte-identical -- proving one
request, seen by both, not two independent fetches. skip != pass when
playwright/chromium, mitmproxy or cryptography is missing.
"""

from __future__ import annotations

import datetime
import ipaddress
import socket
import ssl
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from headless_re_mcp.backends.proxy import ProxyBackend, ProxyError
from headless_re_mcp.backends.web import WebBackend, WebError

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    _CRYPTO = True
except Exception:  # noqa: BLE001 - optional dependency
    _CRYPTO = False

_MARKER = "px-web-chain-marker-9f3a"
_PAGE = (
    "<!doctype html><html><head><title>px-web-chain</title>"
    '<script src="/app.js"></script></head>'
    "<body><h1>through proxy</h1></body></html>"
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


def _mitmproxy_available() -> bool:
    try:
        ProxyBackend()._check_available()
    except ProxyError:
        return False
    return True


def _self_signed(dirpath: Path) -> tuple[Path, Path]:
    """A throwaway localhost cert so the origin speaks TLS both sides must MITM/ignore."""
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
def test_browser_through_mitmproxy_captures_one_https_transaction(tmp_path: Path) -> None:
    if not _playwright_available():
        pytest.skip("playwright not installed — proxy<->web chain Gate not run (skip != pass)")
    if not _mitmproxy_available():
        pytest.skip("mitmproxy not installed — proxy<->web chain Gate not run (skip != pass)")
    if not _CRYPTO:
        pytest.skip("cryptography not installed — cannot mint an origin cert (skip != pass)")

    certfile, keyfile = _self_signed(tmp_path)
    origin_port = _free_port()
    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ctx.load_cert_chain(str(certfile), str(keyfile))
    origin = ThreadingHTTPServer(("127.0.0.1", origin_port), _Origin)
    origin.socket = server_ctx.wrap_socket(origin.socket, server_side=True)
    threading.Thread(target=origin.serve_forever, daemon=True).start()

    proxy = ProxyBackend()
    web = WebBackend()
    proxy_port = _free_port()
    js_url = f"https://localhost:{origin_port}/app.js"
    try:
        # ssl_insecure so mitmproxy accepts the origin's self-signed cert upstream;
        # the browser already ignores mitmproxy's leaf downstream.
        proxy.start("px", host="127.0.0.1", port=proxy_port, ssl_insecure=True)
        time.sleep(0.4)

        page_url = f"https://localhost:{origin_port}/page"
        try:
            opened = web.open(
                "s", page_url, headless=True, timeout=45.0,
                proxy=f"http://127.0.0.1:{proxy_port}",
            )
        except WebError as exc:
            pytest.skip(f"chromium could not launch ({exc.code}) — Gate not run (skip != pass)")

        # web.open echoes the upstream proxy it was told to use.
        assert opened["opened"] is True
        assert str(opened["url"]).startswith("https://"), opened
        assert opened.get("proxy") == f"http://127.0.0.1:{proxy_port}", opened

        # Browser side: wait for the script response, then confirm both requests
        # landed as https 200 and the decrypted script body carries the marker.
        deadline = time.monotonic() + 8.0
        while time.monotonic() < deadline:
            reqs = web.network_list("s")["requests"]
            if any(str(r["url"]).endswith("/app.js") and r["status"] for r in reqs):
                break
            time.sleep(0.2)
        reqs = web.network_list("s")["requests"]
        by_url = {str(r["url"]): r for r in reqs}
        assert any(u.endswith("/page") and by_url[u]["status"] == 200 for u in by_url), by_url
        js_req = next(r for u, r in by_url.items() if u.endswith("/app.js"))
        assert js_req["status"] == 200, js_req
        browser_detail = web.network_get("s", str(js_req["requestId"]), tmp_path / "artifacts")
        browser_body = str(browser_detail.get("body") or "")
        assert _MARKER in browser_body, browser_detail
        console = web.console("s", limit=200)
        assert any(_MARKER in str(i.get("text")) for i in console["console"]), console

        # Proxy side: the browser's traffic really transited mitmproxy, which
        # decrypted it -- the same script shows up as an https flow at 200.
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline and proxy.status("px")["flow_count"] < 2:
            time.sleep(0.1)
        flows = proxy.flows("px")["flows"]
        flow_urls = {str(f["url"]): f for f in flows}
        assert any(u.endswith("/page") for u in flow_urls), flow_urls
        js_flow = next(
            (f for u, f in flow_urls.items() if u == js_url and f.get("status") == 200), None
        )
        assert js_flow is not None, flow_urls
        assert js_flow["method"] == "GET"

        # The decisive claim: one transaction, seen by both lines identically.
        proxy_detail = proxy.flow_get("px", js_flow["id"], tmp_path / "artifacts")
        proxy_body = str(proxy_detail["response"].get("body") or "")
        assert _MARKER in proxy_body, proxy_detail
        assert proxy_body == browser_body, {
            "proxy": proxy_body[:120],
            "browser": browser_body[:120],
        }
    finally:
        web.close_all()
        proxy.close_all()
        origin.shutdown()
        origin.server_close()
