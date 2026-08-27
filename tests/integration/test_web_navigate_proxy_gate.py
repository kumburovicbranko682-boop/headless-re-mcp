"""Live gate: the upstream proxy stays in effect across web.navigate.

web.open gained an upstream ``proxy`` option, and the HTTPS chain gate proves
the *first* page loads through mitmproxy. But navigate() reuses the session's
existing page and context, so nothing proves the proxy still applies after a
move to a second page -- if a refactor ever recreated the context on navigate,
the proxy would silently drop and only the first page would be intercepted,
which no existing gate would catch.

This gate opens page A through mitmproxy, navigates to a distinct page B, and
makes the decisive claim on the *post-navigate* traffic: page B and its script
were also intercepted by the proxy (not just page A), and the body the proxy
recorded for B's script is byte-identical to what the browser fetched -- one
transaction, seen by both lines, after the navigation. skip != pass when
playwright/chromium or mitmproxy is missing.
"""

from __future__ import annotations

import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from headless_re_mcp.backends.proxy import ProxyBackend, ProxyError
from headless_re_mcp.backends.web import WebBackend, WebError

_MARK_A = "navproxy-a-1a2b"
_MARK_B = "navproxy-b-3c4d"
_PAGES: dict[str, tuple[str, str]] = {
    "/a": (
        "<!doctype html><html><head><title>page-a</title>"
        '<script src="/a.js"></script></head><body><h1>AAA</h1></body></html>',
        "text/html; charset=utf-8",
    ),
    "/b": (
        "<!doctype html><html><head><title>page-b</title>"
        '<script src="/b.js"></script></head><body><h1>BBB</h1></body></html>',
        "text/html; charset=utf-8",
    ),
    "/a.js": (f"console.log('{_MARK_A}');", "application/javascript; charset=utf-8"),
    "/b.js": (f"console.log('{_MARK_B}');", "application/javascript; charset=utf-8"),
}


class _Origin(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract
        key = self.path.split("?")[0]
        text, ctype = _PAGES.get(key, ("not found", "text/plain; charset=utf-8"))
        body = text.encode("utf-8")
        self.send_response(200 if key in _PAGES else 404)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: object) -> None:  # keep pytest output clean
        return


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


def _wait_browser(backend: WebBackend, suffix: str, timeout: float = 8.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        reqs = backend.network_list("s")["requests"]
        if any(str(r["url"]).endswith(suffix) and r["status"] for r in reqs):
            return
        time.sleep(0.1)


@pytest.mark.integration
def test_proxy_survives_navigate_and_intercepts_the_second_page(tmp_path: Path) -> None:
    if not _playwright_available():
        pytest.skip("playwright not installed — navigate-proxy Gate not run (skip != pass)")
    if not _mitmproxy_available():
        pytest.skip("mitmproxy not installed — navigate-proxy Gate not run (skip != pass)")

    port = _free_port()
    origin = ThreadingHTTPServer(("127.0.0.1", port), _Origin)
    threading.Thread(target=origin.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{port}"

    proxy = ProxyBackend()
    web = WebBackend()
    proxy_port = _free_port()
    arts = tmp_path / "artifacts"
    try:
        proxy.start("px", host="127.0.0.1", port=proxy_port)
        time.sleep(0.4)

        try:
            opened = web.open(
                "s", f"{base}/a", headless=True, timeout=45.0,
                proxy=f"http://127.0.0.1:{proxy_port}",
            )
        except WebError as exc:
            pytest.skip(f"chromium could not launch ({exc.code}) — Gate not run (skip != pass)")
        assert opened["opened"] is True
        assert opened["title"] == "page-a"
        assert opened.get("proxy") == f"http://127.0.0.1:{proxy_port}", opened
        _wait_browser(web, "/a.js")

        # Move to a distinct page. navigate reuses the session's page/context;
        # the proxy was set at launch, so it must still apply here.
        moved = web.navigate("s", f"{base}/b", timeout=30.0)
        assert moved["title"] == "page-b", moved
        assert str(moved["url"]).endswith("/b"), moved
        _wait_browser(web, "/b.js")

        # Proxy side: wait for all four transactions, then prove the *second*
        # page and its script transited mitmproxy too -- not only the first.
        deadline = time.monotonic() + 6.0
        while time.monotonic() < deadline and proxy.status("px")["flow_count"] < 4:
            time.sleep(0.1)
        flows = proxy.flows("px")["flows"]
        flow_urls = {str(f["url"]): f for f in flows}
        for suffix in ("/a", "/a.js", "/b", "/b.js"):
            assert any(u.endswith(suffix) for u in flow_urls), (suffix, list(flow_urls))
        # The decisive assertions: the post-navigate resources are proxied 200s.
        b_flow = next(f for u, f in flow_urls.items() if u.endswith("/b") and not u.endswith(".js"))
        bjs_flow = next(f for u, f in flow_urls.items() if u.endswith("/b.js"))
        assert b_flow["status"] == 200 and b_flow["method"] == "GET", b_flow
        assert bjs_flow["status"] == 200 and bjs_flow["method"] == "GET", bjs_flow

        # One transaction, seen by both lines, *after* the navigation: the body
        # mitmproxy recorded for B's script equals what the browser fetched.
        bjs_req = next(
            r
            for r in web.network_list("s")["requests"]
            if str(r["url"]).endswith("/b.js")
        )
        browser_detail = web.network_get("s", str(bjs_req["requestId"]), arts)
        browser_body = str(browser_detail.get("body") or "")
        proxy_detail = proxy.flow_get("px", bjs_flow["id"], arts)
        proxy_body = str(proxy_detail["response"].get("body") or "")
        assert _MARK_B in browser_body, browser_detail
        assert _MARK_B in proxy_body, proxy_detail
        assert proxy_body == browser_body, {
            "proxy": proxy_body[:120],
            "browser": browser_body[:120],
        }

        # Console from both pages survived, confirming one session drove both
        # loads through the same proxied context rather than a fresh one.
        console_text = [str(i.get("text")) for i in web.console("s", limit=200)["console"]]
        assert any(_MARK_A in t for t in console_text), console_text
        assert any(_MARK_B in t for t in console_text), console_text
    finally:
        web.close_all()
        proxy.close_all()
        origin.shutdown()
        origin.server_close()
