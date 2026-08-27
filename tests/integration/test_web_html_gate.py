"""Cross-validate the tool-free HTML reader against a real browser's fetches.

describe_html walks a page with stdlib html.parser to report its script,
stylesheet and iframe shape, the hosts it reaches, its forms and its title --
with no browser. But that reader is ours, and nothing proved its view of what
a page loads matches how a real browser parses the same bytes. A browser is
the ground truth for HTML: it actually fetches every external script,
stylesheet and iframe document, and its DOM snapshot is its own re-parse of
the form markup. This serves one page whose subresources are all same-origin
(so chromium really loads them), then requires that the tool-free reader's
counts, script URLs, hosts and form facts match exactly what the browser
fetched and parsed -- neither missing nor inventing a resource. It is the
HTML analogue of the proxy gate cross-checking describe_har against real
mitmproxy output and the WASM gate cross-checking describe_wasm against wabt.

Unlike the wasm cross-check above, this needs a browser (playwright + a
chromium build); skip != pass -- it skips, naming the reason, when the module
or the browser is unavailable.
"""

from __future__ import annotations

import contextlib
import re
import threading
import time
from collections.abc import Callable, Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, cast
from urllib.parse import urlsplit

import pytest

from headless_re_mcp.backends.web import WebBackend
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.core.session import describe_html

# Absolute subresource URLs (not bare paths) so describe_html sees hosts to
# report and the browser and reader can be compared host-for-host. {BASE} is
# filled in once the origin binds its port.
_PAGE_TEMPLATE = (
    "<html><head><title>html-gate</title>"
    '<link rel="stylesheet" href="{BASE}/x.css">'
    '<link rel="stylesheet" href="{BASE}/y.css">'
    '<script src="{BASE}/a.js"></script>'
    '<script src="{BASE}/b.js"></script>'
    "<script>window.__inline=1;</script>"
    "</head><body>"
    '<iframe src="{BASE}/frame.html"></iframe>'
    '<form action="{BASE}/submit" method="post">'
    '<input name="user"><input type="password" name="pass">'
    '<input type="submit" value="go">'
    "</form>"
    "</body></html>"
)

_SUBRESOURCE_PATHS = ("/a.js", "/b.js", "/x.css", "/y.css", "/frame.html")
_SCRIPT_PATHS = ("/a.js", "/b.js")
_FRAME_HTML = b"<html><head><title>frame</title></head><body>f</body></html>"


class _HtmlOrigin(ThreadingHTTPServer):
    def __init__(self) -> None:
        self.routes: dict[str, tuple[str, bytes]] = {}
        super().__init__(("127.0.0.1", 0), _Handler)

    @property
    def base(self) -> str:
        return f"http://127.0.0.1:{self.server_address[1]}"


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler's contract
        entry = cast(_HtmlOrigin, self.server).routes.get(self.path)
        if entry is None:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        content_type, body = entry
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        """Silence the default stderr access log."""


def _browser_available() -> bool:
    try:
        WebBackend()._check_available()
    except Exception:  # noqa: BLE001
        return False
    return True


def _wait_until(predicate: Callable[[], bool], what: str, timeout: float = 30.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.1)
    pytest.fail(f"timed out waiting for {what}")


@contextlib.contextmanager
def _origin() -> Iterator[_HtmlOrigin]:
    server = _HtmlOrigin()
    threading.Thread(target=server.serve_forever, name="html-origin", daemon=True).start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()


@pytest.mark.integration
def test_html_reader_matches_the_browsers_resource_graph(tmp_path: Path) -> None:
    if not _browser_available():
        pytest.skip("playwright not installed — HTML cross-check not run (skip != pass)")
    with _origin() as origin:
        base = origin.base
        page = _PAGE_TEMPLATE.replace("{BASE}", base).encode()
        origin.routes = {
            "/": ("text/html", page),
            "/a.js": ("application/javascript", b"window.__a=1;\n"),
            "/b.js": ("application/javascript", b"window.__b=1;\n"),
            "/x.css": ("text/css", b"body{color:#111}\n"),
            "/y.css": ("text/css", b"body{margin:0}\n"),
            "/frame.html": ("text/html", _FRAME_HTML),
        }

        # The tool-free reader's view of the exact bytes the origin serves.
        page_file = tmp_path / "page.html"
        page_file.write_bytes(page)
        facts = describe_html(page_file)["html"]
        assert facts["title"] == "html-gate"
        assert facts["external_script_count"] == 2
        assert facts["inline_script_count"] == 1
        assert facts["stylesheet_count"] == 2
        assert facts["iframe_count"] == 1
        assert set(facts["external_scripts"]) == {f"{base}/a.js", f"{base}/b.js"}
        assert facts["external_hosts"] == ["127.0.0.1"]
        assert facts["form_count"] == 1
        assert facts["forms"] == [
            {"action": f"{base}/submit", "method": "post", "input_names": ["user", "pass"]}
        ]

        service = AnalysisService()
        try:
            created = service.create_session(f"{base}/", target="web")
            assert created.ok, created.error
            session_id = created.data["session"]["id"]

            opened = service.web_open(session_id, headless=True, timeout=30.0)
            if not opened.ok:
                pytest.skip(
                    "chromium could not launch (browser build missing?): "
                    f"{opened.error.code if opened.error else 'unknown'} — skip != pass"
                )
            try:
                # The browser is the ground truth: it really fetches every
                # external script, stylesheet and iframe document. Wait for the
                # whole subresource set to land in the capture.
                def _fetched() -> dict[str, dict[str, Any]]:
                    listing = service.web_network_list(session_id, limit=1000)
                    assert listing.ok, listing.error
                    rows = cast(list[dict[str, Any]], listing.data["requests"])
                    return {str(r["url"]): r for r in rows}

                expected_urls = {f"{base}{path}" for path in _SUBRESOURCE_PATHS}
                _wait_until(
                    lambda: expected_urls.issubset(set(_fetched())),
                    f"browser to fetch every subresource; expected {sorted(expected_urls)}",
                )

                by_url = _fetched()
                for url in expected_urls:
                    assert by_url[url]["status"] == 200, f"{url}: {by_url[url]}"

                # The browser's subresource set -- everything it loaded except
                # the document itself and the automatic favicon probe -- must be
                # exactly what the reader predicted from the source.
                subresources = {
                    url
                    for url, row in by_url.items()
                    if url != f"{base}/"
                    and not url.endswith("/favicon.ico")
                    and int(row["status"]) == 200
                }
                assert subresources == expected_urls

                # Scripts specifically: the reader's external_scripts list is the
                # exact set of scripts the browser fetched, same URLs.
                browser_scripts = {f"{base}{path}" for path in _SCRIPT_PATHS}
                assert set(facts["external_scripts"]) == browser_scripts
                # Counts must add up to the browser's whole subresource graph:
                # two scripts + two stylesheets + one iframe = five fetches.
                assert (
                    facts["external_script_count"]
                    + facts["stylesheet_count"]
                    + facts["iframe_count"]
                ) == len(expected_urls)

                # The host the reader extracted is the host the browser reached.
                browser_hosts = {urlsplit(url).hostname for url in by_url if urlsplit(url).hostname}
                assert set(facts["external_hosts"]) == browser_hosts == {"127.0.0.1"}

                # The reader's title is the title the live DOM carries.
                dom = service.web_dom_snapshot(session_id)
                assert dom.ok, dom.error
                assert dom.data["title"] == facts["title"] == "html-gate"

                # The form, as chromium parsed it: the DOM snapshot is the
                # browser's own re-serialization of the page, so its <form>
                # element is an independent decode of the same source bytes.
                # The reader's action, method and named fields must match it
                # exactly -- and the unnamed submit button is a field in
                # neither view.
                dom_html = cast(str, dom.data["html"])
                form_match = re.search(r"<form\b([^>]*)>(.*?)</form>", dom_html, re.S)
                assert form_match, dom_html
                form_attrs, form_body = form_match.groups()
                action_match = re.search(r'action="([^"]*)"', form_attrs)
                method_match = re.search(r'method="([^"]*)"', form_attrs)
                assert action_match and method_match, form_attrs
                reader_form = facts["forms"][0]
                assert action_match.group(1) == reader_form["action"] == f"{base}/submit"
                assert method_match.group(1).lower() == reader_form["method"] == "post"
                dom_names = re.findall(r'<input[^>]*\bname="([^"]*)"', form_body)
                assert dom_names == reader_form["input_names"] == ["user", "pass"]
            finally:
                service.web_close(session_id)
        finally:
            service.close_all()
