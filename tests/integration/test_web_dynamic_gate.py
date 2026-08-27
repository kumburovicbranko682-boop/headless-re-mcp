"""Web dynamic-analysis live gate: real page load, network + scripts over CDP.

The existing Web CDP gate opens a ``data:`` URL, which issues no network and
loads no external script, so the traffic-capture surface an operator actually
uses -- ``web.network.list`` / ``web.network.get`` / ``web.script.source`` /
``web.har.export`` / ``web.screenshot`` -- had no live coverage. This drives a
real page against a throwaway local HTTP origin (an HTML document that pulls an
external script which in turn ``fetch()``es a JSON resource) and asserts the
whole capture chain end to end.

It needs no external network and no CA (plain HTTP to 127.0.0.1) and runs the
service layer, not just the backend, so the CDP wiring, artifact spill, and
capture registration are all exercised. It skips honestly when Playwright or a
launchable Chromium is absent -- skip != pass.
"""

from __future__ import annotations

import json
import os
import threading
import time
from collections.abc import Iterator
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from headless_re_mcp.backends.web import WebBackend
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService

_APP_MARKER = "HEADLESS_RE_WEB_APP_MARKER"
_DATA_MARKER = "HEADLESS_RE_WEB_DATA_MARKER"
_CONSOLE_MARKER = "headless-re-inline-console"

_APP_JS = (
    f"// {_APP_MARKER}\n"
    "window.__headless_loaded = true;\n"
    "fetch('/data.json').then(function (r) { return r.json(); })"
    ".then(function (d) { console.log('fetched', d.marker); });\n"
).encode()
_DATA_JSON = json.dumps({"marker": _DATA_MARKER}).encode()
_HTML = (
    "<html><head><title>webdyn</title>"
    f"<script>console.log('{_CONSOLE_MARKER}');</script>"
    "<script src='/app.js'></script></head>"
    "<body><h1>hello webdyn</h1></body></html>"
).encode()


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - name mandated by BaseHTTPRequestHandler
        if self.path == "/app.js":
            body, content_type = _APP_JS, "application/javascript"
        elif self.path == "/data.json":
            body, content_type = _DATA_JSON, "application/json"
        else:
            body, content_type = _HTML, "text/html"
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args: object) -> None:
        """Silence the default stderr access log during the gate."""


def _browser_available() -> bool:
    try:
        WebBackend()._check_available()
    except Exception:
        return False
    return True


@dataclass
class _Harness:
    service: AnalysisService
    session_id: str
    port: int


def _wait_for_paths(
    service: AnalysisService, session_id: str, suffixes: set[str], *, timeout: float = 15.0
) -> list[dict]:
    """Poll the CDP network log until every wanted path has a 200, or give up.

    Network events arrive asynchronously after domcontentloaded (the external
    script and its fetch land later), so a fixed sleep would be a race; this
    waits for the concrete requests the assertions need.
    """
    deadline = time.monotonic() + timeout
    while True:
        requests = service.web_network_list(session_id, limit=200).data["requests"]
        seen = {
            suffix
            for suffix in suffixes
            if any(
                str(r.get("url", "")).endswith(suffix) and r.get("status") == 200
                for r in requests
            )
        }
        if seen == suffixes:
            return requests
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"network log missing {suffixes - seen} within {timeout:g}s; "
                f"saw {[r.get('url') for r in requests]}"
            )
        time.sleep(0.1)


def _request_id_for(requests: list[dict], suffix: str) -> str:
    for entry in requests:
        if str(entry.get("url", "")).endswith(suffix):
            return str(entry["requestId"])
    raise AssertionError(f"no request for {suffix}")


@pytest.fixture(scope="module")
def _harness(tmp_path_factory: pytest.TempPathFactory) -> Iterator[_Harness]:
    if not _browser_available():
        pytest.skip("playwright not installed — Web Dynamic Gate not run (skip != pass)")

    server = HTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]

    # Keep screenshots/HAR out of the real artifact area: point the service at a
    # throwaway root for the life of the module.
    artifact_root = tmp_path_factory.mktemp("web-artifacts")
    previous = os.environ.get("HEADLESS_RE_ARTIFACT_ROOT")
    os.environ["HEADLESS_RE_ARTIFACT_ROOT"] = str(artifact_root)
    service = AnalysisService(settings=Settings.load())
    try:
        url = f"http://127.0.0.1:{port}/"
        session_id = service.create_session(url, target="web").data["session"]["id"]
        opened = service.web_open(session_id, url=url, headless=True, timeout=30.0)
        if not opened.ok:
            pytest.skip(
                "chromium could not launch "
                f"({opened.error.code if opened.error else 'unknown'}) — "
                "Web Dynamic Gate not run (skip != pass)"
            )
        yield _Harness(service=service, session_id=session_id, port=port)
    finally:
        service.close_all()
        server.shutdown()
        thread.join(timeout=5.0)
        if previous is None:
            os.environ.pop("HEADLESS_RE_ARTIFACT_ROOT", None)
        else:
            os.environ["HEADLESS_RE_ARTIFACT_ROOT"] = previous


@pytest.mark.integration
def test_network_list_captures_the_document_script_and_fetch(_harness: _Harness) -> None:
    requests = _wait_for_paths(
        _harness.service, _harness.session_id, {"/", "/app.js", "/data.json"}
    )
    by_suffix = {
        suffix: next(r for r in requests if str(r.get("url", "")).endswith(suffix))
        for suffix in ("/app.js", "/data.json")
    }
    assert by_suffix["/app.js"]["status"] == 200
    assert "javascript" in str(by_suffix["/app.js"]["mimeType"]).lower()
    assert by_suffix["/data.json"]["status"] == 200
    assert "json" in str(by_suffix["/data.json"]["mimeType"]).lower()


@pytest.mark.integration
def test_network_get_returns_the_fetched_json_body(_harness: _Harness) -> None:
    requests = _wait_for_paths(_harness.service, _harness.session_id, {"/data.json"})
    request_id = _request_id_for(requests, "/data.json")
    result = _harness.service.web_network_get(_harness.session_id, request_id)
    assert result.ok, result.error
    # Small body: inline, not spilled, and carrying the marker the origin sent.
    assert _DATA_MARKER in str(result.data.get("body"))
    assert result.data.get("body_error") is None


@pytest.mark.integration
def test_script_source_returns_the_external_script(_harness: _Harness) -> None:
    # The external script parses after load, so wait for it in the scripts list.
    deadline = time.monotonic() + 15.0
    entry = None
    while time.monotonic() < deadline:
        scripts = _harness.service.web_scripts(_harness.session_id, limit=200).data["scripts"]
        entry = next((s for s in scripts if str(s.get("url", "")).endswith("/app.js")), None)
        if entry is not None:
            break
        time.sleep(0.1)
    assert entry is not None, "the external /app.js script never appeared in the CDP script list"
    source = _harness.service.web_script_source(_harness.session_id, str(entry["scriptId"]))
    assert source.ok, source.error
    assert _APP_MARKER in str(source.data.get("source"))


@pytest.mark.integration
def test_console_captures_inline_and_fetched_messages(_harness: _Harness) -> None:
    # The fetched-message log only fires once the fetch resolves; wait for it.
    deadline = time.monotonic() + 15.0
    texts: list[str] = []
    while time.monotonic() < deadline:
        texts = [str(c.get("text", "")) for c in _harness.service.web_console(
            _harness.session_id, limit=200
        ).data["console"]]
        if any(_DATA_MARKER in t for t in texts):
            break
        time.sleep(0.1)
    assert any(_CONSOLE_MARKER in t for t in texts), texts
    assert any(_DATA_MARKER in t for t in texts), texts


@pytest.mark.integration
def test_dom_snapshot_returns_the_rendered_document(_harness: _Harness) -> None:
    dom = _harness.service.web_dom_snapshot(_harness.session_id)
    assert dom.ok, dom.error
    assert dom.data["title"] == "webdyn"
    assert "hello webdyn" in dom.data["html"]


@pytest.mark.integration
def test_screenshot_writes_a_registered_png(_harness: _Harness) -> None:
    shot = _harness.service.web_screenshot(_harness.session_id)
    assert shot.ok, shot.error
    assert shot.data["size"] > 0
    assert Path(shot.data["path"]).is_file()


@pytest.mark.integration
def test_har_export_contains_the_captured_entries(_harness: _Harness) -> None:
    _wait_for_paths(_harness.service, _harness.session_id, {"/", "/app.js", "/data.json"})
    har = _harness.service.web_har_export(_harness.session_id)
    assert har.ok, har.error
    assert har.data["entry_count"] >= 3
    loaded = json.loads(Path(har.data["path"]).read_text(encoding="utf-8"))
    urls = [entry["request"]["url"] for entry in loaded["log"]["entries"]]
    assert any(url.endswith("/data.json") for url in urls), urls
