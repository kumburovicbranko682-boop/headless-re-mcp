"""Web RE gate: CDP browser driving, plus webcrack / wabt when configured.

Each capability skips independently with an explicit "skip != pass" message when
its backend is unavailable, so the gate is honest on a bare machine and real
when Chrome / webcrack / wabt are present.
"""

from __future__ import annotations

import http.server
import socketserver
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.jsre import JsClient, WasmClient
from headless_re_mcp.backends.web import WebBackend
from headless_re_mcp.core.service import AnalysisService

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_JS_FIXTURE = _PROJECT_ROOT / "fixtures" / "web" / "obfuscated_sample.js"

_SITE_PAGE = (
    b"<!doctype html><html><head><title>gate-net</title>"
    b"<script>console.log('gate-sync-line');"
    b"fetch('/data.json').then(r=>r.json()).then(j=>console.log('fetched',j.v));"
    b"</script></head><body><h1>hello</h1></body></html>"
)
_SITE_BODY = b'{"v": 777, "note": "captured-network-body"}'


class _SiteHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args: object) -> None:  # keep the gate output clean
        return

    def do_GET(self) -> None:  # noqa: N802 - http.server hook name
        if self.path.startswith("/data.json"):
            body, ctype = _SITE_BODY, "application/json"
        else:
            body, ctype = _SITE_PAGE, "text/html"
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture
def local_site() -> Iterator[str]:
    """A throwaway 127.0.0.1 site so network capture has real flows to record."""
    httpd = socketserver.TCPServer(("127.0.0.1", 0), _SiteHandler)
    httpd.allow_reuse_address = True
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{httpd.server_address[1]}/index.html"
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5.0)


def _wait_for_request(
    service: AnalysisService, session_id: str, needle: str
) -> dict[str, Any] | None:
    """Poll network_list until a request whose url contains needle has responded."""
    deadline = time.monotonic() + 10.0
    while time.monotonic() < deadline:
        listing = service.web_network_list(session_id)
        if listing.ok:
            for entry in listing.data["requests"]:
                if needle in entry["url"] and entry.get("status") is not None:
                    return entry
        time.sleep(0.1)
    return None

_DATA_URL = (
    "data:text/html,"
    "<html><head><title>gate</title>"
    "<script>window.__x=1;console.log('gate-ready');</script>"
    "</head><body>hello</body></html>"
)


def _browser_available() -> bool:
    backend = WebBackend()
    try:
        backend._check_available()
    except Exception:
        return False
    return True


@pytest.mark.integration
def test_web_cdp_open_and_inspect() -> None:
    if not _browser_available():
        pytest.skip("playwright not installed — Web CDP Gate not run (skip != pass)")
    service = AnalysisService()
    try:
        created = service.create_session(_DATA_URL, target="web")
        assert created.ok, created.error
        session_id = created.data["session"]["id"]

        opened = service.web_open(session_id, headless=True, timeout=30.0)
        if not opened.ok:
            pytest.skip(
                f"chromium could not launch (browser not installed?): "
                f"{opened.error.code if opened.error else 'unknown'} — skip != pass"
            )
        try:
            scripts = service.web_scripts(session_id)
            assert scripts.ok, scripts.error
            assert isinstance(scripts.data["scripts"], list)

            console = service.web_console(session_id)
            assert console.ok, console.error

            dom = service.web_dom_snapshot(session_id)
            assert dom.ok, dom.error
            assert "gate" in dom.data["title"]
        finally:
            service.web_close(session_id)
    finally:
        service.close_all()


@pytest.mark.integration
def test_web_cdp_captures_network_and_exports_a_body_and_har(local_site: str) -> None:
    """The complex half of the CDP surface: capture flows, pull a body, dump HAR.

    ``test_web_cdp_open_and_inspect`` only reaches scripts/console/dom on a
    data: URL, which generates no network. Pointed at a real (local-only) site
    that fetches a JSON resource, this drives the request ring, the on-demand
    response-body fetch, the HAR export and a screenshot end to end -- the paths
    an unattended web capture actually depends on.
    """
    if not _browser_available():
        pytest.skip("playwright not installed — Web CDP Gate not run (skip != pass)")
    service = AnalysisService()
    try:
        created = service.create_session(local_site, target="web")
        assert created.ok, created.error
        session_id = created.data["session"]["id"]

        opened = service.web_open(session_id, headless=True, timeout=30.0)
        if not opened.ok:
            pytest.skip(
                f"chromium could not launch (browser not installed?): "
                f"{opened.error.code if opened.error else 'unknown'} — skip != pass"
            )
        try:
            # The page fetches /data.json asynchronously; wait for that flow.
            data_entry = _wait_for_request(service, session_id, "data.json")
            assert data_entry is not None, "the /data.json request was never captured"
            assert data_entry["status"] == 200
            assert "json" in (data_entry["mimeType"] or "")

            # The page document itself must be in the ring too.
            listing = service.web_network_list(session_id)
            assert listing.ok, listing.error
            urls = [entry["url"] for entry in listing.data["requests"]]
            assert any("index.html" in url for url in urls)
            assert listing.data["total"] >= 2

            # Pull the response body on demand and confirm it is the real bytes.
            body = service.web_network_get(session_id, data_entry["requestId"])
            assert body.ok, body.error
            assert "captured-network-body" in body.data["body"]
            assert body.data["base64_encoded"] is False

            # The synchronous console line must have been recorded over CDP.
            console = service.web_console(session_id)
            assert console.ok, console.error
            assert any(
                "gate-sync-line" in item["text"] for item in console.data["console"]
            )

            # HAR export must include both flows and name a real artifact.
            har = service.web_har_export(session_id)
            assert har.ok, har.error
            assert har.data["entry_count"] >= 2
            assert Path(har.data["path"]).is_file()

            # A screenshot of the live page is a non-empty PNG.
            shot = service.web_screenshot(session_id)
            assert shot.ok, shot.error
            assert shot.data["size"] > 0
            assert Path(shot.data["path"]).is_file()
        finally:
            service.web_close(session_id)
    finally:
        service.close_all()


@pytest.mark.integration
def test_js_deobfuscate_when_webcrack_present() -> None:
    if not JsClient().available:
        pytest.skip("webcrack not installed — JS Gate not run (skip != pass)")
    assert _JS_FIXTURE.is_file(), f"fixture missing: {_JS_FIXTURE}"
    service = AnalysisService()
    try:
        result = service.js_deobfuscate(str(_JS_FIXTURE))
        assert result.ok, result.error
        assert isinstance(result.data["code"], str)
        assert result.data["bytes"] > 0
    finally:
        service.close_all()


@pytest.mark.integration
def test_js_beautify_when_webcrack_present() -> None:
    if not JsClient().available:
        pytest.skip("webcrack not installed — JS beautify Gate not run (skip != pass)")
    assert _JS_FIXTURE.is_file(), f"fixture missing: {_JS_FIXTURE}"
    service = AnalysisService()
    try:
        result = service.js_beautify(str(_JS_FIXTURE))
        assert result.ok, result.error
        assert isinstance(result.data["code"], str)
        assert result.data["bytes"] > 0
    finally:
        service.close_all()


@pytest.mark.integration
def test_js_unpack_bundle_when_webcrack_present() -> None:
    if not JsClient().available:
        pytest.skip("webcrack not installed — JS unpack Gate not run (skip != pass)")
    assert _JS_FIXTURE.is_file(), f"fixture missing: {_JS_FIXTURE}"
    service = AnalysisService()
    try:
        # webcrack refuses a pre-existing output dir without --force; this drives
        # the whole service path so that regression cannot come back unnoticed.
        result = service.js_unpack_bundle(str(_JS_FIXTURE))
        assert result.ok, result.error
        assert result.data["file_count"] >= 1
        assert result.data["files"], "unpack produced no files"
        assert result.data["count"] == len(result.data["files"])
        assert result.data["has_more"] is False
    finally:
        service.close_all()


@pytest.mark.integration
def test_wasm_wat_when_wabt_present(tmp_path: Path) -> None:
    if not WasmClient().available:
        pytest.skip("wabt (wasm2wat) not installed — WASM Gate not run (skip != pass)")
    # The smallest valid module: magic + version, no sections.
    module = tmp_path / "empty.wasm"
    module.write_bytes(b"\x00asm\x01\x00\x00\x00")
    service = AnalysisService()
    try:
        result = service.wasm_wat(str(module))
        assert result.ok, result.error
        assert "module" in result.data["wat"]
    finally:
        service.close_all()


@pytest.mark.integration
def test_wasm_info_when_wabt_present(tmp_path: Path) -> None:
    if not WasmClient().available:
        pytest.skip("wabt (wasm-objdump) not installed — WASM info Gate not run (skip != pass)")
    # magic + version, then one Type section (id 1) declaring a () -> nil func,
    # so wasm-objdump has a real section header to parse rather than an empty one.
    module = tmp_path / "type.wasm"
    module.write_bytes(b"\x00asm\x01\x00\x00\x00" + bytes([0x01, 0x04, 0x01, 0x60, 0x00, 0x00]))
    service = AnalysisService()
    try:
        result = service.wasm_info(str(module))
        if not result.ok and result.error and result.error.code == "capability_unavailable":
            pytest.skip("wasm-objdump not present — WASM info Gate not run (skip != pass)")
        assert result.ok, result.error
        objdump = result.data["objdump"]
        assert "wasm" in objdump
        assert "Type" in objdump
    finally:
        service.close_all()
