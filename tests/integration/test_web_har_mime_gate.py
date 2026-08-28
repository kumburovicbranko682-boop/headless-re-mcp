"""Cross-validate the HAR MIME-masquerade fact against libmagic and a real browser.

describe_har flags responses whose captured bytes open with executable or
container magic while the declared mimeType claims text -- a PE behind
text/html is the drive-by / HTML-smuggling shape. Both halves of that verdict
get an independent referee here:

* the declared side comes from a real capture: chromium (via Playwright)
  records the HAR of a local origin whose routes lie or tell the truth in
  their Content-Type headers, so mimeType is what a browser actually wrote,
  not our fixture dialect;
* the sniffed side is refereed by libmagic: file --mime-type over every
  captured body's decoded bytes must call the flagged bodies executables
  (or wasm) and the unflagged ones text or honestly-declared binary. The
  reader's magic table and libmagic's database must agree on every entry.

The masquerade list must then be exactly the lying routes -- the PE served as
text/html and the WASM served as text/plain -- and nothing else: not the
honest JavaScript, not the ZIP downloaded under its true application/zip.

skip != pass: the test skips, naming the missing piece, only when Playwright,
a chromium build, file(1), or the committed PE fixture is absent.
"""

from __future__ import annotations

import base64
import contextlib
import json
import shutil
import subprocess
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from headless_re_mcp.core.session import describe_har

_PE_FIXTURE = Path(__file__).resolve().parents[2] / "fixtures" / "dotnet" / "minimal_assembly.exe"

# A minimal but real WASM module: magic + version. libmagic calls it
# application/wasm; a browser will happily transfer it as text/plain.
_WASM_BYTES = b"\x00asm\x01\x00\x00\x00"
_APP_JS = b"window.__mime_gate = true;\n"
_PAGE_HTML = (
    b"<html><head><title>har-mime-gate</title></head><body>"
    b"<script>"
    b"fetch('/update').then(r => r.arrayBuffer())"
    b".then(() => fetch('/notes.txt')).then(r => r.arrayBuffer())"
    b".then(() => fetch('/app.js')).then(r => r.text())"
    b".then(() => fetch('/pkg.zip')).then(r => r.arrayBuffer());"
    b"</script></body></html>"
)

# What libmagic may call each of the reader's sniff kinds: the two names for
# PE span libmagic versions; the rest are stable.
_LIBMAGIC_FOR_KIND = {
    "pe": {"application/vnd.microsoft.portable-executable", "application/x-dosexec"},
    "wasm": {"application/wasm"},
    "zip": {"application/zip"},
}


def _routes() -> dict[str, tuple[str, bytes]]:
    import io
    import zipfile

    zip_buf = io.BytesIO()
    with zipfile.ZipFile(zip_buf, "w") as archive:
        archive.writestr("readme.txt", "an honest archive")
    return {
        "/": ("text/html", _PAGE_HTML),
        # The lies: executable bytes under textual claims.
        "/update": ("text/html", _PE_FIXTURE.read_bytes()),
        "/notes.txt": ("text/plain; charset=utf-8", _WASM_BYTES),
        # The truths: text served as text, binary declared as binary.
        "/app.js": ("application/javascript", _APP_JS),
        "/pkg.zip": ("application/zip", zip_buf.getvalue()),
    }


@contextlib.contextmanager
def _origin(routes: dict[str, tuple[str, bytes]]) -> Iterator[str]:
    class _Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler's contract
            content_type, payload = routes.get(self.path, ("text/plain", b"not found"))
            self.send_response(200 if self.path in routes else 404)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, format: str, *args: object) -> None:  # noqa: A002
            """Silence the default stderr access log."""

    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=server.serve_forever, name="mime-origin", daemon=True).start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()


def _record_browser_har(base: str, har_path: Path) -> None:
    from playwright.sync_api import sync_playwright

    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        context = browser.new_context(record_har_path=str(har_path), record_har_content="embed")
        page = context.new_page()
        page.goto(f"{base}/", wait_until="networkidle")
        context.close()
        browser.close()


def _browser_available() -> bool:
    try:
        from playwright.sync_api import sync_playwright

        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True)
            browser.close()
    except Exception:
        return False
    return True


def _decoded_body(content: dict) -> bytes | None:
    text = content.get("text")
    if not isinstance(text, str) or not text:
        return None
    if str(content.get("encoding", "")).lower() == "base64":
        return base64.b64decode(text, validate=True)
    return text.encode("utf-8")


def _libmagic_mime(file_bin: str, data: bytes, scratch: Path) -> str:
    scratch.write_bytes(data)
    result = subprocess.run(
        [file_bin, "--mime-type", "-b", str(scratch)],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr
    return result.stdout.strip()


@pytest.mark.integration
def test_mime_masquerades_agree_with_libmagic_over_a_browser_capture(tmp_path: Path) -> None:
    if not _PE_FIXTURE.is_file():
        pytest.skip(f"fixture missing: {_PE_FIXTURE}")
    file_bin = shutil.which("file")
    if file_bin is None:
        pytest.skip("file(1) not installed — MIME masquerade gate not run (skip != pass)")
    if not _browser_available():
        pytest.skip("playwright/chromium unavailable — MIME masquerade gate not run (skip != pass)")

    har_path = tmp_path / "capture.har"
    routes = _routes()
    with _origin(routes) as base:
        _record_browser_har(base, har_path)

    # The reader's verdict over the browser's own recording.
    info = describe_har(har_path)["har"]
    flagged = {m["url"].rsplit("/", 1)[-1] or "/": m["sniffed"] for m in info["mime_masquerades"]}
    assert flagged == {"update": "pe", "notes.txt": "wasm"}
    assert info["mime_masquerade_count"] == 2

    # libmagic referees every captured body independently: each flagged body
    # must be the executable/container libmagic says it is, and every
    # unflagged body must be either textual bytes or an honestly-declared
    # binary. No entry may fall between the two readers.
    doc = json.loads(har_path.read_text(encoding="utf-8"))
    checked = 0
    for entry in doc["log"]["entries"]:
        content = entry.get("response", {}).get("content", {})
        body = _decoded_body(content)
        if body is None:
            continue
        url_tail = entry["request"]["url"].rsplit("/", 1)[-1] or "/"
        magic_mime = _libmagic_mime(file_bin, body, tmp_path / "scratch.bin")
        declared = str(content.get("mimeType", ""))
        if url_tail in flagged:
            # The reader called it a lie: libmagic must agree the bytes are
            # the claimed executable kind, and the declaration must be texty.
            assert magic_mime in _LIBMAGIC_FOR_KIND[flagged[url_tail]], (url_tail, magic_mime)
            assert declared.split(";")[0].strip().lower().startswith(("text/",)) or (
                declared in ("application/javascript",)
            ), (url_tail, declared)
        else:
            # The reader stayed silent: either the bytes are not one of the
            # sniffable kinds per libmagic, or the declaration was honest
            # (the ZIP downloaded as application/zip).
            libmagic_binary = any(
                magic_mime in names for names in _LIBMAGIC_FOR_KIND.values()
            )
            declared_texty = declared.split(";")[0].strip().lower().startswith("text/")
            assert not (libmagic_binary and declared_texty), (url_tail, magic_mime, declared)
        checked += 1
    # The capture embedded every route's body: page, two lies, two truths.
    assert checked >= 5
