"""Cross-validate describe_har's body-integrity fact against a real browser HAR.

describe_har now reports whether a capture's response bodies are actually
present: per HAR 1.2 it compares each content.size with the decoded length of
content.text, so a whole capture is told from a body-stripped share or a
truncated one. That comparison and the unit fixtures are both ours, so nothing
proved it against a HAR a real recorder wrote. Playwright records one here the
independent way -- chromium's own HAR writer, embedding bodies -- of a local
origin serving known payloads. Three checks close the loop:

* every body the browser embedded decodes to exactly its declared size (an
  independent recomputation over the same JSON, not a call back into the
  reader), and the reader agrees the capture is whole -- bodies_captured
  equals that independently counted set, nothing stripped or mismatched;
* a copy with one entry's content.text removed -- the privacy-scrubbed share --
  must read as one more stripped body and one fewer captured;
* a copy with one entry's content.text truncated -- a capture cut short --
  must read as one size mismatch.

A second test does the mirror for uploaded (POST) bodies: request.bodySize vs
postData.text, with the same pristine / scrubbed / truncated checks against a
real browser's recording of a login POST.

skip != pass: the tests skip, naming the reason, only when Playwright or a
chromium build is unavailable.
"""

from __future__ import annotations

import base64
import contextlib
import json
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.core.session import describe_har

_API_BODY = b'{"answer":"har-body-42","note":"a body worth embedding"}'
_APP_JS = b"window.__loaded = true;\nconsole.log('har-body-gate');\n"
# The exact JSON the page POSTs; the browser records its byte length as
# request.bodySize and its bytes as postData.text, the pair the reader checks.
_LOGIN_BODY = b'{"user":"alice","password":"correct horse battery staple"}'
_PAGE_HTML = (
    b"<html><head><title>har-body-gate</title>"
    b'<script src="/app.js"></script>'
    b"</head><body>"
    b"<script>fetch('/api/data').then(r => r.json());"
    b"fetch('/api/login',{method:'POST',"
    b"headers:{'Content-Type':'application/json'},"
    b'body:JSON.stringify({user:"alice",password:"correct horse battery staple"})});'
    b"</script>"
    b"</body></html>"
)
_ROUTES: dict[str, tuple[str, bytes]] = {
    "/": ("text/html", _PAGE_HTML),
    "/app.js": ("application/javascript", _APP_JS),
    "/api/data": ("application/json", _API_BODY),
    "/api/login": ("application/json", b"{}"),
}


class _OriginHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler's contract
        content_type, payload = _ROUTES.get(self.path, ("text/plain", b"not found"))
        status = 200 if self.path in _ROUTES else 404
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler's contract
        length = int(self.headers.get("Content-Length", "0"))
        self.rfile.read(length)
        body = b'{"ok":true}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        """Silence the default stderr access log."""


@contextlib.contextmanager
def _origin() -> Iterator[str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _OriginHandler)
    threading.Thread(target=server.serve_forever, name="har-origin", daemon=True).start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()


def _record_browser_har(base: str, har_path: Path) -> None:
    """Drive chromium over the origin, letting it write a bodies-embedded HAR."""
    from playwright.sync_api import sync_playwright

    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        # record_har_content='embed' puts each body inline as content.text
        # (base64 for binary) with content.size -- exactly the pair the reader
        # reconciles. The context must be closed for the HAR to flush.
        context = browser.new_context(record_har_path=str(har_path), record_har_content="embed")
        page = context.new_page()
        page.goto(f"{base}/", wait_until="networkidle")
        context.close()
        browser.close()


def _independent_captured_bodies(doc: dict) -> int:
    """Count entries whose embedded body decodes to exactly its declared size.

    A referee that never calls describe_har: it re-derives, straight from the
    HAR JSON the browser wrote, the same 'captured and self-consistent' set the
    reader must report as bodies_captured with nothing mismatched.
    """
    captured = 0
    for entry in doc["log"]["entries"]:
        content = entry.get("response", {}).get("content", {})
        size = content.get("size")
        text = content.get("text")
        if not isinstance(size, int) or size <= 0 or not isinstance(text, str) or not text:
            continue
        if str(content.get("encoding", "")).lower() == "base64":
            measured = len(base64.b64decode(text, validate=True))
        else:
            measured = len(text.encode("utf-8"))
        assert measured == size, f"browser HAR body length {measured} != declared size {size}"
        captured += 1
    return captured


def _browser_available() -> bool:
    try:
        from playwright.sync_api import sync_playwright

        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True)
            browser.close()
    except Exception:  # noqa: BLE001
        return False
    return True


@pytest.mark.integration
def test_har_body_integrity_matches_a_real_browser_capture(tmp_path: Path) -> None:
    if not _browser_available():
        pytest.skip("playwright/chromium unavailable — HAR body gate not run (skip != pass)")

    har_path = tmp_path / "capture.har"
    with _origin() as base:
        _record_browser_har(base, har_path)

    doc = json.loads(har_path.read_text(encoding="utf-8"))
    entries = doc["log"]["entries"]
    # The browser really recorded the exchanges, bodies and all: find the JSON
    # API entry and confirm its embedded body is our exact payload -- ground
    # truth that the capture carries real content, not just declared sizes.
    api = next(e for e in entries if e["request"]["url"].endswith("/api/data"))
    api_content = api["response"]["content"]
    api_bytes = (
        base64.b64decode(api_content["text"])
        if str(api_content.get("encoding", "")).lower() == "base64"
        else api_content["text"].encode("utf-8")
    )
    assert api_bytes == _API_BODY

    # The reader's verdict on the pristine capture must be 'whole': every
    # embedded body captured and self-consistent, none stripped or mismatched.
    pristine = describe_har(har_path)["har"]["body_integrity"]
    expected_captured = _independent_captured_bodies(doc)
    assert expected_captured >= 2  # at least the app.js and the API body
    assert pristine == {
        "responses_with_body": expected_captured,
        "bodies_captured": expected_captured,
        "bodies_stripped": 0,
        "bodies_size_mismatch": 0,
    }

    # A body with a declared size and embedded text -- the entries the reader
    # can meaningfully mutate. The API body qualifies (non-empty, text-encoded).
    def _is_captured(entry: dict[str, Any]) -> bool:
        content = entry.get("response", {}).get("content", {})
        return (
            isinstance(content.get("size"), int)
            and content["size"] > 0
            and isinstance(content.get("text"), str)
            and bool(content["text"])
        )

    # Stripped copy: remove one entry's body text, the privacy-scrubbed share.
    stripped_doc = json.loads(har_path.read_text(encoding="utf-8"))
    victim = next(e for e in stripped_doc["log"]["entries"] if _is_captured(e))
    del victim["response"]["content"]["text"]
    stripped_path = tmp_path / "stripped.har"
    stripped_path.write_text(json.dumps(stripped_doc), encoding="utf-8")
    stripped = describe_har(stripped_path)["har"]["body_integrity"]
    assert stripped["responses_with_body"] == expected_captured
    assert stripped["bodies_stripped"] == 1
    assert stripped["bodies_captured"] == expected_captured - 1
    assert stripped["bodies_size_mismatch"] == 0

    # Truncated copy: shorten one entry's body text below its declared size,
    # a capture cut short. Pick a text (non-base64) body so a shorter string
    # is unambiguously fewer bytes.
    truncated_doc = json.loads(har_path.read_text(encoding="utf-8"))
    text_victim = next(
        e
        for e in truncated_doc["log"]["entries"]
        if _is_captured(e)
        and str(e["response"]["content"].get("encoding", "")).lower() != "base64"
    )
    content = text_victim["response"]["content"]
    assert len(content["text"].encode("utf-8")) == content["size"]
    content["text"] = content["text"][: max(1, len(content["text"]) // 2)]
    truncated_path = tmp_path / "truncated.har"
    truncated_path.write_text(json.dumps(truncated_doc), encoding="utf-8")
    truncated = describe_har(truncated_path)["har"]["body_integrity"]
    assert truncated["bodies_size_mismatch"] == 1
    assert truncated["bodies_captured"] == expected_captured


def _independent_captured_uploads(doc: dict) -> int:
    """Count requests whose postData.text decodes to exactly bodySize bytes.

    The upload-side referee, mirroring _independent_captured_bodies: re-derived
    straight from the HAR the browser wrote, never through describe_har.
    """
    captured = 0
    for entry in doc["log"]["entries"]:
        request = entry.get("request", {})
        size = request.get("bodySize")
        post_data = request.get("postData")
        if not isinstance(size, int) or size <= 0 or not isinstance(post_data, dict):
            continue
        text = post_data.get("text")
        if not isinstance(text, str) or not text:
            continue
        if str(post_data.get("encoding", "")).lower() == "base64":
            measured = len(base64.b64decode(text, validate=True))
        else:
            measured = len(text.encode("utf-8"))
        assert measured == size, f"browser HAR upload length {measured} != bodySize {size}"
        captured += 1
    return captured


@pytest.mark.integration
def test_har_request_body_integrity_matches_a_real_browser_capture(tmp_path: Path) -> None:
    if not _browser_available():
        pytest.skip("playwright/chromium unavailable — HAR upload gate not run (skip != pass)")

    har_path = tmp_path / "capture.har"
    with _origin() as base:
        _record_browser_har(base, har_path)

    doc = json.loads(har_path.read_text(encoding="utf-8"))
    entries = doc["log"]["entries"]
    # Ground truth: the browser recorded the login POST with our exact body as
    # postData.text and its byte length as bodySize.
    login = next(e for e in entries if e["request"]["url"].endswith("/api/login"))
    login_request = login["request"]
    assert login_request["method"] == "POST"
    assert login_request["bodySize"] == len(_LOGIN_BODY)
    assert login_request["postData"]["text"].encode("utf-8") == _LOGIN_BODY

    # Pristine: the reader must call the upload captured and self-consistent,
    # agreeing with the independent count over the same JSON.
    expected = _independent_captured_uploads(doc)
    assert expected >= 1
    pristine = describe_har(har_path)["har"]["request_body_integrity"]
    assert pristine == {
        "requests_with_body": expected,
        "bodies_captured": expected,
        "bodies_stripped": 0,
        "bodies_size_mismatch": 0,
    }

    # Scrubbed copy: drop the login body's text -- the credentials removed
    # before sharing -- and the reader must report one stripped upload.
    scrubbed_doc = json.loads(har_path.read_text(encoding="utf-8"))
    scrub = next(
        e for e in scrubbed_doc["log"]["entries"] if e["request"]["url"].endswith("/api/login")
    )
    del scrub["request"]["postData"]["text"]
    scrubbed_path = tmp_path / "scrubbed.har"
    scrubbed_path.write_text(json.dumps(scrubbed_doc), encoding="utf-8")
    scrubbed = describe_har(scrubbed_path)["har"]["request_body_integrity"]
    assert scrubbed["requests_with_body"] == expected
    assert scrubbed["bodies_stripped"] == 1
    assert scrubbed["bodies_captured"] == expected - 1

    # Truncated copy: shorten the login body below its declared bodySize.
    truncated_doc = json.loads(har_path.read_text(encoding="utf-8"))
    cut = next(
        e for e in truncated_doc["log"]["entries"] if e["request"]["url"].endswith("/api/login")
    )
    post_data = cut["request"]["postData"]
    post_data["text"] = post_data["text"][: len(post_data["text"]) // 2]
    truncated_path = tmp_path / "truncated-upload.har"
    truncated_path.write_text(json.dumps(truncated_doc), encoding="utf-8")
    truncated = describe_har(truncated_path)["har"]["request_body_integrity"]
    assert truncated["bodies_size_mismatch"] == 1
    assert truncated["bodies_captured"] == expected
