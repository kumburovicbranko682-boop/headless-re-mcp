"""Web dynamic gate: the browser capture/artifact surface end to end via service.

Most web gates drive WebBackend directly; only the RE gate reaches
AnalysisService, and it covers open/scripts/console/dom -- none of the four
service methods that register a session artifact. web.screenshot, web.har_export,
web.script_source and web.network_get each hand a captured file to
_register_capture so an agent can read it back and retention can reclaim it, and
screenshot/har also land on the session timeline. That registration is the
service's own work, invisible to the backend gates, and was exercised only by
unit tests with a patched backend.

This gate stands up a local origin whose page links a >200 KiB script and
fetches a >200 KiB resource (past the inline cap, so both spill to files), drives
AnalysisService against a real Chromium, and asserts:

- web.open lands on the timeline with the backend label,
- web.script_source spills the linked script and registers it (kind
  web_script_source), the spilled file carrying the script marker,
- web.network_get spills the fetched body and registers it (kind
  web_response_body),
- web.screenshot and web.har_export always write into web/<session> and register
  (kinds web_screenshot / web_har), each recording its timeline event,
- every registered artifact is discoverable through artifacts.describe /
  artifacts.list,
- web.navigate and web.status answer through the envelope,
- web.close records web.close on the timeline.

Skips honestly when playwright/chromium is unavailable. skip != pass.
"""

from __future__ import annotations

import socket
import threading
import time
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from headless_re_mcp.backends.web import WebBackend, WebError
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService

_SCRIPT_MARKER = "web-svc-script-marker-3a9"
_BODY_MARKER = "web-svc-body-marker-5c2"
# Past the 200 KiB inline cap so script_source / network_get spill to a file
# (and the service then registers that file), well under the 64 MiB capture cap.
_BIG_JS = f"//{_SCRIPT_MARKER}\nvar _pad='{'A' * 250_000}';console.log('script-ready');\n"
_BIG_BIN = (_BODY_MARKER + "-" + "Z" * 250_000).encode("ascii")
_PAGE = (
    "<!doctype html><html><head><title>websvc</title>"
    '<script src="/big.js"></script></head>'
    "<body><h1>WEB-SVC-CAPTURE</h1>"
    "<script>fetch('/big.bin').then(r=>r.arrayBuffer())"
    ".then(b=>console.log('FETCHED='+b.byteLength));</script>"
    "</body></html>"
)


class _Origin(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract
        if self.path.startswith("/big.js"):
            raw, ctype = _BIG_JS.encode("utf-8"), "application/javascript; charset=utf-8"
        elif self.path.startswith("/big.bin"):
            raw, ctype = _BIG_BIN, "application/octet-stream"
        else:
            raw, ctype = _PAGE.encode("utf-8"), "text/html; charset=utf-8"
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, *args: object) -> None:  # keep pytest output clean
        return


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def _browser_available() -> bool:
    try:
        WebBackend()._check_available()
    except WebError:
        return False
    return True


@pytest.mark.integration
def test_web_capture_service_registers_artifacts_end_to_end(tmp_path: Path) -> None:
    if not _browser_available():
        pytest.skip("playwright not installed — web capture service Gate not run (skip != pass)")

    port = _free_port()
    origin = ThreadingHTTPServer(("127.0.0.1", port), _Origin)
    threading.Thread(target=origin.serve_forever, daemon=True).start()

    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    web_tree = settings.artifact_root.expanduser().resolve() / "web"
    service = AnalysisService(settings)
    try:
        created = service.create_session(f"http://127.0.0.1:{port}/page", target="web")
        assert created.ok and created.data is not None, created.error
        session_id = str(created.data["session"]["id"])

        opened = service.web_open(session_id, headless=True, timeout=45.0)
        if not opened.ok:
            code = opened.error.code if opened.error else "unknown"
            pytest.skip(f"chromium could not launch ({code}) — skip != pass")
        assert opened.meta.get("backend") == "web"

        # web.script_source: find the linked >200 KiB script, pull its source,
        # and confirm the service spilled and registered it.
        script_id: str | None = None
        deadline = time.monotonic() + 15.0
        while time.monotonic() < deadline and script_id is None:
            scripts = service.web_scripts(session_id)
            assert scripts.ok and scripts.data is not None, scripts.error
            for entry in scripts.data["scripts"]:
                if str(entry.get("url", "")).endswith("/big.js"):
                    script_id = str(entry["scriptId"])
                    break
            if script_id is None:
                time.sleep(0.1)
        assert script_id is not None, "linked script never parsed"

        src = service.web_script_source(session_id, script_id)
        assert src.ok and src.data is not None, src.error
        src_path = src.data.get("source_path")
        assert isinstance(src_path, str) and src_path, src.data
        spilled_src = Path(src_path).resolve()
        assert web_tree in spilled_src.parents, (spilled_src, web_tree)
        assert _SCRIPT_MARKER in spilled_src.read_text(encoding="utf-8", errors="replace")
        script_artifact = src.data.get("artifact_id")
        assert isinstance(script_artifact, str) and script_artifact, src.data

        # web.network_get: wait for the fetched resource, pull its body, and
        # confirm the service spilled and registered it.
        request_id: str | None = None
        deadline = time.monotonic() + 15.0
        while time.monotonic() < deadline and request_id is None:
            listed = service.web_network_list(session_id)
            assert listed.ok and listed.data is not None, listed.error
            for req in listed.data["requests"]:
                if str(req.get("url", "")).endswith("/big.bin") and req.get("status") == 200:
                    request_id = str(req["requestId"])
                    break
            if request_id is None:
                time.sleep(0.1)
        assert request_id is not None, "fetched resource never captured"

        body = service.web_network_get(session_id, request_id)
        # getResponseBody can briefly race a just-finished load; retry.
        for _ in range(20):
            if body.ok and body.data is not None and not body.data.get("body_error"):
                break
            time.sleep(0.1)
            body = service.web_network_get(session_id, request_id)
        assert body.ok and body.data is not None, body.error
        body_path = body.data.get("body_path")
        assert isinstance(body_path, str) and body_path, body.data
        spilled_body = Path(body_path).resolve()
        assert web_tree in spilled_body.parents, (spilled_body, web_tree)
        body_artifact = body.data.get("artifact_id")
        assert isinstance(body_artifact, str) and body_artifact, body.data

        # web.screenshot and web.har_export always write and register.
        shot = service.web_screenshot(session_id)
        assert shot.ok and shot.data is not None, shot.error
        shot_artifact = shot.data.get("artifact_id")
        assert isinstance(shot_artifact, str) and shot_artifact, shot.data
        assert web_tree in Path(str(shot.data["path"])).resolve().parents

        har = service.web_har_export(session_id)
        assert har.ok and har.data is not None, har.error
        har_artifact = har.data.get("artifact_id")
        assert isinstance(har_artifact, str) and har_artifact, har.data

        # Every registered capture is discoverable through the artifact surface.
        described = service.artifacts_describe(script_artifact)
        assert described.ok and described.data is not None, described.error
        assert described.data["artifact"]["kind"] == "web_script_source"
        listed_art = service.artifacts_list(session_id)
        assert listed_art.ok and listed_art.data is not None, listed_art.error
        kinds = {a["kind"] for a in listed_art.data["artifacts"]}
        assert {
            "web_script_source",
            "web_response_body",
            "web_screenshot",
            "web_har",
        } <= kinds, kinds

        # web.navigate and web.status answer through the envelope.
        nav = service.web_navigate(session_id, f"http://127.0.0.1:{port}/page")
        assert nav.ok and nav.data is not None, nav.error
        status = service.web_status(session_id)
        assert status.ok and status.data is not None, status.error
        assert status.data["state"] and status.data["target"] == "web"

        # Timeline carries open / screenshot / har before the session closes.
        timeline = service.timeline_list(session_id)
        assert timeline.ok and timeline.data is not None, timeline.error
        events = {e.get("event") for e in timeline.data["events"]}
        assert {"web.open", "web.screenshot", "web.har.export"} <= events, events

        closed = service.web_close(session_id)
        assert closed.ok, closed.error
        after_tl = service.timeline_list(session_id)
        assert after_tl.ok and after_tl.data is not None, after_tl.error
        events_after = {e.get("event") for e in after_tl.data["events"]}
        assert "web.close" in events_after, events_after
    finally:
        service.close_all()
        origin.shutdown()
        origin.server_close()
