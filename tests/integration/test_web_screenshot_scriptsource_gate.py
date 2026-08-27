"""Web gate: screenshot + script_source, the CDP paths the RE gate skips.

``test_web_re_gate`` drives web.scripts / console / dom_snapshot, but two
version-sensitive browser paths have no live coverage: ``web.screenshot``
(Playwright ``page.screenshot``) and ``web.script_source`` (CDP
``Debugger.getScriptSource``). ``web.scripts`` alone is only asserted to be a
list, so a break in fetching a script's actual source, or in the screenshot
call, would pass every existing test and only fail at runtime against a real
browser.

This gate opens a data: page carrying a known inline script, then through the
full ``AnalysisService`` stack: screenshots it and checks a real PNG landed, and
walks the parsed scripts fetching each source until it finds that inline marker
-- proving getScriptSource returns real bytes. Skips (skip != pass) when
chromium cannot launch.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.backends.web import WebBackend
from headless_re_mcp.core.service import AnalysisService

_MARKER = "gate-marker-8842"
_DATA_URL = (
    "data:text/html,"
    "<html><head><title>shotgate</title>"
    f"<script>window.__x=1;console.log('{_MARKER}');</script>"
    "</head><body>hello</body></html>"
)


def _browser_available() -> bool:
    try:
        WebBackend()._check_available()
    except Exception:
        return False
    return True


@pytest.mark.integration
def test_web_screenshot_and_script_source() -> None:
    if not _browser_available():
        pytest.skip("playwright not installed — Web screenshot Gate not run (skip != pass)")
    service = AnalysisService()
    try:
        created = service.create_session(_DATA_URL, target="web")
        assert created.ok, created.error
        session_id = created.data["session"]["id"]

        opened = service.web_open(session_id, headless=True, timeout=30.0)
        if not opened.ok:
            pytest.skip(
                f"chromium could not launch: "
                f"{opened.error.code if opened.error else 'unknown'} — skip != pass"
            )
        try:
            # screenshot: page.screenshot must produce a real PNG on disk.
            shot = service.web_screenshot(session_id)
            assert shot.ok, shot.error
            assert shot.data["size"] > 0
            png = Path(shot.data["path"])
            assert png.is_file()
            assert png.read_bytes()[:4] == b"\x89PNG", "screenshot is not a PNG"

            # script_source: walk the parsed scripts and fetch each source until
            # the known inline script turns up, proving Debugger.getScriptSource
            # returns real bytes (not just that scripts enumerated).
            scripts = service.web_scripts(session_id)
            assert scripts.ok, scripts.error
            assert scripts.data["scripts"], "no scripts parsed for the page"

            marker_source = None
            for entry in scripts.data["scripts"]:
                fetched = service.web_script_source(session_id, entry["scriptId"])
                if fetched.ok and _MARKER in fetched.data.get("source", ""):
                    marker_source = fetched.data
                    break
            assert marker_source is not None, "getScriptSource never returned the inline script"
            assert marker_source["bytes"] > 0
            assert marker_source["truncated"] is False
        finally:
            service.web_close(session_id)
    finally:
        service.close_all()
