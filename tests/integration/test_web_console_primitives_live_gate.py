"""web console capture live gate: JS primitives keep their JS spelling.

CDP delivers ``Runtime.consoleAPICalled`` args as RemoteObjects whose primitive
``value`` is a plain Python object. The capture path joined those with ``str()``,
so a page that logged ``true`` / ``false`` / ``null`` was recorded as Python's
``True`` / ``False`` / ``None`` -- and ``null`` read back as ``None`` is exactly
the kind of thing an analyst correlating console output with source would
misread. The unit tests only ever fed console entries as pre-built strings, so a
real boolean or null RemoteObject never went through the renderer and the defect
stayed hidden (the same blind spot that hid the APK certificate DN repr).

The renderer now maps those three back to their JS forms with identity checks, so
the string ``"True"`` and the number ``0`` are left alone. This gate proves it
against a real headless Chromium -- not a synthetic params dict:

  * a line logging ``"s", 42, true, false, null, undefined`` comes back exactly as
    ``s 42 true false null undefined``, and none of ``True`` / ``False`` / ``None``
    appear anywhere in the capture; and
  * a line logging ``0, false`` comes back as ``0 false`` -- proving the boolean
    mapping keys on identity, so ``0`` is not conflated with ``false``.

Skip != pass: the gate skips with a reason when Playwright or its Chromium build
is absent. CI installs both, so a skip there is a real regression.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import pytest

from headless_re_mcp.backends.web.client import WebBackend, WebError

# Two distinct console lines, each prefixed with a marker so the assertions can
# find them regardless of any other console noise the page produces.
_PAGE = b"""<!doctype html><title>console</title><script>
console.log("GATE", "s", 42, true, false, null, undefined);
console.log("ZERO", 0, false);
</script>"""


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args: object) -> None:  # noqa: D401 - silence the server
        pass

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(_PAGE)))
        self.end_headers()
        self.wfile.write(_PAGE)


@pytest.fixture(scope="module")
def base_url() -> Iterator[str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        thread.join(timeout=5)


def _line(messages: list[dict[str, Any]], marker: str) -> str:
    for message in messages:
        text = str(message.get("text", ""))
        if text.startswith(marker):
            return text
    raise AssertionError(f"no console line starting with {marker!r}; got {messages!r}")


@pytest.mark.integration
def test_console_renders_js_primitives_with_js_spelling(base_url: str) -> None:
    backend = WebBackend()
    session_id = "web-console-primitives-gate"
    try:
        backend.open(session_id, base_url, timeout=30.0)
    except WebError as exc:
        pytest.skip(f"web session could not open ({exc.code}: {exc}) — gate not run (skip != pass)")

    try:
        # The script logs at parse time; give the CDP events a beat to arrive.
        time.sleep(0.6)
        messages = backend.console(session_id, limit=50)["console"]

        # The fix: JS primitives keep their JS spelling end to end.
        gate = _line(messages, "GATE")
        assert gate == "GATE s 42 true false null undefined", gate

        # The bug's signature must be gone from the whole capture, not just this
        # line: no Python repr of a JS boolean or null anywhere.
        joined = "\n".join(str(message.get("text", "")) for message in messages)
        assert "True" not in joined, joined
        assert "False" not in joined, joined
        assert "None" not in joined, joined

        # Identity, not equality: 0 is not the boolean false, so it stays "0".
        zero = _line(messages, "ZERO")
        assert zero == "ZERO 0 false", zero
    finally:
        backend.close(session_id)
