"""web.scripts must list the page's scripts, not Playwright's injected ones.

Playwright drives every page through an injected "utility world" -- an isolated
execution context it creates per frame for its own automation. Those scripts
surface via Debugger.scriptParsed with an empty URL, indistinguishable from a
page script, so web.scripts used to list Playwright's own instrumentation as if
the page had authored it (one phantom entry per frame; script_source on it
returned Playwright's internal bundle). The backend now drops scripts whose
scriptParsed event marks a non-default (isolated) execution context.

These drive the real on_script closure wired by _wire_events through a fake CDP
session, so no browser is needed and the exact filter ships under test.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from headless_re_mcp.backends.web.client import WebBackend, _WebSession

JsonObject = dict[str, Any]


class _FakeCdp:
    """Records the handlers _wire_events registers; send() is a no-op."""

    def __init__(self) -> None:
        self.handlers: dict[str, Callable[[JsonObject], None]] = {}

    def send(self, method: str, params: JsonObject | None = None) -> JsonObject:
        return {}

    def on(self, event: str, handler: Callable[[JsonObject], None]) -> None:
        self.handlers[event] = handler


def _wire() -> tuple[_WebSession, Callable[[JsonObject], None]]:
    handle = _WebSession(None, None, None, None, _FakeCdp())
    WebBackend()._wire_events(handle)
    return handle, handle.cdp.handlers["Debugger.scriptParsed"]


def _default_world() -> JsonObject:
    return {"isDefault": True, "type": "default", "frameId": "F"}


def _isolated_world() -> JsonObject:
    return {"isDefault": False, "type": "isolated", "frameId": "F"}


def test_isolated_world_scripts_are_dropped() -> None:
    handle, on_script = _wire()

    on_script(
        {
            "scriptId": "page",
            "url": "http://site/app.js",
            "scriptLanguage": "JavaScript",
            "executionContextAuxData": _default_world(),
        }
    )
    on_script(
        {
            "scriptId": "playwright",
            "url": "",
            "scriptLanguage": "JavaScript",
            "executionContextAuxData": _isolated_world(),
        }
    )

    assert list(handle.scripts) == ["page"]
    assert handle.scripts["page"]["url"] == "http://site/app.js"


def test_default_world_wasm_is_kept() -> None:
    """A WASM module the page instantiates runs in the main world -- keep it."""
    handle, on_script = _wire()

    on_script(
        {
            "scriptId": "wasm",
            "url": "wasm://wasm/abcd",
            "scriptLanguage": "WebAssembly",
            "executionContextAuxData": _default_world(),
        }
    )

    assert list(handle.scripts) == ["wasm"]
    assert handle.scripts["wasm"]["language"] == "WebAssembly"


def test_missing_aux_data_fails_open() -> None:
    """Unknown context shape must never hide a real script."""
    handle, on_script = _wire()

    on_script({"scriptId": "no-aux", "url": "http://site/x.js"})
    on_script(
        {
            "scriptId": "empty-aux",
            "url": "http://site/y.js",
            "executionContextAuxData": {},
        }
    )

    assert list(handle.scripts) == ["no-aux", "empty-aux"]
