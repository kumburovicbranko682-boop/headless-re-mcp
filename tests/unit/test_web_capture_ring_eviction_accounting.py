"""The dropped counts the web readers surface come from the capture handlers.

``test_web_client_guard_paths.py`` pins the handler-side core: each ring
evicts oldest-first at its cap and counts the drop. What it does not pin is
the two contracts layered on top of that accounting, and both matter to an
unattended caller:

* **Reader parity.** ``web.network_list`` and ``web.console`` disclose
  ``dropped`` so a caller knows the ring forgot data before it got around to
  reading. Every pre-existing reader test wrote ``requests_dropped = 7`` into
  the fixture, so nothing proved the number a reader hands out is the one the
  real handlers maintain -- the counter could be renamed, reset on read, or
  never wired through, and both suites would stay green. These tests drive
  the real handlers past a shrunken cap and read ``dropped`` off the public
  readers.

* **A re-parse is not a loss.** ``Debugger.scriptParsed`` fires again for the
  same ``scriptId`` when a page re-evaluates a script. The dict insert
  replaces in place, so the ring must neither evict a held entry to make room
  nor count a drop that never happened: ``dropped > 0`` tells the caller data
  it can no longer fetch existed, and a re-parse is not that.

The caps are monkeypatched down so the fixtures stay cheap; the handlers read
the module globals at call time (and ``_WebSession`` reads ``_MAX_CONSOLE``
at construction), so a small cap exercises the identical code path.
"""

from __future__ import annotations

from typing import Any

from headless_re_mcp.backends.web import client as web_mod
from headless_re_mcp.backends.web.client import WebBackend, _WebSession


class _Cdp:
    """Records the callbacks _wire_events registers so tests can fire them."""

    def __init__(self) -> None:
        self.handlers: dict[str, Any] = {}

    def send(self, method: str, params: Any = None) -> None:
        del method, params

    def on(self, event: str, callback: Any) -> None:
        self.handlers[event] = callback


def _wired_session() -> tuple[_WebSession, _Cdp]:
    cdp = _Cdp()
    handle = _WebSession(object(), object(), object(), object(), cdp)
    WebBackend()._wire_events(handle)
    return handle, cdp


def test_the_network_reader_reports_the_handlers_drop_count(monkeypatch: Any) -> None:
    """dropped travels from the handler to network_list, not from a fixture."""
    monkeypatch.setattr(web_mod, "_MAX_REQUESTS", 5)
    handle, cdp = _wired_session()
    for index in range(8):
        cdp.handlers["Network.requestWillBeSent"](
            {
                "requestId": str(index),
                "request": {"url": f"https://example.test/{index}", "method": "GET"},
                "type": "Fetch",
            }
        )
    backend = WebBackend()
    backend._sessions["s"] = handle

    result = backend.network_list("s", offset=0, limit=100)

    assert result["total"] == 5
    assert result["dropped"] == 3


def test_the_console_reader_reports_the_handlers_drop_count(monkeypatch: Any) -> None:
    # The deque's maxlen is fixed when _WebSession is constructed, so the cap
    # must be patched before the session exists -- unlike the OrderedDict
    # rings, whose handlers consult the module global on every event.
    monkeypatch.setattr(web_mod, "_MAX_CONSOLE", 5)
    handle, cdp = _wired_session()
    for index in range(8):
        cdp.handlers["Runtime.consoleAPICalled"](
            {"type": "log", "args": [{"value": f"line-{index}"}]}
        )
    backend = WebBackend()
    backend._sessions["s"] = handle

    result = backend.console("s", limit=100)

    assert result["count"] == 5
    assert result["dropped"] == 3
    assert result["console"][-1]["text"] == "line-7"


def test_a_reparsed_script_id_replaces_its_row_without_a_phantom_drop(
    monkeypatch: Any,
) -> None:
    monkeypatch.setattr(web_mod, "_MAX_SCRIPTS", 5)
    handle, cdp = _wired_session()
    for index in range(5):
        cdp.handlers["Debugger.scriptParsed"](
            {"scriptId": str(index), "url": f"https://cdn.example.test/{index}.js"}
        )
    cdp.handlers["Debugger.scriptParsed"](
        {"scriptId": "2", "url": "https://cdn.example.test/2.v2.js"}
    )

    assert len(handle.scripts) == 5
    assert handle.scripts_dropped == 0
    assert handle.scripts["2"]["url"] == "https://cdn.example.test/2.v2.js"
