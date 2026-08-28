"""The CDP capture handlers evict oldest-first and account every drop.

``web.network_list``, ``web.scripts`` and ``web.console`` each disclose a
``dropped`` count so an unattended caller knows the ring forgot something
before it got around to reading. But the counters those readers surface are
maintained by the event handlers ``_wire_events`` registers -- ``on_request``
and ``on_script`` run the eviction loop themselves (``popitem(last=False)``
plus ``*_dropped += 1``), and ``on_console`` counts the line its bounded
deque is about to silently discard.

Existing suites pin only the readers: they write ``requests_dropped = 7``
into the fixture, or replicate the eviction loop inline next to the dict
insert. That leaves the real handlers free to stop evicting (unbounded
growth -- the exact leak the rings exist to prevent), stop counting (silent
forgetting: ``dropped`` reads 0 while the ring discards), or evict the
*newest* entry (inverting the "keep the scripts worth fetching" window)
without any test noticing. These tests drive the handlers past their caps
and read the damage off the same session object production uses.

The caps are monkeypatched down so the fixtures stay cheap; the handlers
read the module globals at call time (and ``_WebSession`` reads
``_MAX_CONSOLE`` at construction), so a small cap exercises the identical
code path.
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


def _overflow_requests(monkeypatch: Any) -> _WebSession:
    """Fire 8 distinct requests into a ring capped at 5."""
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
    return handle


def _overflow_console(monkeypatch: Any) -> _WebSession:
    """Fire 8 console lines into a deque bounded at 5.

    The deque's maxlen is fixed when _WebSession is constructed, so the cap
    must be patched before the session exists -- unlike the two OrderedDict
    rings, whose handlers consult the module global on every event.
    """
    monkeypatch.setattr(web_mod, "_MAX_CONSOLE", 5)
    handle, cdp = _wired_session()
    for index in range(8):
        cdp.handlers["Runtime.consoleAPICalled"](
            {"type": "log", "args": [{"value": f"line-{index}"}]}
        )
    return handle


def test_request_overflow_evicts_the_oldest_and_counts_every_drop(
    monkeypatch: Any,
) -> None:
    handle = _overflow_requests(monkeypatch)

    assert len(handle.requests) == 5
    assert handle.requests_dropped == 3
    # Oldest-first: the window keeps the newest requests, which are the ones
    # a caller paging network_list has not had a chance to see yet.
    assert list(handle.requests) == ["3", "4", "5", "6", "7"]


def test_the_network_reader_reports_the_handlers_drop_count(monkeypatch: Any) -> None:
    """dropped travels from the handler to network_list, not from a fixture."""
    handle = _overflow_requests(monkeypatch)
    backend = WebBackend()
    backend._sessions["s"] = handle

    result = backend.network_list("s", offset=0, limit=100)

    assert result["total"] == 5
    assert result["dropped"] == 3


def test_script_overflow_evicts_the_oldest_parse_and_counts_every_drop(
    monkeypatch: Any,
) -> None:
    monkeypatch.setattr(web_mod, "_MAX_SCRIPTS", 5)
    handle, cdp = _wired_session()
    for index in range(8):
        cdp.handlers["Debugger.scriptParsed"](
            {"scriptId": str(index), "url": f"https://cdn.example.test/{index}.js"}
        )

    assert len(handle.scripts) == 5
    assert handle.scripts_dropped == 3
    assert list(handle.scripts) == ["3", "4", "5", "6", "7"]


def test_a_reparsed_script_id_replaces_its_row_without_a_phantom_drop(
    monkeypatch: Any,
) -> None:
    """A page re-parsing a script updates the row; nothing was forgotten.

    scriptParsed fires again for the same scriptId when a page re-evaluates a
    script. The dict insert replaces in place, so the ring must neither evict
    a held entry to make room nor count a drop that never happened -- a
    caller who sees dropped > 0 is being told data it can no longer fetch
    existed, and a re-parse is not that.
    """
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


def test_console_overflow_counts_each_line_the_ring_silently_evicts(
    monkeypatch: Any,
) -> None:
    handle = _overflow_console(monkeypatch)

    assert len(handle.console) == 5
    assert handle.console_dropped == 3
    assert [row["text"] for row in handle.console] == [
        "line-3",
        "line-4",
        "line-5",
        "line-6",
        "line-7",
    ]


def test_the_console_reader_reports_the_handlers_drop_count(monkeypatch: Any) -> None:
    handle = _overflow_console(monkeypatch)
    backend = WebBackend()
    backend._sessions["s"] = handle

    result = backend.console("s", limit=100)

    assert result["count"] == 5
    assert result["dropped"] == 3
