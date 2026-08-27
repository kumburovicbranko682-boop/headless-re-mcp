"""web.console must capture uncaught page exceptions, not only console.* calls.

The capture subscribed to Runtime.consoleAPICalled alone, so a page could crash
with an uncaught TypeError on every load and web.console still read as "the
page logged nothing wrong" -- the chatter was kept while the red error lines a
real browser console shows first were silently dropped. Exceptions arrive on
the already-enabled Runtime domain as Runtime.exceptionThrown; these pin the
entry formatting, the ring bookkeeping, and the actual CDP wiring.
"""

from __future__ import annotations

from typing import Any

import pytest

from headless_re_mcp.backends.web import client as webclient
from headless_re_mcp.backends.web.client import (
    WebBackend,
    _append_console,
    _exception_console_entry,
    _WebSession,
)


def test_an_uncaught_error_becomes_an_exception_entry_with_its_location() -> None:
    entry = _exception_console_entry(
        {
            "exceptionDetails": {
                "text": "Uncaught",
                "url": "https://app.example/main.js",
                "lineNumber": 41,
                "exception": {
                    "type": "object",
                    "subtype": "error",
                    "className": "TypeError",
                    "description": "TypeError: x is not a function\n    at boot",
                },
            }
        }
    )
    assert entry["type"] == "exception"
    assert entry["text"].startswith("Uncaught TypeError: x is not a function")
    # CDP line numbers are zero-based; the entry shows the human line.
    assert entry["text"].endswith("(https://app.example/main.js:42)")
    assert "text_truncated" not in entry


def test_a_thrown_primitive_uses_its_value_when_there_is_no_description() -> None:
    entry = _exception_console_entry(
        {
            "exceptionDetails": {
                "text": "Uncaught",
                "exception": {"type": "string", "value": "boom"},
            }
        }
    )
    assert entry["text"] == "Uncaught boom"


def test_a_malformed_event_still_yields_a_readable_entry() -> None:
    for params in ({}, {"exceptionDetails": "nope"}, {"exceptionDetails": {"exception": 7}}):
        entry = _exception_console_entry(params)
        assert entry["type"] == "exception"
        assert entry["text"] == "uncaught exception"


def test_a_huge_description_is_cut_at_the_console_text_cap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(webclient, "_MAX_CONSOLE_TEXT", 32)
    entry = _exception_console_entry(
        {
            "exceptionDetails": {
                "text": "Uncaught",
                "exception": {"description": "Error: " + "x" * 500},
            }
        }
    )
    assert len(entry["text"]) == 32
    assert entry["text_truncated"] is True


class _FakeCdp:
    def __init__(self) -> None:
        self.handlers: dict[str, Any] = {}
        self.enabled: list[str] = []

    def send(self, method: str, params: Any | None = None) -> Any:
        self.enabled.append(method)
        return {}

    def on(self, event: str, handler: Any) -> None:
        self.handlers[event] = handler


def _wired_session() -> tuple[_WebSession, _FakeCdp]:
    cdp = _FakeCdp()
    handle = _WebSession(None, None, None, None, cdp)
    WebBackend()._wire_events(handle)
    return handle, cdp


def test_the_capture_subscribes_to_exceptions_and_records_them() -> None:
    handle, cdp = _wired_session()
    assert "Runtime.exceptionThrown" in cdp.handlers
    cdp.handlers["Runtime.exceptionThrown"](
        {
            "exceptionDetails": {
                "text": "Uncaught",
                "exception": {"description": "ReferenceError: nope is not defined"},
            }
        }
    )
    assert [e["type"] for e in handle.console] == ["exception"]
    assert "ReferenceError" in handle.console[-1]["text"]


def test_console_calls_and_exceptions_share_one_ring_and_its_eviction_count() -> None:
    handle, cdp = _wired_session()
    cdp.handlers["Runtime.consoleAPICalled"](
        {"type": "log", "args": [{"type": "string", "value": "hello"}]}
    )
    cdp.handlers["Runtime.exceptionThrown"](
        {"exceptionDetails": {"text": "Uncaught", "exception": {"value": "boom"}}}
    )
    assert [e["type"] for e in handle.console] == ["log", "exception"]
    assert handle.console_dropped == 0


def test_append_console_counts_what_the_ring_evicts() -> None:
    handle = _WebSession(None, None, None, None, _FakeCdp())
    handle.console = type(handle.console)(maxlen=2)
    for step in range(3):
        _append_console(handle, {"type": "log", "text": f"line {step}"})
    assert [e["text"] for e in handle.console] == ["line 1", "line 2"]
    assert handle.console_dropped == 1
