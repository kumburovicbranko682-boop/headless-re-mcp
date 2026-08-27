"""Uncaught exceptions belong in the console buffer, like DevTools shows.

``Runtime.consoleAPICalled`` only carries ``console.*`` calls. A ``throw`` that
escapes or a promise that rejects unhandled arrives on ``Runtime.exceptionThrown``
instead, so a console reader that ignored that event missed exactly the failures
an analyst watches for (anti-tamper throws, where obfuscated code blows up). These
tests pin the wiring and the message rendering.
"""

from __future__ import annotations

from collections import OrderedDict, deque
from threading import RLock
from typing import Any

from headless_re_mcp.backends.web.client import (
    _MAX_CONSOLE,
    _MAX_CONSOLE_TEXT,
    WebBackend,
    _clip_console_text,
    _clip_exception_text,
)


class _FakeCdp:
    """Records handler registrations; ``send`` is a no-op enable/command."""

    def __init__(self) -> None:
        self.handlers: dict[str, Any] = {}

    def send(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        return {}

    def on(self, event: str, fn: Any) -> None:
        self.handlers[event] = fn


class _FakeSession:
    def __init__(self) -> None:
        self.cdp = _FakeCdp()
        self.lock = RLock()
        self.console: deque[dict[str, Any]] = deque(maxlen=_MAX_CONSOLE)
        self.console_dropped = 0
        self.requests: OrderedDict[str, dict[str, Any]] = OrderedDict()
        self.requests_dropped = 0
        self.scripts: OrderedDict[str, dict[str, Any]] = OrderedDict()
        self.scripts_dropped = 0


def _wire() -> _FakeSession:
    backend = WebBackend()
    handle = _FakeSession()
    backend._wire_events(handle)
    return handle


def test_exception_handler_is_registered() -> None:
    """The regression that motivated this: only consoleAPICalled was wired."""
    handle = _wire()
    assert "Runtime.exceptionThrown" in handle.cdp.handlers
    assert "Runtime.consoleAPICalled" in handle.cdp.handlers


def test_an_uncaught_error_lands_in_the_console_ring() -> None:
    handle = _wire()
    handle.cdp.handlers["Runtime.exceptionThrown"](
        {
            "exceptionDetails": {
                "text": "Uncaught",
                "url": "https://x/app.js",
                "lineNumber": 0,
                "exception": {
                    "className": "Error",
                    "description": "Error: boom\n    at f (https://x/app.js:1:1)",
                },
            }
        }
    )
    entry = handle.console[-1]
    assert entry["type"] == "error"
    assert entry["uncaught"] is True
    assert entry["text"].startswith("Uncaught Error: boom")
    assert entry["url"] == "https://x/app.js"
    assert entry["line"] == 0


def test_a_thrown_primitive_uses_its_value() -> None:
    handle = _wire()
    handle.cdp.handlers["Runtime.exceptionThrown"](
        {"exceptionDetails": {"text": "Uncaught", "exception": {"type": "string", "value": "nope"}}}
    )
    assert handle.console[-1]["text"] == "Uncaught nope"


def test_an_empty_payload_degrades_to_a_placeholder_not_a_blank_line() -> None:
    handle = _wire()
    handle.cdp.handlers["Runtime.exceptionThrown"]({})
    entry = handle.console[-1]
    assert entry["text"] == "Uncaught (exception)"
    assert entry["uncaught"] is True
    assert "url" not in entry


def test_console_api_calls_still_record_after_the_refactor() -> None:
    """on_console shares the ring writer now; prove it still appends."""
    handle = _wire()
    handle.cdp.handlers["Runtime.consoleAPICalled"](
        {"type": "warning", "args": [{"type": "string", "value": "hi"}]}
    )
    entry = handle.console[-1]
    assert entry["type"] == "warning"
    assert entry["text"] == "hi"
    assert "uncaught" not in entry


def test_console_object_argument_renders_its_members() -> None:
    """A logged object used to collapse to "Object", dropping its payload.

    CDP hands the members over in preview.properties; render them {k: v} so a
    logged config or token survives instead of a bare type name. A leading
    string arg is joined ahead of it the way DevTools shows the line.
    """
    text, truncated = _clip_console_text(
        {
            "type": "log",
            "args": [
                {"type": "string", "value": "user"},
                {
                    "type": "object",
                    "description": "Object",
                    "preview": {
                        "type": "object",
                        "properties": [
                            {"name": "id", "type": "number", "value": "42"},
                            {"name": "token", "type": "string", "value": "abc"},
                        ],
                    },
                },
            ],
        }
    )
    assert truncated is False
    assert text == 'user {id: 42, token: "abc"}'


def test_console_array_argument_renders_bracketed_with_overflow() -> None:
    text, _ = _clip_console_text(
        {
            "type": "log",
            "args": [
                {
                    "type": "object",
                    "subtype": "array",
                    "description": "Array(3)",
                    "preview": {
                        "type": "object",
                        "subtype": "array",
                        "overflow": True,
                        "properties": [
                            {"name": "0", "type": "number", "value": "1"},
                            {"name": "1", "type": "number", "value": "2"},
                        ],
                    },
                }
            ],
        }
    )
    assert text == "[1, 2, …]"


def test_console_object_without_a_preview_falls_back_to_description() -> None:
    text, _ = _clip_console_text(
        {"type": "log", "args": [{"type": "object", "description": "Promise"}]}
    )
    assert text == "Promise"


def test_unhandled_rejection_header_is_preserved() -> None:
    text, truncated = _clip_exception_text(
        {
            "exceptionDetails": {
                "text": "Uncaught (in promise)",
                "exception": {"description": "Error: async\n    at g"},
            }
        }
    )
    assert text.startswith("Uncaught (in promise) Error: async")
    assert truncated is False


def test_a_megabyte_throw_is_clipped_to_the_per_message_cap() -> None:
    big = "x" * (_MAX_CONSOLE_TEXT + 500)
    text, truncated = _clip_exception_text(
        {"exceptionDetails": {"text": "Uncaught", "exception": {"description": big}}}
    )
    assert truncated is True
    assert len(text) == _MAX_CONSOLE_TEXT


def test_non_dict_details_never_raises() -> None:
    assert _clip_exception_text({}) == ("", False)
    assert _clip_exception_text({"exceptionDetails": None}) == ("", False)
