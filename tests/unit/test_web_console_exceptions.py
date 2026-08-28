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
    _MAX_STACK_FRAMES,
    WebBackend,
    _clip_console_text,
    _clip_exception_text,
    _console_call_site,
    _stack_frames,
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


def test_an_uncaught_error_carries_its_call_stack() -> None:
    """The chain of functions that led to the throw is the first triage read."""
    handle = _wire()
    handle.cdp.handlers["Runtime.exceptionThrown"](
        {
            "exceptionDetails": {
                "text": "Uncaught",
                "url": "https://x/app.js",
                "lineNumber": 3,
                "exception": {"className": "Error", "description": "Error: boom"},
                "stackTrace": {
                    "callFrames": [
                        {"functionName": "decrypt", "url": "https://x/app.js", "lineNumber": 3},
                        {"functionName": "", "url": "https://x/vendor.js", "lineNumber": 42},
                    ]
                },
            }
        }
    )
    entry = handle.console[-1]
    assert entry["stack"] == [
        {"function": "decrypt", "url": "https://x/app.js", "line": 3},
        {"function": "", "url": "https://x/vendor.js", "line": 42},
    ]


def test_an_uncaught_error_without_a_stack_omits_it() -> None:
    handle = _wire()
    handle.cdp.handlers["Runtime.exceptionThrown"](
        {"exceptionDetails": {"text": "Uncaught", "exception": {"value": "nope"}}}
    )
    assert "stack" not in handle.console[-1]


def test_stack_frames_bounds_and_degrades() -> None:
    # A deep stack is cut to the frame cap.
    deep = {
        "callFrames": [
            {"functionName": f"f{i}", "url": "https://x/a.js", "lineNumber": i}
            for i in range(_MAX_STACK_FRAMES + 20)
        ]
    }
    frames = _stack_frames(deep)
    assert len(frames) == _MAX_STACK_FRAMES
    assert frames[0] == {"function": "f0", "url": "https://x/a.js", "line": 0}
    # A non-numeric line degrades to None but keeps the frame's url/function.
    odd = _stack_frames({"callFrames": [{"functionName": "g", "url": "https://x/b.js"}]})
    assert odd == [{"function": "g", "url": "https://x/b.js", "line": None}]
    # Missing or malformed stacks yield an empty list, never an exception.
    assert _stack_frames(None) == []
    assert _stack_frames({}) == []
    assert _stack_frames({"callFrames": None}) == []
    assert _stack_frames({"callFrames": [None, 7]}) == []


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


def test_console_entry_carries_the_call_site_from_the_stack() -> None:
    """A logged line should be traceable to the script that emitted it."""
    handle = _wire()
    handle.cdp.handlers["Runtime.consoleAPICalled"](
        {
            "type": "error",
            "args": [{"type": "string", "value": "bad state"}],
            "stackTrace": {
                "callFrames": [
                    {"functionName": "f", "url": "https://x/bundle.js", "lineNumber": 12},
                    {"functionName": "g", "url": "https://x/vendor.js", "lineNumber": 99},
                ]
            },
        }
    )
    entry = handle.console[-1]
    assert entry["text"] == "bad state"
    assert entry["url"] == "https://x/bundle.js"
    assert entry["line"] == 12


def test_console_entry_omits_the_call_site_when_no_stack_is_reported() -> None:
    handle = _wire()
    handle.cdp.handlers["Runtime.consoleAPICalled"](
        {"type": "log", "args": [{"type": "string", "value": "hi"}]}
    )
    entry = handle.console[-1]
    assert "url" not in entry
    assert "line" not in entry


def test_console_call_site_degrades_on_an_odd_stack() -> None:
    assert _console_call_site({}) == ("", None)
    assert _console_call_site({"stackTrace": None}) == ("", None)
    assert _console_call_site({"stackTrace": {"callFrames": []}}) == ("", None)
    assert _console_call_site({"stackTrace": {"callFrames": [None]}}) == ("", None)
    # A frame without a numeric line still yields its url.
    assert _console_call_site(
        {"stackTrace": {"callFrames": [{"url": "https://x/a.js"}]}}
    ) == ("https://x/a.js", None)


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
