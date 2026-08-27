"""web.console must include uncaught exceptions, not just console.* calls.

An uncaught JavaScript exception arrives over Runtime.exceptionThrown, never
Runtime.consoleAPICalled, yet DevTools shows it in the console. Capturing only
console.* meant a page that threw -- a failed decrypt, a broken wasm
instantiate -- looked to an agent like it had logged nothing. These tests pin
that exceptions now land as error rows marked uncaught, bounded like any other
console line, and that ordinary console.log is untouched.
"""

from __future__ import annotations

import ast
from collections import deque
from pathlib import Path
from threading import Lock
from types import SimpleNamespace
from typing import Any

from headless_re_mcp.backends.web.client import (
    _MAX_CONSOLE,
    _MAX_CONSOLE_TEXT,
    WebBackend,
    _exception_text,
)
from headless_re_mcp.tools.web import build_web_tools


def test_exception_text_prefers_the_full_description() -> None:
    """A real Error carries a stack in exception.description; use it."""
    text, truncated = _exception_text(
        {
            "exceptionDetails": {
                "text": "Uncaught",
                "exception": {"description": "TypeError: boom\n    at f (a.js:1:1)"},
            }
        }
    )
    assert text == "TypeError: boom\n    at f (a.js:1:1)"
    assert truncated is False


def test_exception_text_falls_back_to_the_summary_line() -> None:
    """No description (a thrown non-Error): use exceptionDetails.text."""
    text, _ = _exception_text({"exceptionDetails": {"text": "Uncaught 42"}})
    assert text == "Uncaught 42"


def test_exception_text_has_a_last_resort_when_everything_is_missing() -> None:
    text, _ = _exception_text({})
    assert text == "uncaught exception"


def test_exception_text_is_clipped_to_the_console_cap() -> None:
    """A megabyte-long stack must not pin itself in the ring for the session."""
    huge = "E" * (_MAX_CONSOLE_TEXT + 500)
    text, truncated = _exception_text(
        {"exceptionDetails": {"exception": {"description": huge}}}
    )
    assert len(text) == _MAX_CONSOLE_TEXT
    assert truncated is True


def test_exception_text_tolerates_malformed_shapes() -> None:
    """A non-dict exceptionDetails must not crash the event thread."""
    text, _ = _exception_text({"exceptionDetails": "not a dict"})
    assert text == "uncaught exception"


class _FakeCdp:
    def __init__(self) -> None:
        self.handlers: dict[str, Any] = {}

    def send(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        return {}

    def on(self, event: str, handler: Any) -> None:
        self.handlers[event] = handler


def _wire(backend: WebBackend, maxlen: int = _MAX_CONSOLE) -> tuple[_FakeCdp, Any]:
    cdp = _FakeCdp()
    handle = SimpleNamespace(
        cdp=cdp,
        lock=Lock(),
        console=deque(maxlen=maxlen),
        console_dropped=0,
        requests={},
        scripts={},
        requests_dropped=0,
        scripts_dropped=0,
    )
    backend._wire_events(handle)
    return cdp, handle


def test_an_uncaught_exception_lands_in_the_console_as_an_error_row() -> None:
    backend = WebBackend()
    cdp, handle = _wire(backend)
    assert "Runtime.exceptionThrown" in cdp.handlers
    cdp.handlers["Runtime.exceptionThrown"](
        {
            "exceptionDetails": {
                "text": "Uncaught",
                "exception": {"description": "TypeError: x is not a function"},
            }
        }
    )
    assert len(handle.console) == 1
    row = handle.console[0]
    assert row["type"] == "error"
    assert row["uncaught"] is True
    assert "TypeError" in row["text"]


def test_a_console_log_is_recorded_without_the_uncaught_marker() -> None:
    backend = WebBackend()
    cdp, handle = _wire(backend)
    cdp.handlers["Runtime.consoleAPICalled"]({"type": "log", "args": [{"value": "hi"}]})
    row = handle.console[0]
    assert row["type"] == "log"
    assert row["text"] == "hi"
    assert "uncaught" not in row


def test_exceptions_share_the_ring_and_count_evictions() -> None:
    """Both channels feed one bounded ring; overflow bumps console_dropped."""
    backend = WebBackend()
    cdp, handle = _wire(backend, maxlen=1)
    cdp.handlers["Runtime.consoleAPICalled"]({"type": "log", "args": [{"value": "a"}]})
    cdp.handlers["Runtime.exceptionThrown"](
        {"exceptionDetails": {"text": "Uncaught boom"}}
    )
    assert len(handle.console) == 1
    assert handle.console[0]["uncaught"] is True
    assert handle.console_dropped == 1


def _tool_docstring(name: str) -> str:
    source = Path(build_web_tools.__code__.co_filename).read_text(encoding="utf-8")
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        for decorator in node.decorator_list:
            if not isinstance(decorator, ast.Call):
                continue
            for keyword in decorator.keywords:
                if (
                    keyword.arg == "name"
                    and isinstance(keyword.value, ast.Constant)
                    and keyword.value.value == name
                ):
                    return ast.get_docstring(node) or ""
    return ""


def test_docstring_names_uncaught_exceptions() -> None:
    doc = _tool_docstring("web.console")
    assert "uncaught" in doc.lower()
