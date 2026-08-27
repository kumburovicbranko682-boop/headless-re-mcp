"""web.scripts description must name has_more when the capture dropped scripts."""

from __future__ import annotations

import ast
from collections import OrderedDict, deque
from pathlib import Path
from threading import Lock, RLock
from typing import Any

from headless_re_mcp.backends.web.client import WebBackend
from headless_re_mcp.tools.web import build_web_tools


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


class _FakeHandle:
    def __init__(self, count: int, *, dropped: int) -> None:
        self.lock = Lock()
        self.scripts = {
            str(index): {
                "scriptId": str(index),
                "url": f"https://example/{index}.js",
                "language": "JavaScript",
            }
            for index in range(count)
        }
        self.scripts_dropped = dropped


def test_web_scripts_says_when_older_scripts_were_dropped(monkeypatch: Any) -> None:
    """The catalog listed scripts and never said when the buffer dropped some.

    Measured: 5 held, scripts_dropped 3 -> count 5, has_more True. An
    overnight pass that treated scripts as every script the page loaded had
    no field to notice the ones that were evicted.
    """
    backend = WebBackend()
    monkeypatch.setattr(
        backend, "_get", lambda session_id: _FakeHandle(5, dropped=3)
    )
    payload = backend.scripts("s")
    assert payload["count"] == 5
    assert len(payload["scripts"]) == 5
    assert payload["total"] == 5
    assert payload["has_more"] is False
    assert payload["dropped"] == 3
    doc = _tool_docstring("web.scripts")
    assert "Answers with scripts" in doc
    assert "has_more" in doc
    assert "dropped" in doc
    assert "metadata_truncated" in doc


class _Cdp:
    def __init__(self) -> None:
        self.handlers: dict[str, Any] = {}

    def send(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        return {}

    def on(self, event: str, handler: Any) -> None:
        self.handlers[event] = handler


class _WireHandle:
    def __init__(self) -> None:
        self.lock = RLock()
        self.scripts: OrderedDict[str, dict[str, Any]] = OrderedDict()
        self.scripts_dropped = 0
        self.requests: OrderedDict[str, dict[str, Any]] = OrderedDict()
        self.requests_dropped = 0
        self.console: deque[dict[str, Any]] = deque()
        self.console_dropped = 0
        self.cdp = _Cdp()


def test_web_flags_a_runtime_generated_script_and_keeps_its_length() -> None:
    """An eval/new Function script has a blank url; CDP marks it with a
    stackTrace, so flag it dynamic -- that is where a packer's real payload
    lands -- and keep the reported length so a caller can size the blob.
    """
    handle = _WireHandle()
    WebBackend()._wire_events(handle)  # type: ignore[arg-type]

    handle.cdp.handlers["Debugger.scriptParsed"](
        {
            "scriptId": "1",
            "url": "https://x/app.js",
            "scriptLanguage": "JavaScript",
            "length": 1234,
        }
    )
    handle.cdp.handlers["Debugger.scriptParsed"](
        {
            "scriptId": "2",
            "url": "",
            "scriptLanguage": "JavaScript",
            "length": 5678,
            "stackTrace": {"callFrames": [{"url": "https://x/app.js"}]},
        }
    )

    loaded = handle.scripts["1"]
    generated = handle.scripts["2"]
    assert "dynamic" not in loaded
    assert loaded["length"] == 1234
    assert generated["dynamic"] is True
    assert generated["length"] == 5678
    assert generated["url"] == ""
    doc = _tool_docstring("web.scripts")
    assert "dynamic" in doc
    assert "length" in doc


def test_web_wasm_list_says_when_older_scripts_were_dropped(monkeypatch: Any) -> None:
    """wasm.list filters the same ring; eviction is not a JS-only event.

    Measured: 4 held WASM modules, scripts_dropped 3 -> count 4, has_more
    True. Treating wasm_only as a complete list hid the same eviction
    web.scripts already discloses.
    """
    backend = WebBackend()
    handle = _FakeHandle(4, dropped=3)
    for row in handle.scripts.values():
        row["language"] = "WebAssembly"
    monkeypatch.setattr(backend, "_get", lambda session_id: handle)
    payload = backend.scripts("s", wasm_only=True)
    assert payload["count"] == 4
    assert payload["has_more"] is False
    assert payload["dropped"] == 3
    doc = _tool_docstring("web.wasm.list")
    assert "has_more" in doc
    assert "dropped" in doc
    assert "metadata_truncated" in doc
