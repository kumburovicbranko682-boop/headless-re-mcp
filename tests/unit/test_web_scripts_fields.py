"""web.scripts description must name has_more when the capture dropped scripts."""

from __future__ import annotations

import ast
from pathlib import Path
from threading import Lock
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


def test_web_scripts_reads_dropped_under_the_snapshot_lock(monkeypatch: Any) -> None:
    """scripts() must read its dropped counter in the same lock hold as the rows.

    console() and network_list() capture the ring snapshot and its eviction
    counter under one lock so the "how many were dropped" figure matches the
    rows returned. scripts() used to snapshot the ring under the lock, release
    it, filter/page, and only then read scripts_dropped -- so a
    Debugger.scriptParsed eviction landing in that window (the CDP thread bumps
    scripts_dropped as it evicts) inflated dropped past the snapshot the rows
    came from. This drives the window deterministically: the wasm_only filter
    runs outside the lock, and a row whose language lookup bumps the counter
    stands in for that concurrent eviction. dropped must still be the
    snapshot-time value, not the post-filter one.
    """

    class _BumpingHandle:
        def __init__(self) -> None:
            self.lock = Lock()
            self.scripts_dropped = 0
            outer = self

            class _Row(dict):  # type: ignore[type-arg]
                def get(self, key: str, default: Any = None) -> Any:
                    if key == "language":
                        # An eviction lands after the snapshot lock is released,
                        # while the wasm_only filter reads languages outside it.
                        outer.scripts_dropped += 1
                        return "JavaScript"
                    return super().get(key, default)

            self.scripts = {"1": _Row(scriptId="1", url="https://example/a.js")}

    handle = _BumpingHandle()
    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: handle)

    payload = backend.scripts("s", wasm_only=True)
    # The filter bumped the counter to 1, but dropped was captured inside the
    # lock alongside the rows, so it reports the snapshot instant, not the later
    # one -- the same one-lock guarantee console()/network_list() already give.
    assert payload["dropped"] == 0
    assert handle.scripts_dropped == 1
