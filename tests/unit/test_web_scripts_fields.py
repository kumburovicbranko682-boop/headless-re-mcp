"""web.scripts description must name has_more when the capture dropped scripts."""

from __future__ import annotations

import ast
from pathlib import Path
from threading import Lock
from typing import Any

from headless_re_mcp.backends.web.client import WebBackend, _script_in_injected_world
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


def test_injected_world_filter_keeps_page_scripts_and_drops_playwright_ones() -> None:
    """web.scripts must list the target's code, not the driver's instrumentation.

    Debugger.scriptParsed fires for every execution context, and Playwright
    parses its bindings / utilityScript / page.title() probes in an injected
    isolated world. CDP marks the page's own scripts with isDefault True and the
    injected ones with isDefault False, so only the non-default worlds are
    dropped. When auxData is missing or malformed the world is unknown and the
    script is kept, so a real page script is never hidden by a stricter guess.
    """
    # The page's own main-world scripts are kept.
    assert _script_in_injected_world({"isDefault": True, "type": "default"}) is False
    # Playwright's injected isolated-world scripts are dropped.
    assert _script_in_injected_world({"isDefault": False, "type": "isolated"}) is True
    # World unknown -> keep (never hide a real script on a guess).
    assert _script_in_injected_world(None) is False
    assert _script_in_injected_world({}) is False
    assert _script_in_injected_world({"type": "isolated"}) is False
    assert _script_in_injected_world("not-a-dict") is False
