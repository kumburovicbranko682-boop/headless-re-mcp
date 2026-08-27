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


class _FakeUrlHandle:
    """A ring of scripts with distinct urls/languages for the url filter tests."""

    def __init__(self, rows: list[tuple[str, str]], *, dropped: int = 0) -> None:
        self.lock = Lock()
        self.scripts = {
            str(index): {"scriptId": str(index), "url": url, "language": language}
            for index, (url, language) in enumerate(rows)
        }
        self.scripts_dropped = dropped


_URL_ROWS = [
    ("https://cdn.example.com/app.js", "JavaScript"),
    ("https://cdn.example.com/vendor.js", "JavaScript"),
    ("https://other.example.com/APP.min.js", "JavaScript"),
    ("https://cdn.example.com/pkg.wasm", "WebAssembly"),
]


def _urls(payload: dict[str, Any]) -> list[str]:
    return [row["url"] for row in payload["scripts"]]


def test_web_scripts_url_contains_is_case_insensitive_and_flags_filtered(
    monkeypatch: Any,
) -> None:
    """url_contains keeps scripts whose url holds the needle, any case.

    Measured: four scripts -> url_contains 'app' keeps the two app urls
    (app.js and APP.min.js), total 2, filtered True, captured 4; an unmatched
    needle yields an empty, honest list (filtered, not the whole ring).
    """
    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: _FakeUrlHandle(_URL_ROWS))
    payload = backend.scripts("s", url_contains="app")
    assert sorted(_urls(payload)) == [
        "https://cdn.example.com/app.js",
        "https://other.example.com/APP.min.js",
    ]
    assert payload["total"] == 2
    assert payload["filtered"] is True
    assert payload["captured"] == 4
    miss = backend.scripts("s", url_contains="no-such-script")
    assert miss["scripts"] == []
    assert miss["total"] == 0
    assert miss["filtered"] is True
    doc = _tool_docstring("web.scripts")
    for token in ("url_contains", "filtered", "captured"):
        assert token in doc


def test_web_scripts_url_contains_ands_with_wasm_only(monkeypatch: Any) -> None:
    """url_contains and wasm_only both must hold, and captured is the whole ring.

    Measured: wasm_only + url_contains 'pkg' -> only the .wasm module, total 1,
    captured 4 (the pre-filter ring, JS scripts included).
    """
    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: _FakeUrlHandle(_URL_ROWS))
    payload = backend.scripts("s", wasm_only=True, url_contains="pkg")
    assert _urls(payload) == ["https://cdn.example.com/pkg.wasm"]
    assert payload["total"] == 1
    assert payload["captured"] == 4


def test_web_scripts_blank_url_contains_is_ignored_not_matched(monkeypatch: Any) -> None:
    """A whitespace-only url_contains behaves as no filter, not match-all/none."""
    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: _FakeUrlHandle(_URL_ROWS))
    payload = backend.scripts("s", url_contains="   ")
    assert payload["total"] == 4
    assert "filtered" not in payload
    assert "captured" not in payload


def test_web_wasm_list_shape_is_unchanged_by_the_new_filter(monkeypatch: Any) -> None:
    """wasm_only alone keeps its flag-free contract (web.wasm.list depends on it).

    Measured: wasm_only True with no url_contains -> no filtered/captured, so the
    web.wasm.list reply that reuses this path stays byte-for-byte as before.
    """
    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: _FakeUrlHandle(_URL_ROWS))
    payload = backend.scripts("s", wasm_only=True)
    assert _urls(payload) == ["https://cdn.example.com/pkg.wasm"]
    assert "filtered" not in payload
    assert "captured" not in payload


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
