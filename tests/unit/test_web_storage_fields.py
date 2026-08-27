"""web.storage normalizes both stores, bounds values, and stays honest.

The fake page.evaluate mirrors what the in-page script does (cap entries by
maxEntries, slice values by maxValueChars) so the Python normalization,
byte-bounding and per-store honesty are what actually get exercised.
"""

from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from headless_re_mcp.backends.web.client import (
    _MAX_STORAGE_ENTRIES,
    _MAX_STORAGE_VALUE,
    WebBackend,
)
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


class _Immediate:
    def call(self, work: Any, timeout: float | None = None) -> Any:
        return work()


class _StoragePage:
    """A page whose evaluate reproduces the in-page storage dump script."""

    def __init__(
        self,
        *,
        local: list[tuple[str, Any]] | None = None,
        session: list[tuple[str, Any]] | None = None,
        origin: str = "https://example.test",
        local_ok: bool = True,
        session_ok: bool = True,
        session_error: str = "SecurityError: storage disabled",
    ) -> None:
        self.local = local or []
        self.session = session or []
        self.origin = origin
        self.local_ok = local_ok
        self.session_ok = session_ok
        self.session_error = session_error

    def evaluate(self, script: str, caps: dict[str, int]) -> dict[str, Any]:
        del script
        max_entries = caps["maxEntries"]
        max_value = caps["maxValueChars"]

        def dump(items: list[tuple[str, Any]], ok: bool, error: str) -> dict[str, Any]:
            if not ok:
                return {"ok": False, "error": error}
            total = len(items)
            take = min(total, max_entries)
            entries: list[list[Any]] = []
            for key, value in items[:take]:
                text = "" if value is None else str(value)
                cut = False
                if len(text) > max_value:
                    text = text[:max_value]
                    cut = True
                entries.append([key, text, cut])
            return {"ok": True, "total": total, "entries": entries}

        return {
            "origin": self.origin,
            "local": dump(self.local, self.local_ok, ""),
            "session": dump(self.session, self.session_ok, self.session_error),
        }


def _backend(monkeypatch: Any, page: _StoragePage) -> WebBackend:
    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: SimpleNamespace(page=page))
    monkeypatch.setattr(backend, "_runner", lambda handle: _Immediate())
    return backend


def test_web_storage_normalizes_sorts_and_reports_origin(monkeypatch: Any) -> None:
    """Both stores come back sorted by key with the page origin.

    Measured: origin echoed, local sorted (auth before token), each entry a
    {key, value}, and no items or entries field at the top level.
    """
    page = _StoragePage(
        local=[("token", "abc"), ("auth", "xyz")],
        session=[("csrf", "t0k")],
    )
    payload = _backend(monkeypatch, page).storage("s")
    assert payload["origin"] == "https://example.test"
    assert [e["key"] for e in payload["local"]] == ["auth", "token"]
    assert payload["local"][0] == {"key": "auth", "value": "xyz"}
    assert payload["local_count"] == 2
    assert payload["local_total"] == 2
    assert payload["local_has_more"] is False
    assert payload["local_available"] is True
    assert payload["session"] == [{"key": "csrf", "value": "t0k"}]
    assert payload["session_available"] is True
    assert "items" not in payload
    assert "entries" not in payload


def test_web_storage_marks_unavailable_store_distinct_from_empty(monkeypatch: Any) -> None:
    """An origin that forbids a store reports available false + reason.

    Measured: session_available False with session_error carrying the page's
    message, an empty session list, while local stays a normal empty-but-
    available store -- the two cases must not look identical.
    """
    page = _StoragePage(local=[], session=[], session_ok=False)
    payload = _backend(monkeypatch, page).storage("s")
    assert payload["local_available"] is True
    assert payload["local"] == []
    assert payload["local_total"] == 0
    assert "local_error" not in payload
    assert payload["session_available"] is False
    assert payload["session"] == []
    assert payload["session_total"] == 0
    assert payload["session_has_more"] is False
    assert "SecurityError" in payload["session_error"]


def test_web_storage_truncates_long_values_both_paths(monkeypatch: Any) -> None:
    """A value cut in-page (chars) or in Python (bytes) is flagged.

    Measured: a 9000-char ASCII value is sliced in-page and flagged
    value_truncated; a multibyte value under the char cap but over the byte
    cap is cut in Python to 8192 bytes and flagged too.
    """
    ascii_big = "A" * (_MAX_STORAGE_VALUE + 808)
    multibyte = "\u20ac" * 3000  # 3000 chars, 9000 bytes: under char cap, over byte cap
    page = _StoragePage(local=[("ascii", ascii_big), ("euro", multibyte)])
    payload = _backend(monkeypatch, page).storage("s")
    by_key = {e["key"]: e for e in payload["local"]}
    assert by_key["ascii"]["value_truncated"] is True
    assert len(by_key["ascii"]["value"]) == _MAX_STORAGE_VALUE
    assert by_key["euro"]["value_truncated"] is True
    assert len(by_key["euro"]["value"].encode("utf-8")) <= _MAX_STORAGE_VALUE


def test_web_storage_caps_entries_and_flags_has_more(monkeypatch: Any) -> None:
    """A store past the entry cap returns the cap and has_more true.

    Measured: with one more key than the cap, local_count equals the cap,
    local_total is the real length, and local_has_more is true so the page is
    not read as the whole store.
    """
    big = [(f"k{i:05d}", f"v{i}") for i in range(_MAX_STORAGE_ENTRIES + 1)]
    page = _StoragePage(local=big)
    payload = _backend(monkeypatch, page).storage("s")
    assert payload["local_count"] == _MAX_STORAGE_ENTRIES
    assert payload["local_total"] == _MAX_STORAGE_ENTRIES + 1
    assert payload["local_has_more"] is True


def test_web_storage_docstring_names_shape(monkeypatch: Any) -> None:
    doc = _tool_docstring("web.storage")
    assert "origin" in doc
    assert "local" in doc
    assert "session" in doc
    assert "value_truncated" in doc
    assert "available" in doc
