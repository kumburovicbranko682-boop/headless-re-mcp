"""web.storage contract: bounded, paginated localStorage/sessionStorage listing.

Storage is attacker-influenced -- a page writes however many keys of whatever
size it likes, and SPAs park whole state trees there -- so the listing stays
bounded like every other captured web field. The reader is a fixed in-page
script (the surface withholds web.evaluate), and ``which`` picks the store; a
bad ``which`` is rejected before the page is ever touched.
"""

from __future__ import annotations

import ast
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.web.client import (
    _MAX_STORAGE_ITEMS,
    _MAX_STORAGE_VALUE_BYTES,
    WebBackend,
    WebError,
    _WebSession,
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


class _DirectRunner:
    """Run work inline; these tests never start a browser thread."""

    def call(self, work: Callable[[], Any], *, timeout: float = 0.0) -> Any:
        return work()


class _FakePage:
    """Stands in for the Playwright page; records the args the reader passed."""

    def __init__(self, result: Any) -> None:
        self._result = result
        self.calls: list[Any] = []

    def evaluate(self, script: str, arg: Any = None) -> Any:
        self.calls.append(arg)
        if isinstance(self._result, Exception):
            raise self._result
        return self._result


def _backend(result: Any) -> tuple[WebBackend, _FakePage]:
    backend = WebBackend()
    page = _FakePage(result)
    handle = _WebSession(
        playwright=object(),
        browser=object(),
        context=object(),
        page=page,
        cdp=object(),
    )
    handle.runner = _DirectRunner()  # type: ignore[assignment]
    backend._sessions["web"] = handle
    return backend, page


def _items(count: int, *, total: int | None = None) -> dict[str, Any]:
    return {
        "items": [
            {"key": f"k{i}", "value": f"v{i}", "value_clipped": False}
            for i in range(count)
        ],
        "total": count if total is None else total,
    }


class TestStorageFieldContract:
    def test_entries_carry_key_and_value_under_the_documented_names(self) -> None:
        backend, _ = _backend(
            {"items": [{"key": "token", "value": "jwt", "value_clipped": False}], "total": 1}
        )
        result = backend.storage("web", which="local")

        assert result["which"] == "local"
        assert result["count"] == result["total"] == 1
        assert result["offset"] == 0
        assert result["has_more"] is False
        assert result["scan_capped"] is False
        assert result["storage"][0] == {"key": "token", "value": "jwt"}
        # The list field is storage; the sibling names the docstring rules out
        # must not appear instead.
        assert "items" not in result and "entries" not in result

    def test_non_dict_items_are_skipped_not_crashed_on(self) -> None:
        backend, _ = _backend(
            {"items": ["junk", None, {"key": "a", "value": "b"}], "total": 3}
        )
        result = backend.storage("web")

        assert result["count"] == 1
        assert result["storage"][0]["key"] == "a"

    def test_a_non_dict_answer_yields_an_empty_store(self) -> None:
        backend, _ = _backend(["unexpected"])
        result = backend.storage("web")

        assert result["storage"] == []
        assert result["count"] == 0
        assert result["total"] == 0
        assert result["has_more"] is False
        assert result["scan_capped"] is False


class TestStorageWhich:
    def test_the_default_reads_local_storage(self) -> None:
        backend, page = _backend(_items(0))
        result = backend.storage("web")

        assert result["which"] == "local"
        assert page.calls[0]["which"] == "local"

    def test_session_is_passed_through_to_the_reader(self) -> None:
        backend, page = _backend(_items(0))
        result = backend.storage("web", which="SESSION")

        assert result["which"] == "session"
        assert page.calls[0]["which"] == "session"

    def test_a_bad_which_is_rejected_before_the_page_is_touched(self) -> None:
        backend, page = _backend(_items(1))
        with pytest.raises(WebError) as info:
            backend.storage("web", which="cookies")

        assert info.value.code == "invalid_params"
        # The store is chosen from the request alone; the page reader never ran.
        assert page.calls == []


class TestStorageBounding:
    def test_an_oversized_value_is_cut_and_marked(self) -> None:
        huge = "v" * (_MAX_STORAGE_VALUE_BYTES + 1)
        backend, _ = _backend({"items": [{"key": "k", "value": huge}], "total": 1})

        entry = backend.storage("web")["storage"][0]

        assert len(entry["value"].encode("utf-8")) == _MAX_STORAGE_VALUE_BYTES
        assert entry["value_truncated"] is True

    def test_an_in_page_clip_is_surfaced_even_under_the_byte_cap(self) -> None:
        backend, _ = _backend(
            {"items": [{"key": "k", "value": "short", "value_clipped": True}], "total": 1}
        )
        entry = backend.storage("web")["storage"][0]

        assert entry["value"] == "short"
        assert entry["value_truncated"] is True

    def test_the_collection_itself_is_capped(self) -> None:
        backend, _ = _backend(_items(_MAX_STORAGE_ITEMS + 50, total=_MAX_STORAGE_ITEMS + 50))

        result = backend.storage("web", limit=_MAX_STORAGE_ITEMS)

        assert result["total"] == _MAX_STORAGE_ITEMS
        assert result["has_more"] is False

    def test_scan_capped_flags_a_store_larger_than_what_was_collected(self) -> None:
        backend, _ = _backend(_items(3, total=5000))

        result = backend.storage("web")

        assert result["total"] == 3
        assert result["scan_capped"] is True


class TestStoragePagination:
    def test_offset_and_limit_window_the_store(self) -> None:
        backend, _ = _backend(_items(5))

        result = backend.storage("web", offset=2, limit=2)

        assert [row["key"] for row in result["storage"]] == ["k2", "k3"]
        assert result["count"] == 2
        assert result["total"] == 5
        assert result["offset"] == 2
        assert result["has_more"] is True

    def test_an_offset_past_the_end_returns_an_empty_page(self) -> None:
        backend, _ = _backend(_items(1))

        result = backend.storage("web", offset=10)

        assert result["storage"] == []
        assert result["count"] == 0
        assert result["total"] == 1
        assert result["has_more"] is False


class TestStorageErrorPaths:
    def test_a_sandboxed_origin_reports_an_empty_store_with_a_note(self) -> None:
        backend, _ = _backend({"error": "SecurityError: access denied"})

        result = backend.storage("web")

        assert result["storage"] == []
        assert result["count"] == 0
        assert result["total"] == 0
        assert result["scan_capped"] is False
        assert "note" in result
        assert "SecurityError" in result["note"]

    def test_an_unknown_session_is_invalid_state(self) -> None:
        with pytest.raises(WebError) as info:
            WebBackend().storage("nope")

        assert info.value.code == "invalid_state"

    def test_a_failing_evaluate_is_a_backend_error(self) -> None:
        backend, _ = _backend(RuntimeError("driver gone"))

        with pytest.raises(WebError) as info:
            backend.storage("web")

        assert info.value.code == "backend_error"
        assert "driver gone" in info.value.message


def test_web_storage_docstring_names_the_fields_it_returns() -> None:
    doc = _tool_docstring("web.storage")
    assert "Answers with which" in doc
    assert "storage" in doc
    assert "scan_capped" in doc
    assert "value_truncated" in doc
    assert "local|session" in doc
