"""web.console must narrow a noisy console by level and text substring.

These mirror the web.network.list / proxy.flows filter tests, adapted to the
console's shape (type/text) and its "most-recent-N" semantics: an agent hunting
the one error among hundreds of debug lines should not have to read the whole
buffer. Each test measures a concrete buffer and asserts what the filter keeps,
that the recent-N window and has_more page the filtered set (not the raw ring),
and that the reply flags the narrowing (filtered/captured) so a filtered page is
never mistaken for the whole console.
"""

from __future__ import annotations

import ast
from collections import deque
from pathlib import Path
from threading import Lock

from headless_re_mcp.backends.web.client import _MAX_CONSOLE, WebBackend
from headless_re_mcp.tools.web import build_web_tools

# (type, text) in chronological (oldest-first) order, as the ring holds them.
_ROWS = [
    ("log", "boot sequence started"),
    ("info", "config loaded from cache"),
    ("warning", "deprecated API in use"),
    ("error", "failed to fetch /api/users"),
    ("debug", "retry scheduled in 500ms"),
    ("error", "TypeError: undefined is not a function"),
]


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
    def __init__(self, rows: list[tuple[str, str]], *, dropped: int = 0) -> None:
        self.lock = Lock()
        self.console: deque[dict[str, str]] = deque(maxlen=_MAX_CONSOLE)
        for kind, text in rows:
            self.console.append({"type": kind, "text": text})
        self.console_dropped = dropped


def _backend(rows: list[tuple[str, str]], *, dropped: int = 0) -> WebBackend:
    handle = _FakeHandle(rows, dropped=dropped)
    backend = WebBackend()
    backend._get = lambda session_id: handle  # type: ignore[method-assign]
    return backend


def _texts(payload: dict[str, object]) -> list[str]:
    return [row["text"] for row in payload["console"]]  # type: ignore[index]


def test_no_filter_returns_recent_and_omits_the_flags() -> None:
    """Without a filter, every held message is returned and no flags appear.

    Measured: 6 held -> count 6, and neither filtered nor captured is set, so an
    unfiltered reply is byte-for-byte what it always was.
    """
    payload = _backend(_ROWS).console("s")
    assert payload["count"] == 6
    assert "filtered" not in payload
    assert "captured" not in payload


def test_level_filter_is_exact_and_case_insensitive() -> None:
    """level matches the message type exactly, ignoring case, not as a substring.

    Measured: level 'ERROR' (uppercase) -> the two error rows, captured 6,
    filtered True. 'err' matches nothing because the match is exact, not prefix.
    """
    backend = _backend(_ROWS)
    payload = backend.console("s", level="ERROR")
    assert _texts(payload) == [
        "failed to fetch /api/users",
        "TypeError: undefined is not a function",
    ]
    assert payload["count"] == 2
    assert payload["captured"] == 6
    assert payload["filtered"] is True
    assert backend.console("s", level="err")["count"] == 0


def test_text_contains_is_a_case_insensitive_substring() -> None:
    """text_contains keeps any message whose text holds the substring, any case.

    Measured: text_contains 'typeerror' -> the one row carrying 'TypeError',
    filtered True, captured 6.
    """
    payload = _backend(_ROWS).console("s", text_contains="typeerror")
    assert _texts(payload) == ["TypeError: undefined is not a function"]
    assert payload["filtered"] is True
    assert payload["captured"] == 6


def test_filters_are_anded_together() -> None:
    """level and text_contains must both hold for a row to survive.

    Measured: level error + text_contains 'fetch' -> only the fetch error, not
    the TypeError error and not the debug 'retry' line.
    """
    payload = _backend(_ROWS).console("s", level="error", text_contains="fetch")
    assert _texts(payload) == ["failed to fetch /api/users"]


def test_empty_filter_string_is_ignored_not_matched() -> None:
    """A whitespace-only filter behaves as no filter, not match-all/none.

    Measured: level '   ' and text_contains '' -> count 6 and no filtered flag,
    so an accidentally-blank argument does not silently drop or keep everything.
    """
    payload = _backend(_ROWS).console("s", level="   ", text_contains="")
    assert payload["count"] == 6
    assert "filtered" not in payload


def test_filtered_recent_n_pages_the_matches_not_the_buffer() -> None:
    """The recent-N window runs over the filtered set: has_more follows matches.

    Measured: 5 error rows interleaved with 4 debug rows; level error, limit 3 ->
    count 3, the three most-recent errors in order, has_more True, captured 9. A
    limit past the match count clears has_more.
    """
    rows: list[tuple[str, str]] = []
    for index in range(5):
        rows.append(("error", f"boom {index}"))
        if index < 4:
            rows.append(("debug", f"noise {index}"))
    backend = _backend(rows)
    payload = backend.console("s", level="error", limit=3)
    assert payload["count"] == 3
    assert _texts(payload) == ["boom 2", "boom 3", "boom 4"]  # newest three, in order
    assert payload["has_more"] is True
    assert payload["captured"] == 9
    all_errors = backend.console("s", level="error", limit=10)
    assert all_errors["count"] == 5
    assert all_errors["has_more"] is False


def test_dropped_reflects_the_ring_not_the_filter() -> None:
    """dropped stays the count the console ring evicted, independent of filters.

    Measured: a ring that already evicted 9 -> dropped 9 whether or not a filter
    is applied; a filter narrows the view, it does not change what was evicted.
    """
    backend = _backend(_ROWS, dropped=9)
    assert backend.console("s")["dropped"] == 9
    assert backend.console("s", level="error")["dropped"] == 9


def test_web_console_docstring_names_the_filters() -> None:
    """The catalog must describe the filters and the filtered/captured contract."""
    doc = _tool_docstring("web.console")
    for token in ("level", "text_contains", "filtered", "captured", "type"):
        assert token in doc
