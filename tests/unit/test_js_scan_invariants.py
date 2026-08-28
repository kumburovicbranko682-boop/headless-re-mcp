"""Shared pagination/bounding contract across the pure-Python JS scanners.

js.strings, js.endpoints and js.imports each have their own field test, but
those exercise tiny inputs and limits, so the paging envelope the three are
meant to share is never locked at scale:

* they clamp to the same real per-page ceiling (_MAX_JS_*_PAGE = 1000), not a
  monkeypatched stand-in, and a page filled exactly to the ceiling reports
  has_more against the true total rather than being misread as complete;
* they clamp an out-of-range window identically -- limit <= 0 up to one row, a
  huge limit down to the ceiling, a negative offset to zero -- which matters
  because the agent and OpenAI-bridge transports reach these backends without
  the tool schema's pydantic bounds;
* successive pages tile the full result exactly, with no gap, overlap or
  reordering, and an offset past the end is an empty tail, not a wrap;
* the envelope is well-typed and an empty input is all-zero, never a crash.

These are pure-Python, node-free scans, so no webcrack or Node is needed; each
case just writes a hand-built source file to a tmp path.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.jsre.client import (
    _MAX_JS_COMMENTS_PAGE,
    _MAX_JS_ENDPOINTS_PAGE,
    _MAX_JS_IMPORTS_PAGE,
    _MAX_JS_STRINGS_PAGE,
    scan_js_comments,
    scan_js_endpoints,
    scan_js_imports,
    scan_js_strings,
)

_Payload = dict[str, Any]
_Run = Callable[[Path, int, int], _Payload]
_MakeSource = Callable[[int], str]


def _run_strings(path: Path, offset: int, limit: int) -> _Payload:
    return scan_js_strings(path, offset=offset, limit=limit)


def _run_endpoints(path: Path, offset: int, limit: int) -> _Payload:
    return scan_js_endpoints(path, offset=offset, limit=limit)


def _run_imports(path: Path, offset: int, limit: int) -> _Payload:
    return scan_js_imports(path, offset=offset, limit=limit)


def _run_comments(path: Path, offset: int, limit: int) -> _Payload:
    return scan_js_comments(path, offset=offset, limit=limit)


def _src_strings(n: int) -> str:
    return ";".join(f"var s{i} = 'str_value_{i:05d}'" for i in range(n))


def _src_endpoints(n: int) -> str:
    return ";".join(f"f('https://h{i:05d}.example.com/')" for i in range(n))


def _src_imports(n: int) -> str:
    return ";".join(f"import 'pkg{i:05d}'" for i in range(n))


def _src_comments(n: int) -> str:
    return "\n".join(f"// note {i:05d}" for i in range(n))


# (id, make_source, run, list_key, page_ceiling)
_CASES: tuple[tuple[str, _MakeSource, _Run, str, int], ...] = (
    ("strings", _src_strings, _run_strings, "strings", _MAX_JS_STRINGS_PAGE),
    ("endpoints", _src_endpoints, _run_endpoints, "endpoints", _MAX_JS_ENDPOINTS_PAGE),
    ("imports", _src_imports, _run_imports, "imports", _MAX_JS_IMPORTS_PAGE),
    ("comments", _src_comments, _run_comments, "comments", _MAX_JS_COMMENTS_PAGE),
)

_IDS = [case[0] for case in _CASES]

# The envelope keys every JS scanner returns (js.strings adds min_length on top).
_COMMON_KEYS = frozenset(
    {"input_bytes", "count", "total", "offset", "has_more", "scan_capped", "truncated"}
)


def _write(tmp_path: Path, name: str, text: str) -> Path:
    target = tmp_path / f"{name}.js"
    target.write_text(text, encoding="utf-8")
    return target


@pytest.mark.parametrize(("_id", "make_source", "run", "list_key", "_ceiling"), _CASES, ids=_IDS)
def test_envelope_is_well_typed(
    tmp_path: Path,
    _id: str,
    make_source: _MakeSource,
    run: _Run,
    list_key: str,
    _ceiling: int,
) -> None:
    payload = run(_write(tmp_path, _id, make_source(5)), 0, 100)
    assert payload.keys() >= _COMMON_KEYS
    assert isinstance(payload[list_key], list)
    for field in ("input_bytes", "count", "total", "offset"):
        assert isinstance(payload[field], int)
    for field in ("has_more", "scan_capped", "truncated"):
        assert isinstance(payload[field], bool)
    # A clean, small input is neither truncated nor capped, and count mirrors
    # the returned list length and the true total.
    assert payload["total"] == 5
    assert payload["count"] == len(payload[list_key]) == 5
    assert payload["offset"] == 0
    assert payload["has_more"] is False
    assert payload["scan_capped"] is False
    assert payload["truncated"] is False


@pytest.mark.parametrize(("_id", "make_source", "run", "list_key", "ceiling"), _CASES, ids=_IDS)
def test_huge_limit_clamps_to_page_ceiling(
    tmp_path: Path,
    _id: str,
    make_source: _MakeSource,
    run: _Run,
    list_key: str,
    ceiling: int,
) -> None:
    total = ceiling + 25
    payload = run(_write(tmp_path, _id, make_source(total)), 0, 10**9)
    # The real ceiling caps the page; the extra 25 items keep has_more honest.
    assert payload["total"] == total
    assert payload["count"] == len(payload[list_key]) == ceiling
    assert payload["has_more"] is True
    assert payload["scan_capped"] is False


@pytest.mark.parametrize(("_id", "make_source", "run", "list_key", "_ceiling"), _CASES, ids=_IDS)
def test_low_and_negative_bounds_are_clamped(
    tmp_path: Path,
    _id: str,
    make_source: _MakeSource,
    run: _Run,
    list_key: str,
    _ceiling: int,
) -> None:
    path = _write(tmp_path, _id, make_source(5))
    for limit in (0, -7):
        payload = run(path, 0, limit)
        assert payload["count"] == len(payload[list_key]) == 1
    # A negative offset is treated as the start, not a wrap to the tail.
    payload = run(path, -3, 100)
    assert payload["offset"] == 0
    assert payload["count"] == 5


@pytest.mark.parametrize(("_id", "make_source", "run", "list_key", "_ceiling"), _CASES, ids=_IDS)
def test_offset_past_end_is_empty_tail(
    tmp_path: Path,
    _id: str,
    make_source: _MakeSource,
    run: _Run,
    list_key: str,
    _ceiling: int,
) -> None:
    payload = run(_write(tmp_path, _id, make_source(5)), 999, 100)
    assert payload["total"] == 5
    assert payload["count"] == 0
    assert payload[list_key] == []
    assert payload["offset"] == 999
    assert payload["has_more"] is False


@pytest.mark.parametrize(("_id", "make_source", "run", "list_key", "_ceiling"), _CASES, ids=_IDS)
def test_pages_tile_the_full_result(
    tmp_path: Path,
    _id: str,
    make_source: _MakeSource,
    run: _Run,
    list_key: str,
    _ceiling: int,
) -> None:
    path = _write(tmp_path, _id, make_source(25))
    whole = run(path, 0, 1000)[list_key]
    assert len(whole) == 25

    tiled: list[Any] = []
    offset = 0
    step = 10
    while True:
        page = run(path, offset, step)
        rows = page[list_key]
        tiled.extend(rows)
        # has_more must agree with the arithmetic the caller would do itself.
        assert page["has_more"] == (page["offset"] + page["count"] < page["total"])
        if not page["has_more"]:
            break
        offset += step
    assert tiled == whole


@pytest.mark.parametrize(("_id", "make_source", "run", "list_key", "_ceiling"), _CASES, ids=_IDS)
def test_empty_input_is_all_zero(
    tmp_path: Path,
    _id: str,
    make_source: _MakeSource,
    run: _Run,
    list_key: str,
    _ceiling: int,
) -> None:
    payload = run(_write(tmp_path, _id, ""), 0, 100)
    assert payload["input_bytes"] == 0
    assert payload["total"] == 0
    assert payload["count"] == 0
    assert payload[list_key] == []
    assert payload["has_more"] is False
    assert payload["scan_capped"] is False
    assert payload["truncated"] is False
