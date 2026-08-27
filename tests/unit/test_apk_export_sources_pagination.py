"""apk.export_sources pages the decompiled Java tree with a stable offset/limit.

jadx can emit tens of thousands of ``.java`` files. The listing was capped at
``_MAX_LISTED_FILES`` and raised ``has_more`` with no ``offset``, so every name
past the first page was unreachable -- and the sorted first page was a sorted
view of an arbitrary walk-order subset, not the alphabetically first names. It
is now a proper paginated reader like apk.classes/methods/strings: the whole set
is sorted, then sliced, so pages are contiguous, disjoint, and stable.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from headless_re_mcp.backends.jadx import client as mod
from headless_re_mcp.tools.apk import build_apk_tools
from headless_re_mcp.tools.binding import input_schema_for


def _client_over_tree(tmp_path: Path, names: list[str], monkeypatch: Any) -> tuple[Any, Path]:
    out = tmp_path / "out"
    sources = out / "sources"
    sources.mkdir(parents=True)
    for name in names:
        target = sources / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("class C {}", encoding="utf-8")
    client = mod.JadxClient(tmp_path / "jadx.bat")
    monkeypatch.setattr(client, "_run", lambda *args, **kwargs: ("", "", 0))
    return client, out


def test_export_sources_default_page_matches_the_prior_shape(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """No offset/limit keeps the count, java_files and has_more contract."""
    monkeypatch.setattr(mod, "_MAX_LISTED_FILES", 3)
    client, out = _client_over_tree(
        tmp_path, [f"C{index}.java" for index in range(5)], monkeypatch
    )
    payload = client.export_sources(tmp_path / "app.apk", out)
    assert payload["java_file_count"] == 5
    assert len(payload["java_files"]) == 3
    assert payload["count"] == 3
    assert payload["offset"] == 0
    assert payload["has_more"] is True
    assert "files" not in payload
    assert "sources" not in payload


def test_export_sources_pages_are_a_stable_sorted_partition(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """Walking pages with offset reassembles the whole sorted tree exactly once."""
    names = [f"pkg{index % 3}/C{index:02d}.java" for index in range(7)]
    client, out = _client_over_tree(tmp_path, names, monkeypatch)
    expected = sorted(f"sources/{name}" for name in names)

    seen: list[str] = []
    for start in (0, 3, 6):
        payload = client.export_sources(tmp_path / "app.apk", out, offset=start, limit=3)
        assert payload["offset"] == start
        assert payload["java_file_count"] == 7
        assert payload["count"] == len(payload["java_files"])
        seen.extend(payload["java_files"])
        # A page is exactly the corresponding slice of the fully sorted list.
        assert payload["java_files"] == expected[start : start + 3]

    assert seen == expected
    # The last page finished the list; the earlier ones did not.
    tail = client.export_sources(tmp_path / "app.apk", out, offset=6, limit=3)
    assert tail["has_more"] is False
    head = client.export_sources(tmp_path / "app.apk", out, offset=0, limit=3)
    assert head["has_more"] is True


def test_export_sources_offset_past_the_end_is_an_empty_page(
    tmp_path: Path, monkeypatch: Any
) -> None:
    client, out = _client_over_tree(
        tmp_path, [f"C{index}.java" for index in range(4)], monkeypatch
    )
    payload = client.export_sources(tmp_path / "app.apk", out, offset=100, limit=10)
    assert payload["java_files"] == []
    assert payload["count"] == 0
    assert payload["offset"] == 100
    assert payload["java_file_count"] == 4
    assert payload["has_more"] is False


def test_export_sources_clamps_limit_to_the_listing_ceiling(
    tmp_path: Path, monkeypatch: Any
) -> None:
    monkeypatch.setattr(mod, "_MAX_LISTED_FILES", 2)
    client, out = _client_over_tree(
        tmp_path, [f"C{index}.java" for index in range(5)], monkeypatch
    )
    payload = client.export_sources(tmp_path / "app.apk", out, offset=0, limit=1000)
    assert len(payload["java_files"]) == 2
    assert payload["has_more"] is True


def _schema(name: str, field: str) -> dict[str, Any]:
    handler = next(
        binding.handler
        for binding in build_apk_tools(object())  # type: ignore[arg-type]
        if binding.name == name
    )
    field_schema: dict[str, Any] = input_schema_for(handler)["properties"][field]
    return field_schema


def test_export_sources_schema_bounds_offset_and_limit() -> None:
    """The pager advertises the same offset/limit bounds as its siblings."""
    offset = _schema("apk.export_sources", "offset")
    assert offset.get("type") == "integer"
    assert offset.get("minimum") == 0
    assert "maximum" not in offset

    limit = _schema("apk.export_sources", "limit")
    assert limit.get("type") == "integer"
    assert limit.get("minimum") == 1
    assert limit.get("maximum") == 2000
