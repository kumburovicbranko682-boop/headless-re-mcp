"""Unit tests for js.source_maps (node-free sourceMappingURL discovery).

Pure Python, so it runs against real temp files: the modern //#, legacy //@ and
CSS /* */ comment forms, inline data: URIs reported by prefix only, dedupe/sort,
pagination, the collect cap, and the size/existence guards.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.jsre.client import (
    _MAX_MAP_URL_LEN,
    JsReError,
    scan_source_maps,
)


def _write(tmp_path: Path, text: str, name: str = "app.js") -> Path:
    target = tmp_path / name
    target.write_text(text, encoding="utf-8")
    return target


def test_source_maps_modern_line_form(tmp_path: Path) -> None:
    src = _write(tmp_path, "console.log(1);\n//# sourceMappingURL=app.js.map\n")

    payload = scan_source_maps(src)

    assert payload["source_maps"] == [{"url": "app.js.map", "inline": False}]
    assert payload["count"] == 1
    assert payload["total"] == 1
    assert payload["has_more"] is False
    assert payload["scan_capped"] is False


def test_source_maps_legacy_and_block_forms(tmp_path: Path) -> None:
    src = _write(
        tmp_path,
        "a=1;\n//@ sourceMappingURL=/static/legacy.js.map\n"
        "b=2;\n/*# sourceMappingURL=styles.css.map */\n",
        name="mixed.txt",
    )

    payload = scan_source_maps(src)

    assert payload["source_maps"] == [
        {"url": "/static/legacy.js.map", "inline": False},
        {"url": "styles.css.map", "inline": False},
    ]


def test_source_maps_absolute_url(tmp_path: Path) -> None:
    src = _write(
        tmp_path,
        "x;//# sourceMappingURL=https://cdn.example.com/app.js.map",
    )

    payload = scan_source_maps(src)

    assert payload["source_maps"] == [
        {"url": "https://cdn.example.com/app.js.map", "inline": False}
    ]


def test_source_maps_inline_reports_prefix_only(tmp_path: Path) -> None:
    payload_b64 = "A" * 5000
    src = _write(
        tmp_path,
        f"z;//# sourceMappingURL=data:application/json;base64,{payload_b64}",
    )

    payload = scan_source_maps(src)

    assert payload["source_maps"] == [
        {"url": "data:application/json;base64,", "inline": True}
    ]
    # The base64 payload must never reach the reply.
    assert len(payload["source_maps"][0]["url"]) < _MAX_MAP_URL_LEN
    assert "AAAA" not in payload["source_maps"][0]["url"]


def test_source_maps_none_when_absent(tmp_path: Path) -> None:
    src = _write(tmp_path, "const x = 1; // a normal comment, no map here\n")

    payload = scan_source_maps(src)

    assert payload["source_maps"] == []
    assert payload["total"] == 0
    assert payload["has_more"] is False


def test_source_maps_dedupes_and_sorts(tmp_path: Path) -> None:
    src = _write(
        tmp_path,
        "//# sourceMappingURL=b.js.map\n"
        "//# sourceMappingURL=a.js.map\n"
        "//# sourceMappingURL=b.js.map\n",
    )

    payload = scan_source_maps(src)

    assert payload["source_maps"] == [
        {"url": "a.js.map", "inline": False},
        {"url": "b.js.map", "inline": False},
    ]
    assert payload["total"] == 2


def test_source_maps_paginates(tmp_path: Path) -> None:
    lines = "\n".join(f"//# sourceMappingURL=m{i:03d}.js.map" for i in range(5))
    src = _write(tmp_path, lines)

    payload = scan_source_maps(src, offset=2, limit=2)

    assert payload["offset"] == 2
    assert payload["count"] == 2
    assert payload["total"] == 5
    assert payload["has_more"] is True
    assert payload["source_maps"] == [
        {"url": "m002.js.map", "inline": False},
        {"url": "m003.js.map", "inline": False},
    ]


def test_source_maps_collect_cap_sets_scan_capped(
    tmp_path: Path, monkeypatch: Any
) -> None:
    monkeypatch.setattr(
        "headless_re_mcp.backends.jsre.client._MAX_SOURCE_MAPS_COLLECT", 3
    )
    lines = "\n".join(f"//# sourceMappingURL=m{i:03d}.js.map" for i in range(10))
    src = _write(tmp_path, lines)

    payload = scan_source_maps(src)

    assert payload["total"] == 3
    assert payload["scan_capped"] is True


def test_source_maps_clamps_oversized_limit(tmp_path: Path, monkeypatch: Any) -> None:
    monkeypatch.setattr(
        "headless_re_mcp.backends.jsre.client._MAX_SOURCE_MAPS_PAGE", 2
    )
    lines = "\n".join(f"//# sourceMappingURL=m{i:03d}.js.map" for i in range(5))
    src = _write(tmp_path, lines)

    payload = scan_source_maps(src, limit=10**9)

    assert payload["count"] == 2
    assert payload["has_more"] is True


def test_source_maps_missing_file_is_not_found(tmp_path: Path) -> None:
    with pytest.raises(JsReError) as excinfo:
        scan_source_maps(tmp_path / "nope.js")
    assert excinfo.value.code == "not_found"


def test_source_maps_refuses_oversized_input(tmp_path: Path, monkeypatch: Any) -> None:
    monkeypatch.setattr("headless_re_mcp.backends.jsre.client._MAX_INPUT_BYTES", 16)
    src = _write(tmp_path, "//# sourceMappingURL=app.js.map\n" + "x" * 200)

    with pytest.raises(JsReError) as excinfo:
        scan_source_maps(src)
    assert excinfo.value.code == "too_large"


def test_source_maps_docstring_names_shape() -> None:
    doc = scan_source_maps.__doc__ or ""
    assert "Node-free" in doc
    assert "scan_capped" in doc
