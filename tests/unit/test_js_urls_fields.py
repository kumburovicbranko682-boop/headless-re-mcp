"""Unit tests for js.urls (node-free URL extraction from a JS/text file).

Because the scanner is pure Python it is exercised against real temp files:
scheme coverage, delimiter stripping, trailing-punctuation trim, dedupe/sort,
pagination, the distinct-URL collect cap, and the size/existence guards.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.jsre.client import JsReError, scan_urls


def _write(tmp_path: Path, text: str, name: str = "bundle.js") -> Path:
    target = tmp_path / name
    target.write_text(text, encoding="utf-8")
    return target


def test_urls_extracts_all_schemes_deduped_sorted(tmp_path: Path) -> None:
    src = _write(
        tmp_path,
        """
        const a = "https://api.example.com/v1/users?id=1";
        const b = 'http://cdn.example.net/app.js';
        const ws = "wss://live.example.com/socket";
        const dup = "https://api.example.com/v1/users?id=1";
        connect("ws://legacy.example.org/stream");
        """,
    )

    payload = scan_urls(src)

    assert payload["urls"] == [
        "http://cdn.example.net/app.js",
        "https://api.example.com/v1/users?id=1",
        "ws://legacy.example.org/stream",
        "wss://live.example.com/socket",
    ]
    assert payload["count"] == 4
    assert payload["total"] == 4
    assert payload["offset"] == 0
    assert payload["has_more"] is False
    assert payload["scan_capped"] is False


def test_urls_strips_delimiters_and_trailing_punctuation(tmp_path: Path) -> None:
    src = _write(
        tmp_path,
        'fetch("https://a.example.com/end.");\nx = (https://b.example.com/p),',
    )

    payload = scan_urls(src)

    assert payload["urls"] == [
        "https://a.example.com/end",
        "https://b.example.com/p",
    ]


def test_urls_empty_when_none(tmp_path: Path) -> None:
    src = _write(tmp_path, "const x = 1; // no links here\nfunction f(){return x}")

    payload = scan_urls(src)

    assert payload["urls"] == []
    assert payload["total"] == 0
    assert payload["has_more"] is False
    assert payload["scan_capped"] is False


def test_urls_ignores_non_http_schemes(tmp_path: Path) -> None:
    src = _write(
        tmp_path,
        'a="ftp://x.example.com/f"; b="mailto:me@example.com"; c="https://ok.example.com/";',
    )

    payload = scan_urls(src)

    assert payload["urls"] == ["https://ok.example.com/"]


def test_urls_paginates(tmp_path: Path) -> None:
    lines = "\n".join(f'u{i}="https://h{i:03d}.example.com/p";' for i in range(5))
    src = _write(tmp_path, lines)

    payload = scan_urls(src, offset=2, limit=2)

    assert payload["offset"] == 2
    assert payload["count"] == 2
    assert payload["total"] == 5
    assert payload["has_more"] is True
    assert payload["urls"] == [
        "https://h002.example.com/p",
        "https://h003.example.com/p",
    ]


def test_urls_collect_cap_sets_scan_capped(tmp_path: Path, monkeypatch: Any) -> None:
    monkeypatch.setattr("headless_re_mcp.backends.jsre.client._MAX_URLS_COLLECT", 3)
    lines = "\n".join(f'u="https://h{i:03d}.example.com/p";' for i in range(10))
    src = _write(tmp_path, lines)

    payload = scan_urls(src)

    assert payload["total"] == 3
    assert payload["scan_capped"] is True


def test_urls_clamps_oversized_limit(tmp_path: Path, monkeypatch: Any) -> None:
    monkeypatch.setattr("headless_re_mcp.backends.jsre.client._MAX_URLS_PAGE", 2)
    lines = "\n".join(f'u="https://h{i:03d}.example.com/p";' for i in range(5))
    src = _write(tmp_path, lines)

    payload = scan_urls(src, limit=10**9)

    assert payload["count"] == 2
    assert payload["has_more"] is True


def test_urls_missing_file_is_not_found(tmp_path: Path) -> None:
    with pytest.raises(JsReError) as excinfo:
        scan_urls(tmp_path / "does-not-exist.js")
    assert excinfo.value.code == "not_found"


def test_urls_refuses_oversized_input(tmp_path: Path, monkeypatch: Any) -> None:
    monkeypatch.setattr("headless_re_mcp.backends.jsre.client._MAX_INPUT_BYTES", 32)
    src = _write(tmp_path, 'const u = "https://big.example.com/' + "x" * 200 + '";')

    with pytest.raises(JsReError) as excinfo:
        scan_urls(src)
    assert excinfo.value.code == "too_large"


def test_urls_docstring_names_shape() -> None:
    doc = scan_urls.__doc__ or ""
    assert "Node-free" in doc
    assert "scan_capped" in doc
