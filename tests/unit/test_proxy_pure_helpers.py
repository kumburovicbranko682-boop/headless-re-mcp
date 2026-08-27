"""Proxy flow byte-accounting and body/header shapers, pinned without mitmproxy.

Everything on a captured flow is fully untrusted server data, and this backend
retains whole flow objects in a ring, so a family of pure helpers bounds what it
stores and what it hands back:

* ``_content_len`` / ``_encoded_len`` / ``_headers_len`` / ``_flow_stored_bytes``
  measure a flow's retained cost for the memory cap, and must fail *toward*
  overcounting (or a safe zero) rather than raising when a part misbehaves;
* ``_raw_body`` reads body bytes and treats a lazy-decode failure as an empty
  body, not a fetch failure;
* ``_emit_body`` describes a body without ever returning a lossy decode --
  inline text within the cap, otherwise a ``.bin`` spill tagged ``too_large`` or
  ``binary`` so a caller never mistakes replacement characters for real bytes;
* ``_bounded_headers`` still has two edges (a headers object that raises on
  iteration, and the total-size cap) that its count/per-value tests did not hit.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

import headless_re_mcp.backends.proxy.client as proxy
from headless_re_mcp.backends.proxy.client import (
    _MAX_STORED_BODY,
    _bounded_headers,
    _content_len,
    _emit_body,
    _encoded_len,
    _flow_stored_bytes,
    _headers_len,
    _raw_body,
)


class _RaisesOnStr:
    def __str__(self) -> str:
        raise ValueError("cannot stringify")


class _RaisesOnItems:
    def items(self, *args: object, **kwargs: object) -> object:
        raise ValueError("headers exploded")


def test_content_len_reads_length_or_falls_back_to_zero() -> None:
    assert _content_len(None) == 0
    assert _content_len(SimpleNamespace(raw_content=None)) == 0
    assert _content_len(SimpleNamespace(raw_content=b"abcd")) == 4
    # A truthy raw_content with no len() (e.g. an int) must read as 0, not raise.
    assert _content_len(SimpleNamespace(raw_content=1234)) == 0


def test_encoded_len_measures_utf8_and_overcounts_on_failure() -> None:
    assert _encoded_len("abc") == 3
    # A value that cannot be stringified fails toward "too big", so the memory
    # cap treats an unmeasurable part as over the limit rather than free.
    assert _encoded_len(_RaisesOnStr()) == _MAX_STORED_BODY + 1


def test_headers_len_sums_bytes_and_is_zero_on_failure() -> None:
    assert _headers_len(SimpleNamespace()) == 0
    assert _headers_len(SimpleNamespace(headers={"a": "bb"})) == 3
    # A headers object that raises on iteration reads as zero, not a crash.
    assert _headers_len(SimpleNamespace(headers=_RaisesOnItems())) == 0


def test_headers_len_stops_once_past_the_stored_body_cap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(proxy, "_MAX_STORED_BODY", 5)
    total = _headers_len(SimpleNamespace(headers={"k": "xxxxxx"}))
    # 1 (key) + 6 (value) = 7, which is past 5, so it stops there.
    assert total == 7


def test_flow_stored_bytes_totals_bodies_metadata_and_headers() -> None:
    request = SimpleNamespace(
        raw_content=b"ab",
        method="GET",
        pretty_url="http://x",
        host="x",
        headers={"a": "1"},
    )
    response = SimpleNamespace(raw_content=b"cde", headers={"b": "2"})
    flow = SimpleNamespace(request=request, response=response)
    # bodies 2+3, method 3, url 8, host 1, req headers 2, resp headers 2 = 21.
    assert _flow_stored_bytes(flow) == 21


def test_raw_body_returns_bytes_or_empty() -> None:
    assert _raw_body(None) == b""
    assert _raw_body(SimpleNamespace(raw_content=b"body")) == b"body"
    # A non-bytes raw_content (e.g. a str) is not a body we return.
    assert _raw_body(SimpleNamespace(raw_content="text")) == b""

    class _DecodeBlowsUp:
        @property
        def raw_content(self) -> bytes:
            raise RuntimeError("lazy decode failed")

    assert _raw_body(_DecodeBlowsUp()) == b""


def test_emit_body_inlines_short_text(tmp_path: Path) -> None:
    out = _emit_body(b"hello", tmp_path)
    assert out == {"size": 5, "body": "hello"}
    assert list(tmp_path.iterdir()) == []


def test_emit_body_reports_an_empty_body(tmp_path: Path) -> None:
    out = _emit_body(b"", tmp_path)
    assert out == {"size": 0, "body": ""}
    assert list(tmp_path.iterdir()) == []


def test_emit_body_spills_non_utf8_as_binary(tmp_path: Path) -> None:
    out = _emit_body(b"\xff\xfe\x00", tmp_path)
    assert out["size"] == 3
    assert out["spill_reason"] == "binary"
    assert "body" not in out
    spilled = Path(out["body_path"])
    assert spilled.read_bytes() == b"\xff\xfe\x00"


def test_emit_body_spills_an_oversized_body_as_too_large(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(proxy, "_MAX_INLINE_BODY", 4)
    out = _emit_body(b"abcdefgh", tmp_path)
    assert out["size"] == 8
    assert out["spill_reason"] == "too_large"
    assert Path(out["body_path"]).read_bytes() == b"abcdefgh"


def test_bounded_headers_treats_an_iteration_failure_as_dropped() -> None:
    out, truncated = _bounded_headers(SimpleNamespace(headers=_RaisesOnItems()))
    assert out == {}
    assert truncated is True


def test_bounded_headers_stops_at_the_total_byte_cap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(proxy, "_MAX_FLOW_HEADERS_TOTAL_BYTES", 10)
    out, truncated = _bounded_headers(
        SimpleNamespace(headers={"aaaa": "bbbb", "cccc": "dddd"})
    )
    # The first entry (8 bytes) fits; the second would push total to 16 > 10.
    assert out == {"aaaa": "bbbb"}
    assert truncated is True
