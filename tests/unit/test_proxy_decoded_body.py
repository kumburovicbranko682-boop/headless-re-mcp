"""proxy.flow.get must decompress a body before deciding it is unreadable binary.

``_decoded_body`` used to return ``raw_content`` -- the bytes exactly as they
crossed the wire, still gzip/br/deflate/zstd compressed for the common case.
``_emit_body`` then failed the UTF-8 check on those compressed bytes and spilled
a ``.bin`` artifact tagged ``binary``, so fetching a JSON/HTML flow handed back
an opaque blob. The fix prefers ``content`` (decoded per Content-Encoding) and
only falls back to the wire bytes when the encoding cannot be undone.
"""

from __future__ import annotations

import gzip
from pathlib import Path
from types import SimpleNamespace

import pytest

from headless_re_mcp.backends.proxy.client import _decoded_body, _emit_body


class _Part:
    """A message part exposing mitmproxy's content / raw_content contract."""

    def __init__(self, *, content: object, raw_content: object, raises: bool = False) -> None:
        self._content = content
        self._raw = raw_content
        self._raises = raises

    @property
    def content(self) -> object:
        if self._raises:
            raise ValueError("unknown or corrupt Content-Encoding")
        return self._content

    @property
    def raw_content(self) -> object:
        return self._raw


def test_prefers_the_decoded_body_over_the_compressed_wire_bytes() -> None:
    body = b'{"token":"abc","n":42}'
    part = _Part(content=body, raw_content=gzip.compress(body))
    assert _decoded_body(part) == body


def test_falls_back_to_wire_bytes_when_the_encoding_cannot_be_undone() -> None:
    # A body whose Content-Encoding header lies (or names a codec mitmproxy
    # cannot apply) makes content raise; the honest thing left is the raw bytes.
    wire = b"not really gzip"
    part = _Part(content=None, raw_content=wire, raises=True)
    assert _decoded_body(part) == wire


def test_no_body_and_no_part_are_both_empty() -> None:
    assert _decoded_body(_Part(content=None, raw_content=None)) == b""
    assert _decoded_body(None) == b""


def test_a_part_without_a_content_attribute_still_reads_the_raw_body() -> None:
    # The proxy unit fakes elsewhere use SimpleNamespace with only raw_content;
    # accessing .content raises AttributeError, which must degrade to raw_content
    # rather than blank the body.
    plain = b"plain text body"
    assert _decoded_body(SimpleNamespace(raw_content=plain)) == plain


def test_gzipped_text_body_comes_back_inline_not_spilled_as_binary(tmp_path: Path) -> None:
    """Live gate against real mitmproxy: a gzipped JSON response reads as text."""
    try:
        from mitmproxy.http import Headers, Response
    except Exception:  # noqa: BLE001
        pytest.skip("mitmproxy not installed; cannot exercise real Content-Encoding decode")

    body = b'{"hello":"world","items":[1,2,3]}' * 4
    # Pass the decoded body; mitmproxy's content setter encodes it to gzip, so
    # raw_content ends up compressed exactly like a real captured response.
    resp = Response.make(
        200, body, Headers(content_type=b"application/json", content_encoding=b"gzip")
    )
    assert resp.raw_content != body  # actually compressed on the wire
    with pytest.raises(UnicodeDecodeError):
        resp.raw_content.decode("utf-8")  # the old path would have spilled .bin

    assert _decoded_body(resp) == body
    emitted = _emit_body(_decoded_body(resp), tmp_path)
    assert emitted["body"] == body.decode("utf-8")
    assert "body_path" not in emitted
    assert emitted["size"] == len(body)
