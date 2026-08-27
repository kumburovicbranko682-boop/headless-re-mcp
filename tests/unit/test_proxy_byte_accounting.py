"""Device-free coverage for the proxy backend's byte accounting.

``_FlowRecorder.response`` decides whether to retain or omit a captured
flow by weighing it with ``_flow_stored_bytes``; the ring-eviction tests
drive that happy path, but the defensive branches underneath -- the ones
that keep the overnight-OOM guard honest against a mitmproxy object that
does not measure cleanly -- had no coverage.

These pin them with plain fakes, no proxy running:

- ``_content_len`` reads a body length and degrades a None/empty/non-sized
  ``raw_content`` to 0 rather than raising.
- ``_encoded_len`` returns the UTF-8 byte length, and -- the load-bearing
  case -- fails *closed*: a value whose ``str()`` raises counts as over the
  per-body cap, so an unmeasurable header is omitted, never retained
  unmeasured.
- ``_headers_len`` sums key+value bytes, tolerates a Headers whose
  ``items()`` does not accept ``multi=`` (older mitmproxy), short-circuits
  once a single part is already over the cap, and reads a broken headers
  object as 0.
- ``_flow_stored_bytes`` totals request+response bodies, the request
  method/url/host, and both header blocks, and reads an empty flow as 0.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from headless_re_mcp.backends.proxy.client import (
    _MAX_STORED_BODY,
    _content_len,
    _encoded_len,
    _flow_stored_bytes,
    _headers_len,
)


def test_content_len_measures_bytes_and_degrades_safely() -> None:
    assert _content_len(SimpleNamespace(raw_content=b"abcde")) == 5
    assert _content_len(None) == 0
    assert _content_len(SimpleNamespace(raw_content=None)) == 0
    assert _content_len(SimpleNamespace(raw_content=b"")) == 0
    # A truthy raw_content with no __len__ must not raise out of the accounting.
    assert _content_len(SimpleNamespace(raw_content=object())) == 0


def test_encoded_len_counts_utf8_bytes() -> None:
    assert _encoded_len("abc") == 3
    assert _encoded_len("\u20ac") == 3
    assert _encoded_len(123) == 3
    assert _encoded_len(None) == len("None")


def test_encoded_len_fails_closed_on_an_unmeasurable_value() -> None:
    class _Unstringable:
        def __str__(self) -> str:
            raise ValueError("no str for you")

    # Fail closed: an unmeasurable value counts as over the per-body cap, so
    # the recorder omits it rather than retaining an unmeasured blob.
    assert _encoded_len(_Unstringable()) == _MAX_STORED_BODY + 1


class _MultiHeaders:
    def __init__(self, pairs: list[tuple[str, str]]) -> None:
        self._pairs = pairs

    def items(self, multi: bool = False) -> list[tuple[str, str]]:
        del multi
        return list(self._pairs)


class _LegacyHeaders:
    """A Headers whose items() predates the ``multi=`` keyword."""

    def __init__(self, pairs: list[tuple[str, str]]) -> None:
        self._pairs = pairs

    def items(self) -> list[tuple[str, str]]:
        return list(self._pairs)


def test_headers_len_sums_and_handles_none() -> None:
    assert _headers_len(SimpleNamespace(headers=None)) == 0
    headers = _MultiHeaders([("Content-Type", "text/html"), ("X", "yz")])
    expected = sum(len(k) + len(v) for k, v in headers.items())
    assert _headers_len(SimpleNamespace(headers=headers)) == expected


def test_headers_len_falls_back_when_items_rejects_multi() -> None:
    headers = _LegacyHeaders([("a", "bb"), ("ccc", "d")])
    assert _headers_len(SimpleNamespace(headers=headers)) == (1 + 2) + (3 + 1)


def test_headers_len_short_circuits_once_over_the_cap() -> None:
    yielded: list[str] = []

    def _pairs() -> Any:
        for key, value in (
            ("big", "x" * (_MAX_STORED_BODY + 10)),
            ("second", "y"),
            ("third", "z"),
        ):
            yielded.append(key)
            yield key, value

    class _StreamingHeaders:
        def items(self, multi: bool = False) -> Any:
            del multi
            return _pairs()

    total = _headers_len(SimpleNamespace(headers=_StreamingHeaders()))
    assert total > _MAX_STORED_BODY
    # It stopped after the first over-cap pair rather than walking the rest.
    assert yielded == ["big"]


def test_headers_len_reads_a_broken_headers_object_as_zero() -> None:
    class _BrokenHeaders:
        def items(self, multi: bool = False) -> Any:
            del multi
            raise RuntimeError("headers exploded")

    assert _headers_len(SimpleNamespace(headers=_BrokenHeaders())) == 0


def test_flow_stored_bytes_totals_every_measured_part() -> None:
    request = SimpleNamespace(
        raw_content=b"AB",
        method="GET",
        pretty_url="http://x",
        host="x",
        headers=_MultiHeaders([("k", "v")]),
    )
    response = SimpleNamespace(raw_content=b"CDE", headers=None)
    flow = SimpleNamespace(request=request, response=response)
    # 2 + 3 body, 3 + 8 + 1 method/url/host, 1 + 1 request header, 0 response.
    assert _flow_stored_bytes(flow) == 2 + 3 + 3 + 8 + 1 + (1 + 1)


def test_flow_stored_bytes_of_an_empty_flow_is_zero() -> None:
    assert _flow_stored_bytes(SimpleNamespace()) == 0
