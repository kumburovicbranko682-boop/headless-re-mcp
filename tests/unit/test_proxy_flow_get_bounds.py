"""proxy.flow.get bounds the header map it returns inline.

The response body is already spilled or capped, but the header map was dumped
whole via ``dict(headers)``. A chatty or hostile server -- thousands of headers,
a multi-kilobyte ``Set-Cookie`` -- could otherwise return an unbounded blob into
the tool response, out of step with the rest of this byte-bounded backend. These
tests pin the count, per-value and total-size bounds, and that a normal flow is
returned untouched.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

from headless_re_mcp.backends.proxy.client import (
    _MAX_FLOW_HEADERS,
    _MAX_HEADER_VALUE_BYTES,
    ProxyBackend,
    _bounded_headers,
)


def _flow(req_headers: Any, resp_headers: Any, *, body: bytes = b"") -> Any:
    request = SimpleNamespace(method="GET", pretty_url="http://x/1", headers=req_headers)
    response = SimpleNamespace(status_code=200, headers=resp_headers, raw_content=body)
    return SimpleNamespace(request=request, response=response)


class _MultiHeaders:
    """A minimal stand-in for mitmproxy's multidict headers.

    ``items(multi=True)`` yields every line, including repeated names, the way
    the real object does -- a plain dict cannot, since duplicate keys are
    already lost before the helper ever sees them.
    """

    def __init__(self, pairs: list[tuple[str, str]]) -> None:
        self._pairs = pairs

    def items(self, multi: bool = False) -> list[tuple[str, str]]:
        del multi
        return list(self._pairs)


def _backend_returning(flow: Any, monkeypatch: Any) -> ProxyBackend:
    backend = ProxyBackend()
    recorder = SimpleNamespace(raw=lambda flow_id: flow)
    monkeypatch.setattr(backend, "_get", lambda session_id: SimpleNamespace(recorder=recorder))
    return backend


def test_bounded_headers_leaves_a_small_map_intact() -> None:
    out, truncated = _bounded_headers(SimpleNamespace(headers={"a": "1", "b": "2"}))
    assert out == {"a": "1", "b": "2"}
    assert truncated is False


def test_bounded_headers_caps_the_header_count() -> None:
    many = {f"h{index}": "v" for index in range(_MAX_FLOW_HEADERS + 50)}
    out, truncated = _bounded_headers(SimpleNamespace(headers=many))
    assert len(out) == _MAX_FLOW_HEADERS
    assert truncated is True


def test_bounded_headers_caps_a_single_huge_value() -> None:
    huge = "z" * (_MAX_HEADER_VALUE_BYTES * 4)
    out, truncated = _bounded_headers(SimpleNamespace(headers={"big": huge}))
    assert len(out["big"].encode("utf-8")) == _MAX_HEADER_VALUE_BYTES
    assert truncated is True


def test_bounded_headers_on_a_part_without_headers() -> None:
    out, truncated = _bounded_headers(SimpleNamespace())
    assert out == {}
    assert truncated is False


def test_bounded_headers_flags_a_collapsed_duplicate_name() -> None:
    """Repeated header names collapse to the last value and set the flag.

    The helper's contract is that the flag fires whenever the map stops
    faithfully representing the wire headers. Several Set-Cookie lines merged to
    one is exactly such a drop, but count/size bounding alone never sees it, so
    without this a flow with five Set-Cookie headers came back as one with no
    signal that four were lost.
    """
    headers = _MultiHeaders(
        [("Set-Cookie", "a=1"), ("Set-Cookie", "b=2"), ("Content-Type", "text/html")]
    )
    out, truncated = _bounded_headers(SimpleNamespace(headers=headers))
    assert out == {"Set-Cookie": "b=2", "Content-Type": "text/html"}
    assert truncated is True


def test_bounded_headers_does_not_flag_distinct_names() -> None:
    """The multi-valued path with no repeats is not mistaken for a collapse."""
    headers = _MultiHeaders([("Accept", "*/*"), ("Content-Type", "text/html")])
    out, truncated = _bounded_headers(SimpleNamespace(headers=headers))
    assert out == {"Accept": "*/*", "Content-Type": "text/html"}
    assert truncated is False


def test_flow_get_bounds_response_headers_and_flags_truncation(
    tmp_path: Path, monkeypatch: Any
) -> None:
    flow = _flow(
        {"accept": "text/plain"},
        {f"h{index}": "v" for index in range(_MAX_FLOW_HEADERS + 10)},
        body=b"small",
    )
    backend = _backend_returning(flow, monkeypatch)
    payload = backend.flow_get("s", "f1", tmp_path)
    assert len(payload["response"]["headers"]) == _MAX_FLOW_HEADERS
    assert payload["response"]["metadata_truncated"] is True
    # The request headers were small, so that side is not flagged.
    assert "metadata_truncated" not in payload["request"]
    assert payload["response"]["body"] == "small"
    # A bounded header map must not spill an artifact of its own.
    assert list(tmp_path.iterdir()) == []


def test_flow_get_flags_collapsed_duplicate_response_headers(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A flow with several Set-Cookie lines is flagged, not silently merged."""
    flow = _flow(
        {"accept": "*/*"},
        _MultiHeaders([("Set-Cookie", "a=1"), ("Set-Cookie", "b=2")]),
        body=b"ok",
    )
    backend = _backend_returning(flow, monkeypatch)
    payload = backend.flow_get("s", "f1", tmp_path)
    assert payload["response"]["headers"] == {"Set-Cookie": "b=2"}
    assert payload["response"]["metadata_truncated"] is True
    # The request headers had no duplicates, so that side is not flagged.
    assert "metadata_truncated" not in payload["request"]
