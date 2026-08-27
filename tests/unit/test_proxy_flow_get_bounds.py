"""proxy.flow.get returns an ordered, duplicate-preserving, bounded header list.

The response body is already spilled or capped, but the header set must be both
faithful and bounded. Faithful: HTTP headers are ordered and a name may repeat
(several ``Set-Cookie`` lines, a ``Via`` chain), so the map form ``dict(headers)``
that collapsed repeats to the last value silently dropped every cookie but the
last -- exactly what a session/auth analysis needs to read. flow.get now returns
an ordered ``[{name, value}]`` list, the same shape the HAR export uses. Bounded:
a chatty or hostile server (thousands of headers, a multi-kilobyte ``Set-Cookie``)
must not return an unbounded blob into the tool response. These tests pin the
duplicate preservation and wire order alongside the pair-count, per-value and
total-size bounds, and that a normal flow is returned untouched.
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


class _MultiHeaders:
    """Minimal stand-in for mitmproxy's ordered, multi-valued ``Headers``.

    ``items(multi=True)`` yields every pair in wire order including duplicates,
    the way mitmproxy does; ``items()`` returns the collapsed last-value-wins
    view, which is exactly the lossy shape the backend must no longer use.
    """

    def __init__(self, pairs: list[tuple[str, str]]) -> None:
        self._pairs = list(pairs)

    def items(self, multi: bool = False) -> list[tuple[str, str]]:
        if multi:
            return list(self._pairs)
        collapsed: dict[str, str] = {}
        for name, value in self._pairs:
            collapsed[name] = value
        return list(collapsed.items())


def _flow(req_headers: Any, resp_headers: Any, *, body: bytes = b"") -> Any:
    request = SimpleNamespace(method="GET", pretty_url="http://x/1", headers=req_headers)
    response = SimpleNamespace(status_code=200, headers=resp_headers, raw_content=body)
    return SimpleNamespace(request=request, response=response)


def _backend_returning(flow: Any, monkeypatch: Any) -> ProxyBackend:
    backend = ProxyBackend()
    recorder = SimpleNamespace(raw=lambda flow_id: flow)
    monkeypatch.setattr(backend, "_get", lambda session_id: SimpleNamespace(recorder=recorder))
    return backend


def test_bounded_headers_leaves_a_small_list_intact_and_ordered() -> None:
    out, truncated = _bounded_headers(SimpleNamespace(headers={"a": "1", "b": "2"}))
    assert out == [{"name": "a", "value": "1"}, {"name": "b", "value": "2"}]
    assert truncated is False


def test_bounded_headers_preserves_every_repeated_set_cookie_in_order() -> None:
    """The fix: repeated headers survive as separate pairs, in wire order.

    A dict form kept only ``sid=2`` here; a reverse engineer would then see one
    cookie where the server set two, and never know the session cookie existed.
    """
    headers = _MultiHeaders(
        [
            ("Set-Cookie", "sid=1; Path=/"),
            ("Set-Cookie", "sid=2; Path=/; HttpOnly"),
            ("Content-Type", "text/html"),
        ]
    )
    out, truncated = _bounded_headers(SimpleNamespace(headers=headers))
    assert out == [
        {"name": "Set-Cookie", "value": "sid=1; Path=/"},
        {"name": "Set-Cookie", "value": "sid=2; Path=/; HttpOnly"},
        {"name": "Content-Type", "value": "text/html"},
    ]
    # Nothing was dropped, so this is a faithful list, not a truncated one.
    assert truncated is False


def test_bounded_headers_caps_the_pair_count() -> None:
    many = _MultiHeaders([(f"h{index}", "v") for index in range(_MAX_FLOW_HEADERS + 50)])
    out, truncated = _bounded_headers(SimpleNamespace(headers=many))
    assert len(out) == _MAX_FLOW_HEADERS
    assert truncated is True


def test_bounded_headers_caps_a_single_huge_value() -> None:
    huge = "z" * (_MAX_HEADER_VALUE_BYTES * 4)
    out, truncated = _bounded_headers(SimpleNamespace(headers={"big": huge}))
    assert len(out) == 1
    assert out[0]["name"] == "big"
    assert len(out[0]["value"].encode("utf-8")) == _MAX_HEADER_VALUE_BYTES
    assert truncated is True


def test_bounded_headers_on_a_part_without_headers() -> None:
    out, truncated = _bounded_headers(SimpleNamespace())
    assert out == []
    assert truncated is False


def test_flow_get_bounds_response_headers_and_flags_truncation(
    tmp_path: Path, monkeypatch: Any
) -> None:
    flow = _flow(
        {"accept": "text/plain"},
        _MultiHeaders([(f"h{index}", "v") for index in range(_MAX_FLOW_HEADERS + 10)]),
        body=b"small",
    )
    backend = _backend_returning(flow, monkeypatch)
    payload = backend.flow_get("s", "f1", tmp_path)
    headers = payload["response"]["headers"]
    assert isinstance(headers, list)
    assert len(headers) == _MAX_FLOW_HEADERS
    assert all(set(pair) == {"name", "value"} for pair in headers)
    assert payload["response"]["metadata_truncated"] is True
    # The request headers were small, so that side is not flagged.
    assert "metadata_truncated" not in payload["request"]
    assert payload["response"]["body"] == "small"
    # A bounded header list must not spill an artifact of its own.
    assert list(tmp_path.iterdir()) == []


def test_flow_get_keeps_every_set_cookie_pair_end_to_end(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """Through the tool path, both Set-Cookie lines reach the caller in order."""
    flow = _flow(
        {"accept": "*/*"},
        _MultiHeaders(
            [
                ("Set-Cookie", "a=1"),
                ("Set-Cookie", "b=2"),
                ("Content-Type", "application/json"),
            ]
        ),
        body=b"{}",
    )
    backend = _backend_returning(flow, monkeypatch)
    payload = backend.flow_get("s", "f2", tmp_path)
    cookies = [h["value"] for h in payload["response"]["headers"] if h["name"] == "Set-Cookie"]
    assert cookies == ["a=1", "b=2"]
