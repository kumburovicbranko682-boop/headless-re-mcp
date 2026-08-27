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


def _flow(req_headers: dict[str, str], resp_headers: dict[str, str], *, body: bytes = b"") -> Any:
    request = SimpleNamespace(method="GET", pretty_url="http://x/1", headers=req_headers)
    response = SimpleNamespace(status_code=200, headers=resp_headers, raw_content=body)
    return SimpleNamespace(request=request, response=response)


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
