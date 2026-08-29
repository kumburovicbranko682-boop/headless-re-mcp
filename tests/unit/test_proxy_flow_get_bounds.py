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
    _MAX_METADATA_BYTES,
    ProxyBackend,
    _bounded_headers,
)


def _flow(req_headers: dict[str, str], resp_headers: dict[str, str], *, body: bytes = b"") -> Any:
    request = SimpleNamespace(method="GET", pretty_url="http://x/1", headers=req_headers)
    response = SimpleNamespace(status_code=200, headers=resp_headers, raw_content=body)
    return SimpleNamespace(request=request, response=response)


def _errored_flow(*, request: Any, msg: str | None = "net::ERR_CONNECTION_REFUSED") -> Any:
    error = SimpleNamespace(msg=msg) if msg is not None else None
    return SimpleNamespace(request=request, response=None, error=error)


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


def test_flow_get_bounds_request_headers_and_flags_truncation(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """The request side flags truncation independently of the response side.

    The mirror of the response case: a request carrying an oversized header map
    (a hostile client, a huge cookie jar) must have that map capped and the
    request marked metadata_truncated, while a small response stays unflagged.
    Without this only the response side's flag was ever exercised, so a
    regression that dropped the request-side flag would go unnoticed.
    """
    flow = _flow(
        {f"h{index}": "v" for index in range(_MAX_FLOW_HEADERS + 10)},
        {"content-type": "text/plain"},
        body=b"small",
    )
    backend = _backend_returning(flow, monkeypatch)
    payload = backend.flow_get("s", "f1", tmp_path)
    assert len(payload["request"]["headers"]) == _MAX_FLOW_HEADERS
    assert payload["request"]["metadata_truncated"] is True
    # The response headers were small, so that side is not flagged.
    assert "metadata_truncated" not in payload["response"]
    assert list(tmp_path.iterdir()) == []


def test_flow_get_of_an_errored_flow_surfaces_the_reason(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """Drilling into an errored flow must show why it failed, like the summary.

    proxy.flows marks an errored flow with error/error_msg; before this,
    flow.get dropped both, so the detail view of a listed failure was a null
    status and an empty response -- hiding the finding an RE session is after.
    """
    request = SimpleNamespace(method="GET", pretty_url="http://x/e1", headers={})
    backend = _backend_returning(_errored_flow(request=request), monkeypatch)
    payload = backend.flow_get("s", "e1", tmp_path)
    assert payload["error"] is True
    assert payload["error_msg"] == "net::ERR_CONNECTION_REFUSED"
    assert payload["response"]["status"] is None
    assert payload["request"]["url"] == "http://x/e1"


def test_flow_get_of_an_errored_flow_without_a_request_does_not_crash(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """An early failure leaves request None; the summary reads it, so must flow.get.

    A TLS/connection failure the error hook captured before any request line was
    parsed reaches the raw store with request None. Dereferencing req.method
    raised AttributeError and turned a benign, listed row into an internal_error
    incident on drill-in; empty method/url plus the error reason is the honest
    answer.
    """
    backend = _backend_returning(_errored_flow(request=None), monkeypatch)
    payload = backend.flow_get("s", "e1", tmp_path)
    assert payload["request"]["method"] == ""
    assert payload["request"]["url"] == ""
    assert payload["response"]["status"] is None
    assert payload["error"] is True
    assert payload["error_msg"] == "net::ERR_CONNECTION_REFUSED"


def test_flow_get_of_a_completed_flow_carries_no_error(tmp_path: Path, monkeypatch: Any) -> None:
    """The completed path must not sprout a spurious error field.

    The guard's complement: a normal flow (no flow.error) must answer with no
    top-level error/error_msg, so a reader never mistakes a success for a
    failure.
    """
    flow = _flow({"accept": "text/plain"}, {"content-type": "text/plain"}, body=b"ok")
    backend = _backend_returning(flow, monkeypatch)
    payload = backend.flow_get("s", "f1", tmp_path)
    assert "error" not in payload
    assert "error_msg" not in payload
    assert payload["response"]["status"] == 200


def test_flow_get_bounds_a_huge_error_message(tmp_path: Path, monkeypatch: Any) -> None:
    """A hostile/verbose error string is bounded like every other metadata field."""
    request = SimpleNamespace(method="GET", pretty_url="http://x/e1", headers={})
    huge = "é" * (_MAX_METADATA_BYTES + 100)
    backend = _backend_returning(_errored_flow(request=request, msg=huge), monkeypatch)
    payload = backend.flow_get("s", "e1", tmp_path)
    assert len(str(payload["error_msg"]).encode("utf-8")) <= _MAX_METADATA_BYTES
    assert payload["metadata_truncated"] is True
