"""A mitmproxy flow that errored must be captured, not silently dropped.

Only the response hook was wired, so a flow mitmproxy could not complete (TLS
handshake refused, upstream unreachable, connection reset mid-request) never
entered the capture at all -- for an RE session, "this host refused the
handshake" is often the finding, and it was being thrown away. These lock in
that the error hook records such a flow, marks it (error / error_msg, null
status), keeps it retrievable like any other, bounds the message, falls back
when no message is present, and leaves the completed-response path untouched.
"""

from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from headless_re_mcp.backends.proxy.client import (
    _MAX_METADATA_BYTES,
    _OMITTED_BODY,
    _FlowRecorder,
)
from headless_re_mcp.tools.proxy import build_proxy_tools


def _tool_docstring(name: str) -> str:
    source = Path(build_proxy_tools.__code__.co_filename).read_text(encoding="utf-8")
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        for decorator in node.decorator_list:
            if not isinstance(decorator, ast.Call):
                continue
            for keyword in decorator.keywords:
                if (
                    keyword.arg == "name"
                    and isinstance(keyword.value, ast.Constant)
                    and keyword.value.value == name
                ):
                    return ast.get_docstring(node) or ""
    return ""


def _errored_flow(flow_id: str, msg: str | None = "net::ERR_CONNECTION_REFUSED") -> Any:
    request = SimpleNamespace(method="GET", pretty_url=f"http://x/{flow_id}", host="x")
    error = SimpleNamespace(msg=msg) if msg is not None else None
    return SimpleNamespace(id=flow_id, request=request, response=None, error=error)


def _ok_flow(flow_id: str) -> Any:
    request = SimpleNamespace(method="GET", pretty_url=f"http://x/{flow_id}", host="x")
    response = SimpleNamespace(status_code=200, headers={"content-type": "text/plain"})
    return SimpleNamespace(id=flow_id, request=request, response=response)


def test_errored_flow_is_captured_and_marked() -> None:
    recorder = _FlowRecorder(capacity=8)
    recorder.error(_errored_flow("e1"))

    rows = recorder.snapshot()
    assert len(rows) == 1
    row = rows[0]
    assert row["error"] is True
    assert row["error_msg"] == "net::ERR_CONNECTION_REFUSED"
    assert row["status"] is None
    assert row["url"] == "http://x/e1"


def test_errored_flow_is_distinct_from_a_completed_one() -> None:
    recorder = _FlowRecorder(capacity=8)
    recorder.response(_ok_flow("ok"))
    recorder.error(_errored_flow("boom"))

    by_id = {row["id"]: row for row in recorder.snapshot()}
    assert by_id["ok"]["status"] == 200
    assert "error" not in by_id["ok"]
    assert by_id["boom"]["status"] is None
    assert by_id["boom"]["error"] is True


def test_error_message_is_bounded() -> None:
    recorder = _FlowRecorder(capacity=8)
    recorder.error(_errored_flow("big", msg="é" * (_MAX_METADATA_BYTES + 1)))

    row = recorder.snapshot()[0]
    assert len(str(row["error_msg"]).encode()) <= _MAX_METADATA_BYTES
    assert row["metadata_truncated"] is True


def test_error_falls_back_when_no_message() -> None:
    recorder = _FlowRecorder(capacity=8)
    recorder.error(_errored_flow("nomsg", msg=None))

    row = recorder.snapshot()[0]
    assert row["error"] is True
    assert row["error_msg"] == "flow error"


def test_errored_flow_is_retrievable_like_a_normal_flow() -> None:
    # The summary ring and the raw store are kept in lockstep on purpose; an
    # errored flow must live in both so flow_get does not 404 a row the list
    # advertises.
    recorder = _FlowRecorder(capacity=8)
    flow = _errored_flow("e1")
    recorder.error(flow)

    retained = recorder.raw("e1")
    assert retained is flow
    assert retained is not _OMITTED_BODY
    assert recorder.count() == 1


def test_completed_response_path_carries_no_error_field() -> None:
    recorder = _FlowRecorder(capacity=8)
    recorder.response(_ok_flow("ok"))

    row = recorder.snapshot()[0]
    assert "error" not in row
    assert "error_msg" not in row
    assert row["status"] == 200


def _completed_then_errored(flow_id: str) -> Any:
    """One flow that carries both a response and an error.

    mitmproxy delivers this shape when a response completes and the connection
    then resets while the body is still streaming: the flow object gains an
    ``error`` after ``response`` already ran.
    """
    request = SimpleNamespace(method="GET", pretty_url=f"http://x/{flow_id}", host="x")
    response = SimpleNamespace(status_code=200, headers={"content-type": "text/plain"})
    error = SimpleNamespace(msg="net::ERR_INCOMPLETE_CHUNKED_ENCODING")
    return SimpleNamespace(id=flow_id, request=request, response=response, error=error)


def test_a_flow_recorded_twice_is_listed_once() -> None:
    # Since the error hook was wired, mitmproxy can call response() and then
    # error() for the same flow. The raw store is keyed by id and dedups, but
    # the summary ring is an append-only deque: without dropping the stale row
    # the flow would list twice -- one row with a status, one flagged errored --
    # while flow.get returns the single retained flow, the exact two-views
    # disagreement the lockstep eviction exists to prevent.
    recorder = _FlowRecorder(capacity=8)
    flow = _completed_then_errored("dup")

    recorder.response(flow)
    recorder.error(flow)

    rows = recorder.snapshot()
    assert [row["id"] for row in rows] == ["dup"]
    assert recorder.count() == 1
    # The later record wins, so the one surviving row reflects the error.
    assert rows[0]["error"] is True
    assert recorder.raw("dup") is flow


def test_re_recording_a_flow_does_not_inflate_the_dropped_count() -> None:
    # dropped counts flows evicted because the ring filled, not the number of
    # times a flow was touched. A single flow recorded twice must still report
    # zero drops and a total of one, not the seq-minus-length heuristic's stale
    # answer once a re-record could bump the sequence without adding a row.
    from headless_re_mcp.backends.proxy.client import ProxyBackend, _ProxyInstance

    recorder = _FlowRecorder(capacity=8)
    flow = _completed_then_errored("dup")
    recorder.response(flow)
    recorder.error(flow)

    inst = _ProxyInstance("127.0.0.1", 1)
    inst.recorder = recorder
    backend = ProxyBackend()
    backend._instances["s"] = inst
    result = backend.flows("s", offset=0, limit=100)
    assert result["total"] == 1
    assert result["count"] == 1
    assert result["dropped"] == 0


def test_docstring_names_the_error_fields() -> None:
    doc = _tool_docstring("proxy.flows")
    assert "error" in doc
    assert "error_msg" in doc
