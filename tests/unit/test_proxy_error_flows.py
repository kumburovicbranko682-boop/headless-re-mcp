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

import pytest

from headless_re_mcp.backends.proxy.client import (
    _MAX_METADATA_BYTES,
    _OMITTED_BODY,
    ProxyBackend,
    ProxyError,
    _FlowRecorder,
    _ProxyInstance,
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


def test_docstring_names_the_error_fields() -> None:
    doc = _tool_docstring("proxy.flows")
    assert "error" in doc
    assert "error_msg" in doc


class TestFlowGetAndReplayErrorClassification:
    """flow.get / replay must classify a bad flow id, not crash on it.

    The lifecycle gate proves the happy path (record a flow, fetch it, replay
    it); these pin the two error paths an agent hits in practice -- a stale or
    mistyped flow id, and calling before proxy.start -- without launching a real
    proxy. A _ProxyInstance carries a real empty recorder, so raw(flow_id)
    returns None and the not_found branch runs exactly as it would in
    production; a regression that dropped the None check would raise an
    AttributeError on the missing flow and be filed as an internal_error
    incident instead of the honest not_found.
    """

    def _backend_with_empty_session(self, session_id: str = "s") -> ProxyBackend:
        backend = ProxyBackend()
        backend._instances[session_id] = _ProxyInstance("127.0.0.1", 0)
        return backend

    def test_flow_get_unknown_id_is_not_found(self, tmp_path: Path) -> None:
        backend = self._backend_with_empty_session()
        with pytest.raises(ProxyError) as info:
            backend.flow_get("s", "no-such-flow", tmp_path)
        assert info.value.code == "not_found"
        assert info.value.details.get("flow_id") == "no-such-flow"

    def test_replay_unknown_id_is_not_found(self) -> None:
        backend = self._backend_with_empty_session()
        with pytest.raises(ProxyError) as info:
            backend.replay("s", "no-such-flow")
        assert info.value.code == "not_found"
        assert info.value.details.get("flow_id") == "no-such-flow"

    def test_reading_a_session_with_no_proxy_is_invalid_state(self, tmp_path: Path) -> None:
        """Before proxy.start there is no instance, so the lookup itself must
        report invalid_state rather than the read tools dereferencing None."""
        backend = ProxyBackend()
        with pytest.raises(ProxyError) as flow_info:
            backend.flow_get("never-started", "x", tmp_path)
        assert flow_info.value.code == "invalid_state"
        with pytest.raises(ProxyError) as replay_info:
            backend.replay("never-started", "x")
        assert replay_info.value.code == "invalid_state"
