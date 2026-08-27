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
    _MAX_STORED_BODY,
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


def _flow_with_body(flow_id: str, body: bytes) -> Any:
    """A completed flow whose response body is a chosen size.

    The recorder decides to retain or omit a flow by its stored byte count, so a
    body over ``_MAX_STORED_BODY`` is the real trigger for the ``_OMITTED_BODY``
    sentinel -- this drives that decision through the public ``response`` hook
    rather than writing the sentinel into private state by hand.
    """
    request = SimpleNamespace(
        method="POST", pretty_url=f"http://x/{flow_id}", host="x", raw_content=b""
    )
    response = SimpleNamespace(
        status_code=200,
        headers={"content-type": "application/octet-stream"},
        raw_content=body,
    )
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

    def test_flow_get_of_an_omitted_body_is_too_large(self, tmp_path: Path) -> None:
        """A flow the ring dropped to stay under its memory cap is too_large, not a crash.

        A body over ``_MAX_STORED_BODY`` is replaced in the raw store by the
        ``_OMITTED_BODY`` sentinel so an overnight capture cannot OOM the host. flow_get
        must recognise that sentinel and answer too_large: dereferencing it as a real
        flow (``.request``) would raise AttributeError on a bare ``object()`` and be
        filed as an internal_error incident, for what is a documented, benign retention
        outcome. The summary still lists the row with body_omitted, so the caller learns
        the flow existed and only its body is gone -- not a 404 for a row the list shows.
        """
        backend = self._backend_with_empty_session()
        recorder = backend._instances["s"].recorder
        recorder.response(_flow_with_body("big", b"\x00" * (_MAX_STORED_BODY + 1)))
        # Premise: the oversized body really was dropped to the sentinel.
        assert recorder.raw("big") is _OMITTED_BODY
        assert recorder.snapshot()[0].get("body_omitted") is True
        with pytest.raises(ProxyError) as info:
            backend.flow_get("s", "big", tmp_path)
        assert info.value.code == "too_large"
        assert info.value.details.get("flow_id") == "big"

    def test_replay_of_an_omitted_body_is_too_large(self) -> None:
        """Replaying a flow whose body was dropped cannot reconstruct the request.

        replay copies the stored flow and re-sends it; with only the ``_OMITTED_BODY``
        sentinel there is nothing to copy, so it must answer too_large rather than call
        ``.copy()`` on the sentinel object. This is the replay twin of the flow_get guard
        above -- the same retention outcome, refused on the re-send path too, before any
        attempt to reach the (here absent) master.
        """
        backend = self._backend_with_empty_session()
        recorder = backend._instances["s"].recorder
        recorder.response(_flow_with_body("big", b"\x00" * (_MAX_STORED_BODY + 1)))
        assert recorder.raw("big") is _OMITTED_BODY
        with pytest.raises(ProxyError) as info:
            backend.replay("s", "big")
        assert info.value.code == "too_large"
        assert info.value.details.get("flow_id") == "big"

    def test_replay_of_a_retained_flow_without_a_running_master_is_invalid_state(self) -> None:
        """A retrievable flow still cannot be replayed once the proxy is not running.

        Distinct from the no-session case: here the session exists and the flow is
        retained, but the instance has no live master/loop -- it was started then
        stopped, or is mid-teardown. replay needs a running event loop to hand the copy
        to ``replay.client``, so with a None master it must report invalid_state 'proxy
        is not running' rather than dereferencing None. ``_ProxyInstance`` carries a real
        recorder but a None master until start() runs, which is exactly this state.
        """
        backend = self._backend_with_empty_session()
        recorder = backend._instances["s"].recorder
        recorder.response(_ok_flow("ok"))
        # Premise: the flow is genuinely retrievable, so the refusal is about the
        # missing master, not a missing or omitted flow.
        assert recorder.raw("ok") not in (None, _OMITTED_BODY)
        with pytest.raises(ProxyError) as info:
            backend.replay("s", "ok")
        assert info.value.code == "invalid_state"
        assert "not running" in info.value.message
