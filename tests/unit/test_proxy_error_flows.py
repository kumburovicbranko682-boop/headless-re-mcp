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


def _aborted_flow(flow_id: str) -> Any:
    # A flow the client aborted mid-response: mitmproxy handed the response, then
    # fired error on the *same* flow object (same id), so it carries both a
    # response and an error. The recorder sees response(flow) then error(flow).
    request = SimpleNamespace(method="GET", pretty_url=f"http://x/{flow_id}", host="x")
    response = SimpleNamespace(status_code=200, headers={"content-type": "text/plain"})
    error = SimpleNamespace(msg="net::ERR_ABORTED")
    return SimpleNamespace(id=flow_id, request=request, response=response, error=error)


def test_response_then_error_on_one_flow_does_not_double_or_desync() -> None:
    """A re-recorded flow.id must replace its summary, not append a second one.

    mitmproxy fires ``response`` then ``error`` for the same flow when a client
    aborts mid-response, so ``_record`` runs twice for one flow.id. ``_raw``
    already de-duplicates (pop + re-insert), but the summary ring is a deque that
    appended a second row -- so the list showed the flow twice, and the duplicate
    append could push the deque to evict a *different* flow whose raw was still
    retained, the exact summary/raw disagreement the lockstep eviction promises
    can't happen. Here two other flows fill a capacity-2 recorder to a single
    slot each, then a third flow is recorded twice: the ring must still hold two
    distinct ids with no duplicate, and every summarized id must be retrievable.
    """
    recorder = _FlowRecorder(capacity=2)
    recorder.response(_ok_flow("a"))
    aborted = _aborted_flow("b")
    recorder.response(aborted)
    recorder.error(aborted)

    rows = recorder.snapshot()
    ids = [row["id"] for row in rows]
    assert ids.count("b") == 1, "the re-recorded flow was summarized twice"
    assert set(ids) == {"a", "b"}, "a distinct flow was evicted by the duplicate"
    # The second record won and merged: b keeps the upstream status it received
    # (200) and gains the error mark for the aborted delivery -- the informative
    # readout of a client-abort-mid-response. Both summarized ids still resolve in
    # the raw store, so there is no row the list shows that flow_get would 404.
    by_id = {row["id"]: row for row in rows}
    assert by_id["b"]["error"] is True
    assert by_id["b"]["status"] == 200
    for flow_id in ids:
        assert recorder.raw(flow_id) is not None


def test_dropped_counts_evictions_not_re_records() -> None:
    """A re-recorded flow.id must not be counted as a dropped row.

    ``dropped`` used to be inferred in ``flows()`` as the newest summary's seq
    minus the retained count. seq counts ``_record`` calls, so a flow recorded
    twice (mitmproxy's response-then-error on a client abort) bumped seq without
    adding a distinct retained row -- the estimate then reported a phantom drop
    for a ring that lost nothing. The recorder now counts evictions exactly. Here
    a capacity-3 ring takes three distinct flows (nothing evicted) and then
    re-records one of them: dropped must stay 0. A fourth distinct flow then
    evicts the oldest, so dropped becomes exactly 1.
    """
    recorder = _FlowRecorder(capacity=3)
    for flow_id in ("a", "b", "c"):
        recorder.response(_ok_flow(flow_id))
    assert recorder.dropped() == 0

    aborted = _aborted_flow("b")
    recorder.response(aborted)
    recorder.error(aborted)
    assert recorder.dropped() == 0, "a re-record was counted as a dropped row"

    recorder.response(_ok_flow("d"))
    assert recorder.dropped() == 1


def test_docstring_names_the_error_fields() -> None:
    doc = _tool_docstring("proxy.flows")
    assert "error" in doc
    assert "error_msg" in doc
