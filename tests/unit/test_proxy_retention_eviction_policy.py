"""The proxy body-retention budget evicts oldest-first, and only as much as needed.

When a new flow arrives and its body would push ``_retained_bytes`` past
``_MAX_RETAINED_BYTES``, ``_FlowRecorder._record`` walks the retained bodies in
insertion order and omits them one at a time until the newcomer fits, stopping
the moment it does::

    if not omitted:
        for retained_id, retained in list(self._raw.items()):
            if self._retained_bytes + stored_bytes <= _MAX_RETAINED_BYTES:
                break
            if retained is not _OMITTED_BODY:
                self._omit_retained(retained_id)
        omitted = self._retained_bytes + stored_bytes > _MAX_RETAINED_BYTES
    self._raw[flow_id] = _OMITTED_BODY if omitted else flow

Two properties of that loop are load-bearing, and the existing budget test --
two 600-byte flows against a 1000-byte budget -- leaves both inert because it has
only a single eviction candidate:

* **Oldest-first, and no more than necessary.** ``list(self._raw.items())`` is
  insertion order, so the oldest bodies go first, and the ``break`` stops as soon
  as room is made. With one victim you cannot tell oldest-first from newest-first,
  nor "evict just enough" from "evict everything". Iterate newest-first and the
  wrong (recent, more interesting) body is dropped while a stale one is kept; drop
  the ``break`` and a single large arrival flushes the entire retain ring.

* **A newcomer bigger than the whole budget is itself omitted.** After evicting
  everything, if the arrival still does not fit, the recomputed ``omitted`` on the
  line after the loop marks *it* omitted rather than retaining a body that alone
  blows the cap. The existing test's second flow fits once the first is gone, so
  that recompute is never taken in its true branch.

These drive both with a fresh ``_FlowRecorder`` -- no mitmproxy, no sockets.
"""

from __future__ import annotations

from typing import Any

import pytest

from headless_re_mcp.backends.proxy import client as mod


class _FakeHeaders(dict):  # type: ignore[type-arg]
    def get(self, key: str, default: str = "") -> str:
        return dict.get(self, key, default)


def _flow(index: int, body_bytes: int) -> Any:
    flow = type("F", (), {})()
    flow.id = f"flow-{index}"
    flow.request = type(
        "Req",
        (),
        {
            "method": "GET",
            "pretty_url": f"https://example.com/{index}",
            "host": "example.com",
        },
    )()
    flow.response = type(
        "Resp",
        (),
        {"status_code": 200, "headers": _FakeHeaders({"content-type": "text/plain"})},
    )()
    flow.response.raw_content = b"x" * body_bytes
    return flow


def _summary(recorder: mod._FlowRecorder, flow_id: str) -> dict[str, Any]:
    for row in recorder.snapshot():
        if row["id"] == flow_id:
            return row
    raise AssertionError(f"no summary for {flow_id}")


def test_the_oldest_body_is_evicted_first_and_only_as_many_as_needed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A 4th body evicts just the oldest; the two middle bodies and it survive.

    Budget holds three bodies with half a body to spare. Adding a fourth needs
    one slot, so exactly the oldest (``flow-1``) is dropped and ``flow-2`` /
    ``flow-3`` / ``flow-4`` all stay retained. Newest-first would drop ``flow-3``
    and keep ``flow-1``; evicting everything would drop ``flow-2`` and ``flow-3``
    too.
    """
    per_flow = mod._flow_stored_bytes(_flow(1, 1000))
    monkeypatch.setattr(mod, "_MAX_STORED_BODY", per_flow * 100)
    monkeypatch.setattr(mod, "_MAX_RETAINED_BYTES", per_flow * 3 + per_flow // 2)
    recorder = mod._FlowRecorder(capacity=10)

    for index in (1, 2, 3):
        recorder.response(_flow(index, 1000))
    assert recorder.retained_bytes() == per_flow * 3

    recorder.response(_flow(4, 1000))

    assert recorder.raw("flow-1") is mod._OMITTED_BODY
    assert recorder.raw("flow-2") is not mod._OMITTED_BODY
    assert recorder.raw("flow-3") is not mod._OMITTED_BODY
    assert recorder.raw("flow-4") is not mod._OMITTED_BODY
    assert recorder.retained_bytes() == per_flow * 3

    assert _summary(recorder, "flow-1")["body_omitted"] is True
    for kept in ("flow-2", "flow-3", "flow-4"):
        assert "body_omitted" not in _summary(recorder, kept)


def test_a_newcomer_over_the_whole_budget_is_omitted_after_evicting_the_rest(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A body larger than the entire budget is dropped, not retained over cap.

    The arrival is under the per-flow cap but three times the whole retain
    budget. Evicting the one older body frees nothing near enough, so the
    recompute after the loop omits the newcomer itself; retained bytes settle at
    zero rather than blowing past the cap.
    """
    per_flow = mod._flow_stored_bytes(_flow(1, 1000))
    monkeypatch.setattr(mod, "_MAX_STORED_BODY", per_flow * 100)
    monkeypatch.setattr(mod, "_MAX_RETAINED_BYTES", per_flow)
    recorder = mod._FlowRecorder(capacity=10)

    recorder.response(_flow(1, 1000))
    assert recorder.raw("flow-1") is not mod._OMITTED_BODY

    recorder.response(_flow(2, 3000))

    assert recorder.raw("flow-1") is mod._OMITTED_BODY
    assert recorder.raw("flow-2") is mod._OMITTED_BODY
    assert recorder.retained_bytes() == 0
    assert _summary(recorder, "flow-2")["body_omitted"] is True
