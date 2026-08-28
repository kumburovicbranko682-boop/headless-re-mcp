"""The flow recorder's retained-byte budget must evict, not accumulate.

The recorder keeps whole flow objects (bodies included) in ``_raw`` so a later
``proxy.flow.get`` can return the payload. Left unbounded that is how an
unattended capture runs the host out of memory overnight, so two independent
caps apply: a single body over ``_MAX_STORED_BODY`` is never retained, and the
*sum* of retained bodies is held under ``_MAX_RETAINED_BYTES`` by omitting the
oldest bodies as newer flows arrive. The single-body cap is exercised
elsewhere; these pin the cross-flow eviction and the size accounting it rests
on -- the part that, if it silently stopped evicting, would leak memory for
exactly as long as a capture runs and show up as nothing until the OOM.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

import headless_re_mcp.backends.proxy.client as proxy_client
from headless_re_mcp.backends.proxy.client import (
    _MAX_FLOW_HEADERS_TOTAL_BYTES,
    _OMITTED_BODY,
    _bounded_headers,
    _content_len,
    _flow_stored_bytes,
    _FlowRecorder,
    _headers_len,
)


def _flow(flow_id: str, body: bytes) -> Any:
    """A completed flow whose response body is a chosen size.

    Short, predictable metadata so the stored-byte count is dominated by the
    body: the eviction tests choose caps relative to that body length.
    """
    request = SimpleNamespace(
        method="GET", pretty_url=f"http://x/{flow_id}", host="x", raw_content=b""
    )
    response = SimpleNamespace(
        status_code=200,
        headers={"content-type": "application/octet-stream"},
        raw_content=body,
    )
    return SimpleNamespace(id=flow_id, request=request, response=response)


# --- size accounting: the defensive arms that keep accounting from raising ---


def test_content_len_of_an_unmeasurable_body_is_zero_not_a_raise() -> None:
    """A raw_content that is truthy but has no len() counts as zero, not a crash.

    _flow_stored_bytes runs on the recorder's event-loop thread for every flow;
    a body object whose len() raises (a version-varying or hostile stand-in)
    must not take down the capture. The recorder would rather undercount by one
    body than stop recording.
    """

    class _NoLen:
        def __bool__(self) -> bool:
            return True

    part = SimpleNamespace(raw_content=_NoLen())
    assert _content_len(part) == 0


def test_content_len_of_a_bodyless_part_is_zero() -> None:
    assert _content_len(SimpleNamespace(raw_content=b"")) == 0
    assert _content_len(SimpleNamespace()) == 0
    assert _content_len(None) == 0


def test_headers_len_of_an_uniterable_header_set_is_zero_not_a_raise() -> None:
    """Header iteration that raises anything but TypeError still yields zero.

    The inner TypeError fallback handles the items(multi=True) signature drift;
    the outer guard is for a header object that raises something else entirely.
    Either way the accounting returns a number rather than propagating.
    """

    class _AngryHeaders:
        def items(self, *args: Any, **kwargs: Any) -> Any:
            raise RuntimeError("headers cannot be iterated")

    assert _headers_len(SimpleNamespace(headers=_AngryHeaders())) == 0
    assert _headers_len(SimpleNamespace(headers=None)) == 0
    assert _headers_len(SimpleNamespace()) == 0


def test_flow_stored_bytes_counts_the_response_body_it_is_budgeting() -> None:
    """The retained-byte figure must reflect the body, since that is what it caps.

    A flow with a body must account for more bytes than the same flow with an
    empty one, by at least the body length -- if the body did not count, the
    budget would be measuring metadata while the bytes it exists to bound grew
    unchecked.
    """
    empty = _flow_stored_bytes(_flow("a", b""))
    with_body = _flow_stored_bytes(_flow("a", b"\x00" * 4096))
    assert with_body - empty >= 4096


def test_bounded_headers_stops_at_the_total_byte_cap() -> None:
    """flow.get header maps are capped in total size, not just count and value.

    A server can send many headers each under the per-value cap whose sum is
    still megabytes; _bounded_headers stops once the running total crosses
    _MAX_FLOW_HEADERS_TOTAL_BYTES and flags the map as truncated so the caller
    does not read a bounded view as the whole header set.
    """
    value = "v" * 4000  # under _MAX_HEADER_VALUE_BYTES (4 KiB), so not per-value cut
    headers = {f"h{index:03d}": value for index in range(40)}  # 40 * ~4 KiB > 64 KiB
    part = SimpleNamespace(headers=headers)

    mapped, truncated = _bounded_headers(part)

    assert truncated is True
    kept_bytes = sum(len(k.encode()) + len(v.encode()) for k, v in mapped.items())
    assert kept_bytes <= _MAX_FLOW_HEADERS_TOTAL_BYTES
    assert len(mapped) < len(headers)


# --- cross-flow eviction: the overnight-OOM guarantee ---


def test_a_new_flow_evicts_the_oldest_bodies_to_stay_under_the_retained_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When retainable bodies will not all fit, the oldest are omitted first.

    Each body is well under the single-body cap, so each is individually
    retainable; three together exceed the retained-byte budget while two fit.
    Recording the third must omit the oldest flow's body -- and only as many as
    the budget requires -- keeping the raw store and the summary ring in
    lockstep. The eviction scans newest-first to flag the right summary, so this
    also covers passing over a newer, still-retained row to reach the old one.
    """
    monkeypatch.setattr(proxy_client, "_MAX_RETAINED_BYTES", 7000)
    recorder = _FlowRecorder(capacity=8)

    recorder.response(_flow("a", b"\x00" * 3000))
    recorder.response(_flow("b", b"\x00" * 3000))
    assert recorder.raw("a") is not _OMITTED_BODY
    assert recorder.raw("b") is not _OMITTED_BODY

    recorder.response(_flow("c", b"\x00" * 3000))

    # Only the oldest body was dropped -- just enough to fit the newcomer.
    assert recorder.raw("a") is _OMITTED_BODY
    assert recorder.raw("b") is not _OMITTED_BODY
    assert recorder.raw("c") is not _OMITTED_BODY
    assert recorder.retained_bytes() <= 7000
    # The summary ring must agree with the raw store: 'a' is flagged omitted,
    # 'b'/'c' are not, so flow.get and proxy.flows never disagree about a body.
    rows = {row["id"]: row for row in recorder.snapshot()}
    assert rows["a"].get("body_omitted") is True
    assert "body_omitted" not in rows["b"]
    assert "body_omitted" not in rows["c"]


def test_eviction_scan_skips_a_flow_whose_body_is_already_omitted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A flow held only as the omitted sentinel is passed over, not re-omitted.

    An over-cap body is kept in the raw store as the sentinel with no retained
    bytes; a later eviction scan encounters it before a real body. It must skip
    it -- it frees nothing and is already flagged -- and go on to evict an
    actually-retained older flow. Shrinking the per-body cap makes a small body
    over-cap so this needs no multi-megabyte payload.
    """
    monkeypatch.setattr(proxy_client, "_MAX_STORED_BODY", 1000)
    monkeypatch.setattr(proxy_client, "_MAX_RETAINED_BYTES", 1200)
    recorder = _FlowRecorder(capacity=8)

    recorder.response(_flow("big", b"\x00" * 3000))  # over per-body cap -> sentinel
    assert recorder.raw("big") is _OMITTED_BODY
    recorder.response(_flow("a", b"\x00" * 600))  # retained
    assert recorder.raw("a") is not _OMITTED_BODY

    # Recording 'b' overflows the retained budget; the scan meets 'big' (already
    # a sentinel, skipped) then omits the retained 'a' to make room.
    recorder.response(_flow("b", b"\x00" * 600))

    assert recorder.raw("a") is _OMITTED_BODY
    assert recorder.raw("b") is not _OMITTED_BODY
    assert recorder.retained_bytes() <= 1200


def test_a_body_that_alone_blows_the_budget_is_omitted_on_arrival(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A retainable-sized body is still omitted when it alone exceeds the budget.

    This is the second omission trigger, distinct from the single-body cap: the
    body is under _MAX_STORED_BODY (so the per-body check passes) yet larger than
    the whole retained budget, so after finding nothing older to evict the
    recorder omits the arriving flow itself.
    """
    monkeypatch.setattr(proxy_client, "_MAX_RETAINED_BYTES", 1000)
    recorder = _FlowRecorder(capacity=8)

    recorder.response(_flow("solo", b"\x00" * 3000))

    assert recorder.raw("solo") is _OMITTED_BODY
    assert recorder.retained_bytes() == 0
    assert recorder.snapshot()[0].get("body_omitted") is True


def test_omitting_an_already_omitted_flow_is_a_safe_no_op() -> None:
    """_omit_retained must be idempotent, or the retained total would drift.

    The eviction loop guards against calling it twice, but the accounting must
    not depend on that guard being perfect: a second omission of the same flow
    (or of one never retained) leaves the retained total and the summary flag
    exactly as the first left them, never double-subtracting into a negative.
    """
    recorder = _FlowRecorder(capacity=8)
    recorder.response(_flow("a", b"\x00" * 3000))

    recorder._omit_retained("a")
    after_first = recorder.retained_bytes()
    assert recorder.raw("a") is _OMITTED_BODY
    assert after_first >= 0

    recorder._omit_retained("a")  # already omitted -> early return
    recorder._omit_retained("never-seen")  # unknown id -> early return
    assert recorder.retained_bytes() == after_first
    assert recorder.snapshot()[0].get("body_omitted") is True
    # The unknown id must not have been minted into the raw store as a sentinel:
    # without the early return, omitting an id it never held would insert one,
    # leaving flow.get to advertise a body the recorder never captured.
    assert recorder.raw("never-seen") is None


def test_omit_retained_frees_bytes_even_when_the_summary_row_is_already_gone() -> None:
    """The raw store, not the summary ring, is the source of truth for bytes.

    The two rings evict in lockstep, but the summary deque is capacity-bounded
    and can drop a row while the raw body is still held. Omitting such a flow
    must still reclaim its bytes -- the marking loop simply finds no row to flag
    and returns, rather than leaving the retained total stranded above zero.
    """
    recorder = _FlowRecorder(capacity=8)
    recorder.response(_flow("a", b"\x00" * 3000))
    assert recorder.retained_bytes() > 0

    recorder.flows.clear()  # summary row gone; raw body still retained
    recorder._omit_retained("a")

    assert recorder.raw("a") is _OMITTED_BODY
    assert recorder.retained_bytes() == 0
