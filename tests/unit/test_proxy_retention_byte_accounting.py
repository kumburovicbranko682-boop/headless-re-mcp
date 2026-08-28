"""The proxy retain-ring's byte accounting must fail *safe* (no live mitmproxy).

``_FlowRecorder`` keeps whole flow objects -- headers and bodies -- in a ring so
``proxy.flow.get`` can hand back a captured request/response later. That ring is
the piece that runs an unattended capture out of memory overnight, so each flow
is weighed by ``_flow_stored_bytes`` and, when a single flow is heavier than
``_MAX_STORED_BODY``, its body is dropped (``body_omitted``) instead of retained.

The weighing helpers underneath -- ``_content_len``, ``_encoded_len``,
``_headers_len`` -- are where that bound actually holds, and the covered tests
only ever weigh ordinary flows. The load-bearing rule for a memory guard is that
an *un*-measurable input is treated as *over* budget, never under: a value that
cannot be stringified counts as more than the cap (so its flow is omitted), a
header set is summed only up to the cap and not walked unboundedly (a hostile
server can send thousands), and a body length that cannot be taken reads as
zero rather than crashing the recorder. Under-counting any of these would let a
flow that should have been dropped stay resident -- the exact leak the ring
exists to prevent. These tests pin each helper's fail-safe direction and the
end-to-end omission it drives, with the cap shrunk so the fixtures stay cheap.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

import headless_re_mcp.backends.proxy.client as proxy_client
from headless_re_mcp.backends.proxy.client import _FlowRecorder


class _Headers:
    """A minimal mitmproxy-style header map exposing ``items(multi=True)``."""

    def __init__(self, pairs: list[tuple[str, Any]]) -> None:
        self._pairs = pairs

    def items(self, multi: bool = False) -> list[tuple[str, Any]]:
        return list(self._pairs)

    def get(self, name: str, default: str = "") -> str:
        for key, value in self._pairs:
            if key == name:
                return value  # type: ignore[return-value]
        return default


class _Unstringable:
    """A value whose ``str()`` raises -- stands in for any field the accounting
    cannot honestly measure."""

    def __str__(self) -> str:
        raise RuntimeError("this value cannot be rendered")


def _flow(flow_id: str, header_pairs: list[tuple[str, Any]], *, body: bytes = b"body") -> Any:
    request = SimpleNamespace(
        method="GET",
        pretty_url="http://example.test/1",
        host="example.test",
        headers=_Headers(header_pairs),
        raw_content=body,
    )
    return SimpleNamespace(id=flow_id, request=request, response=None)


def test_encoded_len_counts_an_unmeasurable_value_as_over_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A value that cannot be stringified must weigh *more* than the cap.

    This is the direction that matters: if it weighed zero, a flow carrying such
    a field would slip under the retain threshold and stay resident with its
    body. Reported as ``_MAX_STORED_BODY + 1`` it pushes the flow over the line
    and its body is dropped -- fail safe, not fail open.
    """
    monkeypatch.setattr(proxy_client, "_MAX_STORED_BODY", 100)

    assert proxy_client._encoded_len(_Unstringable()) == 101
    # A measurable value is still its exact UTF-8 byte length (three bytes here).
    assert proxy_client._encoded_len("abc") == 3
    # Bytes counted by their encoded length, not character count: é is two bytes.
    assert proxy_client._encoded_len("é") == 2


def test_content_len_takes_a_body_length_or_falls_safely_to_zero() -> None:
    """A real body reports its byte length; an absent, empty, or non-sized
    ``raw_content`` reads as zero rather than raising out of the recorder."""
    assert proxy_client._content_len(None) == 0
    assert proxy_client._content_len(SimpleNamespace(raw_content=b"")) == 0
    assert proxy_client._content_len(SimpleNamespace(raw_content=b"xyz")) == 3
    # A truthy value that has no length (a malformed flow object) does not crash
    # the size probe -- it contributes zero.
    assert proxy_client._content_len(SimpleNamespace(raw_content=5)) == 0


def test_headers_len_stops_summing_at_the_stored_cap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A chatty or hostile server can send thousands of headers; the sum must be
    bounded, not walked whole. Past the cap the count stops, so the result is a
    little over the cap -- never the full, unbounded total."""
    monkeypatch.setattr(proxy_client, "_MAX_STORED_BODY", 100)
    pairs: list[tuple[str, Any]] = [(f"h{index}", "v" * 50) for index in range(20)]
    full_sum = sum(
        len(str(k).encode("utf-8")) + len(str(v).encode("utf-8")) for k, v in pairs
    )

    measured = proxy_client._headers_len(SimpleNamespace(headers=_Headers(pairs)))

    assert measured >= 100, "the sum must reach the cap before it stops"
    assert measured < full_sum, "it must stop at the cap, not walk every header"
    assert measured <= 100 + 60, "at most one over-cap entry is added before the break"


def test_headers_len_of_unreadable_or_absent_headers_is_zero() -> None:
    """A missing header map, or one whose iteration raises, contributes zero
    rather than propagating an exception through flow capture."""

    class _BadHeaders:
        def items(self, multi: bool = False) -> list[tuple[str, Any]]:
            raise RuntimeError("iteration exploded")

    assert proxy_client._headers_len(SimpleNamespace(headers=None)) == 0
    assert proxy_client._headers_len(SimpleNamespace(headers=_BadHeaders())) == 0


def test_a_flow_whose_headers_blow_the_cap_has_its_body_omitted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """End to end: a flow measured heavier than the per-flow cap is recorded
    with its body dropped, so the retain ring never grows by it.

    The summary still lands (the capture is not lost), but ``raw`` holds the
    omission sentinel, ``retained_bytes`` stays at zero, and the summary is
    flagged ``body_omitted`` so a later ``flow.get`` cannot mistake a dropped
    body for an empty one.
    """
    monkeypatch.setattr(proxy_client, "_MAX_STORED_BODY", 100)
    recorder = _FlowRecorder()

    big_headers: list[tuple[str, Any]] = [(f"h{index}", "v" * 50) for index in range(20)]
    recorder.response(_flow("heavy", big_headers))

    assert recorder.retained_bytes() == 0
    assert recorder.raw("heavy") is proxy_client._OMITTED_BODY
    summary = recorder.snapshot()[0]
    assert summary["id"] == "heavy"
    assert summary["body_omitted"] is True


def test_a_flow_within_the_cap_keeps_its_body(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The control: a small flow is retained whole, so the omission above is the
    cap doing its job, not the recorder dropping everything."""
    monkeypatch.setattr(proxy_client, "_MAX_STORED_BODY", 100)
    recorder = _FlowRecorder()

    recorder.response(_flow("light", [("content-type", "text/plain")], body=b"ok"))

    assert recorder.retained_bytes() > 0
    assert recorder.raw("light") is not proxy_client._OMITTED_BODY
    assert "body_omitted" not in recorder.snapshot()[0]
