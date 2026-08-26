"""bounded_tool_result caps tool replies and flags the cut as untrusted.

Both transports funnel tool output through this before it reaches the model:
an oversized reply is replaced by a summary carrying untrusted_tool_output, the
marker that tells the model a truncated blob of tool output is not to be obeyed
as instructions. It is exercised indirectly through apply_result_budget, but
its own edges -- the non-dict wrapping, the exact-size boundary, the summary
cap, and that untrusted marker -- were never pinned.
"""

from __future__ import annotations

import json

from headless_re_mcp.agent.context import bounded_tool_result


def _size(payload: object) -> int:
    return len(json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8"))


def test_a_small_dict_passes_through_unchanged() -> None:
    payload = {"ok": True, "data": {"n": 1}}
    out, truncated = bounded_tool_result(payload, max_bytes=1024)
    assert truncated is False
    assert out is payload


def test_a_non_dict_value_is_wrapped_rather_than_dropped() -> None:
    out, truncated = bounded_tool_result("hello", max_bytes=1024)
    assert truncated is False
    assert out == {"value": "hello"}


def test_an_oversized_reply_is_summarized_and_flagged_untrusted() -> None:
    payload = {"data": "x" * 100_000}
    out, truncated = bounded_tool_result(payload, max_bytes=4096)

    assert truncated is True
    # The security-relevant marker: a truncated tool blob must arrive labeled so
    # the model does not treat it as trusted instructions.
    assert out["untrusted_tool_output"] is True
    assert out["truncated"] is True
    assert out["original_bytes"] == _size(payload)
    # The replacement itself respects the budget it was enforcing.
    assert _size(out) <= 4096
    # The original oversized field is gone, not merely annotated.
    assert "x" * 100_000 not in json.dumps(out)


def test_the_boundary_is_inclusive_so_an_exact_fit_is_not_truncated() -> None:
    # Build a payload whose encoding is exactly the cap, then one byte over.
    base = {"v": ""}
    overhead = _size(base)  # {"v": ""} with empty string
    cap = overhead + 10
    exact = {"v": "a" * 10}
    assert _size(exact) == cap
    out, truncated = bounded_tool_result(exact, max_bytes=cap)
    assert truncated is False
    assert out is exact

    over = {"v": "a" * 11}
    _out, truncated_over = bounded_tool_result(over, max_bytes=cap)
    assert truncated_over is True


def test_the_summary_is_capped_by_half_the_budget_when_the_budget_is_small() -> None:
    payload = {"data": "z" * 50_000}
    out, truncated = bounded_tool_result(payload, max_bytes=1000)
    assert truncated is True
    # summary slice is encoded[: min(16_384, max_bytes // 2)] -> 500 chars here.
    assert len(out["summary"]) <= 500
