"""apk.* pagination is clamped at the backend, not only at the tool schema.

The apk.classes / apk.methods / apk.strings / apk.xrefs schemas bound offset and
limit, but the agent and OpenAI-bridge transports call the backend directly and
never run that pydantic validation -- only the MCP path does. Before the clamp,
a negative offset became a Python tail slice (``names[-1:-1+limit]`` returned an
empty page that still reported ``has_more``), and a negative limit an
all-but-the-tail slice (``names[0:-5]``), so page zero silently misread the DEX.

``_clamp_page`` is the guard that makes the window contract hold on every call
path: offset floors at 0, limit lands in ``1..max_limit``. These pin that
directly, since the enumerations it protects otherwise only run with androguard
and a real DEX.
"""

from __future__ import annotations

import pytest

from headless_re_mcp.backends.apk.client import _clamp_page


def test_a_normal_window_passes_through_unchanged() -> None:
    assert _clamp_page(10, 50, max_limit=100) == (10, 50)


def test_a_negative_offset_floors_at_zero_not_a_tail_slice() -> None:
    """A negative offset must become page zero, never a Python tail slice that
    would return an empty-but-has_more page for a bypassing transport."""
    assert _clamp_page(-1, 50, max_limit=100) == (0, 50)
    assert _clamp_page(-9999, 50, max_limit=100) == (0, 50)


@pytest.mark.parametrize("bad_limit", [0, -1, -500])
def test_a_non_positive_limit_becomes_one_not_an_all_but_tail_slice(
    bad_limit: int,
) -> None:
    """limit <= 0 must clamp to 1, never a negative slice bound that would drop
    the tail of the page."""
    start, cap = _clamp_page(0, bad_limit, max_limit=100)
    assert (start, cap) == (0, 1)


def test_a_limit_over_the_ceiling_is_capped_to_the_max() -> None:
    assert _clamp_page(0, 10_000, max_limit=100) == (0, 100)
    # Exactly at the ceiling is admitted unchanged.
    assert _clamp_page(0, 100, max_limit=100) == (0, 100)


def test_float_inputs_are_coerced_to_int_bounds() -> None:
    """A bypassing transport may hand floats; the window is still integer, so a
    slice built from it cannot raise on a fractional bound."""
    start, cap = _clamp_page(3.9, 7.9, max_limit=100)
    assert (start, cap) == (3, 7)
    assert isinstance(start, int) and isinstance(cap, int)
