"""Coverage for the report value summarizer's dict/scalar branches.

``test_reporting.py`` renders whole reports. This pins ``_summarize_value``
directly, including the empty-dict em-dash the wider suite did not reach.
"""

from __future__ import annotations

from headless_re_mcp.reporting import _summarize_value


def test_empty_dict_summarizes_to_an_em_dash() -> None:
    assert _summarize_value({}) == "—"


def test_nonempty_dict_summarizes_key_value_pairs() -> None:
    summary = _summarize_value({"a": 1, "b": "two"})
    assert "a=1" in summary
    assert "b=two" in summary


def test_scalar_summarizes_through_the_cell_formatter() -> None:
    assert _summarize_value("plain") == "plain"


def test_a_dict_with_more_than_four_keys_says_it_was_cut() -> None:
    """Four keys shown out of six used to read as the whole value."""
    full = _summarize_value({"a": 1, "b": 2, "c": 3, "d": 4})
    assert not full.endswith("…")
    cut = _summarize_value({"a": 1, "b": 2, "c": 3, "d": 4, "e": 5, "f": 6})
    assert cut.endswith(", …")
    assert "e=" not in cut
