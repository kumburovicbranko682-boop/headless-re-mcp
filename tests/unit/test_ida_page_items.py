"""IDA paged lists that hit the cap used to look complete."""

from __future__ import annotations

from headless_re_mcp.backends.ida.worker import _page_items


class TestIdaPagesSayWhenTheyStopped:
    """A page that hit the cap looks exactly like one that ended.

    Measured: 250 items, limit 100, returned=100, total=250, no has_more --
    so a caller that only looks at the page thinks the database ended.
    """

    def test_hitting_the_cap_is_reported(self) -> None:
        result = _page_items([{"n": index} for index in range(250)], 0, 100)
        assert result["returned"] == 100
        assert result["total"] == 250
        assert result["has_more"] is True

    def test_a_complete_answer_is_not_labelled_partial(self) -> None:
        result = _page_items([{"n": index} for index in range(3)], 0, 100)
        assert result["returned"] == 3
        assert result["has_more"] is False

    def test_a_result_that_exactly_fills_the_page_is_complete(self) -> None:
        result = _page_items([{"n": index} for index in range(100)], 0, 100)
        assert result["returned"] == 100
        assert result["has_more"] is False
