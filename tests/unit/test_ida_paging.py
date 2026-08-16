"""IDA list pages must say when they stopped."""

from __future__ import annotations

from headless_re_mcp.backends.ida.worker import _page_items


class TestIdaPageItemsSaysWhenItWasCut:
    """A page that filled used to look like the whole listing if total was unread.

    Measured: 250 items, limit 100, returned=100, total=250, no has_more,
    so an agent that only read the page treated it as the set.
    """

    def test_a_full_page_is_marked(self) -> None:
        page = _page_items([{"i": index} for index in range(250)], 0, 100)
        assert page["returned"] == 100
        assert page["total"] == 250
        assert page["has_more"] is True

    def test_the_last_page_is_not_labelled_partial(self) -> None:
        page = _page_items([{"i": index} for index in range(250)], 200, 100)
        assert page["returned"] == 50
        assert page["has_more"] is False

    def test_an_exact_page_is_complete(self) -> None:
        page = _page_items([{"i": index} for index in range(100)], 0, 100)
        assert page["returned"] == 100
        assert page["has_more"] is False
