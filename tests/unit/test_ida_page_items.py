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


class TestStaticCalleesDescriptionMatchesTheCut:
    """static.callees now pages with has_more, but the tool text hid that.

    Measured: 250 items, limit 100, has_more=true, while the description
    said "list call-type callees" -- so a model treats a page as every callee.
    """

    def test_the_tool_text_says_to_check_has_more(self) -> None:
        from headless_re_mcp.core.service import AnalysisService
        from headless_re_mcp.tools.core import build_static_extended_tools

        service = AnalysisService()
        try:
            tools = {item.name: item for item in build_static_extended_tools(service)}
            doc = tools["static.callees"].handler.__doc__ or ""
        finally:
            service.close_all()
        assert "has_more" in doc


class TestStaticCallersDescriptionMatchesTheCut:
    """static.callers now pages with has_more, but the tool text hid that.

    Measured: 250 items, limit 100, has_more=true, while the description
    said "list call-type callers" -- so a model treats a page as every caller.
    """

    def test_the_tool_text_says_to_check_has_more(self) -> None:
        from headless_re_mcp.core.service import AnalysisService
        from headless_re_mcp.tools.core import build_static_extended_tools

        service = AnalysisService()
        try:
            tools = {item.name: item for item in build_static_extended_tools(service)}
            doc = tools["static.callers"].handler.__doc__ or ""
        finally:
            service.close_all()
        assert "has_more" in doc


class TestStaticExportsDescriptionMatchesTheCut:
    """static.exports now pages with has_more, but the tool text hid that.

    Measured: 250 items, limit 100, has_more=true, while the description
    said "list exported entries" -- so a model treats a page as every export.
    """

    def test_the_tool_text_says_to_check_has_more(self) -> None:
        from headless_re_mcp.core.service import AnalysisService
        from headless_re_mcp.tools.core import build_static_extended_tools

        service = AnalysisService()
        try:
            tools = {item.name: item for item in build_static_extended_tools(service)}
            doc = tools["static.exports"].handler.__doc__ or ""
        finally:
            service.close_all()
        assert "has_more" in doc


class TestStaticXrefsFromDescriptionMatchesTheCut:
    """static.xrefs_from now pages with has_more, but the tool text hid that.

    Measured: 250 items, limit 100, has_more=true, while the description
    said "list cross-references from an address" -- so a model treats a
    page as every outbound xref.
    """

    def test_the_tool_text_says_to_check_has_more(self) -> None:
        from headless_re_mcp.core.service import AnalysisService
        from headless_re_mcp.tools.core import build_static_extended_tools

        service = AnalysisService()
        try:
            tools = {item.name: item for item in build_static_extended_tools(service)}
            doc = tools["static.xrefs_from"].handler.__doc__ or ""
        finally:
            service.close_all()
        assert "has_more" in doc


class TestStaticImportsDescriptionMatchesTheCut:
    """static.imports now pages with has_more, but the tool text hid that.

    Measured: 250 items, limit 100, has_more=true, while the description
    said "list imported symbols" -- so a model treats a page as every import.
    """

    def test_the_tool_text_says_to_check_has_more(self) -> None:
        from headless_re_mcp.core.service import AnalysisService
        from headless_re_mcp.tools.core import build_static_extended_tools

        service = AnalysisService()
        try:
            tools = {item.name: item for item in build_static_extended_tools(service)}
            doc = tools["static.imports"].handler.__doc__ or ""
        finally:
            service.close_all()
        assert "has_more" in doc


class TestStaticXrefsToDescriptionMatchesTheCut:
    """static.xrefs_to now pages with has_more, but the tool text hid that.

    Measured: 250 items, limit 100, has_more=true, while the description
    said "list cross-references to an address" -- so a model treats a page
    as every xref.
    """

    def test_the_tool_text_says_to_check_has_more(self) -> None:
        from headless_re_mcp.core.service import AnalysisService
        from headless_re_mcp.tools.core import build_static_extended_tools

        service = AnalysisService()
        try:
            tools = {item.name: item for item in build_static_extended_tools(service)}
            doc = tools["static.xrefs_to"].handler.__doc__ or ""
        finally:
            service.close_all()
        assert "has_more" in doc
