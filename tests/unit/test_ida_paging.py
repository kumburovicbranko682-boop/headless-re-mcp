"""IDA list pages must say when they stopped."""

from __future__ import annotations

import pytest

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


class TestIdaFunctionsSaysWhenItWasCut:
    """static.functions built its own page and omitted has_more.

    The envelope matched the old _page_items shape: 250 functions, limit
    100, returned=100, total=250, no has_more.
    """

    def test_a_full_page_is_marked(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import sys
        import types

        from headless_re_mcp.backends.ida import worker

        addresses = list(range(250))

        class _Func:
            def __init__(self, ea: int) -> None:
                self.start_ea = ea
                self.end_ea = ea + 16
                self.flags = 0

        idautils = types.ModuleType("idautils")
        idautils.Functions = lambda: addresses  # type: ignore[attr-defined]
        ida_funcs = types.ModuleType("ida_funcs")
        ida_funcs.get_func = lambda ea: _Func(ea)  # type: ignore[attr-defined]
        ida_name = types.ModuleType("ida_name")
        ida_name.get_name = lambda ea: f"sub_{ea:X}"  # type: ignore[attr-defined]
        monkeypatch.setitem(sys.modules, "idautils", idautils)
        monkeypatch.setitem(sys.modules, "ida_funcs", ida_funcs)
        monkeypatch.setitem(sys.modules, "ida_name", ida_name)

        page = worker._functions({"offset": 0, "limit": 100})
        assert page["returned"] == 100
        assert page["total"] == 250
        assert page["has_more"] is True

    def test_an_exact_page_is_complete(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import sys
        import types

        from headless_re_mcp.backends.ida import worker

        addresses = list(range(100))

        class _Func:
            def __init__(self, ea: int) -> None:
                self.start_ea = ea
                self.end_ea = ea + 16
                self.flags = 0

        idautils = types.ModuleType("idautils")
        idautils.Functions = lambda: addresses  # type: ignore[attr-defined]
        ida_funcs = types.ModuleType("ida_funcs")
        ida_funcs.get_func = lambda ea: _Func(ea)  # type: ignore[attr-defined]
        ida_name = types.ModuleType("ida_name")
        ida_name.get_name = lambda ea: f"sub_{ea:X}"  # type: ignore[attr-defined]
        monkeypatch.setitem(sys.modules, "idautils", idautils)
        monkeypatch.setitem(sys.modules, "ida_funcs", ida_funcs)
        monkeypatch.setitem(sys.modules, "ida_name", ida_name)

        page = worker._functions({"offset": 0, "limit": 100})
        assert page["has_more"] is False
        assert page["total"] == 100


class TestIdaStringsSaysWhenItWasCut:
    """static.strings built its own page and omitted has_more.

    The envelope matched functions: 250 strings, limit 100, returned=100,
    total=250, no has_more.
    """

    def test_a_full_page_is_marked(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import sys
        import types

        from headless_re_mcp.backends.ida import worker

        class _Str:
            def __init__(self, ea: int) -> None:
                self.ea = ea
                self.length = 4
                self.strtype = 0

            def __str__(self) -> str:
                return "test"

        idautils = types.ModuleType("idautils")
        idautils.Strings = lambda: [_Str(index) for index in range(250)]  # type: ignore[attr-defined]
        monkeypatch.setitem(sys.modules, "idautils", idautils)

        page = worker._strings({"offset": 0, "limit": 100})
        assert page["returned"] == 100
        assert page["total"] == 250
        assert page["has_more"] is True

    def test_an_exact_page_is_complete(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import sys
        import types

        from headless_re_mcp.backends.ida import worker

        class _Str:
            def __init__(self, ea: int) -> None:
                self.ea = ea
                self.length = 4
                self.strtype = 0

            def __str__(self) -> str:
                return "test"

        idautils = types.ModuleType("idautils")
        idautils.Strings = lambda: [_Str(index) for index in range(100)]  # type: ignore[attr-defined]
        monkeypatch.setitem(sys.modules, "idautils", idautils)

        page = worker._strings({"offset": 0, "limit": 100})
        assert page["has_more"] is False
        assert page["total"] == 100
