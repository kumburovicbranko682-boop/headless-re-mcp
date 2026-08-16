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


class TestIdaBytesReadSaysWhenItWasShort:
    """A short get_bytes used to look like the requested range.

    Measured: size=64, 16 bytes returned, truncated=False.
    """

    def test_a_short_read_is_truncated(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import sys
        import types

        from headless_re_mcp.backends.ida import worker

        ida_bytes = types.ModuleType("ida_bytes")
        ida_bytes.is_loaded = lambda address: True  # type: ignore[attr-defined]
        ida_bytes.get_bytes = lambda address, size: b"\x90" * 16  # type: ignore[attr-defined]
        monkeypatch.setitem(sys.modules, "ida_bytes", ida_bytes)

        result = worker._bytes_read({"address": 0x1000, "size": 64})
        assert result["size"] == 16
        assert result["truncated"] is True

    def test_a_full_read_is_not_truncated(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import sys
        import types

        from headless_re_mcp.backends.ida import worker

        ida_bytes = types.ModuleType("ida_bytes")
        ida_bytes.is_loaded = lambda address: True  # type: ignore[attr-defined]
        ida_bytes.get_bytes = lambda address, size: b"\x90" * size  # type: ignore[attr-defined]
        monkeypatch.setitem(sys.modules, "ida_bytes", ida_bytes)

        result = worker._bytes_read({"address": 0x1000, "size": 64})
        assert result["size"] == 64
        assert result["truncated"] is False


class TestIdaSearchTextSaysWhenItWasCut:
    """A search that stopped at the page used to report has_more=False.

    Measured: 250 hits, limit 100, returned=100, total=100, has_more=False.
    """

    def _install(self, monkeypatch: pytest.MonkeyPatch, hits: list[int]) -> None:
        import sys
        import types

        ida_ida = types.ModuleType("ida_ida")
        ida_ida.inf_get_min_ea = lambda: 0x1000  # type: ignore[attr-defined]
        ida_ida.inf_get_max_ea = lambda: 0x100000  # type: ignore[attr-defined]
        ida_idaapi = types.ModuleType("ida_idaapi")
        ida_idaapi.BADADDR = 0xFFFFFFFFFFFFFFFF  # type: ignore[attr-defined]
        ida_search = types.ModuleType("ida_search")
        ida_search.SEARCH_DOWN = 1  # type: ignore[attr-defined]

        def find_text(ea: int, *_args: object) -> int:
            for hit in hits:
                if hit >= ea:
                    return hit
            return int(ida_idaapi.BADADDR)

        ida_search.find_text = find_text  # type: ignore[attr-defined]
        idc = types.ModuleType("idc")
        idc.BADADDR = ida_idaapi.BADADDR  # type: ignore[attr-defined]
        monkeypatch.setitem(sys.modules, "ida_ida", ida_ida)
        monkeypatch.setitem(sys.modules, "ida_idaapi", ida_idaapi)
        monkeypatch.setitem(sys.modules, "ida_search", ida_search)
        monkeypatch.setitem(sys.modules, "idc", idc)

    def test_a_full_page_is_marked(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from headless_re_mcp.backends.ida import worker

        hits = list(range(0x1000, 0x1000 + 250))
        self._install(monkeypatch, hits)
        page = worker._search_text({"text": "foo", "offset": 0, "limit": 100})
        assert page["returned"] == 100
        assert page["has_more"] is True

    def test_an_exact_page_is_complete(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from headless_re_mcp.backends.ida import worker

        hits = list(range(0x1000, 0x1000 + 100))
        self._install(monkeypatch, hits)
        page = worker._search_text({"text": "foo", "offset": 0, "limit": 100})
        assert page["returned"] == 100
        assert page["has_more"] is False


class TestIdaSearchBytesSaysWhenItWasCut:
    """A byte search that stopped at the page used to report has_more=False.

    Measured: 250 hits, limit 100, returned=100, total=100, has_more=False.
    """

    def _install(self, monkeypatch: pytest.MonkeyPatch, hits: list[int]) -> None:
        import sys
        import types

        ida_bytes = types.ModuleType("ida_bytes")
        ida_bytes.compiled_binpat_vec_t = lambda: object()  # type: ignore[attr-defined]
        ida_bytes.parse_binpat_str = lambda *_args: True  # type: ignore[attr-defined]
        ida_bytes.BIN_SEARCH_FORWARD = 1  # type: ignore[attr-defined]
        ida_bytes.BIN_SEARCH_NOSHOW = 2  # type: ignore[attr-defined]
        bad = 0xFFFFFFFFFFFFFFFF

        def bin_search(ea: int, *_args: object) -> int:
            for hit in hits:
                if hit >= ea:
                    return hit
            return bad

        ida_bytes.bin_search = bin_search  # type: ignore[attr-defined]
        ida_ida = types.ModuleType("ida_ida")
        ida_ida.inf_get_min_ea = lambda: 0x1000  # type: ignore[attr-defined]
        ida_ida.inf_get_max_ea = lambda: 0x100000  # type: ignore[attr-defined]
        ida_idaapi = types.ModuleType("ida_idaapi")
        ida_idaapi.BADADDR = bad  # type: ignore[attr-defined]
        monkeypatch.setitem(sys.modules, "ida_bytes", ida_bytes)
        monkeypatch.setitem(sys.modules, "ida_ida", ida_ida)
        monkeypatch.setitem(sys.modules, "ida_idaapi", ida_idaapi)

    def test_a_full_page_is_marked(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from headless_re_mcp.backends.ida import worker

        hits = list(range(0x1000, 0x1000 + 250))
        self._install(monkeypatch, hits)
        page = worker._search_bytes({"pattern": "90 90", "offset": 0, "limit": 100})
        assert page["returned"] == 100
        assert page["has_more"] is True

    def test_an_exact_page_is_complete(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from headless_re_mcp.backends.ida import worker

        hits = list(range(0x1000, 0x1000 + 100))
        self._install(monkeypatch, hits)
        page = worker._search_bytes({"pattern": "90 90", "offset": 0, "limit": 100})
        assert page["returned"] == 100
        assert page["has_more"] is False


class TestIdaSearchImmediateSaysWhenItWasCut:
    """An immediate search that stopped at the page used to report has_more=False.

    Measured: 250 hits, limit 100, returned=100, total=100, has_more=False.
    """

    def _install(self, monkeypatch: pytest.MonkeyPatch, hits: list[int]) -> None:
        import sys
        import types

        bad = 0xFFFFFFFFFFFFFFFF
        ida_ida = types.ModuleType("ida_ida")
        ida_ida.inf_get_min_ea = lambda: 0x1000  # type: ignore[attr-defined]
        ida_ida.inf_get_max_ea = lambda: 0x100000  # type: ignore[attr-defined]
        ida_idaapi = types.ModuleType("ida_idaapi")
        ida_idaapi.BADADDR = bad  # type: ignore[attr-defined]
        ida_search = types.ModuleType("ida_search")
        ida_search.SEARCH_DOWN = 1  # type: ignore[attr-defined]

        def find_imm(ea: int, *_args: object) -> int:
            for hit in hits:
                if hit >= ea:
                    return hit
            return bad

        ida_search.find_imm = find_imm  # type: ignore[attr-defined]
        idc = types.ModuleType("idc")
        idc.BADADDR = bad  # type: ignore[attr-defined]
        monkeypatch.setitem(sys.modules, "ida_ida", ida_ida)
        monkeypatch.setitem(sys.modules, "ida_idaapi", ida_idaapi)
        monkeypatch.setitem(sys.modules, "ida_search", ida_search)
        monkeypatch.setitem(sys.modules, "idc", idc)

    def test_a_full_page_is_marked(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from headless_re_mcp.backends.ida import worker

        hits = list(range(0x1000, 0x1000 + 250))
        self._install(monkeypatch, hits)
        page = worker._search_immediate({"value": 1, "offset": 0, "limit": 100})
        assert page["returned"] == 100
        assert page["has_more"] is True

    def test_an_exact_page_is_complete(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from headless_re_mcp.backends.ida import worker

        hits = list(range(0x1000, 0x1000 + 100))
        self._install(monkeypatch, hits)
        page = worker._search_immediate({"value": 1, "offset": 0, "limit": 100})
        assert page["returned"] == 100
        assert page["has_more"] is False


class TestIdaCfgSaysWhenItWasCut:
    """static.cfg used to return every block with only node_count.

    Measured: 5000 nodes, 411 KiB, no has_more, so an agent treated the
    dump as the function. 8000 nodes were 664 KiB.
    """

    def _install(self, monkeypatch: pytest.MonkeyPatch, count: int) -> None:
        import sys
        import types

        from headless_re_mcp.backends.ida import worker

        class _Block:
            def __init__(self, index: int, total: int) -> None:
                self.id = index
                self.start_ea = 0x1000 + index * 16
                self.end_ea = self.start_ea + 16
                self.type = 0
                self._total = total

            def succs(self) -> list[_Block]:
                if self.id + 1 < self._total:
                    return [_Block(self.id + 1, self._total)]
                return []

            def preds(self) -> list[_Block]:
                if self.id:
                    return [_Block(self.id - 1, self._total)]
                return []

        class _Chart:
            def __iter__(self) -> object:
                for index in range(count):
                    yield _Block(index, count)

        class _Func:
            start_ea = 0x1000
            end_ea = 0x1000 + count * 16

        ida_gdl = types.ModuleType("ida_gdl")
        ida_gdl.FlowChart = lambda fn: _Chart()  # type: ignore[attr-defined]
        ida_funcs = types.ModuleType("ida_funcs")
        ida_funcs.get_func = lambda ea: _Func()  # type: ignore[attr-defined]
        monkeypatch.setitem(sys.modules, "ida_gdl", ida_gdl)
        monkeypatch.setitem(sys.modules, "ida_funcs", ida_funcs)
        monkeypatch.setattr(worker, "_MAX_CFG_NODES", 100)

    def test_a_full_page_is_marked(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from headless_re_mcp.backends.ida import worker

        self._install(monkeypatch, 250)
        page = worker._cfg({"address": 0x1000})
        assert page["node_count"] == 100
        assert page["total_nodes"] == 250
        assert page["has_more"] is True
        assert len(page["nodes"]) == 100

    def test_an_exact_page_is_complete(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from headless_re_mcp.backends.ida import worker

        self._install(monkeypatch, 100)
        page = worker._cfg({"address": 0x1000})
        assert page["node_count"] == 100
        assert page["total_nodes"] == 100
        assert page["has_more"] is False


class TestIdaDisassembleSaysWhenALineWasCut:
    """A disasm line that hit 512 characters used to look complete.

    Measured: an 800-character line came back as 512 characters with
    truncated absent and partial=False, so an agent treated the fragment
    as the instruction.
    """

    def _install(self, monkeypatch: pytest.MonkeyPatch, text: str) -> None:
        import sys
        import types

        ida_bytes = types.ModuleType("ida_bytes")
        ida_bytes.is_loaded = lambda ea: True  # type: ignore[attr-defined]
        ida_ua = types.ModuleType("ida_ua")

        class _Insn:
            pass

        ida_ua.insn_t = _Insn  # type: ignore[attr-defined]
        ida_ua.decode_insn = lambda insn, ea: 4  # type: ignore[attr-defined]
        idc = types.ModuleType("idc")
        idc.generate_disasm_line = lambda ea, flags: text  # type: ignore[attr-defined]
        monkeypatch.setitem(sys.modules, "ida_bytes", ida_bytes)
        monkeypatch.setitem(sys.modules, "ida_ua", ida_ua)
        monkeypatch.setitem(sys.modules, "idc", idc)

    def test_a_cut_line_is_marked(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from headless_re_mcp.backends.ida import worker

        self._install(monkeypatch, "x" * 800)
        page = worker._disassemble({"address": 0x1000, "count": 1})
        insn = page["instructions"][0]
        assert len(insn["text"]) == 512
        assert insn["truncated"] is True
        assert page["partial"] is False

    def test_a_short_line_is_complete(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from headless_re_mcp.backends.ida import worker

        self._install(monkeypatch, "retn")
        page = worker._disassemble({"address": 0x1000, "count": 1})
        insn = page["instructions"][0]
        assert insn["text"] == "retn"
        assert insn["truncated"] is False
