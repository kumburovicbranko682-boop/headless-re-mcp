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


class TestStaticImportsDescriptionSaysWhenItWasCut:
    """The imports page already carries has_more; the tool text did not say so.

    Measured: 250 imports, limit 100, returned=100, total=250, has_more=True,
    while the description was only ``List imported symbols (...)``. An
    unattended agent that trusted the description treated the page as every
    import.
    """

    def test_a_full_page_is_marked(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import sys
        import types

        from headless_re_mcp.backends.ida import worker

        ida_nalt = types.ModuleType("ida_nalt")
        ida_nalt.get_import_module_qty = lambda: 1  # type: ignore[attr-defined]
        ida_nalt.get_import_module_name = lambda index: "kernel32"  # type: ignore[attr-defined]

        def _enum(index: int, callback: object) -> None:
            for ordinal in range(250):
                callback(0x1000 + ordinal, f"Fn{ordinal}", ordinal)  # type: ignore[operator]

        ida_nalt.enum_import_names = _enum  # type: ignore[attr-defined]
        monkeypatch.setitem(sys.modules, "ida_nalt", ida_nalt)
        page = worker._imports({"offset": 0, "limit": 100})
        assert page["returned"] == 100
        assert page["total"] == 250
        assert page["has_more"] is True

    def test_the_tool_description_says_to_read_has_more(self) -> None:
        from pathlib import Path

        source = (
            Path(__file__).resolve().parents[2]
            / "src"
            / "headless_re_mcp"
            / "tools"
            / "core.py"
        ).read_text(encoding="utf-8")
        block = source.split("def static_imports(")[1].split("def static_exports(")[0]
        assert "has_more" in block


class TestStaticExportsDescriptionSaysWhenItWasCut:
    """The exports page already carries has_more; the tool text did not say so.

    Measured: 250 exports, limit 100, returned=100, total=250, has_more=True,
    while the description was only ``List exported entries.``. An unattended
    agent that trusted the description treated the page as every export.
    """

    def test_a_full_page_is_marked(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import sys
        import types

        from headless_re_mcp.backends.ida import worker

        idautils = types.ModuleType("idautils")
        idautils.Entries = lambda: [  # type: ignore[attr-defined]
            (index, index, 0x1000 + index, f"Exp{index}") for index in range(250)
        ]
        monkeypatch.setitem(sys.modules, "idautils", idautils)
        page = worker._exports({"offset": 0, "limit": 100})
        assert page["returned"] == 100
        assert page["total"] == 250
        assert page["has_more"] is True

    def test_the_tool_description_says_to_read_has_more(self) -> None:
        from pathlib import Path

        source = (
            Path(__file__).resolve().parents[2]
            / "src"
            / "headless_re_mcp"
            / "tools"
            / "core.py"
        ).read_text(encoding="utf-8")
        block = source.split("def static_exports(")[1].split("def static_entrypoints(")[0]
        assert "has_more" in block


class TestStaticSegmentsDescriptionSaysWhenItWasCut:
    """The segments page already carries has_more; the tool text did not say so.

    Measured: 250 segments, limit 100, returned=100, total=250, has_more=True,
    while the description omitted has_more. An unattended agent that trusted
    the description treated the page as every segment.
    """

    def test_a_full_page_is_marked(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import sys
        import types

        from headless_re_mcp.backends.ida import worker

        class _Seg:
            def __init__(self, index: int) -> None:
                self.start_ea = 0x1000 * (index + 1)
                self.end_ea = self.start_ea + 0x100
                self.perm = 5
                self.bitness = 2

        ida_segment = types.ModuleType("ida_segment")
        ida_segment.getseg = lambda ea: _Seg(int(ea) // 0x1000 - 1)  # type: ignore[attr-defined]
        ida_segment.get_segm_name = lambda seg: f".s{seg.start_ea}"  # type: ignore[attr-defined]
        idautils = types.ModuleType("idautils")
        idautils.Segments = lambda: [0x1000 * (index + 1) for index in range(250)]  # type: ignore[attr-defined]
        monkeypatch.setitem(sys.modules, "ida_segment", ida_segment)
        monkeypatch.setitem(sys.modules, "idautils", idautils)
        page = worker._segments({"offset": 0, "limit": 100})
        assert page["returned"] == 100
        assert page["total"] == 250
        assert page["has_more"] is True

    def test_the_tool_description_says_to_read_has_more(self) -> None:
        from pathlib import Path

        source = (
            Path(__file__).resolve().parents[2]
            / "src"
            / "headless_re_mcp"
            / "tools"
            / "core.py"
        ).read_text(encoding="utf-8")
        block = source.split("def static_segments(")[1].split("def static_imports(")[0]
        assert "has_more" in block


class TestStaticXrefsToDescriptionSaysWhenItWasCut:
    """The xref page already carries has_more; the tool text did not say so.

    Measured: 250 xrefs, limit 100, returned=100, total=250, has_more=True,
    while the description was only ``List cross-references to an address.``.
    An unattended agent that trusted the description treated the page as
    every reference.
    """

    def test_a_full_page_is_marked(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import sys
        import types

        from headless_re_mcp.backends.ida import worker

        class _Xref:
            def __init__(self, index: int) -> None:
                self.frm = 0x2000 + index
                self.to = 0x1000
                self.type = 16
                self.iscode = True

        ida_xref = types.ModuleType("ida_xref")
        ida_xref.fl_CF = 16  # type: ignore[attr-defined]
        ida_xref.fl_CN = 17  # type: ignore[attr-defined]
        ida_xref.fl_JF = 18  # type: ignore[attr-defined]
        ida_xref.fl_JN = 19  # type: ignore[attr-defined]
        ida_xref.fl_F = 20  # type: ignore[attr-defined]
        ida_xref.dr_O = 1  # type: ignore[attr-defined]
        ida_xref.dr_W = 2  # type: ignore[attr-defined]
        ida_xref.dr_R = 3  # type: ignore[attr-defined]
        ida_xref.dr_T = 4  # type: ignore[attr-defined]
        ida_xref.dr_I = 5  # type: ignore[attr-defined]
        idautils = types.ModuleType("idautils")
        idautils.XrefsTo = lambda address: [_Xref(index) for index in range(250)]  # type: ignore[attr-defined]
        monkeypatch.setitem(sys.modules, "ida_xref", ida_xref)
        monkeypatch.setitem(sys.modules, "idautils", idautils)
        page = worker._xrefs_to({"address": 0x1000, "offset": 0, "limit": 100})
        assert page["returned"] == 100
        assert page["total"] == 250
        assert page["has_more"] is True

    def test_the_tool_description_says_to_read_has_more(self) -> None:
        from pathlib import Path

        source = (
            Path(__file__).resolve().parents[2]
            / "src"
            / "headless_re_mcp"
            / "tools"
            / "core.py"
        ).read_text(encoding="utf-8")
        block = source.split("def static_xrefs_to(")[1].split("def static_xrefs_from(")[0]
        assert "has_more" in block


class TestStaticXrefsFromDescriptionSaysWhenItWasCut:
    """The xref-from page already carries has_more; the tool text did not say so.

    Measured: 250 xrefs, limit 100, returned=100, total=250, has_more=True,
    while the description was only ``List cross-references from an address.``.
    An unattended agent that trusted the description treated the page as
    every outgoing reference.
    """

    def test_a_full_page_is_marked(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import sys
        import types

        from headless_re_mcp.backends.ida import worker

        class _Xref:
            def __init__(self, index: int) -> None:
                self.frm = 0x1000
                self.to = 0x2000 + index
                self.type = 16
                self.iscode = True

        ida_xref = types.ModuleType("ida_xref")
        ida_xref.fl_CF = 16  # type: ignore[attr-defined]
        ida_xref.fl_CN = 17  # type: ignore[attr-defined]
        ida_xref.fl_JF = 18  # type: ignore[attr-defined]
        ida_xref.fl_JN = 19  # type: ignore[attr-defined]
        ida_xref.fl_F = 20  # type: ignore[attr-defined]
        ida_xref.dr_O = 1  # type: ignore[attr-defined]
        ida_xref.dr_W = 2  # type: ignore[attr-defined]
        ida_xref.dr_R = 3  # type: ignore[attr-defined]
        ida_xref.dr_T = 4  # type: ignore[attr-defined]
        ida_xref.dr_I = 5  # type: ignore[attr-defined]
        idautils = types.ModuleType("idautils")
        idautils.XrefsFrom = lambda address: [_Xref(index) for index in range(250)]  # type: ignore[attr-defined]
        monkeypatch.setitem(sys.modules, "ida_xref", ida_xref)
        monkeypatch.setitem(sys.modules, "idautils", idautils)
        page = worker._xrefs_from({"address": 0x1000, "offset": 0, "limit": 100})
        assert page["returned"] == 100
        assert page["total"] == 250
        assert page["has_more"] is True

    def test_the_tool_description_says_to_read_has_more(self) -> None:
        from pathlib import Path

        source = (
            Path(__file__).resolve().parents[2]
            / "src"
            / "headless_re_mcp"
            / "tools"
            / "core.py"
        ).read_text(encoding="utf-8")
        block = source.split("def static_xrefs_from(")[1].split("def static_callers(")[0]
        assert "has_more" in block


class TestStaticCallersDescriptionSaysWhenItWasCut:
    """The caller page already carries has_more; the tool text did not say so.

    Measured: 250 callers, limit 100, returned=100, total=250, has_more=True,
    while the description omitted has_more. An unattended agent that trusted
    the description treated the page as every caller.
    """

    def test_a_full_page_is_marked(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import sys
        import types

        from headless_re_mcp.backends.ida import worker

        class _Fn:
            def __init__(self, ea: int) -> None:
                self.start_ea = ea
                self.end_ea = ea + 16

        class _Xref:
            def __init__(self, index: int) -> None:
                self.frm = 0x2000 + index * 16
                self.to = 0x1000
                self.type = 16
                self.iscode = True

        ida_xref = types.ModuleType("ida_xref")
        ida_xref.fl_CF = 16  # type: ignore[attr-defined]
        ida_xref.fl_CN = 17  # type: ignore[attr-defined]
        ida_xref.fl_JF = 18  # type: ignore[attr-defined]
        ida_xref.fl_JN = 19  # type: ignore[attr-defined]
        ida_xref.fl_F = 20  # type: ignore[attr-defined]
        ida_xref.dr_O = 1  # type: ignore[attr-defined]
        ida_xref.dr_W = 2  # type: ignore[attr-defined]
        ida_xref.dr_R = 3  # type: ignore[attr-defined]
        ida_xref.dr_T = 4  # type: ignore[attr-defined]
        ida_xref.dr_I = 5  # type: ignore[attr-defined]
        ida_funcs = types.ModuleType("ida_funcs")
        ida_funcs.get_func = lambda ea: _Fn(int(ea))  # type: ignore[attr-defined]
        ida_name = types.ModuleType("ida_name")
        ida_name.get_name = lambda ea: f"sub_{int(ea):X}"  # type: ignore[attr-defined]
        idautils = types.ModuleType("idautils")
        idautils.XrefsTo = lambda address: [_Xref(index) for index in range(250)]  # type: ignore[attr-defined]
        monkeypatch.setitem(sys.modules, "ida_xref", ida_xref)
        monkeypatch.setitem(sys.modules, "ida_funcs", ida_funcs)
        monkeypatch.setitem(sys.modules, "ida_name", ida_name)
        monkeypatch.setitem(sys.modules, "idautils", idautils)
        page = worker._callers({"address": 0x1000, "offset": 0, "limit": 100})
        assert page["returned"] == 100
        assert page["total"] == 250
        assert page["has_more"] is True

    def test_the_tool_description_says_to_read_has_more(self) -> None:
        from pathlib import Path

        source = (
            Path(__file__).resolve().parents[2]
            / "src"
            / "headless_re_mcp"
            / "tools"
            / "core.py"
        ).read_text(encoding="utf-8")
        block = source.split("def static_callers(")[1].split("def static_callees(")[0]
        assert "has_more" in block


class TestStaticCalleesDescriptionSaysWhenItWasCut:
    """The callee page already carries has_more; the tool text did not say so.

    Measured: 250 callees, limit 100, returned=100, total=250, has_more=True,
    while the description omitted has_more. An unattended agent that trusted
    the description treated the page as every callee.
    """

    def test_a_full_page_is_marked(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import sys
        import types

        from headless_re_mcp.backends.ida import worker

        class _Fn:
            start_ea = 0x1000
            end_ea = 0x1000 + 250

        class _Xref:
            def __init__(self, ea: int) -> None:
                self.frm = ea
                self.to = 0x2000 + (ea - 0x1000)
                self.type = 16
                self.iscode = True

        ida_xref = types.ModuleType("ida_xref")
        ida_xref.fl_CF = 16  # type: ignore[attr-defined]
        ida_xref.fl_CN = 17  # type: ignore[attr-defined]
        ida_xref.fl_JF = 18  # type: ignore[attr-defined]
        ida_xref.fl_JN = 19  # type: ignore[attr-defined]
        ida_xref.fl_F = 20  # type: ignore[attr-defined]
        ida_xref.dr_O = 1  # type: ignore[attr-defined]
        ida_xref.dr_W = 2  # type: ignore[attr-defined]
        ida_xref.dr_R = 3  # type: ignore[attr-defined]
        ida_xref.dr_T = 4  # type: ignore[attr-defined]
        ida_xref.dr_I = 5  # type: ignore[attr-defined]
        ida_funcs = types.ModuleType("ida_funcs")
        ida_funcs.get_func = lambda ea: _Fn()  # type: ignore[attr-defined]
        ida_name = types.ModuleType("ida_name")
        ida_name.get_name = lambda ea: f"sub_{int(ea):X}"  # type: ignore[attr-defined]
        ida_bytes = types.ModuleType("ida_bytes")
        ida_bytes.get_item_size = lambda ea: 1  # type: ignore[attr-defined]
        idautils = types.ModuleType("idautils")
        idautils.XrefsFrom = lambda ea: [_Xref(int(ea))]  # type: ignore[attr-defined]
        monkeypatch.setitem(sys.modules, "ida_xref", ida_xref)
        monkeypatch.setitem(sys.modules, "ida_funcs", ida_funcs)
        monkeypatch.setitem(sys.modules, "ida_name", ida_name)
        monkeypatch.setitem(sys.modules, "ida_bytes", ida_bytes)
        monkeypatch.setitem(sys.modules, "idautils", idautils)
        page = worker._callees({"address": 0x1000, "offset": 0, "limit": 100})
        assert page["returned"] == 100
        assert page["total"] == 250
        assert page["has_more"] is True

    def test_the_tool_description_says_to_read_has_more(self) -> None:
        from pathlib import Path

        source = (
            Path(__file__).resolve().parents[2]
            / "src"
            / "headless_re_mcp"
            / "tools"
            / "core.py"
        ).read_text(encoding="utf-8")
        block = source.split("def static_callees(")[1].split("def static_basic_blocks(")[0]
        assert "has_more" in block


class TestStaticBasicBlocksDescriptionSaysWhenItWasCut:
    """The block page already carries has_more; the tool text did not say so.

    Measured: 250 blocks, limit 100, returned=100, total=250, has_more=True,
    while the description omitted has_more. An unattended agent that trusted
    the description treated the page as every block.
    """

    def test_a_full_page_is_marked(self, monkeypatch: pytest.MonkeyPatch) -> None:
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
                return [_Block(self.id + 1, self._total)] if self.id + 1 < self._total else []

            def preds(self) -> list[_Block]:
                return [_Block(self.id - 1, self._total)] if self.id else []

        class _Chart:
            def __iter__(self) -> object:
                for index in range(250):
                    yield _Block(index, 250)

        class _Fn:
            start_ea = 0x1000
            end_ea = 0x1000 + 250 * 16

        ida_gdl = types.ModuleType("ida_gdl")
        ida_gdl.FlowChart = lambda fn: _Chart()  # type: ignore[attr-defined]
        ida_funcs = types.ModuleType("ida_funcs")
        ida_funcs.get_func = lambda ea: _Fn()  # type: ignore[attr-defined]
        monkeypatch.setitem(sys.modules, "ida_gdl", ida_gdl)
        monkeypatch.setitem(sys.modules, "ida_funcs", ida_funcs)
        page = worker._basic_blocks({"address": 0x1000, "offset": 0, "limit": 100})
        assert page["returned"] == 100
        assert page["total"] == 250
        assert page["has_more"] is True

    def test_the_tool_description_says_to_read_has_more(self) -> None:
        from pathlib import Path

        source = (
            Path(__file__).resolve().parents[2]
            / "src"
            / "headless_re_mcp"
            / "tools"
            / "core.py"
        ).read_text(encoding="utf-8")
        block = source.split("def static_basic_blocks(")[1].split("def static_cfg(")[0]
        assert "has_more" in block


class TestStaticNamesDescriptionSaysWhenItWasCut:
    """The names page already carries has_more; the tool text did not say so.

    Measured: 250 names, limit 100, returned=100, total=250, has_more=True,
    while the description was only ``List named addresses in the IDA
    database.``. An unattended agent that trusted the description treated
    the page as every name.
    """

    def test_a_full_page_is_marked(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import sys
        import types

        from headless_re_mcp.backends.ida import worker

        idautils = types.ModuleType("idautils")
        idautils.Names = lambda: [  # type: ignore[attr-defined]
            (0x1000 + index, f"n{index}") for index in range(250)
        ]
        monkeypatch.setitem(sys.modules, "idautils", idautils)
        page = worker._names({"offset": 0, "limit": 100})
        assert page["returned"] == 100
        assert page["total"] == 250
        assert page["has_more"] is True

    def test_the_tool_description_says_to_read_has_more(self) -> None:
        from pathlib import Path

        source = (
            Path(__file__).resolve().parents[2]
            / "src"
            / "headless_re_mcp"
            / "tools"
            / "core.py"
        ).read_text(encoding="utf-8")
        block = source.split("def static_names(")[1].split("def static_types(")[0]
        assert "has_more" in block


class TestStaticGlobalsDescriptionSaysWhenItWasCut:
    """The globals page already carries has_more; the tool text did not say so.

    Measured: 250 globals, limit 100, returned=100, total=250, has_more=True,
    while the description omitted has_more. An unattended agent that trusted
    the description treated the page as every global.
    """

    def test_a_full_page_is_marked(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import sys
        import types

        from headless_re_mcp.backends.ida import worker

        idautils = types.ModuleType("idautils")
        idautils.Names = lambda: [  # type: ignore[attr-defined]
            (0x2000 + index, f"g{index}") for index in range(250)
        ]
        ida_funcs = types.ModuleType("ida_funcs")
        ida_funcs.get_func = lambda ea: None  # type: ignore[attr-defined]
        ida_bytes = types.ModuleType("ida_bytes")
        ida_bytes.get_flags = lambda ea: 0  # type: ignore[attr-defined]
        ida_bytes.is_data = lambda flags: True  # type: ignore[attr-defined]
        ida_bytes.is_code = lambda flags: False  # type: ignore[attr-defined]
        ida_bytes.get_item_size = lambda ea: 8  # type: ignore[attr-defined]
        ida_name = types.ModuleType("ida_name")
        ida_name.get_name = lambda ea: None  # type: ignore[attr-defined]
        monkeypatch.setitem(sys.modules, "idautils", idautils)
        monkeypatch.setitem(sys.modules, "ida_funcs", ida_funcs)
        monkeypatch.setitem(sys.modules, "ida_bytes", ida_bytes)
        monkeypatch.setitem(sys.modules, "ida_name", ida_name)
        page = worker._globals({"offset": 0, "limit": 100})
        assert page["returned"] == 100
        assert page["total"] == 250
        assert page["has_more"] is True

    def test_the_tool_description_says_to_read_has_more(self) -> None:
        from pathlib import Path

        source = (
            Path(__file__).resolve().parents[2]
            / "src"
            / "headless_re_mcp"
            / "tools"
            / "core.py"
        ).read_text(encoding="utf-8")
        block = source.split("def static_globals(")[1].split("def static_names(")[0]
        assert "has_more" in block


class TestStaticEntrypointsDescriptionSaysWhenItWasCut:
    """The entry page already carries has_more; the tool text did not say so.

    Measured: 250 entry points, limit 100, returned=100, total=250,
    has_more=True, while the description omitted has_more. An unattended
    agent that trusted the description treated the page as every entry.
    """

    def test_a_full_page_is_marked(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import sys
        import types

        from headless_re_mcp.backends.ida import worker

        ida_ida = types.ModuleType("ida_ida")

        def _start_ip() -> int:
            raise RuntimeError("no start ip")

        ida_ida.inf_get_start_ip = _start_ip  # type: ignore[attr-defined]
        ida_entry = types.ModuleType("ida_entry")
        ida_entry.get_entry_qty = lambda: 250  # type: ignore[attr-defined]
        ida_entry.get_entry_ordinal = lambda index: index  # type: ignore[attr-defined]
        ida_entry.get_entry = lambda ordinal: 0x1000 + ordinal  # type: ignore[attr-defined]
        ida_entry.get_entry_name = lambda ordinal: f"e{ordinal}"  # type: ignore[attr-defined]
        ida_name = types.ModuleType("ida_name")
        ida_name.get_name = lambda ea: None  # type: ignore[attr-defined]
        monkeypatch.setitem(sys.modules, "ida_ida", ida_ida)
        monkeypatch.setitem(sys.modules, "ida_entry", ida_entry)
        monkeypatch.setitem(sys.modules, "ida_name", ida_name)
        page = worker._entrypoints({"offset": 0, "limit": 100})
        assert page["returned"] == 100
        assert page["total"] == 250
        assert page["has_more"] is True

    def test_the_tool_description_says_to_read_has_more(self) -> None:
        from pathlib import Path

        source = (
            Path(__file__).resolve().parents[2]
            / "src"
            / "headless_re_mcp"
            / "tools"
            / "core.py"
        ).read_text(encoding="utf-8")
        block = source.split("def static_entrypoints(")[1].split("def static_disassemble(")[0]
        assert "has_more" in block


class TestStaticTypesDescriptionSaysWhenItWasCut:
    """The type page already carries has_more; the tool text did not say so.

    Measured: 250 types, limit 100, returned=100, total=250, has_more=True,
    while the description omitted has_more. An unattended agent that trusted
    the description treated the page as every local type.
    """

    def test_a_full_page_is_marked(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import sys
        import types

        from headless_re_mcp.backends.ida import worker

        ida_typeinf = types.ModuleType("ida_typeinf")
        ida_typeinf.get_idati = lambda: object()  # type: ignore[attr-defined]
        ida_typeinf.get_ordinal_limit = lambda til: 251  # type: ignore[attr-defined]
        ida_typeinf.get_numbered_type_name = (  # type: ignore[attr-defined]
            lambda til, ordinal: f"T{ordinal}"
        )

        class _Tinfo:
            def get_numbered_type(self, til: object, ordinal: int) -> bool:
                del til, ordinal
                return False

        ida_typeinf.tinfo_t = _Tinfo  # type: ignore[attr-defined]
        monkeypatch.setitem(sys.modules, "ida_typeinf", ida_typeinf)
        page = worker._types({"offset": 0, "limit": 100})
        assert page["returned"] == 100
        assert page["total"] == 250
        assert page["has_more"] is True

    def test_the_tool_description_says_to_read_has_more(self) -> None:
        from pathlib import Path

        source = (
            Path(__file__).resolve().parents[2]
            / "src"
            / "headless_re_mcp"
            / "tools"
            / "core.py"
        ).read_text(encoding="utf-8")
        block = source.split("def static_types(")[1].split("def static_structs(")[0]
        assert "has_more" in block


class TestStaticStructsDescriptionSaysWhenItWasCut:
    """The struct page already carries has_more; the tool text did not say so.

    Measured: 250 structs, limit 100, returned=100, total=250, has_more=True,
    while the description omitted has_more. An unattended agent that trusted
    the description treated the page as every struct.
    """

    def test_a_full_page_is_marked(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import sys
        import types

        from headless_re_mcp.backends.ida import worker

        ida_typeinf = types.ModuleType("ida_typeinf")
        ida_typeinf.get_idati = lambda: object()  # type: ignore[attr-defined]
        ida_typeinf.get_ordinal_limit = lambda til: 251  # type: ignore[attr-defined]
        ida_typeinf.get_numbered_type_name = (  # type: ignore[attr-defined]
            lambda til, ordinal: f"S{ordinal}"
        )

        class _Tinfo:
            def get_numbered_type(self, til: object, ordinal: int) -> bool:
                del til, ordinal
                return True

            def is_udt(self) -> bool:
                return True

            def is_union(self) -> bool:
                return False

            def get_size(self) -> int:
                return 16

        ida_typeinf.tinfo_t = _Tinfo  # type: ignore[attr-defined]
        monkeypatch.setitem(sys.modules, "ida_typeinf", ida_typeinf)
        page = worker._structs({"offset": 0, "limit": 100})
        assert page["returned"] == 100
        assert page["total"] == 250
        assert page["has_more"] is True

    def test_the_tool_description_says_to_read_has_more(self) -> None:
        from pathlib import Path

        source = (
            Path(__file__).resolve().parents[2]
            / "src"
            / "headless_re_mcp"
            / "tools"
            / "core.py"
        ).read_text(encoding="utf-8")
        block = source.split("def static_structs(")[1].split("def static_enums(")[0]
        assert "has_more" in block


class TestIdaDecompileDoesNotInventEmptySource:
    """An empty Hex-Rays result used to look like a finished decompile.

    Measured: decompile() returning ``""`` still answered ``{'code': ''}``.
    ``None`` already failed. An unattended agent then treats a failed
    decompile as empty source.
    """

    def _install(self, monkeypatch: pytest.MonkeyPatch, result: object) -> None:
        import sys
        import types

        class _Fn:
            start_ea = 0x1000
            end_ea = 0x1100

        ida_funcs = types.ModuleType("ida_funcs")
        ida_funcs.get_func = lambda ea: _Fn()  # type: ignore[attr-defined]
        ida_hexrays = types.ModuleType("ida_hexrays")
        ida_hexrays.init_hexrays_plugin = lambda: True  # type: ignore[attr-defined]
        ida_hexrays.decompile = lambda ea: result  # type: ignore[attr-defined]
        idautils = types.ModuleType("idautils")
        idautils.Functions = lambda: [0x1000]  # type: ignore[attr-defined]
        monkeypatch.setitem(sys.modules, "ida_funcs", ida_funcs)
        monkeypatch.setitem(sys.modules, "ida_hexrays", ida_hexrays)
        monkeypatch.setitem(sys.modules, "idautils", idautils)

    def test_empty_code_is_not_a_decompile(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from headless_re_mcp.backends.ida import worker

        self._install(monkeypatch, "")
        with pytest.raises(worker.WorkerRequestError) as info:
            worker._decompile({"address": 0x1000})
        assert info.value.code == "decompilation_failed"
        assert "no code" in str(info.value)

    def test_whitespace_code_is_not_a_decompile(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from headless_re_mcp.backends.ida import worker

        self._install(monkeypatch, "   \n")
        with pytest.raises(worker.WorkerRequestError) as info:
            worker._decompile({"address": 0x1000})
        assert info.value.code == "decompilation_failed"

    def test_real_code_is_a_decompile(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from headless_re_mcp.backends.ida import worker

        self._install(monkeypatch, "void foo(void) {}")
        page = worker._decompile({"address": 0x1000})
        assert page["code"] == "void foo(void) {}"
        assert page["address"] == 0x1000
