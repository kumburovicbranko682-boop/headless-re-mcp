"""How a refused idalib open is described to the caller.

idalib opens a binary in place, so one sample has one database and a second
process asking for it is refused. That is a lock clearing on its own, and
telling an unattended caller it is permanent costs it the sample.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from headless_re_mcp.backends.ida.client import IdaWorkerError
from headless_re_mcp.backends.ida.worker import (
    _DATABASE_IN_USE,
    _MAX_CFG_NODES,
    _MAX_DECOMPILE_CHARS,
    _bytes_read,
    _cfg,
    _decompile,
    _exports,
    _functions,
    _globals,
    _imports,
    _metadata,
    _names,
    _open_database_error,
    _overview,
    _page_items,
    _search_immediate,
    _search_text,
    _strings,
    _types,
)


def test_a_database_held_elsewhere_is_named_and_marked_retryable() -> None:
    """Code 4 was reported as a bare number and as permanent.

    Measured with two processes cycling one fixture, 40 of 50 opens failed this
    way, and none did when the same cycles ran one after another. batch.analyze
    opens up to eight static sessions at once, so the collision is something the
    surface invites rather than an accident.
    """
    error = _open_database_error(_DATABASE_IN_USE, Path(r"C:\samples\packed.exe"))

    assert "packed.exe" in str(error), "the caller has to know which sample"
    assert "already open in another process" in str(error)
    assert getattr(error, "retryable", False) is True


def test_any_other_open_failure_keeps_its_code_and_stays_permanent() -> None:
    """Only the one condition proven transient is described as transient."""
    error = _open_database_error(1, Path("sample.exe"))

    assert "code 1" in str(error), "an unclassified failure must still name its code"
    assert getattr(error, "retryable", False) is False


def test_the_worker_envelope_carries_retryable_through_to_the_client() -> None:
    """The flag is only useful if it survives the hop out of the worker."""
    payload = {
        "code": "worker_start_failed",
        "message": "RuntimeError: the IDA database for packed.exe is already open",
        "details": {},
        "retryable": True,
    }

    parsed = IdaWorkerError.from_payload(payload)

    assert parsed.code == "worker_start_failed"
    assert parsed.retryable is True


def test_a_function_page_says_what_was_left_out() -> None:
    """500 items and limit=100 came back as returned=100, total=500, no has_more."""
    result = _page_items([{"i": index} for index in range(500)], 0, 100)
    assert result["returned"] == 100
    assert result["total"] == 500
    assert result["has_more"] is True
    assert len(result["items"]) == 100


def test_the_last_function_page_is_complete() -> None:
    result = _page_items([{"i": index} for index in range(500)], 400, 100)
    assert result["returned"] == 100
    assert result["has_more"] is False


def test_a_short_byte_read_says_so(monkeypatch: Any) -> None:
    """Asked 64, got 16, truncated=False — the rest of the range vanished."""
    import sys
    import types

    ida = types.ModuleType("ida_bytes")
    ida.is_loaded = lambda addr: True  # type: ignore[attr-defined]
    ida.get_bytes = lambda addr, size: b"\x00" * 16  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "ida_bytes", ida)
    result = _bytes_read({"address": 0x1000, "size": 64})
    assert result["size"] == 16
    assert result["requested"] == 64
    assert result["truncated"] is True
    assert len(result["hex"]) == 32


def test_a_function_list_page_says_what_was_left_out(monkeypatch: Any) -> None:
    """The live list does not use _page_items; 500/100 had total and no has_more."""
    import sys
    import types

    idautils = types.ModuleType("idautils")
    idautils.Functions = lambda: list(range(500))  # type: ignore[attr-defined]
    ida_funcs = types.ModuleType("ida_funcs")

    class Func:
        def __init__(self, ea: int) -> None:
            self.start_ea = ea
            self.end_ea = ea + 1
            self.flags = 0

    ida_funcs.get_func = lambda ea: Func(int(ea))  # type: ignore[attr-defined]
    ida_name = types.ModuleType("ida_name")
    ida_name.get_name = lambda ea: f"f{ea}"  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "idautils", idautils)
    monkeypatch.setitem(sys.modules, "ida_funcs", ida_funcs)
    monkeypatch.setitem(sys.modules, "ida_name", ida_name)
    result = _functions({"offset": 0, "limit": 100})
    assert result["returned"] == 100
    assert result["total"] == 500
    assert result["has_more"] is True


def test_a_string_list_page_says_what_was_left_out(monkeypatch: Any) -> None:
    import sys
    import types

    class Item:
        def __init__(self, index: int) -> None:
            self.ea = index
            self.length = 1
            self.strtype = 0

        def __str__(self) -> str:
            return f"s{self.ea}"

    idautils = types.ModuleType("idautils")
    idautils.Strings = lambda: [Item(index) for index in range(500)]  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "idautils", idautils)
    result = _strings({"offset": 0, "limit": 100})
    assert result["returned"] == 100
    assert result["total"] == 500
    assert result["has_more"] is True


def test_a_full_byte_read_is_complete(monkeypatch: Any) -> None:
    import sys
    import types

    ida = types.ModuleType("ida_bytes")
    ida.is_loaded = lambda addr: True  # type: ignore[attr-defined]
    ida.get_bytes = lambda addr, size: b"\x00" * size  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "ida_bytes", ida)
    result = _bytes_read({"address": 0x1000, "size": 64})
    assert result["size"] == 64
    assert result["requested"] == 64
    assert result["truncated"] is False


def _install_hexrays(monkeypatch: Any, text: str) -> None:
    import sys
    import types

    class Func:
        start_ea = 0x1000
        end_ea = 0x1100

    ida_funcs = types.ModuleType("ida_funcs")
    ida_funcs.get_func = lambda ea: Func()  # type: ignore[attr-defined]
    ida_hexrays = types.ModuleType("ida_hexrays")
    ida_hexrays.init_hexrays_plugin = lambda: True  # type: ignore[attr-defined]
    ida_hexrays.decompile = lambda ea: text  # type: ignore[attr-defined]
    idautils = types.ModuleType("idautils")
    idautils.Functions = lambda: [0x1000]  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "ida_funcs", ida_funcs)
    monkeypatch.setitem(sys.modules, "ida_hexrays", ida_hexrays)
    monkeypatch.setitem(sys.modules, "idautils", idautils)


def test_a_huge_decompile_says_how_much_was_cut(monkeypatch: Any) -> None:
    """520000 characters came back in full with no truncated or bytes."""
    full = "int f(void) { return 0; }\n" * 20_000
    assert len(full) > _MAX_DECOMPILE_CHARS
    _install_hexrays(monkeypatch, full)
    result = _decompile({"address": 0x1000})
    assert result["code"] == full[:_MAX_DECOMPILE_CHARS]
    assert result["truncated"] is True
    assert result["bytes"] == len(full)


def test_a_short_decompile_is_complete(monkeypatch: Any) -> None:
    _install_hexrays(monkeypatch, "int f(void) { return 1; }")
    result = _decompile({"address": 0x1000})
    assert result["code"] == "int f(void) { return 1; }"
    assert result["truncated"] is False
    assert result["bytes"] == len(result["code"])


def test_a_default_decompile_does_not_list_every_function(monkeypatch: Any) -> None:
    """No address used to list every function just to pick the first.

    Measured: 20000 addresses were materialized before Hex-Rays ran.
    """
    import sys
    import types

    class Counting:
        def __init__(self) -> None:
            self.yielded = 0

        def __iter__(self):
            for index in range(20_000):
                self.yielded += 1
                yield index

    class Func:
        start_ea = 0
        end_ea = 1

    funcs = Counting()
    idautils = types.ModuleType("idautils")
    idautils.Functions = lambda: funcs  # type: ignore[attr-defined]
    ida_funcs = types.ModuleType("ida_funcs")
    ida_funcs.get_func = lambda ea: Func()  # type: ignore[attr-defined]
    ida_hexrays = types.ModuleType("ida_hexrays")
    ida_hexrays.init_hexrays_plugin = lambda: True  # type: ignore[attr-defined]
    ida_hexrays.decompile = lambda ea: "int f(){}"  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "idautils", idautils)
    monkeypatch.setitem(sys.modules, "ida_funcs", ida_funcs)
    monkeypatch.setitem(sys.modules, "ida_hexrays", ida_hexrays)
    result = _decompile({})
    assert result["address"] == 0
    assert funcs.yielded == 1


def test_overview_does_not_keep_every_function(monkeypatch: Any) -> None:
    """Open used to list every function and string just to count them.

    Measured: 20000 addresses and 20000 strings were materialized for the
    ready event.
    """
    import sys
    import types

    class Counting:
        def __init__(self) -> None:
            self.yielded = 0

        def __iter__(self):
            for index in range(20_000):
                self.yielded += 1
                yield index

    functions = Counting()
    strings = Counting()
    idautils = types.ModuleType("idautils")
    idautils.Functions = lambda: functions  # type: ignore[attr-defined]
    idautils.Strings = lambda: strings  # type: ignore[attr-defined]
    ida_idaapi = types.ModuleType("ida_idaapi")
    ida_idaapi.BADADDR = 0xFFFFFFFFFFFFFFFF  # type: ignore[attr-defined]
    ida_kernwin = types.ModuleType("ida_kernwin")
    ida_kernwin.get_kernel_version = lambda: "8.3"  # type: ignore[attr-defined]
    ida_nalt = types.ModuleType("ida_nalt")
    ida_nalt.get_imagebase = lambda: 0x1000  # type: ignore[attr-defined]
    ida_hexrays = types.ModuleType("ida_hexrays")
    ida_hexrays.init_hexrays_plugin = lambda: False  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "idautils", idautils)
    monkeypatch.setitem(sys.modules, "ida_idaapi", ida_idaapi)
    monkeypatch.setitem(sys.modules, "ida_kernwin", ida_kernwin)
    monkeypatch.setitem(sys.modules, "ida_nalt", ida_nalt)
    monkeypatch.setitem(sys.modules, "ida_hexrays", ida_hexrays)
    result = _overview()
    assert result["function_count"] == 20_000
    assert result["string_count"] == 20_000
    assert result["entry_function"] == 0
    assert "functions" not in result
    assert "strings" not in result
    assert functions.yielded == 20_000
    assert strings.yielded == 20_000


def test_metadata_does_not_keep_every_function(monkeypatch: Any) -> None:
    """Metadata used to list every function and string just to count them.

    Measured: 20000 addresses and 20000 strings were materialized for a
    snapshot that only reports the counts.
    """
    import sys
    import types

    class Counting:
        def __init__(self) -> None:
            self.yielded = 0

        def __iter__(self):
            for index in range(20_000):
                self.yielded += 1
                yield index

    functions = Counting()
    strings = Counting()
    idautils = types.ModuleType("idautils")
    idautils.Functions = lambda: functions  # type: ignore[attr-defined]
    idautils.Strings = lambda: strings  # type: ignore[attr-defined]
    ida_ida = types.ModuleType("ida_ida")
    ida_ida.inf_get_start_ip = lambda: 0x401000  # type: ignore[attr-defined]
    ida_ida.inf_is_64bit = lambda: True  # type: ignore[attr-defined]
    ida_ida.inf_get_procname = lambda: "metapc"  # type: ignore[attr-defined]
    ida_nalt = types.ModuleType("ida_nalt")
    ida_nalt.get_imagebase = lambda: 0x1000  # type: ignore[attr-defined]
    ida_nalt.get_input_file_path = lambda: "sample.exe"  # type: ignore[attr-defined]
    ida_hexrays = types.ModuleType("ida_hexrays")
    ida_hexrays.init_hexrays_plugin = lambda: False  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "idautils", idautils)
    monkeypatch.setitem(sys.modules, "ida_ida", ida_ida)
    monkeypatch.setitem(sys.modules, "ida_nalt", ida_nalt)
    monkeypatch.setitem(sys.modules, "ida_hexrays", ida_hexrays)
    result = _metadata({})
    assert result["function_count"] == 20_000
    assert result["string_count"] == 20_000
    assert result["start_ip"] == 0x401000
    assert "functions" not in result
    assert "strings" not in result
    assert functions.yielded == 20_000
    assert strings.yielded == 20_000


def test_a_search_page_says_when_there_is_more(monkeypatch: Any) -> None:
    """500 text hits and limit=100 came back as total=100, has_more=False."""
    import sys
    import types

    hits = list(range(0x1000, 0x1000 + 500))

    def find_text(ea: int, y: int, x: int, text: str, flags: int) -> int:
        del y, x, text, flags
        for addr in hits:
            if addr >= ea:
                return addr
        return 0xFFFFFFFFFFFFFFFF

    ida_ida = types.ModuleType("ida_ida")
    ida_ida.inf_get_min_ea = lambda: 0x1000  # type: ignore[attr-defined]
    ida_ida.inf_get_max_ea = lambda: 0x1000 + 10_000  # type: ignore[attr-defined]
    ida_idaapi = types.ModuleType("ida_idaapi")
    ida_idaapi.BADADDR = 0xFFFFFFFFFFFFFFFF  # type: ignore[attr-defined]
    ida_search = types.ModuleType("ida_search")
    ida_search.SEARCH_DOWN = 1  # type: ignore[attr-defined]
    ida_search.find_text = find_text  # type: ignore[attr-defined]
    idc = types.ModuleType("idc")
    idc.BADADDR = 0xFFFFFFFFFFFFFFFF  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "ida_ida", ida_ida)
    monkeypatch.setitem(sys.modules, "ida_idaapi", ida_idaapi)
    monkeypatch.setitem(sys.modules, "ida_search", ida_search)
    monkeypatch.setitem(sys.modules, "idc", idc)
    result = _search_text({"text": "MZ", "offset": 0, "limit": 100})
    assert result["returned"] == 100
    assert result["has_more"] is True
    assert "total" not in result
    assert len(result["items"]) == 100


def test_a_finished_search_reports_its_total(monkeypatch: Any) -> None:
    import sys
    import types

    hits = list(range(0x1000, 0x1000 + 30))

    def find_imm(ea: int, flags: int, value: int) -> int:
        del flags, value
        for addr in hits:
            if addr >= ea:
                return addr
        return 0xFFFFFFFFFFFFFFFF

    ida_ida = types.ModuleType("ida_ida")
    ida_ida.inf_get_min_ea = lambda: 0x1000  # type: ignore[attr-defined]
    ida_ida.inf_get_max_ea = lambda: 0x1000 + 10_000  # type: ignore[attr-defined]
    ida_idaapi = types.ModuleType("ida_idaapi")
    ida_idaapi.BADADDR = 0xFFFFFFFFFFFFFFFF  # type: ignore[attr-defined]
    ida_search = types.ModuleType("ida_search")
    ida_search.SEARCH_DOWN = 1  # type: ignore[attr-defined]
    ida_search.find_imm = find_imm  # type: ignore[attr-defined]
    idc = types.ModuleType("idc")
    idc.BADADDR = 0xFFFFFFFFFFFFFFFF  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "ida_ida", ida_ida)
    monkeypatch.setitem(sys.modules, "ida_idaapi", ida_idaapi)
    monkeypatch.setitem(sys.modules, "ida_search", ida_search)
    monkeypatch.setitem(sys.modules, "idc", idc)
    result = _search_immediate({"value": 0, "offset": 0, "limit": 100})
    assert result["returned"] == 30
    assert result["has_more"] is False
    assert result["total"] == 30


def _install_flowchart(monkeypatch: Any, block_count: int) -> None:
    import sys
    import types

    class Block:
        def __init__(self, index: int, total: int) -> None:
            self.id = index
            self.start_ea = 0x1000 + index * 16
            self.end_ea = self.start_ea + 16
            self.type = 0
            self._total = total

        def succs(self) -> list[Block]:
            nxt = self.id + 1
            return [Block(nxt, self._total)] if nxt < self._total else []

    class Chart:
        def __init__(self, total: int) -> None:
            self._total = total

        def __iter__(self) -> Any:
            for index in range(self._total):
                yield Block(index, self._total)

    class Func:
        start_ea = 0x1000
        end_ea = 0x1000 + 16

    ida_gdl = types.ModuleType("ida_gdl")
    ida_gdl.FlowChart = lambda function: Chart(block_count)  # type: ignore[attr-defined]
    ida_funcs = types.ModuleType("ida_funcs")
    ida_funcs.get_func = lambda ea: Func()  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "ida_gdl", ida_gdl)
    monkeypatch.setitem(sys.modules, "ida_funcs", ida_funcs)


def test_a_huge_cfg_says_how_much_was_cut(monkeypatch: Any) -> None:
    """5000 blocks came back in full with no truncated or has_more."""
    _install_flowchart(monkeypatch, 5000)
    result = _cfg({"address": 0x1000})
    assert result["node_count"] == _MAX_CFG_NODES
    assert result["total_nodes"] == 5000
    assert result["total_edges"] == 4999
    assert result["truncated"] is True
    assert result["has_more"] is True
    assert len(result["nodes"]) == _MAX_CFG_NODES
    kept = {node["id"] for node in result["nodes"]}
    assert all(edge["src"] in kept and edge["dst"] in kept for edge in result["edges"])


def test_a_short_cfg_is_complete(monkeypatch: Any) -> None:
    _install_flowchart(monkeypatch, 3)
    result = _cfg({"address": 0x1000})
    assert result["node_count"] == 3
    assert result["total_nodes"] == 3
    assert result["truncated"] is False
    assert result["has_more"] is False


def test_a_name_page_does_not_build_the_whole_idb(monkeypatch: Any) -> None:
    """5000 names and limit=100 still built 5000 dicts before slicing."""
    import sys
    import types

    import headless_re_mcp.backends.ida.worker as worker

    idautils = types.ModuleType("idautils")
    idautils.Names = lambda: [(index, f"n{index}") for index in range(5000)]  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "idautils", idautils)

    def boom(items: list[Any], offset: int, limit: int) -> Any:
        raise AssertionError(f"materialised {len(items)} name dicts")

    monkeypatch.setattr(worker, "_page_items", boom)
    result = _names({"offset": 0, "limit": 100})
    assert result["returned"] == 100
    assert result["total"] == 5000
    assert result["has_more"] is True
    assert len(result["items"]) == 100


def test_a_globals_page_does_not_build_the_whole_idb(monkeypatch: Any) -> None:
    import sys
    import types

    import headless_re_mcp.backends.ida.worker as worker

    idautils = types.ModuleType("idautils")
    idautils.Names = lambda: [(index, f"n{index}") for index in range(5000)]  # type: ignore[attr-defined]
    ida_funcs = types.ModuleType("ida_funcs")
    ida_funcs.get_func = lambda ea: None  # type: ignore[attr-defined]
    ida_bytes = types.ModuleType("ida_bytes")
    ida_bytes.get_flags = lambda ea: 0  # type: ignore[attr-defined]
    ida_bytes.is_data = lambda flags: True  # type: ignore[attr-defined]
    ida_bytes.is_code = lambda flags: False  # type: ignore[attr-defined]
    ida_bytes.get_item_size = lambda ea: 4  # type: ignore[attr-defined]
    ida_name = types.ModuleType("ida_name")
    ida_name.get_name = lambda ea: f"n{ea}"  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "idautils", idautils)
    monkeypatch.setitem(sys.modules, "ida_funcs", ida_funcs)
    monkeypatch.setitem(sys.modules, "ida_bytes", ida_bytes)
    monkeypatch.setitem(sys.modules, "ida_name", ida_name)

    def boom(items: list[Any], offset: int, limit: int) -> Any:
        raise AssertionError(f"materialised {len(items)} global dicts")

    monkeypatch.setattr(worker, "_page_items", boom)
    result = _globals({"offset": 0, "limit": 100})
    assert result["returned"] == 100
    assert result["total"] == 5000
    assert result["has_more"] is True
    assert len(result["items"]) == 100


def test_a_type_page_does_not_build_the_whole_til(monkeypatch: Any) -> None:
    """5000 types and limit=100 still built 5000 dicts before slicing."""
    import sys
    import types

    import headless_re_mcp.backends.ida.worker as worker

    ida_typeinf = types.ModuleType("ida_typeinf")

    class Tinfo:
        def get_numbered_type(self, til: object, ordinal: int) -> bool:
            del til, ordinal
            return True

        def is_udt(self) -> bool:
            return False

        def is_union(self) -> bool:
            return False

        def is_enum(self) -> bool:
            return False

        def is_func(self) -> bool:
            return False

        def is_ptr(self) -> bool:
            return False

    ida_typeinf.get_idati = lambda: object()  # type: ignore[attr-defined]
    ida_typeinf.get_ordinal_limit = lambda til: 5001  # type: ignore[attr-defined]
    ida_typeinf.get_numbered_type_name = lambda til, ordinal: f"T{ordinal}"  # type: ignore[attr-defined]
    ida_typeinf.tinfo_t = Tinfo  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "ida_typeinf", ida_typeinf)

    def boom(items: list[Any], offset: int, limit: int) -> Any:
        raise AssertionError(f"materialised {len(items)} type dicts")

    monkeypatch.setattr(worker, "_page_items", boom)
    result = _types({"offset": 0, "limit": 100})
    assert result["returned"] == 100
    assert result["total"] == 5000
    assert result["has_more"] is True
    assert len(result["items"]) == 100


def test_an_import_page_does_not_build_the_whole_table(monkeypatch: Any) -> None:
    """5000 imports and limit=100 still built 5000 dicts before slicing."""
    import sys
    import types

    import headless_re_mcp.backends.ida.worker as worker

    ida_nalt = types.ModuleType("ida_nalt")
    ida_nalt.get_import_module_qty = lambda: 1  # type: ignore[attr-defined]
    ida_nalt.get_import_module_name = lambda index: "kernel32"  # type: ignore[attr-defined]

    def enum_import_names(index: int, callback: Any) -> bool:
        del index
        for ordinal in range(5000):
            callback(0x1000 + ordinal, f"Fn{ordinal}", ordinal)
        return True

    ida_nalt.enum_import_names = enum_import_names  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "ida_nalt", ida_nalt)

    def boom(items: list[Any], offset: int, limit: int) -> Any:
        raise AssertionError(f"materialised {len(items)} import dicts")

    monkeypatch.setattr(worker, "_page_items", boom)
    result = _imports({"offset": 0, "limit": 100})
    assert result["returned"] == 100
    assert result["total"] == 5000
    assert result["has_more"] is True
    assert len(result["items"]) == 100


def test_an_export_page_does_not_build_the_whole_table(monkeypatch: Any) -> None:
    import sys
    import types

    import headless_re_mcp.backends.ida.worker as worker

    idautils = types.ModuleType("idautils")
    idautils.Entries = lambda: [  # type: ignore[attr-defined]
        (index, index, 0x1000 + index, f"E{index}") for index in range(5000)
    ]
    monkeypatch.setitem(sys.modules, "idautils", idautils)

    def boom(items: list[Any], offset: int, limit: int) -> Any:
        raise AssertionError(f"materialised {len(items)} export dicts")

    monkeypatch.setattr(worker, "_page_items", boom)
    result = _exports({"offset": 0, "limit": 100})
    assert result["returned"] == 100
    assert result["total"] == 5000
    assert result["has_more"] is True
    assert len(result["items"]) == 100
