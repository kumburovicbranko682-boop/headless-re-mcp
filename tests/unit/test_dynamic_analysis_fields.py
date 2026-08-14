"""memory.regions must name the field the x64dbg adapter actually returns."""

from __future__ import annotations

import ast
from pathlib import Path

from headless_re_mcp.tools.dynamic_analysis import build_dynamic_analysis_tools


def _tool_docstring(name: str) -> str:
    source = Path(build_dynamic_analysis_tools.__code__.co_filename).read_text(encoding="utf-8")
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        for decorator in node.decorator_list:
            if not isinstance(decorator, ast.Call):
                continue
            for keyword in decorator.keywords:
                if (
                    keyword.arg == "name"
                    and isinstance(keyword.value, ast.Constant)
                    and keyword.value.value == name
                ):
                    return ast.get_docstring(node) or ""
    return ""


def _list_memory_regions_cpp() -> str:
    native = (
        Path(__file__).resolve().parents[2]
        / "native"
        / "xdbg-headless-rpc"
        / "rpc_methods.cpp"
    ).read_text(encoding="utf-8")
    start = native.index("Outcome ListMemoryRegions")
    return native[start : native.index("Outcome QueryMemoryProtect", start)]


def test_memory_regions_description_names_regions_not_items() -> None:
    """The catalog said pagination and never named the list field.

    Measured against ListMemoryRegions: the page is regions, with count, total,
    offset, limit and has_more. There is no items or memory field.
    tests/unit/test_dynamic_service.py already drives a fake worker that puts
    the page in regions. Looking for items after a successful list reads as
    VirtualQuery finding none.
    """
    chunk = _list_memory_regions_cpp()
    assert 'JsonSet(result.get(), "regions"' in chunk
    assert 'JsonSet(result.get(), "count"' in chunk
    assert 'JsonSet(result.get(), "total"' in chunk
    assert 'JsonSet(result.get(), "has_more"' in chunk
    returned = chunk[chunk.index("auto result = JsonObject()") :]
    assert '"items"' not in returned
    assert '"memory"' not in returned
    described = _tool_docstring("memory.regions")
    assert "Answers with regions" in described
    assert "has_more" in described
    assert "no items" in described
    assert "no memory field" in described

def _trace_stack_cpp() -> str:
    native = (
        Path(__file__).resolve().parents[2]
        / "native"
        / "xdbg-headless-rpc"
        / "rpc_methods.cpp"
    ).read_text(encoding="utf-8")
    start = native.index("Outcome TraceStack")
    return native[start : native.index("Outcome ReadDisassembly", start)]


def test_stack_trace_description_names_frames_not_stack() -> None:
    """The catalog said call stack and never named the list field.

    Measured against TraceStack: the page is frames, with count, total, limit
    and has_more. There is no stack or items field. Looking for stack after a
    successful trace reads as an empty call stack.
    """
    chunk = _trace_stack_cpp()
    assert 'JsonSet(result.get(), "frames"' in chunk
    assert 'JsonSet(result.get(), "count"' in chunk
    assert 'JsonSet(result.get(), "total"' in chunk
    assert 'JsonSet(result.get(), "has_more"' in chunk
    returned = chunk[chunk.index("auto result = JsonObject()") :]
    assert '"stack"' not in returned
    assert '"items"' not in returned
    described = _tool_docstring("stack.trace")
    assert "Answers with frames" in described
    assert "has_more" in described
    assert "no stack field" in described
    assert "no items" in described

def _read_disassembly_cpp() -> str:
    native = (
        Path(__file__).resolve().parents[2]
        / "native"
        / "xdbg-headless-rpc"
        / "rpc_methods.cpp"
    ).read_text(encoding="utf-8")
    start = native.index("Outcome ReadDisassembly")
    return native[start : native.index("struct BoundedSymbolContext", start)]


def test_disassembly_read_description_names_instructions_not_disasm() -> None:
    """The catalog said disassemble and never named the list field.

    Measured against ReadDisassembly: the page is instructions, each carrying
    instruction (not text), plus address and count. There is no disasm or items
    field. Looking for disasm after a successful read reads as empty.
    """
    chunk = _read_disassembly_cpp()
    assert 'JsonSet(result.get(), "instructions"' in chunk
    assert 'JsonSet(value.get(), "instruction"' in chunk
    returned = chunk[chunk.index("auto result = JsonObject()") :]
    assert '"disasm"' not in returned
    assert '"items"' not in returned
    assert '"text"' not in returned
    described = _tool_docstring("disassembly.read")
    assert "Answers with instructions" in described
    assert "instruction" in described
    assert "no disasm field" in described
    assert "no items" in described
    assert "no text field" in described

def _current_thread_cpp() -> str:
    native = (
        Path(__file__).resolve().parents[2]
        / "native"
        / "xdbg-headless-rpc"
        / "rpc_methods.cpp"
    ).read_text(encoding="utf-8")
    start = native.index("JsonPtr ThreadObject")
    return native[start : native.index("bool SwitchThread", start)]


def test_threads_current_description_names_tid_not_thread() -> None:
    """The catalog said current thread and never named the payload fields.

    Measured against CurrentThread: success is a ThreadObject at the top level
    (tid, entry, teb, cip, name, suspend_count, current). There is no thread
    field. Looking for thread after a successful read reads as no current TID.
    """
    chunk = _current_thread_cpp()
    assert 'JsonSet(value.get(), "tid"' in chunk
    assert 'JsonSet(value.get(), "entry"' in chunk
    assert 'JsonSet(value.get(), "cip"' in chunk
    assert "ThreadObject(list.list[list.CurrentThread], true)" in chunk
    success = chunk[chunk.index("Outcome CurrentThread") :]
    assert '"thread"' not in success
    described = _tool_docstring("threads.current")
    assert "Answers with tid" in described
    assert "no thread field" in described

def _max_region_count() -> int:
    header = (
        Path(__file__).resolve().parents[2]
        / "native"
        / "xdbg-headless-rpc"
        / "rpc_internal.h"
    ).read_text(encoding="utf-8")
    marker = "constexpr std::uint64_t MaxRegionCount = "
    start = header.index(marker) + len(marker)
    return int(header[start : header.index(";", start)])


def test_memory_regions_schema_matches_native_region_cap() -> None:
    """The catalog accepted any offset and an unbounded limit.

    Measured: input schema offset has no minimum and limit has no maximum.
    Native ListMemoryRegions caps both at MaxRegionCount (8192) and rejects
    a larger limit. A caller that asks for 10**9 regions still occupies a
    worker until the adapter refuses, and a negative offset is only caught
    after the tool is already dispatched.
    """
    from headless_re_mcp.tools.binding import input_schema_for

    cap = _max_region_count()
    assert cap == 8192
    handler = next(
        binding.handler
        for binding in build_dynamic_analysis_tools(object())  # type: ignore[arg-type]
        if binding.name == "memory.regions"
    )
    props = input_schema_for(handler)["properties"]
    assert props["offset"]["minimum"] == 0
    integer_limit = next(item for item in props["limit"]["anyOf"] if item.get("type") == "integer")
    assert integer_limit["minimum"] == 1
    assert integer_limit["maximum"] == cap

def _max_import_candidates() -> int:
    header = (
        Path(__file__).resolve().parents[2]
        / "native"
        / "xdbg-headless-rpc"
        / "rpc_internal.h"
    ).read_text(encoding="utf-8")
    marker = "constexpr std::uint64_t MaxImportCandidates = "
    start = header.index(marker) + len(marker)
    return int(header[start : header.index(";", start)])


def test_imports_scan_schema_matches_native_candidate_cap() -> None:
    """The catalog accepted an unbounded max_candidates.

    Measured: input schema max_candidates has no maximum. Native ScanImports
    caps it at MaxImportCandidates (32) and rejects a larger ask. A caller
    that asks for thousands still occupies a worker until the adapter refuses.
    """
    from headless_re_mcp.tools.binding import input_schema_for

    cap = _max_import_candidates()
    assert cap == 32
    handler = next(
        binding.handler
        for binding in build_dynamic_analysis_tools(object())  # type: ignore[arg-type]
        if binding.name == "imports.scan"
    )
    props = input_schema_for(handler)["properties"]
    assert props["max_candidates"]["minimum"] == 1
    assert props["max_candidates"]["maximum"] == cap

def test_modules_dump_schema_matches_native_dump_cap() -> None:
    """The catalog accepted an unbounded dump size.

    Measured: input schema size has no maximum. Native MaxDumpBytes and the
    service dump_too_large path are 64 MiB. A caller that asks for a 2 GiB
    dump still occupies a worker until the service refuses.
    """
    from headless_re_mcp.tools.binding import input_schema_for

    header = (
        Path(__file__).resolve().parents[2]
        / "native"
        / "xdbg-headless-rpc"
        / "rpc_internal.h"
    ).read_text(encoding="utf-8")
    assert "MaxDumpBytes = 64U * 1024U * 1024U" in header
    cap = 64 * 1024 * 1024
    handler = next(
        binding.handler
        for binding in build_dynamic_analysis_tools(object())  # type: ignore[arg-type]
        if binding.name == "modules.dump"
    )
    props = input_schema_for(handler)["properties"]
    integer_size = next(item for item in props["size"]["anyOf"] if item.get("type") == "integer")
    assert integer_size["minimum"] == 1
    assert integer_size["maximum"] == cap

def test_imports_read_schema_matches_native_scan_cap() -> None:
    """The catalog accepted an unbounded IAT read size.

    Measured: input schema size has no maximum. Native ReadImports rejects
    anything above MaxImportScanBytes (16 MiB). A caller that asks for a
    2 GiB IAT still occupies a worker until the adapter refuses.
    """
    from headless_re_mcp.tools.binding import input_schema_for

    header = (
        Path(__file__).resolve().parents[2]
        / "native"
        / "xdbg-headless-rpc"
        / "rpc_internal.h"
    ).read_text(encoding="utf-8")
    assert "MaxImportScanBytes = 16U * 1024U * 1024U" in header
    cap = 16 * 1024 * 1024
    handler = next(
        binding.handler
        for binding in build_dynamic_analysis_tools(object())  # type: ignore[arg-type]
        if binding.name == "imports.read"
    )
    props = input_schema_for(handler)["properties"]
    assert props["size"]["minimum"] == 1
    assert props["size"]["maximum"] == cap


def test_imports_scan_schema_matches_native_search_size_cap() -> None:
    """The catalog accepted an unbounded IAT search window.

    Measured: input schema search_size has no maximum. Native ScanImports
    rejects anything above MaxImportScanBytes (16 MiB) as out of range. A
    caller that asks to scan 2 GiB still occupies a worker until the adapter
    refuses.
    """
    from headless_re_mcp.tools.binding import input_schema_for

    header = (
        Path(__file__).resolve().parents[2]
        / "native"
        / "xdbg-headless-rpc"
        / "rpc_internal.h"
    ).read_text(encoding="utf-8")
    assert "MaxImportScanBytes = 16U * 1024U * 1024U" in header
    cap = 16 * 1024 * 1024
    handler = next(
        binding.handler
        for binding in build_dynamic_analysis_tools(object())  # type: ignore[arg-type]
        if binding.name == "imports.scan"
    )
    props = input_schema_for(handler)["properties"]
    integer_size = next(
        item for item in props["search_size"]["anyOf"] if item.get("type") == "integer"
    )
    assert integer_size["minimum"] == 1
    assert integer_size["maximum"] == cap

def _resolve_symbol_cpp() -> str:
    native = (
        Path(__file__).resolve().parents[2]
        / "native"
        / "xdbg-headless-rpc"
        / "rpc_methods.cpp"
    ).read_text(encoding="utf-8")
    start = native.index("Outcome ResolveSymbol")
    return native[start : native.index("bool ParseHardwareType", start)]


def test_symbols_resolve_description_names_value_not_address() -> None:
    """The catalog said address and never named the payload field.

    Measured against ResolveSymbol: the VA is value, plus expression and
    resolved. There is no address field. Looking for address after a
    successful resolve reads as the symbol not resolving.
    """
    chunk = _resolve_symbol_cpp()
    assert 'JsonSet(result.get(), "value"' in chunk
    assert 'JsonSet(result.get(), "resolved"' in chunk
    returned = chunk[chunk.index("auto result = JsonObject()") :]
    assert '"address"' not in returned
    described = _tool_docstring("symbols.resolve")
    assert "Answers with value" in described
    assert "resolved" in described
    assert "no address field" in described

def _read_pe_headers_cpp() -> str:
    native = (
        Path(__file__).resolve().parents[2]
        / "native"
        / "xdbg-headless-rpc"
        / "rpc_methods.cpp"
    ).read_text(encoding="utf-8")
    start = native.index("Outcome ReadPeHeadersRuntime")
    return native[start : native.index("struct ModuleRecord", start)]


def test_pe_headers_runtime_description_names_sections_not_headers() -> None:
    """The catalog said PE headers and never named the payload fields.

    Measured against ReadPeHeadersRuntime: sections and directories are
    top-level, plus architecture, entry_point_rva and optional header_artifact.
    There is no headers or pe field. Looking for headers after a successful
    read reads as an empty image.
    """
    chunk = _read_pe_headers_cpp()
    returned = chunk[chunk.rindex("auto result = JsonObject()") :]
    assert 'JsonSet(result.get(), "sections"' in returned
    assert 'JsonSet(result.get(), "directories"' in returned
    assert 'JsonSet(result.get(), "architecture"' in returned
    assert '"headers"' not in returned
    assert '"pe"' not in returned
    described = _tool_docstring("pe.headers.runtime")
    assert "Answers with sections" in described
    assert "directories" in described
    assert "no headers field" in described

def test_modules_dump_description_names_output_path_not_dump() -> None:
    """The catalog said artifact path and never named the payload fields.

    Measured: the service puts the file in output_path and adds sha256 and
    artifact_kind. There is no dump or bytes field. Looking for dump after a
    successful dump reads as the module not being written.
    """
    source = (
        Path(__file__).resolve().parents[2]
        / "src"
        / "headless_re_mcp"
        / "core"
        / "service_dynamic_inspect.py"
    ).read_text(encoding="utf-8")
    start = source.index("def modules_dump")
    chunk = source[start : source.index("def pe_headers_runtime", start)]
    assert 'data["output_path"]' in chunk
    assert 'data["sha256"]' in chunk
    assert 'data["artifact_kind"] = "module_dump"' in chunk
    described = _tool_docstring("modules.dump")
    assert "Answers with output_path" in described
    assert "sha256" in described
    assert "artifact_kind" in described
    assert "no dump field" in described

def test_imports_scan_description_names_candidates_not_iat() -> None:
    """The catalog said IAT candidates and never named the list field.

    Measured against ScanImports: the page is candidates, plus candidate_count
    and blind_selection false. There is no iat field. Looking for iat after a
    successful scan reads as no import table found.
    """
    native = (
        Path(__file__).resolve().parents[2]
        / "native"
        / "xdbg-headless-rpc"
        / "rpc_methods.cpp"
    ).read_text(encoding="utf-8")
    start = native.index("Outcome ScanImports")
    chunk = native[start : native.index("Outcome ReadImports", start)]
    returned = chunk[chunk.rindex("auto result = JsonObject()") :]
    assert 'JsonSet(result.get(), "candidates"' in returned
    assert 'JsonSet(result.get(), "blind_selection"' in returned
    assert '"iat"' not in returned
    described = _tool_docstring("imports.scan")
    assert "Answers with candidates" in described
    assert "blind_selection" in described
    assert "no iat field" in described

def test_imports_read_description_names_entries_not_imports() -> None:
    """The catalog said IAT range and never named the list field.

    Measured against ReadImports: thunks are entries, plus resolved_count,
    iat_va and size. There is no imports field. Looking for imports after a
    successful read reads as an empty table.
    """
    native = (
        Path(__file__).resolve().parents[2]
        / "native"
        / "xdbg-headless-rpc"
        / "rpc_methods.cpp"
    ).read_text(encoding="utf-8")
    start = native.index("Outcome ReadImports")
    chunk = native[start : native.index("Outcome ListModules", start)]
    returned = chunk[chunk.rindex("auto result = JsonObject()") :]
    assert 'JsonSet(result.get(), "entries"' in returned
    assert 'JsonSet(result.get(), "resolved_count"' in returned
    assert '"imports"' not in returned
    described = _tool_docstring("imports.read")
    assert "Answers with entries" in described
    assert "resolved_count" in described
    assert "no imports field" in described
