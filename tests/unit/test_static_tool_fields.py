"""static.functions must name the field the IDA worker actually returns."""

from __future__ import annotations

import ast
from pathlib import Path

from headless_re_mcp.tools.core import build_static_core_tools


def _docstring(name: str) -> str:
    source = Path(build_static_core_tools.__code__.co_filename).read_text(encoding="utf-8")
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return ast.get_docstring(node) or ""
    return ""


def test_static_functions_description_names_items_not_functions() -> None:
    """The live catalog omitted the list field.

    tests/unit/test_service.py already drives a fake IDA worker and reads
    functions.data['items'][0]['name']. The worker returns items with address,
    name, end, size and flags, and no functions field. A caller looking for
    functions after a successful list reads it as IDA finding none.
    """
    described = _docstring("static_functions")
    assert "Answers with items" in described
    assert "no functions field" in described
    assert "address" in described
    assert "end" in described
    worker = (
        Path(__file__).resolve().parents[2]
        / "src"
        / "headless_re_mcp"
        / "backends"
        / "ida"
        / "worker.py"
    ).read_text(encoding="utf-8")
    start = worker.index("def _functions")
    chunk = worker[start : start + 900]
    assert '"items": items' in chunk
    assert '"functions"' not in chunk.split("return")[-1]

def test_static_decompile_description_names_code_not_text() -> None:
    """The live catalog omitted the decompiled-text field.

    tests/unit/test_service.py already drives a fake IDA worker and reads
    decompiled.data['code']. The worker returns address, end and code, and no
    text field. A caller looking for text after a successful decompile reads
    it as IDA returning nothing.
    """
    described = _docstring("static_decompile")
    assert "Answers with code" in described
    assert "no text field" in described
    assert "address" in described
    assert "end" in described
    worker = (
        Path(__file__).resolve().parents[2]
        / "src"
        / "headless_re_mcp"
        / "backends"
        / "ida"
        / "worker.py"
    ).read_text(encoding="utf-8")
    start = worker.index("def _decompile")
    chunk = worker[start : worker.index("def _require_function", start)]
    assert '"code": text' in chunk
    returned = chunk.split("return")[-1]
    assert '"code"' in returned
    assert '"text"' not in returned

def test_static_strings_description_names_items_and_value() -> None:
    """The live catalog omitted the list field and named the string body wrong.

    tests/unit/test_service.py already drives a fake IDA worker and reads
    strings.data['items'][0]['value']. The worker returns items with address,
    length, type, value and truncated, and no strings or text field. A caller
    looking for strings or text after a successful list reads it as IDA
    finding none.
    """
    described = _docstring("static_strings")
    assert "Answers with items" in described
    assert "no strings field" in described
    assert "no text field" in described
    assert "value" in described
    worker = (
        Path(__file__).resolve().parents[2]
        / "src"
        / "headless_re_mcp"
        / "backends"
        / "ida"
        / "worker.py"
    ).read_text(encoding="utf-8")
    start = worker.index("def _strings")
    chunk = worker[start : worker.index("def _decompile", start)]
    assert '"items": items' in chunk
    assert '"value": value[:max_length]' in chunk
    assert '"strings":' not in chunk
    assert '"text":' not in chunk

def test_static_disassemble_description_names_instructions() -> None:
    """The live catalog omitted the instruction-list field.

    tests/unit/test_service.py already drives a fake IDA worker and reads
    disasm.data['instructions']. The worker returns instructions with ea,
    size and text, and no items or disassembly field. A caller looking for
    items after a successful disassemble reads it as IDA finding none.
    """
    described = _docstring("static_disassemble")
    joined = " ".join(described.split())
    assert "Answers with instructions" in joined
    assert "no items field" in joined
    assert "no disassembly field" in joined
    worker = (
        Path(__file__).resolve().parents[2]
        / "src"
        / "headless_re_mcp"
        / "backends"
        / "ida"
        / "worker.py"
    ).read_text(encoding="utf-8")
    start = worker.index("def _disassemble")
    chunk = worker[start : worker.index("def _xref_type_name", start)]
    assert '"instructions": instructions' in chunk
    assert '"items":' not in chunk
    assert '"disassembly":' not in chunk

def test_static_bytes_read_description_names_hex() -> None:
    """The live catalog omitted the hex payload field.

    tests/unit/test_service.py already drives a fake IDA worker and reads
    raw.data['hex']. The worker returns address, size, hex, base64 and
    truncated, and no bytes or data field. A caller looking for bytes after a
    successful read reads it as IDA returning nothing.
    """
    described = " ".join(_docstring("static_bytes_read").split())
    assert "Answers with hex" in described
    assert "no bytes field" in described
    assert "no data field" in described
    worker = (
        Path(__file__).resolve().parents[2]
        / "src"
        / "headless_re_mcp"
        / "backends"
        / "ida"
        / "worker.py"
    ).read_text(encoding="utf-8")
    start = worker.index("def _bytes_read")
    chunk = worker[start : worker.index("def _normalize_bin_pattern", start)]
    assert '"hex": data.hex()' in chunk
    assert '"base64"' in chunk
    assert '"bytes":' not in chunk


def test_static_segments_description_names_items_not_segments() -> None:
    """The live catalog omitted the list field.

    tests/unit/test_service.py already drives a fake IDA worker and reads
    segments.data['items'][0]['name']. The worker pages items with start,
    end, size, name, perm and bitness, and no segments field. A caller
    looking for segments after a successful list reads it as IDA finding
    none.
    """
    described = " ".join(_docstring("static_segments").split())
    assert "Answers with items" in described
    assert "no segments field" in described
    assert "perm" in described
    assert "start" in described
    worker = (
        Path(__file__).resolve().parents[2]
        / "src"
        / "headless_re_mcp"
        / "backends"
        / "ida"
        / "worker.py"
    ).read_text(encoding="utf-8")
    start = worker.index("def _segments")
    chunk = worker[start : worker.index("def _imports", start)]
    assert "return _page_items(items, offset, limit)" in chunk
    assert '"start": int(seg.start_ea)' in chunk
    assert '"perm": int(seg.perm)' in chunk
    assert '"segments"' not in chunk
    paging = worker[worker.index("def _page_items") : worker.index("def _metadata")]
    assert '"items": window' in paging
    assert '"total": len(items)' in paging
    assert '"has_more"' not in paging


def test_static_imports_description_names_items_not_imports() -> None:
    """The live catalog omitted the list field.

    tests/unit/test_service.py already drives a fake IDA worker and reads
    imports.data['items'][0]['name']. The worker pages items with ea,
    module, name and ordinal, and no imports field. A caller looking for
    imports after a successful list reads it as IDA finding none.
    """
    described = " ".join(_docstring("static_imports").split())
    assert "Answers with items" in described
    assert "no imports field" in described
    assert "ordinal" in described
    worker = (
        Path(__file__).resolve().parents[2]
        / "src"
        / "headless_re_mcp"
        / "backends"
        / "ida"
        / "worker.py"
    ).read_text(encoding="utf-8")
    start = worker.index("def _imports")
    chunk = worker[start : worker.index("def _exports", start)]
    assert "return _page_items(items, offset, limit)" in chunk
    assert '"module": _module' in chunk
    assert '"ordinal": int(ordinal)' in chunk
    assert '"imports"' not in chunk


def test_static_exports_description_names_items_not_exports() -> None:
    """The live catalog omitted the list field.

    The IDA worker pages items with index, ordinal, ea and name, and no
    exports field. tests/unit/test_service.py's fake worker uses the same
    items page. A caller looking for exports after a successful list reads
    it as IDA finding none.
    """
    described = " ".join(_docstring("static_exports").split())
    assert "Answers with items" in described
    assert "no exports field" in described
    assert "ordinal" in described
    worker = (
        Path(__file__).resolve().parents[2]
        / "src"
        / "headless_re_mcp"
        / "backends"
        / "ida"
        / "worker.py"
    ).read_text(encoding="utf-8")
    start = worker.index("def _exports")
    chunk = worker[start : worker.index("def _entrypoints", start)]
    assert "return _page_items(items, offset, limit)" in chunk
    assert '"index": int(index)' in chunk
    assert '"ordinal": int(ordinal)' in chunk
    assert '"exports"' not in chunk


def test_static_entrypoints_description_names_items_not_entrypoints() -> None:
    """The live catalog omitted the list field.

    The IDA worker pages items with ea, name, kind and ordinal, and no
    entrypoints field. tests/unit/test_service.py's fake worker uses the
    same items page. A caller looking for entrypoints after a successful
    list reads it as IDA finding none.
    """
    described = " ".join(_docstring("static_entrypoints").split())
    assert "Answers with items" in described
    assert "no entrypoints field" in described
    assert "kind" in described
    worker = (
        Path(__file__).resolve().parents[2]
        / "src"
        / "headless_re_mcp"
        / "backends"
        / "ida"
        / "worker.py"
    ).read_text(encoding="utf-8")
    start = worker.index("def _entrypoints")
    chunk = worker[start : worker.index("def _disassemble", start)]
    assert "return _page_items(unique, offset, limit)" in chunk
    assert '"kind": "start_ip"' in chunk
    assert '"kind": "entry"' in chunk
    assert '"entrypoints"' not in chunk


def test_static_xrefs_to_description_names_frm_not_from() -> None:
    """The live catalog omitted the list field and named the source wrong.

    The IDA worker pages items with frm, to, type, type_name and iscode,
    and no from or xrefs field. A caller looking for from after a
    successful list reads it as IDA finding no xref sources.
    """
    described = " ".join(_docstring("static_xrefs_to").split())
    assert "Answers with items" in described
    assert "frm" in described
    assert "no from field" in described
    assert "no xrefs field" in described
    worker = (
        Path(__file__).resolve().parents[2]
        / "src"
        / "headless_re_mcp"
        / "backends"
        / "ida"
        / "worker.py"
    ).read_text(encoding="utf-8")
    start = worker.index("def _xrefs_to")
    chunk = worker[start : worker.index("def _xrefs_from", start)]
    assert '"frm": int(xref.frm)' in chunk
    assert '"to": int(xref.to)' in chunk
    assert '"from"' not in chunk
    assert '"xrefs"' not in chunk


def test_static_xrefs_from_description_names_frm_not_from() -> None:
    """The live catalog omitted the list field and named the source wrong.

    Same payload as xrefs_to: items with frm, not from, and no xrefs field.
    Looking for from after a successful list reads as IDA finding no xref
    sources.
    """
    described = " ".join(_docstring("static_xrefs_from").split())
    assert "Answers with items" in described
    assert "frm" in described
    assert "no from field" in described
    assert "no xrefs field" in described
    worker = (
        Path(__file__).resolve().parents[2]
        / "src"
        / "headless_re_mcp"
        / "backends"
        / "ida"
        / "worker.py"
    ).read_text(encoding="utf-8")
    start = worker.index("def _xrefs_from")
    chunk = worker[start : worker.index("def _callers", start)]
    assert '"frm": int(xref.frm)' in chunk
    assert '"to": int(xref.to)' in chunk
    assert '"from"' not in chunk
    assert '"xrefs"' not in chunk


def test_static_callers_description_names_items_not_callers() -> None:
    """The live catalog omitted the list field.

    The IDA worker pages items with ea, name, site and type_name, plus a
    note that this is call-type xrefs only, and no callers field. A caller
    looking for callers after a successful list reads it as IDA finding
    none.
    """
    described = " ".join(_docstring("static_callers").split())
    assert "Answers with items" in described
    assert "no callers field" in described
    assert "site" in described
    worker = (
        Path(__file__).resolve().parents[2]
        / "src"
        / "headless_re_mcp"
        / "backends"
        / "ida"
        / "worker.py"
    ).read_text(encoding="utf-8")
    start = worker.index("def _callers")
    chunk = worker[start : worker.index("def _callees", start)]
    assert '"site": int(xref.frm)' in chunk
    assert "call-type xrefs only" in chunk
    assert '"callers"' not in chunk


def test_static_callees_description_names_items_not_callees() -> None:
    """The live catalog omitted the list field.

    The IDA worker pages items with ea, name, site and type_name, plus a
    note that this is call-type xrefs from the function body, and no
    callees field. A caller looking for callees after a successful list
    reads it as IDA finding none.
    """
    described = " ".join(_docstring("static_callees").split())
    assert "Answers with items" in described
    assert "no callees field" in described
    assert "site" in described
    worker = (
        Path(__file__).resolve().parents[2]
        / "src"
        / "headless_re_mcp"
        / "backends"
        / "ida"
        / "worker.py"
    ).read_text(encoding="utf-8")
    start = worker.index("def _callees")
    chunk = worker[start : worker.index("def _functions", start)]
    assert '"site": int(xref.frm)' in chunk
    assert "call-type xrefs from function body" in chunk
    assert '"callees"' not in chunk


def test_static_basic_blocks_description_names_items_not_blocks() -> None:
    """The live catalog omitted the list field.

    tests/unit/test_service.py already drives a fake IDA worker and reads
    blocks.data['items']. The worker pages items with id, start, end, size,
    type, succ_ids and pred_ids, and no blocks field. A caller looking for
    blocks after a successful list reads it as IDA finding none.
    """
    described = " ".join(_docstring("static_basic_blocks").split())
    assert "Answers with items" in described
    assert "no blocks field" in described
    assert "succ_ids" in described
    worker = (
        Path(__file__).resolve().parents[2]
        / "src"
        / "headless_re_mcp"
        / "backends"
        / "ida"
        / "worker.py"
    ).read_text(encoding="utf-8")
    start = worker.index("def _basic_blocks")
    chunk = worker[start : worker.index("def _cfg", start)]
    assert '"succ_ids"' in chunk
    assert '"pred_ids"' in chunk
    assert '"blocks"' not in chunk


def test_static_cfg_description_names_nodes_and_edges_not_cfg() -> None:
    """The live catalog omitted the graph fields.

    tests/unit/test_service.py already drives a fake IDA worker and reads
    cfg.data['node_count']. The worker returns nodes and edges, not a cfg
    field. A caller looking for cfg after a successful call reads it as
    IDA finding no graph.
    """
    described = " ".join(_docstring("static_cfg").split())
    assert "Answers with nodes" in described
    assert "edges" in described
    assert "no cfg field" in described
    worker = (
        Path(__file__).resolve().parents[2]
        / "src"
        / "headless_re_mcp"
        / "backends"
        / "ida"
        / "worker.py"
    ).read_text(encoding="utf-8")
    start = worker.index("def _cfg")
    chunk = worker[start : worker.index("def _names", start)]
    assert '"nodes": nodes' in chunk
    assert '"edges": edges' in chunk
    assert '"cfg"' not in chunk


def test_static_globals_description_names_items_not_globals() -> None:
    """The live catalog omitted the list field.

    The IDA worker pages items with ea, name, is_data, is_code and size,
    plus a note that this is named addresses outside functions, and no
    globals field. A caller looking for globals after a successful list
    reads it as IDA finding none.
    """
    described = " ".join(_docstring("static_globals").split())
    assert "Answers with items" in described
    assert "no globals field" in described
    assert "is_data" in described
    worker = (
        Path(__file__).resolve().parents[2]
        / "src"
        / "headless_re_mcp"
        / "backends"
        / "ida"
        / "worker.py"
    ).read_text(encoding="utf-8")
    start = worker.index("def _globals")
    chunk = worker[start : worker.index("def _iter_numbered_types", start)]
    assert '"is_data"' in chunk
    assert "named addresses outside functions" in chunk
    assert '"globals"' not in chunk


def test_static_names_description_names_items_not_names() -> None:
    """The live catalog omitted the list field.

    tests/unit/test_service.py already drives a fake IDA worker and reads
    names.data['items'][0]['name']. The worker pages items with ea and
    name, and no names field. A caller looking for names after a
    successful list reads it as IDA finding none.
    """
    described = " ".join(_docstring("static_names").split())
    assert "Answers with items" in described
    assert "no names field" in described
    worker = (
        Path(__file__).resolve().parents[2]
        / "src"
        / "headless_re_mcp"
        / "backends"
        / "ida"
        / "worker.py"
    ).read_text(encoding="utf-8")
    start = worker.index("def _names")
    chunk = worker[start : worker.index("def _globals", start)]
    assert "return _page_items(items, offset, limit)" in chunk
    assert '"ea": int(ea)' in chunk
    assert '"name": name' in chunk
    assert '"names"' not in chunk


def test_static_types_description_names_items_not_types() -> None:
    """The live catalog omitted the list field.

    The IDA worker pages items with ordinal, name, kind and optional size,
    plus a note about best-effort kind classification, and no types field.
    A caller looking for types after a successful list reads it as IDA
    finding none.
    """
    described = " ".join(_docstring("static_types").split())
    assert "Answers with items" in described
    assert "no types field" in described
    assert "ordinal" in described
    worker = (
        Path(__file__).resolve().parents[2]
        / "src"
        / "headless_re_mcp"
        / "backends"
        / "ida"
        / "worker.py"
    ).read_text(encoding="utf-8")
    start = worker.index("def _types")
    chunk = worker[start : worker.index("def _structs", start)]
    assert "return payload" in chunk
    assert "local type library ordinals" in chunk
    assert '"types"' not in chunk


def test_static_structs_description_names_items_not_structs() -> None:
    """The live catalog omitted the list field.

    The IDA worker pages items whose kind is struct or union, each carrying
    ordinal, name, kind and optional size, and no structs field. A caller
    looking for structs after a successful list reads it as IDA finding
    none.
    """
    described = " ".join(_docstring("static_structs").split())
    assert "Answers with items" in described
    assert "no structs field" in described
    assert "ordinal" in described
    worker = (
        Path(__file__).resolve().parents[2]
        / "src"
        / "headless_re_mcp"
        / "backends"
        / "ida"
        / "worker.py"
    ).read_text(encoding="utf-8")
    start = worker.index("def _structs")
    chunk = worker[start : worker.index("def _enums", start)]
    assert "return _page_items(items, offset, limit)" in chunk
    assert '{"struct", "union"}' in chunk
    assert '"structs"' not in chunk


def test_static_enums_description_names_items_not_enums() -> None:
    """The live catalog omitted the list field.

    The IDA worker pages items whose kind is enum, each carrying ordinal,
    name, kind and optional size, and no enums field. A caller looking
    for enums after a successful list reads it as IDA finding none.
    """
    described = " ".join(_docstring("static_enums").split())
    assert "Answers with items" in described
    assert "no enums field" in described
    assert "ordinal" in described
    worker = (
        Path(__file__).resolve().parents[2]
        / "src"
        / "headless_re_mcp"
        / "backends"
        / "ida"
        / "worker.py"
    ).read_text(encoding="utf-8")
    start = worker.index("def _enums")
    chunk = worker[start : worker.index("def _bytes_read", start)]
    assert "return _page_items(items, offset, limit)" in chunk
    assert 'item.get("kind") == "enum"' in chunk
    assert '"enums"' not in chunk


def test_static_search_bytes_description_names_items_not_matches() -> None:
    """The live catalog omitted the list field.

    The IDA worker pages items with ea, plus pattern, normalized_pattern,
    start, end and note, and no matches field. A caller looking for
    matches after a successful search reads it as IDA finding none.
    """
    described = " ".join(_docstring("static_search_bytes").split())
    assert "Answers with items" in described
    assert "no matches field" in described
    assert "normalized_pattern" in described
    worker = (
        Path(__file__).resolve().parents[2]
        / "src"
        / "headless_re_mcp"
        / "backends"
        / "ida"
        / "worker.py"
    ).read_text(encoding="utf-8")
    start = worker.index("def _search_bytes")
    chunk = worker[start : worker.index("def _search_text", start)]
    assert "payload = _page_items(matches, offset, limit)" in chunk
    assert 'matches.append({"ea": found_ea})' in chunk
    assert '"matches":' not in chunk
    assert '"normalized_pattern"' in chunk


def test_static_search_text_description_names_items_not_matches() -> None:
    """The live catalog omitted the list field.

    The IDA worker pages items with ea, plus text, start and end, and no
    matches field. A caller looking for matches after a successful search
    reads it as IDA finding none.
    """
    described = " ".join(_docstring("static_search_text").split())
    assert "Answers with items" in described
    assert "no matches field" in described
    worker = (
        Path(__file__).resolve().parents[2]
        / "src"
        / "headless_re_mcp"
        / "backends"
        / "ida"
        / "worker.py"
    ).read_text(encoding="utf-8")
    start = worker.index("def _search_text")
    chunk = worker[start : worker.index("def _search_immediate", start)]
    assert "payload = _page_items(matches, offset, limit)" in chunk
    assert 'matches.append({"ea": found_ea})' in chunk
    assert '"matches":' not in chunk


def test_static_search_immediate_description_names_items_not_matches() -> None:
    """The live catalog omitted the list field.

    The IDA worker pages items with ea, value and optional operand, plus
    value, start and end, and no matches field. A caller looking for
    matches after a successful search reads it as IDA finding none.
    """
    described = " ".join(_docstring("static_search_immediate").split())
    assert "Answers with items" in described
    assert "no matches field" in described
    assert "operand" in described
    worker = (
        Path(__file__).resolve().parents[2]
        / "src"
        / "headless_re_mcp"
        / "backends"
        / "ida"
        / "worker.py"
    ).read_text(encoding="utf-8")
    start = worker.index("def _search_immediate")
    chunk = worker[start : worker.index("def _name_set", start)]
    assert "payload = _page_items(matches, offset, limit)" in chunk
    assert '"ea": found_ea' in chunk
    assert '"operand"' in chunk
    assert '"matches":' not in chunk


def test_static_name_set_description_names_previous_name() -> None:
    """The live catalog omitted the payload fields.

    The IDA worker returns address, name, previous_name and ok, and no
    renamed field. A caller looking for renamed after a successful write
    cannot tell what was overwritten.
    """
    described = " ".join(_docstring("static_name_set").split())
    assert "Answers with address" in described
    assert "previous_name" in described
    assert "no renamed field" in described
    worker = (
        Path(__file__).resolve().parents[2]
        / "src"
        / "headless_re_mcp"
        / "backends"
        / "ida"
        / "worker.py"
    ).read_text(encoding="utf-8")
    start = worker.index("def _name_set")
    chunk = worker[start : worker.index("def _comment_set", start)]
    assert '"previous_name": before' in chunk
    assert '"name": after' in chunk
    assert '"renamed"' not in chunk


def test_static_comment_set_description_names_previous_comment() -> None:
    """The live catalog omitted the payload fields.

    The IDA worker returns address, comment, previous_comment, repeatable
    and ok, and no text field. A caller looking for text after a successful
    write cannot tell what was overwritten.
    """
    described = " ".join(_docstring("static_comment_set").split())
    assert "Answers with address" in described
    assert "previous_comment" in described
    assert "no text field" in described
    worker = (
        Path(__file__).resolve().parents[2]
        / "src"
        / "headless_re_mcp"
        / "backends"
        / "ida"
        / "worker.py"
    ).read_text(encoding="utf-8")
    start = worker.index("def _comment_set")
    chunk = worker[start : worker.index("def _type_apply", start)]
    assert '"previous_comment": before' in chunk
    assert '"comment": after' in chunk
    assert '"text"' not in chunk


def test_static_type_apply_description_names_previous_type() -> None:
    """The live catalog omitted the payload fields.

    The IDA worker returns address, type, previous_type and ok, and no
    applied field. A caller looking for applied after a successful write
    cannot tell what type was overwritten.
    """
    described = " ".join(_docstring("static_type_apply").split())
    assert "Answers with address" in described
    assert "previous_type" in described
    assert "no applied field" in described
    worker = (
        Path(__file__).resolve().parents[2]
        / "src"
        / "headless_re_mcp"
        / "backends"
        / "ida"
        / "worker.py"
    ).read_text(encoding="utf-8")
    start = worker.index("def _type_apply")
    chunk = worker[start : worker.index("def _function_create", start)]
    assert '"previous_type": before' in chunk
    assert '"type": after' in chunk
    assert '"applied"' not in chunk


def test_static_function_create_description_names_created() -> None:
    """The live catalog omitted created, so an existing function looks new.

    The IDA worker returns created False with a note when the function
    already exists, otherwise created True, plus start, end and ok. There
    is no function field. A caller looking for function after a successful
    call cannot tell whether anything was created.
    """
    described = " ".join(_docstring("static_function_create").split())
    assert "Answers with address" in described
    assert "created" in described
    assert "already existed" in described
    assert "no function field" in described
    worker = (
        Path(__file__).resolve().parents[2]
        / "src"
        / "headless_re_mcp"
        / "backends"
        / "ida"
        / "worker.py"
    ).read_text(encoding="utf-8")
    start = worker.index("def _function_create")
    chunk = worker[start : worker.index("def _function_delete", start)]
    assert '"created": False' in chunk
    assert '"created": True' in chunk
    assert "function already exists" in chunk
    assert '"function"' not in chunk


def test_static_function_delete_description_names_deleted() -> None:
    """The live catalog omitted the payload fields.

    The IDA worker returns address, end, deleted and ok, and no function
    field. A caller looking for function after a successful delete cannot
    tell which range was removed.
    """
    described = " ".join(_docstring("static_function_delete").split())
    assert "Answers with address" in described
    assert "deleted" in described
    assert "no function field" in described
    worker = (
        Path(__file__).resolve().parents[2]
        / "src"
        / "headless_re_mcp"
        / "backends"
        / "ida"
        / "worker.py"
    ).read_text(encoding="utf-8")
    start = worker.index("def _function_delete")
    chunk = worker[start : worker.index("def _bytes_patch", start)]
    assert '"deleted": True' in chunk
    assert '"end": end' in chunk
    assert '"function":' not in chunk


def test_static_bytes_patch_description_names_before_hex() -> None:
    """The live catalog omitted the payload fields.

    The IDA worker returns address, size, before_hex, after_hex and ok, and
    no bytes or hex field. The service then names the record file
    patch_artifact. A caller looking for bytes or hex after a successful
    patch cannot tell what changed.
    """
    described = " ".join(_docstring("static_bytes_patch").split())
    assert "Answers with address" in described
    assert "before_hex" in described
    assert "after_hex" in described
    assert "patch_artifact" in described
    assert "no bytes field" in described
    assert "no hex field" in described
    worker = (
        Path(__file__).resolve().parents[2]
        / "src"
        / "headless_re_mcp"
        / "backends"
        / "ida"
        / "worker.py"
    ).read_text(encoding="utf-8")
    start = worker.index("def _bytes_patch")
    chunk = worker[start : worker.index("_BATCH_MAX_ITEMS", start)]
    returned = chunk.split("return")[-1]
    assert '"before_hex":' in returned
    assert '"after_hex":' in returned
    assert '"bytes"' not in returned
    assert '"hex":' not in returned
    service = (
        Path(__file__).resolve().parents[2]
        / "src"
        / "headless_re_mcp"
        / "core"
        / "service_static.py"
    ).read_text(encoding="utf-8")
    record = service[
        service.index("def _record_static_patch") : service.index(
            "def _maybe_spill_static_text"
        )
    ]
    assert 'payload["patch_artifact"]' in record


def test_static_batch_description_names_results() -> None:
    """The live catalog omitted the payload fields.

    The IDA worker returns results, each with index, command, ok and either
    data or error, plus count and max_items. There is no commands field and
    no items field. tests/unit/test_static_write_service.py already reads
    count. A caller looking for commands or items after a successful batch
    reads it as IDA running none.
    """
    described = " ".join(_docstring("static_batch").split())
    assert "Answers with results" in described
    assert "count" in described
    assert "max_items" in described
    assert "no commands field" in described
    assert "no items field" in described
    worker = (
        Path(__file__).resolve().parents[2]
        / "src"
        / "headless_re_mcp"
        / "backends"
        / "ida"
        / "worker.py"
    ).read_text(encoding="utf-8")
    start = worker.index("def _batch")
    chunk = worker[start : worker.index("def _dispatch", start)]
    returned = chunk.split("return")[-1]
    assert '"results": results' in returned
    assert '"count":' in returned
    assert '"max_items":' in returned
    assert '"commands"' not in returned
    assert '"items"' not in returned


def test_static_metadata_description_names_image_base() -> None:
    """The live catalog omitted the payload fields.

    tests/unit/test_service.py already drives a fake IDA worker and reads
    meta.data['image_base'] and meta.data['capabilities']. The worker
    returns those keys at the top of the payload, and no metadata field. A
    caller looking for metadata after a successful call reads it as IDA
    returning nothing.
    """
    described = " ".join(_docstring("static_metadata").split())
    assert "Answers with input_path" in described
    assert "image_base" in described
    assert "function_count" in described
    assert "no metadata field" in described
    worker = (
        Path(__file__).resolve().parents[2]
        / "src"
        / "headless_re_mcp"
        / "backends"
        / "ida"
        / "worker.py"
    ).read_text(encoding="utf-8")
    start = worker.index("def _metadata")
    chunk = worker[start : worker.index("def _segments", start)]
    returned = chunk.split("return")[-1]
    assert '"image_base": image_base' in returned
    assert '"function_count":' in returned
    assert '"capabilities":' in returned
    assert '"metadata":' not in returned


def test_static_open_description_names_backend_reused_session() -> None:
    """The live catalog omitted the payload fields.

    tests/integration/test_m8_static_batch1_gate.py already reads
    opened.data['backend']. _open_backend returns session, backend and
    reused, and no top-level session_id. A caller looking for session_id
    after a successful open cannot tell whether IDA was already running.
    """
    described = " ".join(_docstring("static_open").split())
    assert "Answers with backend" in described
    assert "reused" in described
    assert "session" in described
    assert "no top-level session_id" in described
    service = (
        Path(__file__).resolve().parents[2]
        / "src"
        / "headless_re_mcp"
        / "core"
        / "service.py"
    ).read_text(encoding="utf-8")
    start = service.index("def _open_backend")
    chunk = service[start : service.index("def _abandon_open", start)]
    assert '"reused": True' in chunk
    assert '"reused": False' in chunk
    assert '"backend":' in chunk
    assert '"session":' in chunk


def test_session_close_description_names_already_closed_not_closed() -> None:
    """The live catalog omitted the payload fields.

    _close_session returns session and already_closed, true when the
    session was already gone. There is no closed field. A caller looking
    for closed after a successful call cannot tell whether anything was
    torn down.
    """
    described = " ".join(_docstring("session_close").split())
    assert "Answers with session" in described
    assert "already_closed" in described
    assert "no closed field" in described
    service = (
        Path(__file__).resolve().parents[2]
        / "src"
        / "headless_re_mcp"
        / "core"
        / "service.py"
    ).read_text(encoding="utf-8")
    start = service.index("def _close_session")
    chunk = service[start : service.index("def record_artifact", start)]
    assert '"already_closed": True' in chunk
    assert '"already_closed": False' in chunk
    assert '"session":' in chunk
    assert '"closed": True' not in chunk
    assert '"closed": False' not in chunk


def test_workflow_status_description_names_nested_workflow() -> None:
    """The live catalog omitted the payload field.

    tests/unit/test_dynamic_service.py already reads result.data['workflow']
    and then workflow['state']. The service nests the runtime under
    workflow, and there is no top-level status or state field. A caller
    looking for status after a successful call reads a live workflow as
    missing.
    """
    described = " ".join(_docstring("workflow_status").split())
    assert "Answers with workflow" in described
    assert "no top-level status field" in described
    assert "no state field" in described
    service = (
        Path(__file__).resolve().parents[2]
        / "src"
        / "headless_re_mcp"
        / "core"
        / "service_workflow.py"
    ).read_text(encoding="utf-8")
    start = service.index("def workflow_status")
    chunk = service[start : service.index("def workflow_reset", start)]
    assert '{"workflow": terminal.to_dict()}' in chunk or '"workflow": terminal.to_dict()' in chunk
    assert '"workflow": workflow.to_dict()' in chunk
    runtime = (
        Path(__file__).resolve().parents[2]
        / "src"
        / "headless_re_mcp"
        / "workflows"
        / "runtime.py"
    ).read_text(encoding="utf-8")
    start = runtime.index("def to_dict(self) -> JsonObject:")
    chunk = runtime[start : runtime.index("def create_workflow_runtime", start)]
    assert '"status": self.status.value' in chunk
    assert '"state":' in chunk
    assert '"id": self.id' in chunk


def test_workflow_reset_description_names_nested_workflow() -> None:
    """The live catalog omitted the payload field.

    tests/unit/test_dynamic_service.py already reads reset.data['workflow'].
    The service returns the replacement runtime under workflow, and no
    reset field. A caller looking for reset after a successful call cannot
    tell that the previous workflow was replaced.
    """
    described = " ".join(_docstring("workflow_reset").split())
    assert "Answers with workflow" in described
    assert "no reset field" in described
    service = (
        Path(__file__).resolve().parents[2]
        / "src"
        / "headless_re_mcp"
        / "core"
        / "service_workflow.py"
    ).read_text(encoding="utf-8")
    start = service.index("def workflow_reset")
    chunk = service[start : service.index("def workflow_cancel", start)]
    assert '"workflow": reset.to_dict()' in chunk
    assert '"reset"' not in chunk.split("return")[-1]


def test_workflow_cancel_description_names_nested_workflow() -> None:
    """The live catalog omitted the payload field.

    The service returns the cancelled runtime under workflow, and no
    cancelled field. A caller looking for cancelled after a successful
    call cannot tell that navigation stopped.
    """
    described = " ".join(_docstring("workflow_cancel").split())
    assert "Answers with workflow" in described
    assert "no cancelled field" in described
    service = (
        Path(__file__).resolve().parents[2]
        / "src"
        / "headless_re_mcp"
        / "core"
        / "service_workflow.py"
    ).read_text(encoding="utf-8")
    start = service.index("def workflow_cancel")
    chunk = service[start : service.index("def workflow_events_consume", start)]
    assert '"workflow": updated.to_dict()' in chunk
    assert '"cancelled"' not in chunk.split("return {")[-1]


def test_workflow_events_consume_description_names_events_not_workflow() -> None:
    """The live catalog omitted the payload fields.

    workflow.events.consume is dynamic.events plus reconciliation.
    tests/unit/test_dynamic_service.py already reads first.data['events'].
    There is no workflow field. A caller looking for workflow after a
    successful consume reads the batch as empty.
    """
    described = " ".join(_docstring("workflow_events_consume").split())
    assert "Answers with events" in described
    assert "Same payload as dynamic.events" in described
    assert "no workflow field" in described
    assert "no items field" in described
    service = (
        Path(__file__).resolve().parents[2]
        / "src"
        / "headless_re_mcp"
        / "core"
        / "service_workflow.py"
    ).read_text(encoding="utf-8")
    start = service.index("def workflow_events_consume")
    chunk = service[start : service.index("def workflow_module_track", start)]
    assert "return self.dynamic_events(" in chunk
    events = (
        Path(__file__).resolve().parents[2]
        / "src"
        / "headless_re_mcp"
        / "core"
        / "events.py"
    ).read_text(encoding="utf-8")
    batch = events.split("class DebugEventBatch")[1]
    returned = batch[batch.index("def to_dict") : batch.index("class DebugEventCursor")]
    assert '"events":' in returned
    assert '"has_more":' in returned
    assert '"workflow"' not in returned
    assert '"items"' not in returned


def test_workflow_module_track_description_names_module_key() -> None:
    """The live catalog omitted the payload fields.

    The service returns workflow and module_key, and no module or tracked
    field. tests/unit/test_dynamic_service.py already drives track but only
    asserts ok. A caller looking for module after a successful call cannot
    tell which key was recorded.
    """
    described = " ".join(_docstring("workflow_module_track").split())
    assert "Answers with workflow" in described
    assert "module_key" in described
    assert "no module field" in described
    assert "no tracked field" in described
    service = (
        Path(__file__).resolve().parents[2]
        / "src"
        / "headless_re_mcp"
        / "core"
        / "service_workflow.py"
    ).read_text(encoding="utf-8")
    start = service.index("def workflow_module_track")
    chunk = service[start : service.index("def workflow_module_untrack", start)]
    assert '"workflow": updated.to_dict()' in chunk
    assert '"module_key": key.strip()' in chunk
    returned = chunk.split("return {")[-1]
    assert '"module"' not in returned
    assert '"tracked"' not in returned

