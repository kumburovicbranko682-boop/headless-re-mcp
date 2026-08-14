"""dynamic.events must name the field the event batch actually returns."""

from __future__ import annotations

import ast
from pathlib import Path

from headless_re_mcp.core.events import DebugEvent, DebugEventBatch
from headless_re_mcp.tools.dynamic import build_dynamic_tools


def _tool_docstring(name: str) -> str:
    source = Path(build_dynamic_tools.__code__.co_filename).read_text(encoding="utf-8")
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


def test_dynamic_events_description_names_events_not_items() -> None:
    """The live catalog omitted the batch list field.

    tests/unit/test_dynamic_service.py already reads first.data['events'] and
    first.data['durable_log']. DebugEventBatch.to_dict puts the callbacks in
    events (sequence, timestamp_unix_ms, source, kind, data) and has no items
    field. A caller looking for items after a successful poll reads it as the
    debugger going quiet.
    """
    described = " ".join(_tool_docstring("dynamic.events").split())
    assert "Answers with events" in described
    assert "no items field" in described
    payload = DebugEventBatch(
        events=(
            DebugEvent(
                sequence=1,
                timestamp_unix_ms=0,
                source="x64dbg",
                kind="pause",
                data={},
            ),
        ),
        cursor=0,
        next_cursor=1,
        oldest_sequence=1,
        latest_sequence=1,
        dropped=0,
        dropped_total=0,
        has_more=False,
        capacity=256,
    ).to_dict()
    assert "events" in payload
    assert "items" not in payload
    assert payload["events"][0]["kind"] == "pause"
    assert payload["events"][0]["sequence"] == 1

def test_dynamic_memory_read_schema_matches_native_size_cap() -> None:
    """The catalog accepted an unbounded size.

    Measured: input schema size has no maximum. Native ReadMemory caps size
    at MaxMemoryBytes (2 MiB) and rejects zero. A caller that asks for 10**9
    bytes still occupies a worker until the adapter refuses, and the catalog
    never said the read would be rejected.
    """
    from headless_re_mcp.tools.binding import input_schema_for

    header = (
        Path(__file__).resolve().parents[2]
        / "native"
        / "xdbg-headless-rpc"
        / "rpc_internal.h"
    ).read_text(encoding="utf-8")
    marker = "constexpr std::uint64_t MaxMemoryBytes = "
    start = header.index(marker) + len(marker)
    expr = header[start : header.index(";", start)]
    assert "2U * 1024U * 1024U" in expr
    cap = 2 * 1024 * 1024
    native = (
        Path(__file__).resolve().parents[2]
        / "native"
        / "xdbg-headless-rpc"
        / "rpc_methods.cpp"
    ).read_text(encoding="utf-8")
    chunk = native[native.index("Outcome ReadMemory") : native.index("Outcome WriteMemory")]
    assert 'ReadUnsigned(params, "size", size, error, MaxMemoryBytes)' in chunk
    assert 'return InvalidField("size", "size must be positive")' in chunk
    handler = next(
        binding.handler
        for binding in build_dynamic_tools(object())  # type: ignore[arg-type]
        if binding.name == "dynamic.memory.read"
    )
    props = input_schema_for(handler)["properties"]
    assert props["size"]["minimum"] == 1
    assert props["size"]["maximum"] == cap
