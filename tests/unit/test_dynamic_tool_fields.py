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
