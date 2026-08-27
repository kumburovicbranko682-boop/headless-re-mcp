"""r2.xrefs description must name items_truncated when the list was cut."""

from __future__ import annotations

import ast
import json
from pathlib import Path

from headless_re_mcp.backends.common.json_budget import RESULT_BUDGET_BYTES
from headless_re_mcp.backends.r2.mapping import _MAX_ITEMS, enrich_r2_payload
from headless_re_mcp.tools.r2 import build_r2_tools


def _tool_docstring(name: str) -> str:
    source = Path(build_r2_tools.__code__.co_filename).read_text(encoding="utf-8")
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


def test_r2_xrefs_says_when_the_list_was_cut(tmp_path: Path) -> None:
    """The catalog named items and never named the cut.

    Measured: 4099 xrefs whose enriched rows encode past the result budget, so
    the list comes back trimmed below the 4096 count cap with items_truncated
    True and items_total 4099 -- not nuked whole to a ~16 KiB summary. Looking
    for a complete xref list after a successful call reads the rest of the graph
    as empty, and a payload that overran the budget reads as nothing at all.
    """
    binary = tmp_path / "f.exe"
    binary.write_bytes(b"MZ" + b"\x00" * 200)
    entries = [
        {"from": 0x140002000 + index, "to": 0x140001000, "type": "CODE"}
        for index in range(_MAX_ITEMS + 3)
    ]
    payload = enrich_r2_payload(
        {"raw": json.dumps(entries), "commands": ["axj"], "address": 0x140001000},
        binary=binary,
    )
    assert payload["count"] == len(payload["items"])
    assert 0 < payload["count"] < _MAX_ITEMS  # the size budget bit before the count cap
    assert payload["items_truncated"] is True
    assert payload["items_total"] == 4099
    assert payload["items_limit"] == _MAX_ITEMS
    # raw is the same list unparsed; it is dropped so it cannot double the payload.
    assert "raw" not in payload
    assert "xrefs" not in payload
    assert "has_more" not in payload
    encoded = len(json.dumps(payload, ensure_ascii=False).encode("utf-8"))
    assert encoded <= RESULT_BUDGET_BYTES
    doc = _tool_docstring("r2.xrefs")
    assert "items_truncated" in doc
    assert "no" in doc and "xrefs" in doc


def test_r2_listing_survives_the_transport_budget(tmp_path: Path) -> None:
    """A big xref listing must pass the transport intact, not be nuked whole.

    Enriches 4099 xrefs -- before dropping the redundant raw and byte-bounding
    items, that payload (raw JSON plus 4096 enriched rows) ran well past the
    budget, so the transport replaced it with a ~16 KiB summary. Confirm
    bounded_tool_result now returns it with items present and no summary.
    """
    from headless_re_mcp.agent.context import bounded_tool_result

    binary = tmp_path / "f.exe"
    binary.write_bytes(b"MZ" + b"\x00" * 200)
    entries = [
        {"from": 0x140002000 + index, "to": 0x140001000, "type": "CODE"}
        for index in range(_MAX_ITEMS + 3)
    ]
    payload = enrich_r2_payload(
        {"raw": json.dumps(entries), "commands": ["axj"], "address": 0x140001000},
        binary=binary,
    )
    bounded, truncated = bounded_tool_result(payload, max_bytes=RESULT_BUDGET_BYTES)
    assert truncated is False, "r2 listing should already fit the transport budget"
    assert "summary" not in bounded
    assert "items" in bounded
    assert len(bounded["items"]) == payload["count"]


def test_r2_xrefs_count_cap_holds_when_rows_are_tiny(tmp_path: Path) -> None:
    """The 4096 count cap still applies when the size budget does not bite.

    With rows small enough that 4099 of them stay under the result budget, the
    count cap is what cuts the list -- proving it still guards enrichment work
    rather than being wholly superseded by the byte bound.
    """
    binary = tmp_path / "f.exe"
    binary.write_bytes(b"MZ" + b"\x00" * 200)
    entries = [{"i": index} for index in range(_MAX_ITEMS + 3)]
    payload = enrich_r2_payload(
        {"raw": json.dumps(entries), "commands": ["axj"], "address": 0x140001000},
        binary=binary,
    )
    assert payload["count"] == _MAX_ITEMS
    assert payload["items_truncated"] is True
    assert payload["items_total"] == _MAX_ITEMS + 3
    encoded = len(json.dumps(payload, ensure_ascii=False).encode("utf-8"))
    assert encoded <= RESULT_BUDGET_BYTES
