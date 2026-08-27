"""r2 merges the dynamic and static symbol tables, so an export is listed twice.

An ELF shared object's ``iEj`` returns every export once from ``.dynsym`` and
once from ``.symtab`` -- the rows are identical but for their ``ordinal`` -- so
``r2.exports`` reported ``count`` double and a reader saw each export listed
once per table. ``enrich_r2_payload`` now collapses rows that are identical
except for their ordinal and says how many it dropped. The payloads below are
real ``r2 -q0 -c iEj`` output (radare2 6.2.0, a libt.so built by gcc).
"""

from __future__ import annotations

import ast
import json
from pathlib import Path

from headless_re_mcp.backends.r2.mapping import _MAX_ITEMS, enrich_r2_payload
from headless_re_mcp.tools.r2 import build_r2_tools

# Real iEj rows: exported_add appears at ordinal 9 and 27, msg at 10 and 30 --
# identical apart from the ordinal, which is exactly the dynsym/symtab merge.
_REAL_IEJ = [
    {
        "name": "exported_add",
        "flagname": "sym.exported_add",
        "realname": "exported_add",
        "ordinal": 9,
        "bind": "GLOBAL",
        "size": 46,
        "type": "FUNC",
        "vaddr": 4498,
        "paddr": 4498,
        "is_imported": False,
    },
    {
        "name": "msg",
        "flagname": "obj.msg",
        "realname": "msg",
        "ordinal": 10,
        "bind": "GLOBAL",
        "size": 8,
        "type": "OBJ",
        "vaddr": 16424,
        "paddr": 12328,
        "is_imported": False,
    },
    {
        "name": "exported_add",
        "flagname": "sym.exported_add",
        "realname": "exported_add",
        "ordinal": 27,
        "bind": "GLOBAL",
        "size": 46,
        "type": "FUNC",
        "vaddr": 4498,
        "paddr": 4498,
        "is_imported": False,
    },
    {
        "name": "msg",
        "flagname": "obj.msg",
        "realname": "msg",
        "ordinal": 30,
        "bind": "GLOBAL",
        "size": 8,
        "type": "OBJ",
        "vaddr": 16424,
        "paddr": 12328,
        "is_imported": False,
    },
]


def _enrich(entries: list[dict], command: str = "iEj") -> dict:
    binary = Path("/tmp/does-not-need-to-exist.so")
    return enrich_r2_payload({"raw": json.dumps(entries), "commands": [command]}, binary=binary)


def test_merged_table_duplicates_collapse_to_the_unique_exports() -> None:
    payload = _enrich(_REAL_IEJ)
    names = [item["name"] for item in payload["items"]]
    assert names == ["exported_add", "msg"]
    assert payload["count"] == 2
    # The two dropped rows are said out loud, not swallowed.
    assert payload["items_deduplicated"] == 2
    # The survivor keeps the first ordinal seen and its resolved address.
    survivor = payload["items"][0]
    assert survivor["ordinal"] == 9
    assert survivor["address"]["va"] == 4498


def test_same_name_at_a_different_address_is_not_a_duplicate() -> None:
    # An alias and its target share a name but not an address: two distinct
    # exports, both must survive -- the dedup keys on the whole row, not name.
    entries = [
        {"name": "open", "ordinal": 1, "vaddr": 4000, "type": "FUNC"},
        {"name": "open", "ordinal": 2, "vaddr": 8000, "type": "FUNC"},
    ]
    payload = _enrich(entries)
    assert payload["count"] == 2
    assert "items_deduplicated" not in payload


def test_rows_differing_by_more_than_ordinal_both_survive() -> None:
    # Conservative: only rows identical except for ordinal collapse. A row that
    # also differs in bind is a different row and is kept.
    entries = [
        {"name": "sym", "ordinal": 1, "vaddr": 4000, "type": "FUNC", "bind": "GLOBAL"},
        {"name": "sym", "ordinal": 2, "vaddr": 4000, "type": "FUNC", "bind": "LOCAL"},
    ]
    payload = _enrich(entries)
    assert payload["count"] == 2
    assert "items_deduplicated" not in payload


def test_lists_without_an_ordinal_are_never_deduplicated() -> None:
    # Functions/xrefs/disassembly carry no ordinal; even byte-identical rows
    # (which do not happen there, but prove the guard) are left alone.
    entries = [
        {"name": "fcn", "addr": 4000, "size": 10},
        {"name": "fcn", "addr": 4000, "size": 10},
    ]
    payload = _enrich(entries, command="aflj")
    assert payload["count"] == 2
    assert "items_deduplicated" not in payload


def test_dedup_happens_before_the_cap_and_both_are_reported() -> None:
    # 4096 unique exports, each duplicated once (8192 rows). Dedup first leaves
    # 4096 unique -- exactly the cap -- so nothing is truncated, and the drop is
    # reported. This proves the cap sees unique rows, not the doubled raw list.
    unique = [
        {"name": f"e{index}", "ordinal": index, "vaddr": 0x1000 + index * 4, "type": "FUNC"}
        for index in range(_MAX_ITEMS)
    ]
    doubled = []
    for entry in unique:
        doubled.append(entry)
        clone = dict(entry)
        clone["ordinal"] = entry["ordinal"] + 100000
        doubled.append(clone)
    payload = _enrich(doubled)
    assert payload["count"] == _MAX_ITEMS
    assert payload["items_deduplicated"] == _MAX_ITEMS
    assert "items_truncated" not in payload


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


def test_exports_docstring_names_the_dedup() -> None:
    assert "items_deduplicated" in _tool_docstring("r2.exports")
