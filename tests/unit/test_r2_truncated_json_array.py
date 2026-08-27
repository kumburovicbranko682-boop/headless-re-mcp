"""A truncated r2 *j array must salvage its intact rows, not misparse to one.

The 1MB output cap in ``R2Client.run`` can fall inside an ``aflj`` / ``izj``
array. ``parse_r2_json`` then skipped the unparsable root ``[`` and returned the
first element as if it were the whole document, so ``r2.functions`` on a large
binary answered ``parsed: True`` with a single object and no ``items`` -- the
opposite of what the tool documents. ``enrich_r2_payload`` now salvages the
complete leading rows and flags the cut.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from headless_re_mcp.backends.common.bounded_run import Completed
from headless_re_mcp.backends.r2 import client as r2_client
from headless_re_mcp.backends.r2.client import _MAX_OUTPUT, R2Client
from headless_re_mcp.backends.r2.mapping import (
    _MAX_ITEMS,
    enrich_r2_payload,
    salvage_r2_json_array,
)


def _minimal_pe(tmp_path: Path) -> Path:
    binary = tmp_path / "f.exe"
    binary.write_bytes(b"MZ" + b"\x00" * 200)
    return binary


def test_salvage_returns_the_complete_leading_rows_of_a_cut_array() -> None:
    entries = [{"offset": 0x1000 + index, "name": f"f{index}"} for index in range(4)]
    encoded = [json.dumps(entry) for entry in entries]
    # Three whole objects, then a fourth cut in half and no closing bracket.
    raw = "[" + ",".join(encoded[:3]) + "," + encoded[3][: len(encoded[3]) // 2]
    salvaged = salvage_r2_json_array(raw)
    assert isinstance(salvaged, list)
    assert [item["name"] for item in salvaged] == ["f0", "f1", "f2"]


def test_salvage_ignores_a_prompt_bracket_before_the_array() -> None:
    """r2 may print a banner like ``[0x00000000]>`` before the JSON."""
    entries = [{"offset": 0x1000, "name": "f0"}, {"offset": 0x1008, "name": "f1"}]
    encoded = [json.dumps(entry) for entry in entries]
    raw = "[0x00000000]> [" + encoded[0] + "," + encoded[1][: len(encoded[1]) // 2]
    salvaged = salvage_r2_json_array(raw)
    assert isinstance(salvaged, list)
    assert [item["name"] for item in salvaged] == ["f0"]


def test_salvage_returns_none_for_non_object_text() -> None:
    assert salvage_r2_json_array("arch x86\nbits 64\nbintype pe\n") is None
    assert salvage_r2_json_array("") is None


def test_enrich_salvages_a_truncated_functions_array_instead_of_reporting_one_object(
    tmp_path: Path,
) -> None:
    binary = _minimal_pe(tmp_path)
    entries = [
        {"offset": 0x140001000 + index * 0x10, "name": f"f{index}", "size": 16}
        for index in range(4)
    ]
    encoded = [json.dumps(entry) for entry in entries]
    raw = "[" + ",".join(encoded[:3]) + "," + encoded[3][: len(encoded[3]) // 2]
    enriched = enrich_r2_payload(
        {
            "raw": raw,
            "commands": ["aa", "aflj"],
            "truncated": True,
            "output_bytes": _MAX_OUTPUT + 40,
            "returned_bytes": _MAX_OUTPUT,
        },
        binary=binary,
    )
    # The intact rows survive as items, and the cut is admitted -- not hidden
    # behind a single "info" object with parsed: True.
    assert enriched["parsed"] is True
    assert enriched["count"] == 3
    assert [item["name"] for item in enriched["items"]] == ["f0", "f1", "f2"]
    assert enriched["items_truncated"] is True
    assert enriched["truncated"] is True
    assert "info" not in enriched


def test_enrich_reports_parsed_false_when_a_cut_leaves_no_object(
    tmp_path: Path,
) -> None:
    """A truncated ``i`` (text) dump has nothing object-shaped to salvage."""
    binary = _minimal_pe(tmp_path)
    enriched = enrich_r2_payload(
        {"raw": "X" * 4096, "commands": ["i"], "truncated": True},
        binary=binary,
    )
    assert enriched["parsed"] is False
    assert "items" not in enriched
    assert "info" not in enriched


def test_run_salvages_a_functions_list_cut_at_the_output_cap(
    tmp_path: Path, monkeypatch: object
) -> None:
    """End to end: a real >1MB ``aflj`` dump is cut mid-element by run().

    Before the fix run() flagged truncated=True but enrich returned the first
    function as ``info`` with parsed: True and no items. Now the intact rows are
    salvaged and both cuts (byte buffer and item cap) are reported.
    """
    entries = [
        {"offset": 0x140000000 + index, "name": f"function_{index:08d}_" + "x" * 40, "size": 16}
        for index in range(15000)
    ]
    stdout = json.dumps(entries).encode("utf-8")
    assert len(stdout) > _MAX_OUTPUT
    monkeypatch.setattr(
        r2_client,
        "run_bounded",
        lambda *args, **kwargs: Completed(returncode=0, stdout=stdout, stderr=b""),
    )
    binary = _minimal_pe(tmp_path)
    payload = R2Client(Path(sys.executable)).run(binary, ["aa", "aflj"])
    assert payload["truncated"] is True
    assert payload["parsed"] is True
    assert payload["count"] == _MAX_ITEMS
    assert payload["items_truncated"] is True
    assert payload["items"][0]["name"] == "function_00000000_" + "x" * 40
    assert "info" not in payload
