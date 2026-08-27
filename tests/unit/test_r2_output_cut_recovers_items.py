"""A r2 JSON list cut at the output buffer must still yield its whole rows.

R2Client.run caps stdout at a megabyte before mapping.enrich_r2_payload parses
it. A binary whose aflj / izj / iij / iEj / axj array runs past that cap arrives
as a half array: json cannot load it at all, and parse_r2_json's first
decodable value is element 0 (a dict), so the payload used to take the dict
branch -- reported parsed with a bogus info object and no items. The entire
listing vanished on any non-trivial binary (aflj rows are ~500 bytes, so a
megabyte is only ~2000 functions). These pin the recovery: the elements that
arrived whole come back under items with items_truncated set, and the info /
raw-text paths still behave.
"""

from __future__ import annotations

import json
from pathlib import Path

from headless_re_mcp.backends.r2.mapping import _MAX_ITEMS, enrich_r2_payload
from headless_re_mcp.core.models import Architecture


def _binary(tmp_path: Path) -> Path:
    binary = tmp_path / "big.exe"
    binary.write_bytes(b"MZ" + b"\x00" * 200)
    return binary


def _cut(text: str, keep: int) -> str:
    """A megabyte cut lands mid-array; mimic it by keeping a byte prefix."""
    return text[:keep]


def test_a_truncated_function_array_recovers_the_whole_rows(tmp_path: Path) -> None:
    """The listing came back as items, not a one-object info dict."""
    entries = [
        {"offset": 0x140001000 + index * 0x10, "name": f"f{index}", "size": 16}
        for index in range(50)
    ]
    full = json.dumps(entries)
    # Cut partway through so the tail objects never arrive complete.
    raw = _cut(full, len(full) // 2)
    payload = enrich_r2_payload(
        {"raw": raw, "commands": ["aa", "aflj"], "truncated": True},
        binary=_binary(tmp_path),
        architecture=Architecture.X64,
    )
    assert payload["parsed"] is True
    assert "info" not in payload, "a half array must not collapse to a single info object"
    assert payload["items_truncated"] is True
    assert payload["items_limit"] == _MAX_ITEMS
    assert "items_total" not in payload, "the true count is unknown once the tail is cut"
    # Every recovered row is a complete object with the mapped address field.
    assert 0 < payload["count"] < 50
    assert payload["items"][0]["name"] == "f0"
    assert payload["items"][0]["address"]["va"] == 0x140001000
    for item in payload["items"]:
        assert "name" in item and "size" in item


def test_recovery_stops_at_the_item_cap(tmp_path: Path) -> None:
    """A cut array with more whole rows than the cap still stops at the cap."""
    entries = [
        {"from": 0x1000 + index, "to": 0x2000, "type": "CODE"}
        for index in range(_MAX_ITEMS + 500)
    ]
    # No closing bracket: emulate a cut that left far more than the cap intact.
    raw = json.dumps(entries)[:-1]
    payload = enrich_r2_payload(
        {"raw": raw, "commands": ["axj"], "truncated": True},
        binary=_binary(tmp_path),
    )
    assert payload["parsed"] is True
    assert payload["count"] == _MAX_ITEMS
    assert payload["items_truncated"] is True
    assert "items_total" not in payload


def test_a_complete_array_is_unchanged(tmp_path: Path) -> None:
    """The recovery path never fires when the whole array loaded cleanly."""
    entries = [{"offset": 0x140001000, "name": "entry0", "size": 8}]
    payload = enrich_r2_payload(
        {"raw": json.dumps(entries), "commands": ["aa", "aflj"]},
        binary=_binary(tmp_path),
        architecture=Architecture.X64,
    )
    assert payload["parsed"] is True
    assert payload["count"] == 1
    assert "items_truncated" not in payload
    assert "items_limit" not in payload


def test_non_json_identity_text_still_reads_as_unparsed(tmp_path: Path) -> None:
    """An `i` listing has no leading bracket, so it must not hit recovery."""
    payload = enrich_r2_payload(
        {"raw": "arch     x86\nbits     64\nos       windows\n", "commands": ["i"]},
        binary=_binary(tmp_path),
    )
    assert payload["parsed"] is False
    assert "items" not in payload
    assert "items_truncated" not in payload


def test_a_single_object_payload_still_reads_as_info(tmp_path: Path) -> None:
    """A dict payload (leading brace, not bracket) still lands in info."""
    payload = enrich_r2_payload(
        {"raw": json.dumps({"format": "pe", "bits": 64}), "commands": ["ij"]},
        binary=_binary(tmp_path),
    )
    assert payload["parsed"] is True
    assert payload["info"] == {"format": "pe", "bits": 64}
    assert "items" not in payload
    assert "items_truncated" not in payload
