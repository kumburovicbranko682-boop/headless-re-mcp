"""r2.xrefs must answer for the address it was asked about, not the whole DB.

radare2's ``axj`` lists the *entire* cross-reference table and ignores the
``@ addr`` seek, so ``r2.xrefs`` returned the same program-wide list for every
address -- 0x0, a real function, and a bogus VA all came back identical. An
agent pivoting "who references this function" got noise it could not trust.

The fix filters the ``axj`` dump to rows whose origin or target is the requested
address, inside ``enrich_r2_payload`` and *before* the item cap so a hot target
is never truncated away by unrelated rows. These tests pin that contract without
needing radare2: they drive the enrichment directly with synthetic ``axj`` JSON,
including the r2-version drift in the target key (``to`` vs ``addr``).
"""

from __future__ import annotations

import json
from pathlib import Path

from headless_re_mcp.backends.r2.mapping import _MAX_ITEMS, enrich_r2_payload

_IMAGE_BASE = 0x140000000


def _pe(tmp_path: Path) -> Path:
    """A minimal PE64 so enrich can map VAs to rva/module without spawning r2."""
    pe = tmp_path / "demo64.exe"
    image = bytearray(0x200)
    image[0:2] = b"MZ"
    image[0x3C:0x40] = (0x80).to_bytes(4, "little")
    image[0x80:0x84] = b"PE\0\0"
    image[0x94:0x96] = (0xF0).to_bytes(2, "little")
    image[0x98:0x9A] = (0x20B).to_bytes(2, "little")
    image[0xB0:0xB8] = (_IMAGE_BASE).to_bytes(8, "little")
    pe.write_bytes(bytes(image))
    return pe


def _enrich(tmp_path: Path, entries: list[dict], *, target: int | None) -> dict:
    return enrich_r2_payload(
        {"raw": json.dumps(entries), "commands": ["axj"], "address": target},
        binary=_pe(tmp_path),
        xref_filter_va=target,
    )


def test_filter_keeps_only_rows_touching_the_target_to_endpoint(tmp_path: Path) -> None:
    target = 0x140001000
    entries = [
        {"from": 0x140002000, "to": target, "type": "CALL"},
        {"from": 0x140002010, "to": target, "type": "CODE"},
        {"from": 0x140002020, "to": 0x140009999, "type": "CALL"},  # unrelated
    ]
    payload = _enrich(tmp_path, entries, target=target)
    assert payload["count"] == 2
    assert {item["from"] for item in payload["items"]} == {0x140002000, 0x140002010}


def test_filter_matches_the_r2_5x_addr_target_key(tmp_path: Path) -> None:
    # r2 5.x names the referenced address ``addr`` (with ``from`` the origin),
    # not ``to``. The filter must recognise it or every 5.x xref would drop.
    target = 0x140003010
    entries = [
        {"from": 0x14000106B, "addr": target, "type": "CALL", "refname": "sym.imp.Sleep"},
        {"from": 0x1400011B4, "addr": target, "type": "CALL", "refname": "sym.imp.Sleep"},
        {"from": 0x140001053, "addr": 0x140003318, "type": "DATA"},  # unrelated
    ]
    payload = _enrich(tmp_path, entries, target=target)
    assert payload["count"] == 2
    assert all(item["addr"] == target for item in payload["items"])


def test_filter_matches_the_origin_endpoint_too(tmp_path: Path) -> None:
    # "to and from address": a row that *originates* at the target counts.
    origin = 0x140001053
    entries = [
        {"from": origin, "addr": 0x140003318, "type": "DATA", "refname": "str.debug"},
        {"from": 0x140002000, "addr": 0x140003010, "type": "CALL"},  # unrelated
    ]
    payload = _enrich(tmp_path, entries, target=origin)
    assert payload["count"] == 1
    assert payload["items"][0]["from"] == origin


def test_bogus_address_yields_a_clean_empty_list_not_the_whole_db(tmp_path: Path) -> None:
    entries = [{"from": 0x140002000 + i, "to": 0x140001000, "type": "CODE"} for i in range(20)]
    payload = _enrich(tmp_path, entries, target=0xFFFFFFFF)
    assert payload["count"] == 0
    assert payload["items"] == []
    assert payload["parsed"] is True  # empty because filtered, not because unparsed


def test_filter_runs_before_the_item_cap(tmp_path: Path) -> None:
    # A pathological DB: cap+50 unrelated rows first, then a handful that touch
    # the target. If filtering ran after the cap the target rows -- sitting past
    # index 4096 -- would be discarded and the answer would be a wrong empty set.
    target = 0x1400ABCD
    noise = [
        {"from": 0x150000000 + i, "to": 0x160000000 + i, "type": "CODE"}
        for i in range(_MAX_ITEMS + 50)
    ]
    hits = [{"from": 0x140002000 + i, "to": target, "type": "CALL"} for i in range(4)]
    payload = _enrich(tmp_path, noise + hits, target=target)
    assert payload["count"] == 4
    assert "items_truncated" not in payload  # 4 survivors, nothing was cut
    assert all(item["to"] == target for item in payload["items"])


def test_no_filter_preserves_the_unfiltered_contract(tmp_path: Path) -> None:
    # Callers other than xrefs (and the existing tests) pass no filter; the dump
    # must still come through whole so that behaviour is untouched.
    entries = [{"from": 0x140002000 + i, "to": 0x140001000, "type": "CODE"} for i in range(5)]
    payload = enrich_r2_payload(
        {"raw": json.dumps(entries), "commands": ["axj"], "address": 0x140001000},
        binary=_pe(tmp_path),
    )
    assert payload["count"] == 5
