"""A byte-cut r2 listing must not be parsed as whatever fragment survives.

run() cuts stdout at 1_000_000 bytes and says so with ``truncated``. When the
cut fell mid-array -- routine for ``aflj``/``izj`` on a large binary -- the
single-value parse could not decode the root, so it scanned on and returned
the first fragment that did decode. Measured through run() on a real
oversized ``aflj`` (r2 5.5.0, byte cap shrunk): ``parsed: True`` with items
holding the first function's nested ``callrefs`` array -- call references
masquerading as the function listing. A dict-shaped first entry landed in
``info`` the same way. Both are fabricated analysis, not truncation.

The fix trusts only the first structural character of cut output: a value
that decodes to completion there is used as usual (the cut fell after it); an
unterminated root array has its complete top-level entries salvaged and the
payload says ``items_salvaged``; anything else is ``parsed: False`` with the
raw text intact.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

import headless_re_mcp.backends.r2.client as r2_client
from headless_re_mcp.backends.common.bounded_run import Completed
from headless_re_mcp.backends.r2.client import R2Client
from headless_re_mcp.backends.r2.mapping import (
    _MAX_ITEMS,
    enrich_r2_payload,
    reparse_cut_output,
)


def _binary(tmp_path: Path) -> Path:
    path = tmp_path / "target.bin"
    path.write_bytes(b"\x7fELF" + b"\x00" * 64)
    return path


def _cut_payload(raw: str) -> dict[str, Any]:
    return {"raw": raw, "commands": ["aflj"], "truncated": True, "output_bytes": 2_000_000}


def test_cut_listing_salvages_the_complete_entries_and_says_so(tmp_path: Path) -> None:
    intact = json.dumps(
        [
            {"offset": 4096, "name": "main"},
            {"offset": 8192, "name": "helper"},
            {"offset": 12288, "name": "other"},
        ]
    )
    cut = intact[: intact.index('"other"')]  # third entry lost mid-write
    out = enrich_r2_payload(_cut_payload(cut), binary=_binary(tmp_path))

    assert out["parsed"] is True
    assert out["items_salvaged"] is True
    assert [item["name"] for item in out["items"]] == ["main", "helper"]
    assert out["count"] == 2
    assert "info" not in out


def test_cut_inside_the_first_entry_never_promotes_a_nested_fragment(tmp_path: Path) -> None:
    """The measured fabrication: nested callrefs presented as the listing.

    aflj entries carry nested arrays (callrefs/datarefs). With the cut inside
    the first entry, the entry itself never decodes but its complete nested
    array does -- and the old first-decodable-value scan returned exactly
    that, parsed: True. The only honest answer here is no parse at all.
    """
    cut = (
        '[{"offset": 4096, "name": "entry0", '
        '"callrefs": [{"addr": 4210648, "type": "CALL", "at": 4198495}], '
        '"datarefs": [4210712], "signature": "int entry0 (in'
    )
    out = enrich_r2_payload(_cut_payload(cut), binary=_binary(tmp_path))

    assert out["parsed"] is False
    assert "items" not in out
    assert "info" not in out
    assert "items_salvaged" not in out
    assert out["raw"] == cut  # the caller can still read what arrived


def test_cut_first_entry_dict_never_lands_in_info(tmp_path: Path) -> None:
    # Same scan failure, dict flavour: the first complete entry of a cut root
    # used to come back as an info-command answer.
    cut = '[{"offset": 4096, "name": "main"}, {"offset": 8192, "na'
    out = enrich_r2_payload(_cut_payload(cut), binary=_binary(tmp_path))
    assert out["parsed"] is True
    assert out["items_salvaged"] is True
    assert [item["name"] for item in out["items"]] == ["main"]
    assert "info" not in out


def test_cut_after_a_complete_root_parses_as_usual(tmp_path: Path) -> None:
    # truncated=True but the root array closed before the cap: nothing to
    # salvage, no salvage flag, ordinary items.
    raw = json.dumps([{"offset": 4096, "name": "main"}]) + '\n[{"tail": "was cu'
    out = enrich_r2_payload(_cut_payload(raw), binary=_binary(tmp_path))
    assert out["parsed"] is True
    assert "items_salvaged" not in out
    assert [item["name"] for item in out["items"]] == ["main"]


def test_salvage_still_respects_the_items_cap(tmp_path: Path) -> None:
    intact = json.dumps([{"offset": index} for index in range(_MAX_ITEMS + 10)])
    cut = intact[:-30]  # loses the closing bracket and a couple of entries
    out = enrich_r2_payload(_cut_payload(cut), binary=_binary(tmp_path))
    assert out["parsed"] is True
    assert out["items_salvaged"] is True
    assert out["count"] == _MAX_ITEMS
    assert out["items_truncated"] is True
    assert out["items_limit"] == _MAX_ITEMS


def test_untruncated_dict_output_still_lands_in_info(tmp_path: Path) -> None:
    # The info branch is for output that *is* a complete dict, and only the
    # truncated path changes: no truncated flag, no salvage logic.
    out = enrich_r2_payload(
        {"raw": '{"format": "elf64"}', "commands": ["i"]},
        binary=_binary(tmp_path),
    )
    assert out["parsed"] is True
    assert out["info"] == {"format": "elf64"}


def test_untruncated_cut_still_uses_the_forgiving_scan(tmp_path: Path) -> None:
    # Without the truncated flag the payload takes the original scan, so a
    # payload that merely looks cut (but was not flagged) is unchanged -- the
    # salvage path is gated strictly on truncated to keep the common case fast.
    cut = '[{"offset": 4096, "name": "main"}, {"offset": 8192, "na'
    out = enrich_r2_payload({"raw": cut, "commands": ["aflj"]}, binary=_binary(tmp_path))
    # The old forgiving scan returns the first decodable value (a dict here),
    # which the info branch keeps. Pinning it documents that only truncated
    # output changed behaviour.
    assert out["parsed"] is True
    assert out["info"]["name"] == "main"


def test_reparse_cut_output_refuses_text_and_non_array_roots() -> None:
    assert reparse_cut_output("") == (None, False)
    assert reparse_cut_output("plain text, no json") == (None, False)
    # A cut root *dict* has no whitelisted producer; refusing beats guessing.
    assert reparse_cut_output('{"key": {"nested": 1}, "cut": "he') == (None, False)


def test_reparse_cut_output_uses_a_complete_leading_value(tmp_path: Path) -> None:
    # When the first value decodes whole, the cut fell after it: return it
    # unflagged, exactly as the normal parse would.
    value, salvaged = reparse_cut_output('[{"offset": 1}]\n[{"tail": cut')
    assert salvaged is False
    assert value == [{"offset": 1}]


def test_run_cut_mid_listing_salvages_end_to_end(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The seam that was measured live: run() cuts, enrichment salvages."""
    listing = json.dumps(
        [{"offset": 4096, "name": "main"}, {"offset": 8192, "name": "helper"}]
    ).encode()
    monkeypatch.setattr(r2_client, "_MAX_OUTPUT", len(listing) - 10)
    monkeypatch.setattr(
        r2_client, "run_bounded", lambda cmd, **kw: Completed(0, listing, b"")
    )
    executable = tmp_path / "r2"
    executable.write_bytes(b"")
    binary = tmp_path / "sample.bin"
    binary.write_bytes(b"\x7fELF" + b"\x00" * 16)

    out = R2Client(executable).run(binary, ["aflj"])

    assert out["truncated"] is True
    assert out["output_bytes"] == len(listing)
    assert out["parsed"] is True
    assert out["items_salvaged"] is True
    assert [item["name"] for item in out["items"]] == ["main"]
