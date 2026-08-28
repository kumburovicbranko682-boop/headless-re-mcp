"""r2.xrefs must return the queried address's refs, not the whole program's.

The shipped command was ``axj @ addr``, and axj is not address-relative: it
dumps every cross-reference radare2 knows and ignores the seek. Measured on
r2 5.5.0 against /bin/ls: ``axj @ entry0`` and ``axj @ 0x1`` returned the
identical 820-entry list, so the tool answered every address with the same
table and the required ``address`` argument meant nothing. The fix runs the
address-relative pair -- ``axtj`` (refs TO the seek) and ``axfj`` (refs FROM
it) -- in one process, and merges the two arrays. These tests pin the merge
contract the live gate exercises for real:

* axtj entries carry ``from`` and leave the target implicit; the queried
  address is filled in as ``to`` (and mirrored for axfj) so every item has
  both endpoints and enrichment can map from_address/to_address.
* position identifies direction (both commands print ``[]`` when empty), and
  a missing second array degrades to no from-refs rather than a crash.
* a self-reference appears in both directions once endpoints are filled and
  must be reported once.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from headless_re_mcp.backends.r2.client import R2Client
from headless_re_mcp.backends.r2.mapping import parse_r2_json_arrays

JsonObject = dict[str, Any]


def _client_with_raw(tmp_path: Path, raw: str) -> R2Client:
    client = R2Client(executable=tmp_path / "r2")

    def _fake_capture(binary: Path, commands: list[str], *, timeout: float = 30.0) -> JsonObject:
        return {"raw": raw, "commands": commands}

    client._capture = _fake_capture  # type: ignore[method-assign]
    return client


def _binary(tmp_path: Path) -> Path:
    target = tmp_path / "sample.bin"
    target.write_bytes(b"\x90" * 16)
    return target


def test_xrefs_fills_the_implicit_endpoint_for_both_directions(
    tmp_path: Path,
) -> None:
    raw = "\n".join(
        [
            # axtj: who references 0x1000 -- ``to`` is implicit.
            json.dumps([{"from": 0x2000, "type": "CALL", "opcode": "call fcn.1000"}]),
            # axfj: what 0x1000 references -- r2 prints both endpoints here.
            json.dumps([{"from": 0x1000, "to": 0x3000, "type": "DATA"}]),
        ]
    )
    client = _client_with_raw(tmp_path, raw)

    payload = client.xrefs(_binary(tmp_path), 0x1000)

    assert payload["parsed"] is True
    assert payload["count"] == 2
    incoming, outgoing = payload["items"]
    assert incoming["from"] == 0x2000
    assert incoming["to"] == 0x1000, "axtj's implicit target must be filled in"
    assert incoming["from_address"] == {"va": 0x2000}
    assert incoming["to_address"] == {"va": 0x1000}
    assert outgoing["from"] == 0x1000
    assert outgoing["to"] == 0x3000
    assert outgoing["to_address"] == {"va": 0x3000}


def test_xrefs_with_no_refs_and_with_a_missing_second_array(tmp_path: Path) -> None:
    """``[]\\n[]`` is the no-refs shape; a truncated raw that lost the axfj
    array must degrade to no from-refs, not misattribute or raise."""
    empty = _client_with_raw(tmp_path, "[]\n[]\n")
    payload = empty.xrefs(_binary(tmp_path), 0x40)
    assert payload["parsed"] is True
    assert payload["items"] == []

    cut = _client_with_raw(tmp_path, json.dumps([{"from": 0x2000, "type": "CALL"}]))
    payload = cut.xrefs(_binary(tmp_path), 0x40)
    assert payload["count"] == 1
    assert payload["items"][0]["to"] == 0x40


def test_xrefs_reports_a_self_reference_once(tmp_path: Path) -> None:
    """A self-loop shows up under axtj (from=addr) and axfj (to=addr); after
    endpoint fill both read from=addr,to=addr and must merge to one item."""
    raw = "\n".join(
        [
            json.dumps([{"from": 0x1000, "type": "CODE"}]),
            json.dumps([{"from": 0x1000, "to": 0x1000, "type": "CODE"}]),
        ]
    )
    client = _client_with_raw(tmp_path, raw)
    payload = client.xrefs(_binary(tmp_path), 0x1000)
    assert payload["count"] == 1


def test_parse_r2_json_arrays_skips_banners_and_nested_brackets() -> None:
    raw = (
        "WARN: [analysis] something with a [ bracket\n"
        '[{"from": 1, "opcode": "mov eax, dword [rbp+0x10]"}]\n'
        "[]\n"
    )
    arrays = parse_r2_json_arrays(raw)
    assert len(arrays) == 2
    assert arrays[0][0]["from"] == 1
    assert arrays[1] == []
