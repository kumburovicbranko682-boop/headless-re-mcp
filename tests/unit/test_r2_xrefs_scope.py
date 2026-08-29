"""r2.xrefs answers about one address, never the whole xref database.

``axj @ addr`` -- the command xrefs() used to build -- lists every cross
reference in the binary; the ``@`` seek changes nothing (measured on r2
5.5.0: a two-caller fixture answered with entry0/printf/section relocs for
every address asked, and the entries named their target ``addr``, so the
documented ``to``/``to_address`` fields never existed either). The scoped
commands are ``axtj`` (references to the seek) and ``axfj`` (references from
it); the client runs both in one spawn and ``enrich_xrefs_payload`` merges
the two arrays positionally, tagging each item with ``direction`` and
defaulting the endpoint the raw entry leaves implicit.

These tests pin the merge itself: the tagging, the endpoint defaults, the
honest ``parsed: False`` when the output stops looking like two arrays, and
the multi-value parse the merge stands on.
"""

from __future__ import annotations

import json
from pathlib import Path

from headless_re_mcp.backends.r2.mapping import (
    enrich_xrefs_payload,
    parse_r2_json_values,
)

_ADDRESS = 0x401130


def _binary(tmp_path: Path) -> Path:
    path = tmp_path / "target.bin"
    path.write_bytes(b"\x7fELF" + b"\x00" * 64)
    return path


def _payload(raw: str) -> dict[str, object]:
    return {
        "raw": raw,
        "commands": [f"axtj @ {_ADDRESS}", f"axfj @ {_ADDRESS}"],
        "address": _ADDRESS,
    }


def test_merge_tags_directions_and_fills_the_implicit_endpoint(tmp_path: Path) -> None:
    """axtj entries gain to=address; axfj entries keep their own endpoints.

    An axtj entry names only its origin (``from``) -- the requested address
    is the implied target. Without the default, every incoming reference
    would carry a from_address but no to/to_address, and the tool docstring
    promises both ends on every item.
    """
    raw = (
        json.dumps([{"from": 0x401164, "type": "CALL"}, {"from": 0x401171, "type": "CALL"}])
        + "\n"
        + json.dumps([{"from": _ADDRESS, "to": 0x401000, "type": "DATA"}])
    )
    out = enrich_xrefs_payload(_payload(raw), binary=_binary(tmp_path), address=_ADDRESS)

    assert out["parsed"] is True
    assert out["count"] == 3
    assert [item["direction"] for item in out["items"]] == ["to", "to", "from"]
    incoming, _, outgoing = out["items"]
    assert incoming["to"] == _ADDRESS
    assert incoming["to_address"]["va"] == _ADDRESS
    assert incoming["from_address"]["va"] == 0x401164
    assert outgoing["to"] == 0x401000
    assert outgoing["to_address"]["va"] == 0x401000
    # Every item touches the requested address -- the property the old
    # whole-database dump violated for all but a handful of entries.
    assert all(item["from"] == _ADDRESS or item["to"] == _ADDRESS for item in out["items"])


def test_merge_defaults_a_missing_axfj_origin_to_the_address(tmp_path: Path) -> None:
    raw = "[]\n" + json.dumps([{"to": 0x401000, "type": "DATA"}])
    out = enrich_xrefs_payload(_payload(raw), binary=_binary(tmp_path), address=_ADDRESS)
    assert out["items"] == [
        {
            "to": 0x401000,
            "type": "DATA",
            "from": _ADDRESS,
            "direction": "from",
            "address": {"va": _ADDRESS},
            "from_address": {"va": _ADDRESS},
            "to_address": {"va": 0x401000},
        }
    ]


def test_drifted_output_is_parsed_false_not_a_half_answer(tmp_path: Path) -> None:
    """One array, or three, means the format drifted; say so, don't guess.

    run() pre-enriches the payload generically, and that pass sees only the
    first array -- so on drift the input dict already carries items/count
    built from the axtj half alone. Those must not survive as an
    authoritative-looking answer.
    """
    for raw in ("[]", '[{"from": 1}]', "[]\n[]\n[]"):
        stale = {
            **_payload(raw),
            "items": [{"from": 1}],
            "count": 1,
            "parsed": True,
            "items_truncated": True,
            "items_total": 5000,
            "items_limit": 4096,
        }
        out = enrich_xrefs_payload(stale, binary=_binary(tmp_path), address=_ADDRESS)
        assert out["parsed"] is False, raw
        for key in ("items", "count", "items_truncated", "items_total", "items_limit"):
            assert key not in out, (raw, key)
        # The raw text and the request coordinate stay for the caller to read.
        assert out["raw"] == raw
        assert out["address_va"] == _ADDRESS


def test_merge_tolerates_banner_text_and_skips_non_dict_entries(tmp_path: Path) -> None:
    raw = "WARN: cannot analyze rip\n" + json.dumps([{"from": 0x401164}, 7, "x"]) + "\n[]"
    out = enrich_xrefs_payload(_payload(raw), binary=_binary(tmp_path), address=_ADDRESS)
    assert out["parsed"] is True
    # Non-dict entries are dropped from items but counted like the generic
    # enrichment counts them: count is what survived.
    assert out["count"] == 1
    assert out["items"][0]["from"] == 0x401164


def test_parse_r2_json_values_returns_every_value_in_order() -> None:
    """The single-value parse stops at the first array; the merge needs both.

    Brackets inside strings must not double-count (the axtj opcode field
    carries ``[rbp+0x10]`` shapes), and undecodable ``[``/``{`` from banners
    are stepped over exactly like parse_r2_json does.
    """
    raw = '[x] noise\n[{"opcode": "mov eax, [rbp+0x10]"}]\n{"k": 1}\n[]'
    values = parse_r2_json_values(raw)
    assert values == [[{"opcode": "mov eax, [rbp+0x10]"}], {"k": 1}, []]
    assert parse_r2_json_values("") == []
    assert parse_r2_json_values("no json here") == []
