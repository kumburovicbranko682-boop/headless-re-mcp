"""Branch coverage for the r2 payload enrichment helpers in r2/mapping.py.

address_dict / parse_r2_json / _item_va / enrich_r2_payload turn raw r2 -q0
output into items carrying unified Address fields, on every non-PE (and PE)
tool call. The address-mapping tests pin the happy coordinates; these fill the
defensive and shaping branches that a malformed or unusual payload takes:

- address_dict refusing an rva it cannot attach to a module (empty module),
- parse_r2_json declining empty output and stepping past a ``[`` that is not
  JSON (an opcode's ``[rbp+0x10]``) to find the real array later,
- _item_va reading a hex-string address and skipping an unparseable one,
- enrich_r2_payload dropping a request address it cannot map, skipping a
  non-dict list entry and an item with no address, and shaping a single-object
  (``iIj``-style) payload into ``info``.

All are pure over an in-memory payload; the binary is only opened to read a
base, so a nonexistent path (which degrades to va-only) keeps these focused on
the enrichment logic itself.
"""

from __future__ import annotations

from pathlib import Path

from headless_re_mcp.backends.r2.mapping import (
    _item_va,
    address_dict,
    enrich_r2_payload,
    parse_r2_json,
)

_NO_BINARY = Path("does-not-exist-on-disk.bin")


# --- address_dict -----------------------------------------------------------


def test_address_dict_refuses_an_rva_without_a_module() -> None:
    # va is above the base, so an rva is computed, but Address forbids an rva
    # with no module; the helper degrades to None rather than raising.
    assert address_dict(0x2000, module="", image_base=0x1000, architecture=None) is None


def test_address_dict_is_va_only_below_the_image_base() -> None:
    got = address_dict(0x500, module="m", image_base=0x1000, architecture=None)
    assert got == {"va": 0x500}


def test_address_dict_rejects_a_non_int_or_negative_va() -> None:
    assert address_dict(None, module="m", image_base=0, architecture=None) is None
    assert address_dict(-1, module="m", image_base=0, architecture=None) is None


# --- parse_r2_json ----------------------------------------------------------


def test_parse_r2_json_declines_empty_output() -> None:
    assert parse_r2_json("   ") is None
    assert parse_r2_json("") is None


def test_parse_r2_json_steps_past_a_bracket_that_is_not_json() -> None:
    # The first '[' is inside a banner token, not the root array; raw_decode
    # fails there and the scan continues to the real array.
    assert parse_r2_json("startup [oops] then [1, 2, 3]") == [1, 2, 3]


def test_parse_r2_json_returns_none_when_no_value_decodes() -> None:
    assert parse_r2_json("only { broken json here") is None


# --- _item_va ---------------------------------------------------------------


def test_item_va_reads_a_hex_string_address() -> None:
    assert _item_va({"offset": "0x1000"}, ("offset",)) == 0x1000


def test_item_va_skips_an_unparseable_string_then_takes_the_next_key() -> None:
    assert _item_va({"offset": "not-a-number", "vaddr": 32}, ("offset", "vaddr")) == 32


def test_item_va_is_none_when_no_key_yields_an_address() -> None:
    assert _item_va({"name": "foo"}, ("offset", "vaddr")) is None


# --- enrich_r2_payload ------------------------------------------------------


def test_enrich_does_not_remap_a_request_address_it_cannot_map() -> None:
    # A negative request address maps to None, so the Address overlay is
    # skipped: the raw value is left as-is and no address_va is added.
    out = enrich_r2_payload(
        {"address": -1, "raw": "[]", "commands": ["axj @ 0"]}, binary=_NO_BINARY
    )
    assert out["address"] == -1
    assert "address_va" not in out
    assert out["parsed"] is True
    assert out["items"] == []


def test_enrich_skips_a_non_dict_list_entry() -> None:
    out = enrich_r2_payload(
        {"raw": '[1, {"offset": 16}]', "commands": ["aflj"]}, binary=_NO_BINARY
    )
    # The bare int is skipped; only the dict becomes an item.
    assert out["count"] == 1
    assert out["items"][0]["offset"] == 16


def test_enrich_keeps_an_item_without_an_address() -> None:
    out = enrich_r2_payload({"raw": '[{"name": "sym"}]', "commands": ["izj"]}, binary=_NO_BINARY)
    assert out["count"] == 1
    # No recognizable va key, so no address field is fabricated.
    assert "address" not in out["items"][0]
    assert out["items"][0]["name"] == "sym"


def test_enrich_shapes_a_single_object_payload_into_info() -> None:
    out = enrich_r2_payload(
        {"raw": '{"bintype": "elf", "bits": 64}', "commands": ["iIj"]}, binary=_NO_BINARY
    )
    assert out["parsed"] is True
    assert out["info"] == {"bintype": "elf", "bits": 64}
    assert "items" not in out


def test_enrich_marks_unparseable_output_as_not_parsed() -> None:
    out = enrich_r2_payload({"raw": "not json at all", "commands": ["i"]}, binary=_NO_BINARY)
    assert out["parsed"] is False
