"""Edge-case coverage for r2 payload mapping helpers.

Covers the PE-header reject arms of pe_preferred_base, the address_dict
validation failure, the parse_r2_json undecodable-prefix skip, the string /
garbage variants of the per-item VA reader, and the non-dict-entry and
object-payload arms of enrich_r2_payload.
"""

from __future__ import annotations

import json
from pathlib import Path

from headless_re_mcp.backends.r2 import mapping


def _pe(
    path: Path,
    *,
    pe_sig: bool = True,
    optional_size: int = 0xF0,
    magic: int = 0x20B,
    image_base: int = 0x140000000,
    total: int = 0x200,
) -> Path:
    image = bytearray(total)
    image[0:2] = b"MZ"
    image[0x3C:0x40] = (0x80).to_bytes(4, "little")
    if pe_sig:
        image[0x80:0x84] = b"PE\0\0"
    image[0x94:0x96] = optional_size.to_bytes(2, "little")
    opt = 0x80 + 24
    image[opt : opt + 2] = magic.to_bytes(2, "little")
    if magic == 0x20B:
        image[opt + 24 : opt + 32] = image_base.to_bytes(8, "little")
    elif magic == 0x10B:
        image[opt + 28 : opt + 32] = image_base.to_bytes(4, "little")
    path.write_bytes(bytes(image))
    return path


def test_pe_preferred_base_rejects_short_optional_header(tmp_path: Path) -> None:
    pe = _pe(tmp_path / "short.exe", optional_size=40, total=0x100)
    assert mapping.pe_preferred_base(pe) == (None, None)


def test_pe_preferred_base_rejects_unknown_magic(tmp_path: Path) -> None:
    pe = _pe(tmp_path / "magic.exe", magic=0x999)
    assert mapping.pe_preferred_base(pe) == (None, None)


def test_pe_preferred_base_returns_arch_without_zero_image_base(tmp_path: Path) -> None:
    pe = _pe(tmp_path / "zerobase.exe", image_base=0)
    arch, base = mapping.pe_preferred_base(pe)
    assert arch is not None
    assert base is None


def test_pe_preferred_base_rejects_missing_pe_signature(tmp_path: Path) -> None:
    pe = _pe(tmp_path / "nopesig.exe", pe_sig=False, total=0x100)
    assert mapping.pe_preferred_base(pe) == (None, None)


def test_address_dict_returns_none_when_module_missing_for_rva() -> None:
    # rva present (va >= image_base) but module empty -> Address rejects it.
    assert mapping.address_dict(0x100, module="", image_base=0, architecture=None) is None


def test_parse_r2_json_skips_an_undecodable_prefix() -> None:
    assert mapping.parse_r2_json('[oops {"ok": 1}') == {"ok": 1}


def test_parse_r2_json_returns_none_without_json() -> None:
    assert mapping.parse_r2_json("just a banner line") is None
    assert mapping.parse_r2_json("   ") is None


def test_enrich_reads_hex_string_offsets(tmp_path: Path) -> None:
    payload = mapping.enrich_r2_payload(
        {"raw": json.dumps([{"offset": "0x2000"}]), "commands": ["aflj"]},
        binary=tmp_path / "absent.bin",
    )
    assert payload["items"][0]["address"]["va"] == 0x2000


def test_enrich_ignores_unparseable_string_offsets(tmp_path: Path) -> None:
    payload = mapping.enrich_r2_payload(
        {"raw": json.dumps([{"offset": "not-a-number"}]), "commands": ["aflj"]},
        binary=tmp_path / "absent.bin",
    )
    assert "address" not in payload["items"][0]


def test_enrich_skips_non_dict_entries(tmp_path: Path) -> None:
    payload = mapping.enrich_r2_payload(
        {"raw": json.dumps([{"offset": 0x1000}, 7, "x"]), "commands": ["aflj"]},
        binary=tmp_path / "absent.bin",
    )
    assert payload["count"] == 1


def test_enrich_reports_object_payload_as_info(tmp_path: Path) -> None:
    payload = mapping.enrich_r2_payload(
        {"raw": json.dumps({"arch": "x86", "bits": 32}), "commands": ["ij"]},
        binary=tmp_path / "absent.bin",
    )
    assert payload["parsed"] is True
    assert payload["info"] == {"arch": "x86", "bits": 32}
