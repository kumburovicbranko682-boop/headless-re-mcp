"""Edge-branch coverage for r2 payload enrichment (no live radare2 required).

Complements ``test_r2_address_mapping.py`` (the x64 happy path) with the guard
and honesty branches inside ``backends/r2/mapping.py``:

* ``pe_preferred_base`` for a 32-bit (PE32) image, an unknown optional-header
  magic, a zero ImageBase, a truncated optional header, a DOS stub longer than
  the first read window (the two-read loop), and a file that starts with ``MZ``
  but is not a PE.
* ``address_dict`` refusing an rva without a module.
* ``parse_r2_json`` on empty output and on a leading ``[``/``{`` token that does
  not start valid JSON (an r2 banner before the payload).
* ``_item_va`` reading a hex-string address and skipping an unparsable one.
* ``enrich_r2_payload`` for an object (``info``) payload, a list carrying a
  non-dict entry, an entry with no address key, and a request address that does
  not map.
"""

from __future__ import annotations

import json
from pathlib import Path

from headless_re_mcp.backends.r2.mapping import (
    address_dict,
    enrich_r2_payload,
    parse_r2_json,
    pe_preferred_base,
)
from headless_re_mcp.core.models import Architecture


def _pe(
    tmp_path: Path,
    name: str,
    *,
    pe_offset: int = 0x80,
    optional_magic: int = 0x20B,
    optional_size: int = 0xF0,
    image_base: int = 0x140000000,
    put_pe_sig: bool = True,
    total_size: int = 0x200,
) -> Path:
    """Write a minimal PE whose header fields are set per keyword.

    The defaults are a valid PE32+ (x64). Callers flip one field at a time to
    reach a specific guard branch: a wrong ``optional_magic``, a zero
    ``image_base``, a too-small ``optional_size``, a ``pe_offset`` past the
    read window, or ``put_pe_sig=False`` for an MZ file that is not a PE.
    """
    data = bytearray(total_size)
    data[0:2] = b"MZ"
    data[0x3C:0x40] = pe_offset.to_bytes(4, "little")
    if put_pe_sig:
        data[pe_offset : pe_offset + 4] = b"PE\0\0"
    data[pe_offset + 20 : pe_offset + 22] = optional_size.to_bytes(2, "little")
    optional_off = pe_offset + 24
    data[optional_off : optional_off + 2] = optional_magic.to_bytes(2, "little")
    if optional_magic == 0x10B:
        data[optional_off + 28 : optional_off + 32] = image_base.to_bytes(4, "little")
    elif optional_magic == 0x20B:
        data[optional_off + 24 : optional_off + 32] = image_base.to_bytes(8, "little")
    path = tmp_path / name
    path.write_bytes(bytes(data))
    return path


# --- pe_preferred_base ------------------------------------------------------


def test_pe_preferred_base_reads_a_32bit_image(tmp_path: Path) -> None:
    """A PE32 (magic 0x10B) reports x86 and its 4-byte ImageBase."""
    binary = _pe(
        tmp_path,
        "x86.exe",
        optional_magic=0x10B,
        optional_size=0xE0,
        image_base=0x400000,
    )
    arch, base = pe_preferred_base(binary)
    assert arch is Architecture.X86
    assert base == 0x400000


def test_pe_preferred_base_rejects_an_unknown_optional_magic(tmp_path: Path) -> None:
    """Neither PE32 nor PE32+: no architecture can be claimed."""
    binary = _pe(tmp_path, "weird.exe", optional_magic=0x999)
    assert pe_preferred_base(binary) == (None, None)


def test_pe_preferred_base_keeps_arch_but_drops_a_zero_image_base(tmp_path: Path) -> None:
    """ImageBase 0 is not a usable base; the architecture is still known.

    A zero base must not be handed on as if it were real, or every rva would be
    computed against it; the architecture came from the magic and survives.
    """
    binary = _pe(tmp_path, "zerobase.exe", image_base=0)
    arch, base = pe_preferred_base(binary)
    assert arch is Architecture.X64
    assert base is None


def test_pe_preferred_base_rejects_a_truncated_optional_header(tmp_path: Path) -> None:
    """SizeOfOptionalHeader below the ImageBase field means nothing to read."""
    binary = _pe(tmp_path, "short.exe", optional_size=40)
    assert pe_preferred_base(binary) == (None, None)


def test_pe_preferred_base_re_reads_past_a_large_dos_stub(tmp_path: Path) -> None:
    """A DOS stub past the 64 KiB window forces the second (and third) read.

    The first read stops short of the PE signature, so the loop seeks back and
    re-reads enough to reach the file header and then the optional header. The
    header still parses; the base comes back intact.
    """
    binary = _pe(
        tmp_path,
        "bigstub.exe",
        pe_offset=0x10000,
        image_base=0x140000000,
        total_size=0x10200,
    )
    arch, base = pe_preferred_base(binary)
    assert arch is Architecture.X64
    assert base == 0x140000000


def test_pe_preferred_base_on_an_mz_file_that_is_not_a_pe(tmp_path: Path) -> None:
    """A DOS/MZ stub with no PE signature is not a PE at all."""
    binary = _pe(tmp_path, "dos.exe", put_pe_sig=False)
    assert pe_preferred_base(binary) == (None, None)


def test_pe_preferred_base_on_a_non_mz_file(tmp_path: Path) -> None:
    """An ELF (or any non-MZ) target yields no PE base, never an error."""
    binary = tmp_path / "a.out"
    binary.write_bytes(b"\x7fELF" + b"\x00" * 0x100)
    assert pe_preferred_base(binary) == (None, None)


def test_pe_preferred_base_on_a_missing_file_is_silent(tmp_path: Path) -> None:
    """The OSError path returns (None, None) rather than raising."""
    assert pe_preferred_base(tmp_path / "nope.bin") == (None, None)


# --- address_dict -----------------------------------------------------------


def test_address_dict_refuses_an_rva_without_a_module() -> None:
    """An rva needs a module to be meaningful; the Address model enforces it.

    With no module name but an image base the va sits above, an rva is computed
    and Address rejects it; the mapper swallows that as None rather than letting
    the ValueError escape.
    """
    assert address_dict(0x1000, module="", image_base=0x1000, architecture=None) is None


def test_address_dict_rejects_a_non_int_or_negative_va() -> None:
    assert address_dict(None, module="m", image_base=None, architecture=None) is None
    assert address_dict(-1, module="m", image_base=None, architecture=None) is None


def test_address_dict_without_image_base_keeps_va_only() -> None:
    """No base means no rva; the va survives on its own."""
    mapped = address_dict(0x1000, module="m", image_base=None, architecture=None)
    assert mapped == {"va": 0x1000}


# --- parse_r2_json ----------------------------------------------------------


def test_parse_r2_json_on_empty_output_is_none() -> None:
    assert parse_r2_json("") is None
    assert parse_r2_json("   \n  ") is None


def test_parse_r2_json_skips_a_bracket_that_does_not_start_json() -> None:
    """A leading '[' inside an r2 banner must not abort the scan.

    The first bracket is not valid JSON; the scan keeps going and returns the
    real object that follows rather than giving up.
    """
    parsed = parse_r2_json('[warning] loaded\n{"k": 5}')
    assert parsed == {"k": 5}


def test_parse_r2_json_returns_none_when_nothing_decodes() -> None:
    assert parse_r2_json("[ not json at all") is None


def test_parse_r2_json_does_not_crash_on_deeply_nested_brackets() -> None:
    """A truncated izj payload whose crafted string is a long run of '[' used to
    raise RecursionError (a RuntimeError, so the ``except JSONDecodeError`` in
    the scan missed it) and escape as an internal_error. It must degrade to
    "no JSON here" instead."""
    payload = '[{"vaddr":4096,"string":"' + "[" * 40000
    assert parse_r2_json(payload) is None


def test_parse_r2_json_scan_is_bounded_on_a_bracket_heavy_body() -> None:
    """The scan probes at most a fixed number of openers, so a body that is
    almost entirely '[' cannot turn the first-valid-JSON search into an O(n)
    walk of deep-nesting parse attempts."""
    import time

    text = "x" + "[" * 500_000
    started = time.monotonic()
    assert parse_r2_json(text) is None
    # Generous: the point is that it returns promptly rather than spending
    # seconds walking half a million parse attempts.
    assert time.monotonic() - started < 2.0


def test_parse_r2_json_still_finds_json_after_a_short_bracket_banner() -> None:
    """The opener cap must not stop the scan from skipping a normal banner and
    returning the real payload that follows."""
    assert parse_r2_json('[note] [x] {"k": 5}') == {"k": 5}
    assert parse_r2_json('[warn]\n[{"vaddr": 4096}]') == [{"vaddr": 4096}]


# --- enrich_r2_payload ------------------------------------------------------


def test_enrich_reads_a_hex_string_address_and_skips_an_unparsable_one(
    tmp_path: Path,
) -> None:
    """_item_va accepts ``0x..`` strings and steps past junk to the next key.

    The first key here is an unparsable string; the mapper does not stop on it
    but reads the next key's hex string as the address.
    """
    binary = _pe(tmp_path, "app.exe")
    raw = json.dumps([{"offset": "not-a-number", "vaddr": "0x140001000"}])
    out = enrich_r2_payload({"raw": raw, "commands": ["aflj"]}, binary=binary)
    assert out["count"] == 1
    assert out["items"][0]["address"]["va"] == 0x140001000
    assert out["items"][0]["address"]["rva"] == 0x1000


def test_enrich_keeps_a_list_entry_that_has_no_address_key(tmp_path: Path) -> None:
    """An entry with no offset/vaddr/... is kept verbatim, without an address."""
    binary = _pe(tmp_path, "app.exe")
    raw = json.dumps([{"name": "no_addr_here"}])
    out = enrich_r2_payload({"raw": raw, "commands": ["aflj"]}, binary=binary)
    assert out["count"] == 1
    assert out["items"][0]["name"] == "no_addr_here"
    assert "address" not in out["items"][0]


def test_enrich_skips_a_non_dict_entry_in_the_list(tmp_path: Path) -> None:
    """r2 arrays occasionally hold scalars; those are dropped, dicts kept."""
    binary = _pe(tmp_path, "app.exe")
    raw = json.dumps([1, "two", {"offset": 0x140002000, "name": "real"}])
    out = enrich_r2_payload({"raw": raw, "commands": ["aflj"]}, binary=binary)
    assert out["count"] == 1
    assert out["items"][0]["name"] == "real"


def test_enrich_puts_a_json_object_payload_under_info(tmp_path: Path) -> None:
    """A ``{...}`` payload (not a list) is surfaced as info, parsed True."""
    binary = _pe(tmp_path, "app.exe")
    raw = json.dumps({"bin": {"arch": "x86", "bits": 64}})
    out = enrich_r2_payload({"raw": raw, "commands": ["ij"]}, binary=binary)
    assert out["parsed"] is True
    assert out["info"] == {"bin": {"arch": "x86", "bits": 64}}
    assert "items" not in out


def test_enrich_does_not_synthesize_an_address_that_does_not_map(tmp_path: Path) -> None:
    """A request address that cannot map is not turned into an Address.

    The mapped ``address`` dict and its ``address_va`` marker appear only when
    the request address maps; here a negative value cannot, so ``address_va`` is
    absent and the raw request field is left untouched rather than replaced with
    a bogus mapped address. (In production the client validates the address to a
    non-negative int, so this is the defensive arc, not a normal one.)
    """
    binary = _pe(tmp_path, "app.exe")
    out = enrich_r2_payload({"raw": "[]", "commands": ["axj"], "address": -5}, binary=binary)
    assert out["count"] == 0
    assert "address_va" not in out
    assert out["address"] == -5
