"""``pe_preferred_base`` is the r2 enrichment's PE/non-PE fork (no live r2).

Every r2 tool payload runs through ``enrich_r2_payload``, which asks
``pe_preferred_base`` for a preferred ImageBase. When that answer is a real
base, each address the caller sees is dressed as ``{module, rva, va}`` -- the
shape that says "this offset belongs to *this* image, at *this* file-relative
address". When the answer is ``None``, the same offsets stay bare ``{va}``.

So this one header reader decides, for a file r2 just opened, whether the
analyst is handed module-relative coordinates or raw virtual addresses. The
happy PE path is covered elsewhere; the fork's *other* leg is not. A hostile or
merely non-PE input -- an ELF, a truncated header, a stub that claims a
signature it does not carry, a legal PE whose ImageBase is zero -- must land on
bare VA (or, for the zero-base PE, architecture-without-base), never on
fabricated ``rva``/``module`` fields that name an image the file is not.

These tests pin each malformed/pathological leg, plus the pathological-but-valid
large-DOS-stub case the two-read loop exists to serve, and the
``address_dict`` guard that refuses an RVA it cannot attribute to a module.
"""

from __future__ import annotations

from pathlib import Path

from headless_re_mcp.backends.r2.mapping import (
    _MAX_HEADER,
    _needed_header_bytes,
    address_dict,
    pe_preferred_base,
)
from headless_re_mcp.core.models import Architecture

_MZ = b"MZ"
_PE = b"PE\0\0"


def _pe_bytes(
    *,
    magic: int,
    image_base: int,
    pe_offset: int = 0x80,
    optional_size: int = 0xF0,
    write_pe_sig: bool = True,
    total: int | None = None,
) -> bytes:
    """A little-endian PE image header with every field caller-controlled.

    ``optional_size`` is written into the file header's
    ``SizeOfOptionalHeader``; the optional header body is laid out to match so
    the reader either finds a full 60+ byte optional header or, when the caller
    shrinks ``optional_size``, a truncated one.
    """
    body_end = pe_offset + 24 + optional_size + 64
    data = bytearray(total if total is not None else max(0x200, body_end))
    data[0:2] = _MZ
    data[0x3C:0x40] = pe_offset.to_bytes(4, "little")
    if write_pe_sig:
        data[pe_offset : pe_offset + 4] = _PE
    data[pe_offset + 20 : pe_offset + 22] = optional_size.to_bytes(2, "little")
    optional_off = pe_offset + 24
    data[optional_off : optional_off + 2] = magic.to_bytes(2, "little")
    if magic == 0x20B:
        data[optional_off + 24 : optional_off + 32] = image_base.to_bytes(8, "little")
    elif magic == 0x10B:
        data[optional_off + 28 : optional_off + 32] = image_base.to_bytes(4, "little")
    return bytes(data)


def _write(tmp_path: Path, name: str, payload: bytes) -> Path:
    path = tmp_path / name
    path.write_bytes(payload)
    return path


def test_an_unknown_optional_magic_reads_as_no_pe_base(tmp_path: Path) -> None:
    """Only PE32 (0x10B) and PE32+ (0x20B) name where ImageBase lives.

    A file that carries MZ, a valid PE signature and an optional header whose
    magic is neither must not be mined for a base from bytes that mean nothing
    under an unknown format -- every offset from it stays a bare VA.
    """
    binary = _write(tmp_path, "unknown.bin", _pe_bytes(magic=0x1FF, image_base=0x400000))

    assert pe_preferred_base(binary) == (None, None)


def test_a_zero_image_base_keeps_the_architecture_but_drops_the_base(tmp_path: Path) -> None:
    """ImageBase 0 is a real header value, not a base to subtract.

    The magic still identifies the architecture, so that is reported; but with
    no usable base every offset must remain a bare VA rather than an ``rva``
    measured from zero (which would equal the VA and falsely read as
    file-relative). The two returned fields move independently: arch known,
    base unknown.
    """
    binary = _write(tmp_path, "zerobase.bin", _pe_bytes(magic=0x20B, image_base=0))

    assert pe_preferred_base(binary) == (Architecture.X64, None)


def test_a_truncated_optional_header_yields_no_base(tmp_path: Path) -> None:
    """ImageBase sits at optional-header offset 24/28; a stub shorter than that
    cannot hold one, so a header that claims a tiny ``SizeOfOptionalHeader``
    (here 48 < 60) is refused rather than read past its own end."""
    binary = _write(
        tmp_path,
        "trunc.bin",
        _pe_bytes(magic=0x20B, image_base=0x140000000, optional_size=0x30, total=0x200),
    )

    assert pe_preferred_base(binary) == (None, None)


def test_mz_with_a_valid_offset_but_no_pe_signature_is_not_a_pe(tmp_path: Path) -> None:
    """A DOS ``MZ`` and an in-range ``e_lfanew`` are not enough: without the
    ``PE\\0\\0`` signature at that offset the file is a DOS/other binary that
    merely starts with ``MZ``, and its addresses stay bare VA."""
    binary = _write(
        tmp_path,
        "mz_nope.bin",
        _pe_bytes(magic=0x20B, image_base=0x140000000, write_pe_sig=False),
    )

    assert pe_preferred_base(binary) == (None, None)


def test_a_large_dos_stub_past_the_first_window_still_finds_the_base(tmp_path: Path) -> None:
    """The re-read loop exists for exactly this file.

    ``e_lfanew`` here points past the 64 KiB first read, so the header the base
    lives in is not in the initial window. A single-shot reader would give up
    and call a perfectly valid PE base-less; the seek-and-reread loop must
    recover the architecture and the real ImageBase.
    """
    pe_offset = 0x11000  # 68 KiB: beyond the 64 KiB first read
    binary = _write(
        tmp_path,
        "bigstub.bin",
        _pe_bytes(magic=0x20B, image_base=0x140000000, pe_offset=pe_offset),
    )

    assert pe_preferred_base(binary) == (Architecture.X64, 0x140000000)


def test_a_large_stub_without_the_signature_at_that_offset_bails(tmp_path: Path) -> None:
    """The re-read must not be gullible: reaching a far ``e_lfanew`` and finding
    no ``PE\\0\\0`` there is a malformed/hostile file, answered with no base --
    not a base scavenged from whatever bytes happen to sit at that offset."""
    pe_offset = 0x11000
    payload = bytearray(pe_offset + 0x200)
    payload[0:2] = _MZ
    payload[0x3C:0x40] = pe_offset.to_bytes(4, "little")
    # deliberately leave the PE signature and optional header unwritten
    binary = _write(tmp_path, "bigstub_nosig.bin", bytes(payload))

    assert pe_preferred_base(binary) == (None, None)


def test_needed_header_bytes_refuses_an_offset_past_the_ceiling() -> None:
    """A stub-length probe caps how far it will ask a caller to re-read.

    ``_needed_header_bytes`` is what tells the loop how many bytes to pull for
    the second read. An ``e_lfanew`` beyond the 1 MiB ceiling is a header this
    reader will not chase -- returning ``None`` stops the loop instead of
    requesting a multi-megabyte slurp keyed off an attacker-chosen field.
    """
    head = bytearray(0x40)
    head[0:2] = _MZ
    head[0x3C:0x40] = (_MAX_HEADER + 0x1000).to_bytes(4, "little")

    assert _needed_header_bytes(bytes(head)) is None


def test_needed_header_bytes_asks_for_a_reread_when_the_offset_is_past_the_window() -> None:
    """When ``e_lfanew`` sits past the current slice but under the ceiling, the
    probe asks for just enough to reach the file header (``e_lfanew`` + 24), so
    the loop can re-read and learn the optional-header length from there."""
    pe_offset = 0x11000
    head = bytearray(0x40)
    head[0:2] = _MZ
    head[0x3C:0x40] = pe_offset.to_bytes(4, "little")

    assert _needed_header_bytes(bytes(head)) == pe_offset + 24


def test_address_dict_refuses_an_rva_it_cannot_attribute_to_a_module() -> None:
    """An ``rva`` names an offset *within a named image*; without a module name
    it is meaningless. When a base yields an rva but the module label is blank,
    the address is dropped (``None``) rather than emitted as an unattributed
    rva or allowed to raise out of enrichment."""
    mapped = address_dict(
        0x140001000,
        module="",
        image_base=0x140000000,
        architecture=Architecture.X64,
    )

    assert mapped is None


def test_address_dict_without_a_base_stays_a_bare_va() -> None:
    """The non-PE leg of the fork: no base means the offset is reported as a
    plain VA with no ``rva`` and no ``module`` invented for it."""
    mapped = address_dict(
        0x401000,
        module="prog.elf",
        image_base=None,
        architecture=None,
    )

    assert mapped == {"va": 0x401000}
