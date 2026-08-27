"""r2 address mapping on a NON-PE target: VA only, no invented rva or module.

r2/rizin is the cross-platform backend -- its whole reason to exist beside the
Windows-only tooling is ELF and Mach-O. Every r2 payload is enriched through
``mapping.py``, which asks ``pe_preferred_base`` for an ImageBase and then, in
``address_dict``, maps each address:

    if image_base is not None and va >= image_base:
        rva = va - image_base

so a module-relative ``rva`` (and the ``module`` that must accompany it) is added
*only* when there is a PE image base and the address sits at or above it.
``pe_preferred_base`` returns ``(None, None)`` for anything that is not a PE, so
on an ELF the address is VA-only: ``{va, architecture}`` with no ``rva`` and no
``module``, and the payload carries no ``image_base``.

Both halves of that guard are load-bearing and neither is exercised by the
existing r2 suite, which builds a PE with ``_minimal_pe`` for every case:

* Drop ``image_base is not None`` and an ELF call does ``va - None`` -> TypeError
  (or, if someone "helpfully" defaulted the base to 0, ``rva == va`` and a bogus
  ``module`` on every ELF address).
* Drop ``va >= image_base`` and an address below the base computes a negative
  ``rva``; ``Address``'s ``ge=0`` then rejects it, ``address_dict`` returns None,
  and the item silently loses its address entirely.

`test_r2_address_mapping.py` pins the PE direction (``test_address_dict_with_rva``,
``test_enrich_functions_payload``) but never the no-base one, so a refactor that
assumed an image base was always present would break ELF/Mach-O mapping while the
PE tests stayed green. These tests pin the non-PE direction directly: ``image_base
=None`` and ``va < image_base`` both yield VA-only, and a full ``enrich_r2_payload``
over a non-PE file emits VA-only items and request address, no ``image_base`` in
the payload, while ``architecture`` (which the caller can supply independently of
any header) still flows through.
"""

from __future__ import annotations

import json
from pathlib import Path

from headless_re_mcp.backends.r2.mapping import (
    address_dict,
    enrich_r2_payload,
    pe_preferred_base,
)
from headless_re_mcp.core.models import Architecture


def _non_pe(tmp_path: Path) -> Path:
    """A file that is decidedly not a PE, so pe_preferred_base declines it."""
    path = tmp_path / "prog.elf"
    path.write_bytes(b"\x7fELF" + b"\x00" * 300)
    return path


def test_pe_preferred_base_declines_a_non_pe_file(tmp_path: Path) -> None:
    """The precondition for everything below: no MZ/PE means no arch, no base."""
    assert pe_preferred_base(_non_pe(tmp_path)) == (None, None)


def test_address_dict_without_image_base_is_va_only(tmp_path: Path) -> None:
    """image_base=None -> {va, architecture}; never an rva, never a module.

    This is the ELF/Mach-O path. A ``module`` is even passed in, to prove it is
    dropped rather than paired with a non-existent rva: an address with no image
    base is not module-relative, and ``Address`` forbids rva-without-module, so
    the only correct shape is VA alone.
    """
    mapped = address_dict(
        0x401000, module="prog.elf", image_base=None, architecture=Architecture.X64
    )
    assert mapped == {"va": 0x401000, "architecture": "x64"}
    assert "rva" not in mapped
    assert "module" not in mapped


def test_address_dict_below_the_image_base_gets_no_negative_rva(tmp_path: Path) -> None:
    """va < image_base falls to the VA-only branch, not a negative rva.

    The ``va >= image_base`` half exists so an address beneath the base does not
    become ``rva = va - base < 0``. If it did, ``Address(ge=0)`` would reject it
    and the address would vanish (address_dict returns None). Pin that such an
    address survives as VA-only instead.
    """
    mapped = address_dict(
        0x1000, module="m", image_base=0x140000000, architecture=Architecture.X64
    )
    assert mapped == {"va": 0x1000, "architecture": "x64"}
    assert "rva" not in mapped


def test_enrich_maps_a_non_pe_binary_to_va_only_addresses(tmp_path: Path) -> None:
    """End to end on a non-PE file: VA-only items and request, no image_base.

    ``architecture`` is supplied by the caller (r2's ``i`` line, or the session
    target) and must still appear -- it is independent of the PE header the file
    does not have. But no ``image_base`` may be invented, and neither the items
    nor the request address may carry an ``rva`` or ``module``.
    """
    binary = _non_pe(tmp_path)
    raw = json.dumps(
        [
            {"offset": 0x401000, "name": "main", "size": 20},
            {"offset": 0x401200, "name": "helper", "size": 8},
        ]
    )
    enriched = enrich_r2_payload(
        {"raw": raw, "commands": ["aa", "aflj"], "address": 0x401000, "count": 2},
        binary=binary,
        architecture=Architecture.X64,
    )

    assert enriched["parsed"] is True
    assert "image_base" not in enriched
    assert enriched["architecture"] == "x64"

    first = enriched["items"][0]["address"]
    assert first == {"va": 0x401000, "architecture": "x64"}
    assert "rva" not in first
    assert "module" not in first

    # The request address is mapped the same way, with the raw VA kept alongside.
    assert enriched["address"] == {"va": 0x401000, "architecture": "x64"}
    assert enriched["address_va"] == 0x401000
