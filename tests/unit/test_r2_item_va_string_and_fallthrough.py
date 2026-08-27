"""``_item_va`` accepts hex/decimal-string addresses and falls past unusable keys.

Every r2 payload is enriched through ``mapping.py``. For each parsed item,
``_item_va`` pulls the address out by trying a fixed list of keys in order
(``offset``, ``vaddr``, ``addr``, ``from``, ``to``, ``plt``, ``paddr``) and
taking the first that holds a usable address:

    for key in keys:
        value = entry.get(key)
        if type(value) is int and value >= 0:
            return value
        if isinstance(value, str) and value:
            try:
                return int(value, 0)
            except ValueError:
                continue
    return None

Two arms of that loop carry weight and neither is exercised by the r2 suite,
which feeds only integer addresses (``{"offset": 0x..}`` / ``{"plt": 0x..}`` /
``{"vaddr": 0x..}`` / ``{"from": 0x..}`` across the mapping, imports, exports,
strings and xrefs tests):

* The **string arm** parses ``int(value, 0)`` -- base 0, so a ``"0x140001000"``
  hex string decodes to its value, exactly like the integer form. r2/rizin
  address fields are integers in the common ``*j`` outputs, but the helper also
  accepts the hex/decimal-string form some payloads carry, and this arm is the
  only reason that works. Refactor it to ``int(value)`` (base 10) and every
  hex-string address raises ``ValueError``, gets swallowed by ``except ...:
  continue``, and the item silently loses its address -- with no r2 test failing.

* The **fall-through** skips a key whose value is unusable (an empty or
  unparseable string, or a negative sentinel that ``value >= 0`` rejects) and
  keeps trying later keys. Turn the ``continue`` into ``return None`` / ``break``
  and an item whose first candidate key is junk but whose later key holds the
  real address would come back address-less.

These pin both arms directly, then confirm a hex-string address flows all the
way through ``enrich_r2_payload`` into the item's ``{va, rva, module}`` Address
just as an integer one does.
"""

from __future__ import annotations

import json
from pathlib import Path

from headless_re_mcp.backends.r2.mapping import _item_va, enrich_r2_payload
from headless_re_mcp.core.models import Architecture

# The exact key list ``enrich_r2_payload`` passes for an item's primary address.
_KEYS = ("offset", "vaddr", "addr", "from", "to", "plt", "paddr")


def _minimal_pe(tmp_path: Path) -> Path:
    """A tiny x64 PE with ImageBase 0x140000000, so rva = va - base is checkable."""
    path = tmp_path / "demo64.exe"
    data = bytearray(0x200)
    data[0:2] = b"MZ"
    pe_offset = 0x80
    data[0x3C:0x40] = pe_offset.to_bytes(4, "little")
    data[pe_offset : pe_offset + 4] = b"PE\0\0"
    data[pe_offset + 20 : pe_offset + 22] = (0xF0).to_bytes(2, "little")
    optional_off = pe_offset + 24
    data[optional_off : optional_off + 2] = (0x20B).to_bytes(2, "little")
    data[optional_off + 24 : optional_off + 32] = (0x140000000).to_bytes(8, "little")
    data[optional_off + 56 : optional_off + 60] = (0x10000).to_bytes(4, "little")
    path.write_bytes(bytes(data))
    return path


def test_item_va_parses_a_hex_string_address_with_base_zero() -> None:
    """A "0x…" address string decodes to its value; base 0 is what makes it work.

    ``int("0x140001000", 0)`` == 0x140001000, whereas ``int("0x140001000")``
    (base 10) raises -- so this pins that the helper uses base 0, not that it
    merely calls int(). A decimal string is accepted the same way.
    """
    assert _item_va({"vaddr": "0x140001000"}, _KEYS) == 0x140001000
    assert _item_va({"offset": "4096"}, _KEYS) == 4096


def test_item_va_skips_an_unusable_earlier_key_for_a_later_real_one() -> None:
    """An empty/garbage string or a negative sentinel must not shadow the address.

    Each earlier key here is present but not a usable address, so the loop must
    ``continue`` to the key that is. If the unparseable string returned None (or
    broke the loop) instead of continuing, or if the negative value were taken
    despite ``value >= 0``, the real address would be lost.
    """
    # Unparseable string in offset -> fall through to the vaddr integer.
    assert _item_va({"offset": "not-an-address", "vaddr": 0x401000}, _KEYS) == 0x401000
    # Empty string is skipped by the ``and value`` guard -> fall through to plt.
    assert _item_va({"offset": "", "plt": 0x1234}, _KEYS) == 0x1234
    # A negative sentinel fails ``value >= 0`` -> fall through to vaddr.
    assert _item_va({"offset": -1, "vaddr": 0x2000}, _KEYS) == 0x2000


def test_item_va_returns_none_when_no_key_holds_a_usable_address() -> None:
    """No candidate key present, or only unusable ones -> None (no fabricated VA)."""
    assert _item_va({"name": "helper"}, _KEYS) is None
    assert _item_va({"offset": -1, "addr": "junk"}, _KEYS) is None


def test_enrich_maps_a_hex_string_address_like_an_integer_one(tmp_path: Path) -> None:
    """End to end: a hex-string ``plt`` becomes the same Address an int would.

    r2.imports items carry the thunk VA under ``plt``; when a payload spells it
    as a hex string the enriched item must still get ``{va, rva, module}`` with
    the rva computed off the PE ImageBase -- identical to the integer path the
    existing imports test pins.
    """
    binary = _minimal_pe(tmp_path)
    raw = json.dumps([{"name": "NtClose", "plt": "0x140001000", "lib": "ntdll"}])
    enriched = enrich_r2_payload(
        {"raw": raw, "commands": ["iij"]},
        binary=binary,
        architecture=Architecture.X64,
    )
    address = enriched["items"][0]["address"]
    assert address == {
        "module": "demo64.exe",
        "rva": 0x1000,
        "va": 0x140001000,
        "architecture": "x64",
    }
