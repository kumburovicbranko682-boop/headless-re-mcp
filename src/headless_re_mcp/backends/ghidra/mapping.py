"""Enrich Ghidra export payloads with the same Address shape r2 emits.

ExportJson.py returns addresses as bare absolute-VA hex strings (``entry`` for
functions, ``address`` for symbols, ``from``/``to`` for xrefs, top-level
``entry`` for decompile). The r2 backend already turns its addresses into a
``{module, rva, va, architecture}`` object via ``enrich_r2_payload``; this does
the same for Ghidra so an agent correlating the two engines on one binary joins
on the same coordinates -- most usefully on ELF, which previously had no rva or
module anywhere in either engine until the r2 side gained it.

The enrichment is strictly additive: every original string field is preserved
and a companion object is added beside it (``entry_address`` for ``entry``,
``from_address``/``to_address`` for the xref endpoints -- the same names r2
uses -- and ``address_detail`` for symbols, whose field is literally
``address`` and so cannot host the object without shadowing the string). The
PE/ELF header parsers are shared from the r2 mapping module rather than
duplicated: they are format-level helpers, not r2-specific.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from headless_re_mcp.backends.r2.mapping import (
    address_dict,
    elf_preferred_base,
    pe_preferred_base,
)

JsonObject = dict[str, Any]

# mode -> ((source string field, additive object field), ...)
_ITEM_ADDRESS_FIELDS: dict[str, tuple[tuple[str, str], ...]] = {
    "functions": (("entry", "entry_address"),),
    "symbols": (("address", "address_detail"),),
    "xrefs": (("from", "from_address"), ("to", "to_address")),
}


def _to_int(value: object) -> int | None:
    """Parse a Ghidra address string to an int, tolerating prefixes.

    Ghidra prints default-space addresses as plain hex (``0040114e``) but can
    prepend an address-space (``ram:0040114e``); a ``0x`` form is accepted too.
    Anything unparseable yields None, so a non-address label never invents a
    bogus coordinate.
    """
    if value is None:
        return None
    text = str(value).strip()
    if ":" in text:
        text = text.rsplit(":", 1)[-1]
    if not text:
        return None
    try:
        return int(text, 0) if text.lower().startswith("0x") else int(text, 16)
    except ValueError:
        return None


def enrich_ghidra_payload(payload: JsonObject, *, binary: Path) -> JsonObject:
    """Return a copy of a Ghidra export payload with Address objects attached.

    Adds top-level ``module`` (always) and ``image_base``/``architecture`` (when
    the header names them), then per item attaches the object companion for each
    address string the mode carries. Unknown formats simply yield va-only
    objects, exactly as the r2 mapping does.
    """
    module = binary.name
    arch, image_base = pe_preferred_base(binary)
    # A PE parse that found neither arch nor base means this is not a PE; fall
    # back to the ELF header. A PE that named its arch keeps PE semantics.
    if arch is None and image_base is None:
        arch, image_base = elf_preferred_base(binary)

    out = dict(payload)
    out["module"] = module
    if image_base is not None:
        out["image_base"] = image_base
    if arch is not None:
        out["architecture"] = arch.value

    mode = str(payload.get("mode") or "")
    field_map = _ITEM_ADDRESS_FIELDS.get(mode, ())
    items = payload.get("items")
    if field_map and isinstance(items, list):
        enriched_items: list[Any] = []
        for entry in items:
            if not isinstance(entry, dict):
                enriched_items.append(entry)
                continue
            item = dict(entry)
            for source_field, object_field in field_map:
                mapped = address_dict(
                    _to_int(entry.get(source_field)),
                    module=module,
                    image_base=image_base,
                    architecture=arch,
                )
                if mapped is not None:
                    item[object_field] = mapped
            enriched_items.append(item)
        out["items"] = enriched_items

    if mode == "decompile":
        mapped = address_dict(
            _to_int(payload.get("entry")),
            module=module,
            image_base=image_base,
            architecture=arch,
        )
        if mapped is not None:
            out["entry_address"] = mapped

    return out
