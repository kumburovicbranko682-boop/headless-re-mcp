from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from headless_re_mcp.backends.common.endpoint_scan import iter_endpoint_matches
from headless_re_mcp.backends.common.secret_scan import iter_secret_matches
from headless_re_mcp.core.models import Address, Architecture

JsonObject = dict[str, Any]
_MAX_ITEMS = 4096
# r2.endpoints / r2.secrets aggregate the shared scanners over the strings r2
# recovered (izj, the same set r2.strings lists); these bound the distinct
# finding sets, the per-finding value/source kept, the host summary and the page.
_MAX_R2_EP_FINDINGS = 50000
_MAX_R2_EP_VALUE = 512
_MAX_R2_EP_SOURCE = 512
_MAX_R2_EP_HOSTS = 512
_MAX_R2_SEC_FINDINGS = 20000
_MAX_R2_SEC_VALUE = 512
_MAX_R2_SEC_SOURCE = 512
_R2_SCAN_PAGE = 2000
# Enough for any PE header: the DOS stub and the optional header live in the
# first pages. The second read below covers the pathological ones.
_HEADER_WINDOW = 64 * 1024
_MAX_HEADER = 1024 * 1024


def pe_preferred_base(binary: Path) -> tuple[Architecture | None, int | None]:
    """Read PE preferred ImageBase without spawning r2.

    A prefix, not the file. Every r2 tool call enriches its payload through
    here, and slurping the target to read one header field cost, measured on a
    200 MB sample, 200 MB of RSS per call and 0.41s for six calls.
    """
    try:
        with binary.open("rb") as stream:
            data = stream.read(_HEADER_WINDOW)
            # Twice at most: the first re-read reveals the file header, which is
            # what says how long the optional header is.
            for _ in range(2):
                header_end = _needed_header_bytes(data)
                if header_end is None or header_end <= len(data) or header_end > _MAX_HEADER:
                    break
                stream.seek(0)
                data = stream.read(header_end)
    except OSError:
        return None, None
    if len(data) < 0x40 or data[:2] != b"MZ":
        return None, None
    pe_offset = int.from_bytes(data[0x3C:0x40], "little")
    if pe_offset <= 0 or pe_offset + 24 > len(data) or data[pe_offset : pe_offset + 4] != b"PE\0\0":
        return None, None
    optional_size = int.from_bytes(data[pe_offset + 20 : pe_offset + 22], "little")
    optional = data[pe_offset + 24 : pe_offset + 24 + optional_size]
    if len(optional) < 60:
        return None, None
    magic = int.from_bytes(optional[0:2], "little")
    if magic == 0x10B:
        architecture = Architecture.X86
        image_base = int.from_bytes(optional[28:32], "little")
    elif magic == 0x20B:
        architecture = Architecture.X64
        image_base = int.from_bytes(optional[24:32], "little")
    else:
        return None, None
    if image_base <= 0:
        return architecture, None
    return architecture, image_base


def _needed_header_bytes(head: bytes) -> int | None:
    """How far into the file the optional header runs, if this looks like a PE."""
    if len(head) < 0x40 or head[:2] != b"MZ":
        return None
    pe_offset = int.from_bytes(head[0x3C:0x40], "little")
    if pe_offset <= 0 or pe_offset + 24 > len(head):
        # Either not a PE, or the stub is longer than the window; ask for enough
        # to reach the file header and let the caller re-read.
        return pe_offset + 24 if 0 < pe_offset < _MAX_HEADER else None
    if head[pe_offset : pe_offset + 4] != b"PE\0\0":
        return None
    optional_size = int.from_bytes(head[pe_offset + 20 : pe_offset + 22], "little")
    return pe_offset + 24 + optional_size


def address_dict(
    va: int | None,
    *,
    module: str,
    image_base: int | None,
    architecture: Architecture | None,
) -> JsonObject | None:
    if type(va) is not int or va < 0:
        return None
    rva: int | None = None
    if image_base is not None and va >= image_base:
        rva = va - image_base
    try:
        if rva is not None:
            addr = Address(module=module, rva=rva, va=va, architecture=architecture)
        else:
            addr = Address(va=va, architecture=architecture)
    except ValueError:
        return None
    return addr.model_dump(mode="json", exclude_none=True)


def parse_r2_json(raw: str) -> Any | None:
    """Extract the first JSON value from r2 -q0 output (may include banners).

    ``rfind("[")`` is wrong here: ``pdj`` / ``axj`` / ``izj`` put ``[`` inside
    opcodes (``mov eax, dword [rbp+0x10]``), C++ names, and strings. That
    slice is not the root array, so the ``{…}`` fallback loaded only the last
    object and ``enrich_r2_payload`` reported ``parsed: True`` with no items.
    """
    text = (raw or "").strip()
    if not text:
        return None
    decoder = json.JSONDecoder()
    for index, char in enumerate(text):
        if char not in "[{":
            continue
        try:
            value, _end = decoder.raw_decode(text, index)
        except json.JSONDecodeError:
            continue
        return value
    return None


def _item_va(entry: JsonObject, keys: tuple[str, ...]) -> int | None:
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


def enrich_r2_payload(
    data: JsonObject,
    *,
    binary: Path,
    architecture: Architecture | None = None,
) -> JsonObject:
    """Parse *j payloads into items with unified Address fields."""
    module = binary.name
    pe_arch, image_base = pe_preferred_base(binary)
    arch = architecture or pe_arch
    raw = str(data.get("raw") or "")
    commands = list(data.get("commands") or [])
    parsed = parse_r2_json(raw)
    out = dict(data)
    out["module"] = module
    if image_base is not None:
        out["image_base"] = image_base
    if arch is not None:
        out["architecture"] = arch.value

    # Preserve request address as Address when present.
    request_address = data.get("address")
    if type(request_address) is int:
        mapped = address_dict(
            request_address, module=module, image_base=image_base, architecture=arch
        )
        if mapped is not None:
            out["address"] = mapped
            out["address_va"] = request_address

    items: list[JsonObject] = []
    if isinstance(parsed, list):
        available = len(parsed)
        for entry in parsed[:_MAX_ITEMS]:
            if not isinstance(entry, dict):
                continue
            item = dict(entry)
            va = _item_va(
                entry,
                ("offset", "vaddr", "addr", "from", "to", "plt", "paddr"),
            )
            mapped = address_dict(va, module=module, image_base=image_base, architecture=arch)
            if mapped is not None:
                item["address"] = mapped
            # Named endpoints for xrefs
            for edge_key in ("from", "to"):
                edge_va = _item_va(entry, (edge_key,))
                edge_mapped = address_dict(
                    edge_va, module=module, image_base=image_base, architecture=arch
                )
                if edge_mapped is not None:
                    item[f"{edge_key}_address"] = edge_mapped
            items.append(item)
        out["items"] = items
        out["count"] = len(items)
        if available > _MAX_ITEMS:
            # Said out loud, like the raw-output cut beside it. A list that
            # stopped at the cap looks exactly like a list that ended, and a
            # caller deciding "these are all the xrefs" is deciding wrongly.
            out["items_truncated"] = True
            out["items_total"] = available
            out["items_limit"] = _MAX_ITEMS
        out["parsed"] = True
    elif isinstance(parsed, dict):
        out["info"] = parsed
        out["parsed"] = True
    else:
        out["parsed"] = False
    out["commands"] = commands
    return out


def _r2_scan_base(data: JsonObject) -> JsonObject:
    """Carry the identity fields the enriched payload already resolved."""
    base: JsonObject = {}
    for key in ("module", "image_base", "architecture"):
        if key in data:
            base[key] = data[key]
    return base


def _r2_page(rows: list[JsonObject], offset: int, limit: int) -> tuple[list[JsonObject], int, bool]:
    start = max(0, int(offset))
    cap = max(1, min(int(limit), _R2_SCAN_PAGE))
    window = rows[start : start + cap]
    return window, start, start + len(window) < len(rows)


def _r2_string_items(data: JsonObject) -> list[JsonObject]:
    items = data.get("items")
    return [it for it in items if isinstance(it, dict)] if isinstance(items, list) else []


def aggregate_r2_endpoints(
    data: JsonObject,
    *,
    include_paths: bool = True,
    name_filter: str = "",
    offset: int = 0,
    limit: int = 200,
) -> JsonObject:
    """Aggregate network endpoints from the strings r2 recovered (izj).

    The native counterpart to apk.endpoints / dotnet.endpoints: the shared
    URL/path recogniser run over the same strings r2.strings lists. Each finding
    carries the containing string's vaddr and address so r2.xrefs / r2.disasm can
    pivot to the code that references it.
    """
    aggregates: dict[str, JsonObject] = {}
    scan_capped = bool(data.get("items_truncated"))
    stop = False
    for item in _r2_string_items(data):
        source = str(item.get("string") or "")
        if not source:
            continue
        vaddr = item.get("vaddr")
        address = item.get("address") if isinstance(item.get("address"), dict) else None
        for value, kind, scheme, host in iter_endpoint_matches(source, include_paths=include_paths):
            current = aggregates.get(value)
            if current is None:
                if len(aggregates) >= _MAX_R2_EP_FINDINGS:
                    scan_capped = True
                    stop = True
                    break
                row: JsonObject = {
                    "value": value[:_MAX_R2_EP_VALUE],
                    "kind": kind,
                    "scheme": scheme,
                    "host": host,
                    "source": source[:_MAX_R2_EP_SOURCE],
                    "count": 1,
                }
                if len(value) > _MAX_R2_EP_VALUE:
                    row["value_truncated"] = True
                if len(source) > _MAX_R2_EP_SOURCE:
                    row["source_truncated"] = True
                if isinstance(vaddr, int):
                    row["vaddr"] = vaddr
                if address is not None:
                    row["address"] = address
                aggregates[value] = row
            else:
                current["count"] = int(current["count"]) + 1
        if stop:
            break
    endpoints = list(aggregates.values())
    needle = name_filter.strip().casefold() if isinstance(name_filter, str) else ""
    if needle:
        endpoints = [
            e
            for e in endpoints
            if needle in str(e["value"]).casefold() or needle in str(e["host"]).casefold()
        ]
    endpoints.sort(key=lambda e: (-int(e["count"]), str(e["value"])))
    host_set = sorted({str(e["host"]) for e in endpoints if e["kind"] == "url" and e["host"]})
    window, start, has_more = _r2_page(endpoints, offset, limit)
    out = _r2_scan_base(data)
    out.update(
        {
            "endpoints": window,
            "count": len(window),
            "total": len(endpoints),
            "offset": start,
            "has_more": has_more,
            "hosts": host_set[:_MAX_R2_EP_HOSTS],
            "hosts_truncated": len(host_set) > _MAX_R2_EP_HOSTS,
            "scan_capped": scan_capped,
        }
    )
    return out


def aggregate_r2_secrets(
    data: JsonObject,
    *,
    include_generic: bool = False,
    name_filter: str = "",
    offset: int = 0,
    limit: int = 200,
) -> JsonObject:
    """Detect embedded credentials in the strings r2 recovered (izj).

    The native counterpart to apk.secrets / dotnet.secrets: the same shared
    detector table run over the strings r2.strings lists. Each finding carries
    the containing string's vaddr and address for an r2.xrefs pivot.
    """
    aggregates: dict[tuple[str, str], JsonObject] = {}
    scan_capped = bool(data.get("items_truncated"))
    stop = False
    for item in _r2_string_items(data):
        source = str(item.get("string") or "")
        if not source:
            continue
        vaddr = item.get("vaddr")
        address = item.get("address") if isinstance(item.get("address"), dict) else None
        for detector, matched in iter_secret_matches(source, include_generic=include_generic):
            key = (detector, matched)
            current = aggregates.get(key)
            if current is None:
                if len(aggregates) >= _MAX_R2_SEC_FINDINGS:
                    scan_capped = True
                    stop = True
                    break
                row: JsonObject = {
                    "detector": detector,
                    "value": matched[:_MAX_R2_SEC_VALUE],
                    "source": source[:_MAX_R2_SEC_SOURCE],
                    "count": 1,
                }
                if len(matched) > _MAX_R2_SEC_VALUE:
                    row["value_truncated"] = True
                if len(source) > _MAX_R2_SEC_SOURCE:
                    row["source_truncated"] = True
                if isinstance(vaddr, int):
                    row["vaddr"] = vaddr
                if address is not None:
                    row["address"] = address
                aggregates[key] = row
            else:
                current["count"] = int(current["count"]) + 1
        if stop:
            break
    secrets = list(aggregates.values())
    needle = name_filter.strip().casefold() if isinstance(name_filter, str) else ""
    if needle:
        secrets = [
            s
            for s in secrets
            if needle in str(s["detector"]).casefold() or needle in str(s["value"]).casefold()
        ]
    secrets.sort(key=lambda s: (str(s["detector"]), -int(s["count"]), str(s["value"])))
    detectors = sorted({str(s["detector"]) for s in secrets})
    window, start, has_more = _r2_page(secrets, offset, limit)
    out = _r2_scan_base(data)
    out.update(
        {
            "secrets": window,
            "count": len(window),
            "total": len(secrets),
            "offset": start,
            "has_more": has_more,
            "detectors": detectors,
            "scan_capped": scan_capped,
        }
    )
    return out
