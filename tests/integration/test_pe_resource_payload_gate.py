"""Cross-validate the PE resource-payload census against pefile.

A session over a PE now lists resources whose bytes open with executable magic
-- the Windows dropper's stash, a nested PE in an RT_RCDATA blob it writes out
and runs, an ELF for a cross-platform loader, a ZIP that is a "bitmap". The
resource-tree walk and the magic table are both ours, so pefile referees them:
it parses the same IMAGE_RESOURCE_DIRECTORY tree independently and hands back
each leaf's bytes through pe.get_data, which an independent magic sniff here
classifies. The reader's census must name exactly the resources pefile's tree
carries with executable magic -- same resource type, same kind, same size --
and stay silent on the benign manifest pefile also enumerates.

pefile ships in the project's ``pe`` extra, so this needs no system tool. skip
!= pass: it skips only when pefile is unavailable.
"""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from headless_re_mcp.core.service import AnalysisService

# An independent magic table (not imported from the reader): the point is a
# second implementation agreeing. MZ carries a 0x40-byte floor like the reader.
_MAGIC: tuple[tuple[bytes, str], ...] = (
    (b"\x7fELF", "elf"),
    (b"dex\n", "dex"),
    (b"PK\x03\x04", "zip"),
    (b"\xcf\xfa\xed\xfe", "macho"),
    (b"MZ", "pe"),
)


def _pefile() -> object | None:
    try:
        import pefile
    except ImportError:
        return None
    return pefile


def _sniff(data: bytes) -> str | None:
    for magic, kind in _MAGIC:
        if data.startswith(magic):
            if kind == "pe" and len(data) < 0x40:
                return None
            return kind
    return None


def _pe_with_resources(resources: list[tuple[int, int, bytes]]) -> bytes:
    """A minimal PE32+ whose .rsrc holds a Type -> Name -> Language tree."""
    dirh, ent, datae = 16, 8, 16
    n = len(resources)
    rsrc_rva = 0x1000
    off = dirh + n * ent
    name_dir_offs = [off + i * (dirh + ent) for i in range(n)]
    off += n * (dirh + ent)
    lang_dir_offs = [off + i * (dirh + ent) for i in range(n)]
    off += n * (dirh + ent)
    data_entry_offs = [off + i * datae for i in range(n)]
    off += n * datae
    payload_offs: list[int] = []
    for _type_id, _name_id, payload in resources:
        if off % 8:
            off += 8 - (off % 8)
        payload_offs.append(off)
        off += len(payload)
    rsrc_size = off
    buf = bytearray(rsrc_size)
    struct.pack_into("<IIHHHH", buf, 0, 0, 0, 0, 0, 0, n)
    for i, (type_id, name_id, payload) in enumerate(resources):
        name_dir, lang_dir = name_dir_offs[i], lang_dir_offs[i]
        struct.pack_into("<II", buf, dirh + i * ent, type_id, 0x80000000 | name_dir)
        struct.pack_into("<IIHHHH", buf, name_dir, 0, 0, 0, 0, 0, 1)
        struct.pack_into("<II", buf, name_dir + dirh, name_id, 0x80000000 | lang_dir)
        struct.pack_into("<IIHHHH", buf, lang_dir, 0, 0, 0, 0, 0, 1)
        struct.pack_into("<II", buf, lang_dir + dirh, 0x0409, data_entry_offs[i])
        struct.pack_into(
            "<IIII", buf, data_entry_offs[i], rsrc_rva + payload_offs[i], len(payload), 0, 0
        )
        buf[payload_offs[i] : payload_offs[i] + len(payload)] = payload
    dos = bytearray(0x40)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x40)
    opt_size = 0xF0
    coff = b"PE\x00\x00" + struct.pack("<HHIIIHH", 0x8664, 1, 0, 0, 0, opt_size, 0x2022)
    opt = bytearray(opt_size)
    struct.pack_into("<H", opt, 0, 0x20B)
    struct.pack_into("<I", opt, 108, 16)
    struct.pack_into("<II", opt, 112 + 2 * 8, rsrc_rva, rsrc_size)
    raw_off = 0x40 + len(coff) + opt_size
    if raw_off % 0x200:
        raw_off += 0x200 - (raw_off % 0x200)
    sect = bytearray(40)
    sect[0:5] = b".rsrc"
    struct.pack_into("<I", sect, 8, rsrc_size)
    struct.pack_into("<I", sect, 12, rsrc_rva)
    struct.pack_into("<I", sect, 16, rsrc_size)
    struct.pack_into("<I", sect, 20, raw_off)
    struct.pack_into("<I", sect, 36, 0x40000040)
    out = bytearray(dos + coff + opt + sect)
    if len(out) < raw_off:
        out += b"\x00" * (raw_off - len(out))
    out += bytes(buf)
    return bytes(out)


def _pefile_census(pefile_mod: object, data: bytes) -> dict[int, tuple[str, str, int]]:
    """pefile's independent view: name_id -> (type_label, kind, size) for flagged leaves."""
    pe = pefile_mod.PE(data=data)  # type: ignore[attr-defined]
    type_names = pefile_mod.RESOURCE_TYPE  # type: ignore[attr-defined]
    out: dict[int, tuple[str, str, int]] = {}
    for type_entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        raw_name = type_names.get(type_entry.id, f"type_{type_entry.id}")
        label = raw_name[3:].lower() if raw_name.startswith("RT_") else str(raw_name).lower()
        for name_entry in type_entry.directory.entries:
            for lang_entry in name_entry.directory.entries:
                blob = lang_entry.data.struct
                payload = pe.get_data(blob.OffsetToData, blob.Size)
                kind = _sniff(payload)
                if kind is not None:
                    out[int(name_entry.id)] = (label, kind, int(blob.Size))
    return out


def _session_resource_payloads(path: Path) -> list[dict]:
    service = AnalysisService()
    try:
        created = service.create_session(str(path))
        assert created.ok, created.error
        return created.data["session"]["metadata"]["pe"]["resource_payloads"]
    finally:
        service.close_all()


@pytest.mark.integration
def test_resource_payload_census_agrees_with_pefile(tmp_path: Path) -> None:
    pefile_mod = _pefile()
    if pefile_mod is None:
        pytest.skip("pefile not installed — PE resource-payload gate not run (skip != pass)")

    nested_pe = b"MZ" + b"\x90" * 62 + b"stage-two payload body"
    resources = [
        (10, 101, nested_pe),  # RT_RCDATA -> nested PE
        (10, 102, b"\x7fELF" + b"\x00" * 40),  # RT_RCDATA -> ELF
        (24, 1, b'<?xml version="1.0"?><assembly xmlns="urn:schemas"/>'),  # manifest
        (2, 103, b"PK\x03\x04" + b"\x00" * 40),  # "bitmap" that is a ZIP
    ]
    data = _pe_with_resources(resources)
    dropper = tmp_path / "dropper.exe"
    dropper.write_bytes(data)

    # pefile's independent census over the same tree.
    expected = _pefile_census(pefile_mod, data)
    # Ground truth: pefile flags exactly the three executable-magic resources.
    assert set(expected) == {101, 102, 103}
    assert expected[101][1] == "pe"
    assert expected[102][1] == "elf"
    assert expected[103][1] == "zip"

    # The reader's census over the same file, keyed the same way.
    payloads = _session_resource_payloads(dropper)
    census = {int(p["name"]): (p["type"], p["kind"], p["size"]) for p in payloads}

    # Byte for byte, resource for resource: the two parsers agree, and the
    # benign manifest (name id 1) is in neither census.
    assert census == expected
    assert 1 not in census
