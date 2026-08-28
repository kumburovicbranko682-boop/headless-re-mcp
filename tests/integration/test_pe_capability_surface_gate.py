"""Cross-validate the native PE import/export surface against pefile.

A session over a PE now lists its import directory (which native functions from
which DLLs the loader must bind -- the strongest triage signal after arch, and
the PE pair to an ELF/Mach-O's imported symbols) and its export name table
(what a DLL offers -- the pair to exported symbols). The descriptor walk, the
PE32/PE32+ thunk-width switch, the ordinal decode and the export-name walk are
all ours, so pefile referees them: it parses the same import and export
directories independently and hands back the DLL/function pairs and export
names, which this compares against the reader's fact byte for byte.

pefile ships in the project's ``pe`` extra, so this needs no system tool. skip
!= pass: it skips only when pefile is unavailable.
"""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from headless_re_mcp.core.service import AnalysisService


def _pefile() -> object | None:
    try:
        import pefile
    except ImportError:
        return None
    return pefile


def _pe_with_imports_exports(
    imports: list[tuple[str, list[object]]],
    exports: list[str],
    *,
    magic: int = 0x20B,
) -> bytes:
    """A minimal PE carrying the given import (index 1) and export (index 0)
    directories in one section -- the shape pefile parses. A function entry is a
    name or an int (an ordinal import). Built here independently of the reader's
    own test builder so the two implementations cannot share a blind spot.
    """
    sect_rva = 0x1000
    sec = bytearray()

    def emit(data: bytes) -> int:
        off = len(sec)
        sec.extend(data)
        return off

    def align(n: int) -> None:
        while len(sec) % n:
            sec.append(0)

    def rva(off: int) -> int:
        return sect_rva + off

    thunk_fmt = "<Q" if magic == 0x20B else "<I"
    thunk_size = 8 if magic == 0x20B else 4
    ordinal_flag = (1 << 63) if magic == 0x20B else (1 << 31)

    n = len(imports)
    desc_off = emit(b"\x00" * (20 * (n + 1)))
    descriptors: list[tuple[int, int]] = []
    for dll, funcs in imports:
        thunks: list[int] = []
        for fn in funcs:
            if isinstance(fn, int):
                thunks.append(ordinal_flag | fn)
                continue
            align(2)
            hint_name = emit(struct.pack("<H", 0) + fn.encode() + b"\x00")
            thunks.append(rva(hint_name))
        align(thunk_size)
        ilt_off = len(sec)
        for value in thunks:
            emit(struct.pack(thunk_fmt, value))
        emit(struct.pack(thunk_fmt, 0))
        dll_off = emit(dll.encode() + b"\x00")
        descriptors.append((rva(ilt_off), rva(dll_off)))
    for i, (ilt_rva, dll_rva) in enumerate(descriptors):
        struct.pack_into("<IIIII", sec, desc_off + i * 20, ilt_rva, 0, 0, dll_rva, ilt_rva)
    imp_dir_rva, imp_dir_size = rva(desc_off), 20 * (n + 1)

    exp_dir_rva = exp_dir_size = 0
    if exports:
        name_rvas = [rva(emit(name.encode() + b"\x00")) for name in exports]
        align(4)
        eat_off = len(sec)
        for _ in exports:
            emit(struct.pack("<I", sect_rva))
        align(4)
        names_off = len(sec)
        for name_rva in name_rvas:
            emit(struct.pack("<I", name_rva))
        ord_off = len(sec)
        for i in range(len(exports)):
            emit(struct.pack("<H", i))
        dll_name = emit(b"self.dll\x00")
        align(4)
        exp_off = len(sec)
        emit(b"\x00" * 40)
        struct.pack_into(
            "<IIHHIIIIIII", sec, exp_off,
            0, 0, 0, 0, rva(dll_name), 1,
            len(exports), len(exports), rva(eat_off), rva(names_off), rva(ord_off),
        )
        exp_dir_rva, exp_dir_size = rva(exp_off), 40

    dos = bytearray(0x40)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x40)
    opt_size = 0xF0
    machine = 0x8664 if magic == 0x20B else 0x14C
    coff = b"PE\x00\x00" + struct.pack("<HHIIIHH", machine, 1, 0, 0, 0, opt_size, 0x2022)
    opt = bytearray(opt_size)
    struct.pack_into("<H", opt, 0, magic)
    dir_count_off = 108 if magic == 0x20B else 92
    struct.pack_into("<I", opt, 32, 0x1000)
    struct.pack_into("<I", opt, 36, 0x200)
    struct.pack_into("<I", opt, dir_count_off, 16)
    dir_arr = dir_count_off + 4
    struct.pack_into("<II", opt, dir_arr + 0 * 8, exp_dir_rva, exp_dir_size)
    struct.pack_into("<II", opt, dir_arr + 1 * 8, imp_dir_rva, imp_dir_size)

    raw_off = 0x40 + len(coff) + opt_size
    if raw_off % 0x200:
        raw_off += 0x200 - (raw_off % 0x200)
    rsize = (len(sec) + 0x1FF) & ~0x1FF
    struct.pack_into("<I", opt, 56, 0x2000 + rsize)
    struct.pack_into("<I", opt, 60, raw_off)

    sect = bytearray(40)
    sect[0:6] = b".idata"
    struct.pack_into("<I", sect, 8, len(sec))
    struct.pack_into("<I", sect, 12, sect_rva)
    struct.pack_into("<I", sect, 16, rsize)
    struct.pack_into("<I", sect, 20, raw_off)
    struct.pack_into("<I", sect, 36, 0xC0000040)

    out = bytearray(dos + coff + opt + sect)
    if len(out) < raw_off:
        out += b"\x00" * (raw_off - len(out))
    out += sec
    if len(out) % 0x200:
        out += b"\x00" * (0x200 - (len(out) % 0x200))
    return bytes(out)


def _pefile_imports(pefile_mod: object, data: bytes) -> list[tuple[str, list[str]]]:
    pe = pefile_mod.PE(data=data)  # type: ignore[attr-defined]
    out: list[tuple[str, list[str]]] = []
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        funcs = [
            imp.name.decode() if imp.name else f"#{imp.ordinal}" for imp in entry.imports
        ]
        out.append((entry.dll.decode(), funcs))
    return out


def _pefile_exports(pefile_mod: object, data: bytes) -> list[str]:
    pe = pefile_mod.PE(data=data)  # type: ignore[attr-defined]
    if not hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        return []
    return sorted(s.name.decode() for s in pe.DIRECTORY_ENTRY_EXPORT.symbols if s.name)


def _session_surface(path: Path) -> tuple[list[dict], list[str]]:
    service = AnalysisService()
    try:
        created = service.create_session(str(path))
        assert created.ok, created.error
        pe = created.data["session"]["metadata"]["pe"]
        return pe["imports"], pe["exports"]
    finally:
        service.close_all()


@pytest.mark.integration
@pytest.mark.parametrize("magic", [0x20B, 0x10B], ids=["pe32+", "pe32"])
def test_capability_surface_agrees_with_pefile(tmp_path: Path, magic: int) -> None:
    pefile_mod = _pefile()
    if pefile_mod is None:
        pytest.skip("pefile not installed — PE capability-surface gate not run (skip != pass)")

    # The ordinal-only DLL is a made-up name so pefile has no known-ordinal
    # table for it and, like the reader, renders each import as #N -- otherwise
    # pefile would helpfully resolve a real DLL's ordinals (ws2_32!115 ->
    # WSAStartup) from its bundled database and the two would disagree for a
    # reason that is not a reader bug.
    imports = [
        ("KERNEL32.dll", ["CreateFileA", "WriteFile", "ExitProcess"]),
        ("USER32.dll", ["MessageBoxW"]),
        ("enginecore.dll", [3, 7]),  # ordinal-only imports into an unknown DLL
    ]
    exports = ["ZetaExport", "AlphaExport", "MidExport"]
    data = _pe_with_imports_exports(imports, exports, magic=magic)
    binary = tmp_path / f"surface_{magic:x}.exe"
    binary.write_bytes(data)

    # Independent ground truth: pefile parses the same directories itself.
    expected_imports = _pefile_imports(pefile_mod, data)
    expected_exports = _pefile_exports(pefile_mod, data)
    # The tables must be what we planted, so pefile is a genuine second opinion.
    assert {dll for dll, _ in expected_imports} == {
        "KERNEL32.dll",
        "USER32.dll",
        "enginecore.dll",
    }
    assert expected_exports == ["AlphaExport", "MidExport", "ZetaExport"]

    reader_imports, reader_exports = _session_surface(binary)

    # DLL for DLL, function for function: the reader's import table matches
    # pefile's, including the ordinal-only DLL rendered as #N on both sides.
    reader_map = {entry["dll"]: entry["functions"] for entry in reader_imports}
    pefile_map = {dll: funcs for dll, funcs in expected_imports}
    assert reader_map == pefile_map
    assert reader_exports == expected_exports
