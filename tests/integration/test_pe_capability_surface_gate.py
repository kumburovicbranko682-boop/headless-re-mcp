"""Cross-validate the native PE import/export surface against pefile.

A session over a PE now lists its import directory (which native functions from
which DLLs the loader must bind -- the strongest triage signal after arch, and
the PE pair to an ELF/Mach-O's imported symbols), its delay-load directory
(the lazy channel: DLLs that bind on first call rather than at load, exactly
where evasive binaries park the capability a scan of the regular table misses)
and its export name table (what a DLL offers -- the pair to exported symbols).
The descriptor walks, the PE32/PE32+ thunk-width switch, the ordinal decode,
the VC6 VA-based delay-descriptor rebase and the export-name walk are all
ours, so pefile referees them: it parses the same directories independently
and hands back the DLL/function pairs, export names and forwarder targets,
which this compares against the reader's facts byte for byte.

pefile ships in the project's ``pe`` extra, so this needs no system tool. skip
!= pass: it skips only when pefile is unavailable.
"""

from __future__ import annotations

import hashlib
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
    delay: list[tuple[str, list[object]]] | None = None,
    delay_va_based: bool = False,
    image_base: int = 0,
    forwarders: dict[str, str] | None = None,
) -> bytes:
    """A minimal PE carrying the given import (index 1) and export (index 0)
    directories in one section -- the shape pefile parses. A function entry is a
    name or an int (an ordinal import). ``delay`` adds a delay-load directory
    (index 13); ``delay_va_based`` writes its descriptors in VC6's VA dialect
    (attribute bit 0 clear, DWORD fields biased by ``image_base``).
    ``forwarders`` maps an export name to a ``TARGET.Func`` string whose EAT
    entry then points inside the export directory at that string. Built here
    independently of the reader's own test builder so the two implementations
    cannot share a blind spot.
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

    dly_dir_rva = dly_dir_size = 0
    if delay:
        dly_n = len(delay)
        dly_desc_off = emit(b"\x00" * (32 * (dly_n + 1)))
        dly_descriptors: list[tuple[int, int, int]] = []
        for dll, funcs in delay:
            thunks = []
            for fn in funcs:
                if isinstance(fn, int):
                    thunks.append(ordinal_flag | fn)
                    continue
                align(2)
                hint_name = emit(struct.pack("<H", 0) + fn.encode() + b"\x00")
                thunks.append(rva(hint_name))
            align(thunk_size)
            int_off = len(sec)
            for value in thunks:
                emit(struct.pack(thunk_fmt, value))
            emit(struct.pack(thunk_fmt, 0))
            # A distinct delay IAT chain (same thunks): pefile requires pIAT.
            align(thunk_size)
            iat_off = len(sec)
            for value in thunks:
                emit(struct.pack(thunk_fmt, value))
            emit(struct.pack(thunk_fmt, 0))
            dll_off = emit(dll.encode() + b"\x00")
            dly_descriptors.append((rva(int_off), rva(iat_off), rva(dll_off)))
        bias = image_base if delay_va_based else 0
        attrs = 0 if delay_va_based else 1  # bit 0: fields are RVAs
        for i, (int_rva, iat_rva, dll_rva) in enumerate(dly_descriptors):
            struct.pack_into(
                "<IIIIIIII",
                sec,
                dly_desc_off + i * 32,
                attrs,
                dll_rva + bias,
                0,
                iat_rva + bias,
                int_rva + bias,
                0,
                0,
                0,
            )
        dly_dir_rva, dly_dir_size = rva(dly_desc_off), 32 * (dly_n + 1)

    exp_dir_rva = exp_dir_size = 0
    forwarders = forwarders or {}
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
        # Forwarder target strings sit inside the directory's declared size,
        # and the matching EAT entry points at them instead of at code.
        for idx, name in enumerate(exports):
            if name in forwarders:
                target_off = emit(forwarders[name].encode() + b"\x00")
                struct.pack_into("<I", sec, eat_off + idx * 4, rva(target_off))
        exp_dir_rva, exp_dir_size = rva(exp_off), len(sec) - exp_off

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
    if image_base:
        if magic == 0x20B:
            struct.pack_into("<Q", opt, 24, image_base)
        else:
            struct.pack_into("<I", opt, 28, image_base)
    dir_arr = dir_count_off + 4
    struct.pack_into("<II", opt, dir_arr + 0 * 8, exp_dir_rva, exp_dir_size)
    struct.pack_into("<II", opt, dir_arr + 1 * 8, imp_dir_rva, imp_dir_size)
    struct.pack_into("<II", opt, dir_arr + 13 * 8, dly_dir_rva, dly_dir_size)

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


def _pefile_forwarders(pefile_mod: object, data: bytes) -> list[dict[str, str]]:
    pe = pefile_mod.PE(data=data)  # type: ignore[attr-defined]
    if not hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        return []
    out: list[dict[str, str]] = []
    for s in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        if s.forwarder:
            name = s.name.decode() if s.name else f"#{s.ordinal}"
            out.append({"name": name, "forward": s.forwarder.decode()})
    out.sort(key=lambda item: item["name"])
    return out


def _pefile_delay_imports(pefile_mod: object, data: bytes) -> list[tuple[str, list[str]]]:
    pe = pefile_mod.PE(data=data)  # type: ignore[attr-defined]
    if not hasattr(pe, "DIRECTORY_ENTRY_DELAY_IMPORT"):
        return []
    out: list[tuple[str, list[str]]] = []
    for entry in pe.DIRECTORY_ENTRY_DELAY_IMPORT:
        funcs = [
            imp.name.decode() if imp.name else f"#{imp.ordinal}" for imp in entry.imports
        ]
        out.append((entry.dll.decode(), funcs))
    return out


def _session_surface(path: Path) -> tuple[list[dict], list[dict], list[str], list[dict]]:
    service = AnalysisService()
    try:
        created = service.create_session(str(path))
        assert created.ok, created.error
        pe = created.data["session"]["metadata"]["pe"]
        return pe["imports"], pe["delay_imports"], pe["exports"], pe["forwarded_exports"]
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

    reader_imports, reader_delay, reader_exports, reader_fwd = _session_surface(binary)

    # DLL for DLL, function for function: the reader's import table matches
    # pefile's, including the ordinal-only DLL rendered as #N on both sides.
    reader_map = {entry["dll"]: entry["functions"] for entry in reader_imports}
    pefile_map = {dll: funcs for dll, funcs in expected_imports}
    assert reader_map == pefile_map
    assert reader_exports == expected_exports
    # No delay directory or forwarder was planted, and neither view invents one.
    assert reader_delay == []
    assert reader_fwd == []
    assert _pefile_delay_imports(pefile_mod, data) == []
    assert _pefile_forwarders(pefile_mod, data) == []


@pytest.mark.integration
@pytest.mark.parametrize("magic", [0x20B, 0x10B], ids=["pe32+", "pe32"])
def test_delay_imports_agree_with_pefile(tmp_path: Path, magic: int) -> None:
    pefile_mod = _pefile()
    if pefile_mod is None:
        pytest.skip("pefile not installed — PE delay-import gate not run (skip != pass)")

    # The lazy channel next to a small regular table: the reader must keep the
    # two apart (a delay-loaded DLL never appears among load-time imports).
    imports = [("KERNEL32.dll", ["ExitProcess"])]
    delay = [
        ("WINHTTP.dll", ["WinHttpOpen", "WinHttpConnect"]),
        ("lazyengine.dll", [9]),  # ordinal into an unknown DLL: #9 on both sides
    ]
    data = _pe_with_imports_exports(imports, [], magic=magic, delay=delay)
    binary = tmp_path / f"delay_{magic:x}.exe"
    binary.write_bytes(data)

    expected_delay = _pefile_delay_imports(pefile_mod, data)
    # pefile really sees the planted lazy table, so it is a genuine referee.
    assert {dll for dll, _ in expected_delay} == {"WINHTTP.dll", "lazyengine.dll"}

    reader_imports, reader_delay, _, _ = _session_surface(binary)
    reader_map = {entry["dll"]: entry["functions"] for entry in reader_delay}
    assert reader_map == {dll: funcs for dll, funcs in expected_delay}
    # The regular table stays the regular table: no leak in either direction.
    assert {entry["dll"] for entry in reader_imports} == {"KERNEL32.dll"}


@pytest.mark.integration
def test_va_based_delay_descriptors_agree_with_pefile(tmp_path: Path) -> None:
    """VC6's VA dialect: DWORD fields biased by ImageBase, attribute bit clear.

    The rebase is the delay walk's one non-obvious branch, so it gets its own
    gate: pefile applies the same ImageBase subtraction, and both views must
    name the same DLL and functions off the same biased descriptor.
    """
    pefile_mod = _pefile()
    if pefile_mod is None:
        pytest.skip("pefile not installed — PE delay-import gate not run (skip != pass)")

    data = _pe_with_imports_exports(
        [],
        [],
        magic=0x10B,
        delay=[("OLD32.dll", ["LegacyInit", "LegacyRun"])],
        delay_va_based=True,
        image_base=0x400000,
    )
    binary = tmp_path / "delay_va.exe"
    binary.write_bytes(data)

    expected_delay = _pefile_delay_imports(pefile_mod, data)
    assert expected_delay == [("OLD32.dll", ["LegacyInit", "LegacyRun"])]

    _, reader_delay, _, _ = _session_surface(binary)
    assert reader_delay == [{"dll": "OLD32.dll", "functions": ["LegacyInit", "LegacyRun"]}]


@pytest.mark.integration
@pytest.mark.parametrize("magic", [0x20B, 0x10B], ids=["pe32+", "pe32"])
def test_forwarded_exports_agree_with_pefile(tmp_path: Path, magic: int) -> None:
    """The forwarded-export walk against pefile's, at both magics.

    A forwarder's EAT entry points inside the export directory at a
    ``TARGET.Func`` string; pefile exposes the same target on each symbol's
    ``forwarder`` attribute. Both views must name the same forwards and,
    crucially, leave the one plain export out of the forwarder list while
    keeping it among the exports.
    """
    pefile_mod = _pefile()
    if pefile_mod is None:
        pytest.skip("pefile not installed — PE forwarded-export gate not run (skip != pass)")

    exports = ["HeapAlloc", "HeapFree", "LocalRealFn"]
    forwarders = {
        "HeapAlloc": "NTDLL.RtlAllocateHeap",
        "HeapFree": "NTDLL.RtlFreeHeap",
    }
    data = _pe_with_imports_exports([], exports, magic=magic, forwarders=forwarders)
    binary = tmp_path / f"forward_{magic:x}.dll"
    binary.write_bytes(data)

    expected_fwd = _pefile_forwarders(pefile_mod, data)
    expected_exports = _pefile_exports(pefile_mod, data)
    # pefile really sees the two forwards (and only those), so it is a genuine
    # second opinion, not an echo of the reader.
    assert expected_fwd == [
        {"name": "HeapAlloc", "forward": "NTDLL.RtlAllocateHeap"},
        {"name": "HeapFree", "forward": "NTDLL.RtlFreeHeap"},
    ]
    assert "LocalRealFn" in expected_exports

    _, _, reader_exports, reader_fwd = _session_surface(binary)
    # Forward for forward, target for target: the reader matches pefile.
    assert reader_fwd == expected_fwd
    # The forwarded names still list as exports, alongside the plain one.
    assert reader_exports == expected_exports
    # And the plain export is on nobody's forwarder list.
    assert "LocalRealFn" not in {item["name"] for item in reader_fwd}


def _session_imphash(path: Path) -> str | None:
    service = AnalysisService()
    try:
        created = service.create_session(str(path))
        assert created.ok, created.error
        return created.data["session"]["metadata"]["pe"].get("imphash")
    finally:
        service.close_all()


@pytest.mark.integration
@pytest.mark.parametrize("magic", [0x20B, 0x10B], ids=["pe32+", "pe32"])
def test_imphash_agrees_with_pefile(tmp_path: Path, magic: int) -> None:
    """The import-table fingerprint against pefile's own get_imphash.

    imphash is the convention threat intel pivots on (VirusTotal, YARA's
    pe.imphash), and pefile's implementation *is* that convention -- so the
    session's hash must equal it byte for byte on a table mixing mixed-case
    DLL names, a mixed-case function, and a plain-DLL ordinal (which the
    convention hashes as ordN). Both magics, since the thunk width and
    ordinal flag differ.
    """
    pefile_mod = _pefile()
    if pefile_mod is None:
        pytest.skip("pefile not installed — PE imphash gate not run (skip != pass)")

    data = _pe_with_imports_exports(
        [
            ("KERNEL32.dll", ["VirtualAlloc", "Sleep"]),
            ("ADVAPI32.dll", ["RegOpenKeyExW"]),
            ("custom.dll", [7, "Named"]),
        ],
        [],
        magic=magic,
    )
    binary = tmp_path / f"fingerprint_{magic:x}.exe"
    binary.write_bytes(data)

    pe = pefile_mod.PE(data=data)  # type: ignore[attr-defined]
    expected = pe.get_imphash()
    assert expected, "pefile computed no imphash from the planted table"
    assert _session_imphash(binary) == expected


@pytest.mark.integration
def test_a_table_named_ordinal_withholds_the_imphash(tmp_path: Path) -> None:
    """An ordinal only pefile's bundled tables can name yields no session hash.

    pefile resolves a ws2_32 ordinal to its real function name through a
    lookup table this reader does not carry; hashing ordN instead would
    produce a value the rest of the ecosystem disagrees with. The referee
    proves the divergence is real -- pefile's hash over the resolved name
    differs from a hash over ordN -- and the session answers with absence.
    """
    pefile_mod = _pefile()
    if pefile_mod is None:
        pytest.skip("pefile not installed — PE imphash gate not run (skip != pass)")

    data = _pe_with_imports_exports([("ws2_32.dll", [23, "connect"])], [])
    binary = tmp_path / "socket_ordinal.exe"
    binary.write_bytes(data)

    pe = pefile_mod.PE(data=data)  # type: ignore[attr-defined]
    resolved = pe.get_imphash()
    naive = hashlib.md5(b"ws2_32.ord23,ws2_32.connect").hexdigest()  # noqa: S324
    # pefile really names ordinal 23 from its table (it is not ord23), so a
    # naive hash would disagree with the convention -- absence is correct.
    assert resolved != naive
    assert _session_imphash(binary) is None
