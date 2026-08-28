"""Cross-validate the PE TLS-callback surface against pefile and an mcs PE.

A session over a PE now reports its code-before-main: whether a TLS directory
(data directory index 9) exists and how many AddressOfCallBacks entries the
loader would run before the entry point -- the pair to the ELF/Mach-O
``init_funcs`` facts, and the classic home for a packer's anti-debug checks.
The directory locate, the VA-to-RVA rebase off ImageBase and the PE32/PE32+
pointer-width switch are all ours, so pefile referees them: it parses the same
TLS directory independently and this gate walks the callback array through
pefile's own VA accessors (get_qword_at_rva/get_dword_at_rva), comparing the
count against the reader's fact. A second case compiles a real PE with Mono's
mcs -- which emits no TLS directory -- so the absent verdict is gated against a
producer neither builder controls.

pefile ships in the project's ``pe`` extra; mcs comes from mono-mcs in CI. skip
!= pass: each test skips only when its own referee is unavailable.
"""

from __future__ import annotations

import shutil
import struct
import subprocess
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.core.service import AnalysisService


def _pefile() -> Any | None:
    try:
        import pefile
    except ImportError:
        return None
    return pefile


def _pe_with_tls_callbacks(count: int, *, magic: int) -> bytes:
    """A minimal one-section PE whose TLS directory carries ``count`` callbacks.

    Built here independently of the reader's own test builder so the two
    implementations cannot share a blind spot: the callback array sits at the
    section start and the IMAGE_TLS_DIRECTORY behind it at +0x80, both linked
    by VAs off the preferred image base, the layout the loader expects.
    """
    image_base = 0x1_4000_0000 if magic == 0x20B else 0x40_0000
    ptr = 8 if magic == 0x20B else 4
    fmt = "<Q" if magic == 0x20B else "<I"
    sect_rva = 0x1000

    sec = bytearray(max(0x200, (count + 1) * ptr + 0x100))
    if len(sec) % 0x200:
        sec += b"\x00" * (0x200 - len(sec) % 0x200)
    for i in range(count):
        struct.pack_into(fmt, sec, i * ptr, image_base + 0x3000 + i * 0x20)
    tls_dir_off = 0x80
    dir_fmt = "<QQQQII" if magic == 0x20B else "<IIIIII"
    struct.pack_into(dir_fmt, sec, tls_dir_off, 0, 0, 0, image_base + sect_rva, 0, 0)

    dos = bytearray(0x40)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x40)
    machine = 0x8664 if magic == 0x20B else 0x14C
    opt_size = 0xF0 if magic == 0x20B else 0xE0
    coff = b"PE\x00\x00" + struct.pack("<HHIIIHH", machine, 1, 0, 0, 0, opt_size, 0x0102)
    opt = bytearray(opt_size)
    struct.pack_into("<H", opt, 0, magic)
    if magic == 0x20B:
        struct.pack_into("<Q", opt, 24, image_base)
    else:
        struct.pack_into("<I", opt, 28, image_base)
    struct.pack_into("<I", opt, 32, 0x1000)  # SectionAlignment
    struct.pack_into("<I", opt, 36, 0x200)  # FileAlignment
    struct.pack_into("<I", opt, 56, sect_rva + len(sec))  # SizeOfImage
    dir_count_off = 108 if magic == 0x20B else 92
    struct.pack_into("<I", opt, dir_count_off, 16)
    tls_dir_size = 40 if magic == 0x20B else 24
    struct.pack_into(
        "<II", opt, dir_count_off + 4 + 9 * 8, sect_rva + tls_dir_off, tls_dir_size
    )

    raw_off = 0x40 + len(coff) + opt_size + 40
    if raw_off % 0x200:
        raw_off += 0x200 - (raw_off % 0x200)
    struct.pack_into("<I", opt, 60, raw_off)  # SizeOfHeaders

    sect = bytearray(40)
    sect[0:4] = b".tls"
    struct.pack_into("<I", sect, 8, len(sec))
    struct.pack_into("<I", sect, 12, sect_rva)
    struct.pack_into("<I", sect, 16, len(sec))
    struct.pack_into("<I", sect, 20, raw_off)
    struct.pack_into("<I", sect, 36, 0xC0000040)

    out = bytearray(dos + coff + opt + sect)
    if len(out) < raw_off:
        out += b"\x00" * (raw_off - len(out))
    return bytes(out + sec)


def _pefile_tls_callback_count(pefile_mod: Any, path: Path) -> int:
    """The callback count as pefile sees it, walked through its VA accessors."""
    pe = pefile_mod.PE(str(path))
    tls = pe.DIRECTORY_ENTRY_TLS.struct
    callbacks_va = tls.AddressOfCallBacks
    assert callbacks_va, "the planted TLS directory must declare a callback array"
    ptr = 8 if pe.OPTIONAL_HEADER.Magic == 0x20B else 4
    read = pe.get_qword_at_rva if ptr == 8 else pe.get_dword_at_rva
    rva = callbacks_va - pe.OPTIONAL_HEADER.ImageBase
    count = 0
    while True:
        value = read(rva + count * ptr)
        if not value:
            break
        count += 1
    return count


def _session_tls(path: Path) -> dict[str, Any]:
    service = AnalysisService()
    try:
        created = service.create_session(str(path))
        assert created.ok, created.error
        tls = created.data["session"]["metadata"]["pe"]["tls"]
        assert isinstance(tls, dict)
        return tls
    finally:
        service.close_all()


@pytest.mark.integration
@pytest.mark.parametrize("magic", [0x20B, 0x10B], ids=["pe32+", "pe32"])
def test_tls_callback_count_agrees_with_pefile(tmp_path: Path, magic: int) -> None:
    pefile_mod = _pefile()
    if pefile_mod is None:
        pytest.skip("pefile not installed — PE TLS gate not run (skip != pass)")

    binary = tmp_path / f"tls_{magic:x}.exe"
    binary.write_bytes(_pe_with_tls_callbacks(3, magic=magic))

    # Independent ground truth: pefile parses the TLS directory itself and this
    # walk rebases and reads each callback slot through pefile's accessors. The
    # array must hold what we planted, so pefile is a genuine second opinion.
    expected = _pefile_tls_callback_count(pefile_mod, binary)
    assert expected == 3

    assert _session_tls(binary) == {"present": True, "callbacks": expected}


@pytest.mark.integration
def test_an_mcs_compiled_pe_reads_tls_absent_like_pefile(tmp_path: Path) -> None:
    pefile_mod = _pefile()
    if pefile_mod is None:
        pytest.skip("pefile not installed — PE TLS gate not run (skip != pass)")
    mcs = shutil.which("mcs")
    if mcs is None:
        pytest.skip("mcs (mono-mcs) not installed — compiler-PE gate not run (skip != pass)")

    # A real compiler's PE: Mono's linker ships managed exes without a TLS
    # directory, so the absent verdict is gated on a binary neither this
    # gate's builder nor the reader's test builder wrote.
    source = tmp_path / "hello.cs"
    source.write_text('class P { static void Main() { System.Console.WriteLine("hi"); } }\n')
    binary = tmp_path / "hello.exe"
    subprocess.run(
        [mcs, f"-out:{binary}", str(source)], check=True, capture_output=True, timeout=120
    )

    pe = pefile_mod.PE(str(binary))
    assert not hasattr(pe, "DIRECTORY_ENTRY_TLS")

    assert _session_tls(binary) == {"present": False, "callbacks": 0}
