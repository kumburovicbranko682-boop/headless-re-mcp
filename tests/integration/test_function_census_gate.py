"""Cross-validate the stripping-proof function census on all three members.

A session now counts functions out of the structures the runtime itself
needs, which symbol stripping therefore never removes: the ELF .eh_frame_hdr
fde_count (one FDE per function, binary-searched by the unwinder), the PE
exception directory's RUNTIME_FUNCTION entries (x64 SEH is table-driven) and
Mach-O LC_FUNCTION_STARTS (dyld and the crash reporter read it). For a
stripped image these counts are the honest size of the analysis surface.

Each member gets an independent referee over a real or independently decoded
artifact: gcc builds the ELF and llvm-dwarfdump walks the .eh_frame FDEs (a
different structure than the header the session reads -- the linker keeps
them consistent); mingw builds the PE and pefile decodes each
RUNTIME_FUNCTION out of the directory; the Mach-O table is laid down by hand
here (byte-for-byte, no reader code) and llvm-objdump --macho
--function-starts decodes the same ULEB128 run. The strip legs prove the
census survives: binutils strip on the ELF and the MinGW strip on the PE
must leave both sides' counts unchanged while the symbol tables vanish.

skip != pass: each test skips, naming the missing piece, only when its own
referee is unavailable.
"""

from __future__ import annotations

import re
import shutil
import struct
import subprocess
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from headless_re_mcp.core.service import AnalysisService

_UPX_ROOT = Path(__file__).resolve().parents[2] / "fixtures" / "upx"
_FDE_RE = re.compile(r"^[0-9a-f]{8} .* FDE cie=", re.MULTILINE)


def _pefile() -> ModuleType | None:
    try:
        import pefile
    except ImportError:
        return None
    return pefile


def _session_facts(path: Path, key: str) -> dict[str, Any]:
    service = AnalysisService()
    try:
        created = service.create_session(str(path))
        assert created.ok, created.error
        return created.data["session"]["metadata"][key]
    finally:
        service.close_all()


@pytest.mark.integration
def test_elf_fde_count_agrees_with_dwarfdump_and_survives_strip(tmp_path: Path) -> None:
    gcc = shutil.which("gcc") or shutil.which("cc")
    if gcc is None:
        pytest.skip("gcc not installed — ELF function-census gate not run (skip != pass)")
    dwarfdump = shutil.which("llvm-dwarfdump")
    if dwarfdump is None:
        pytest.skip("llvm-dwarfdump not installed — ELF function-census gate not run"
                    " (skip != pass)")
    strip = shutil.which("strip")
    if strip is None:
        pytest.skip("strip not installed — ELF function-census gate not run (skip != pass)")

    source = tmp_path / "many.c"
    source.write_text(
        "#include <stdio.h>\n"
        + "".join(f"int f{i}(int x) {{ return x + {i}; }}\n" for i in range(5))
        + "int main(void) { printf(\"%d\\n\", f0(f1(f2(f3(f4(1)))))); return 0; }\n"
    )
    built = tmp_path / "many"
    subprocess.run(
        [gcc, "-o", str(built), str(source)], check=True, capture_output=True, timeout=300
    )

    # The referee walks the .eh_frame FDEs themselves -- a different structure
    # than the .eh_frame_hdr count the session reads; the linker keeps the
    # search table consistent with the FDE list, so the counts must meet.
    dump = subprocess.run(
        [dwarfdump, "--eh-frame", str(built)],
        check=True,
        capture_output=True,
        text=True,
        timeout=120,
    )
    referee_count = len(_FDE_RE.findall(dump.stdout))
    assert referee_count > 5, "a gcc build should carry FDEs for every function"
    assert _session_facts(built, "native")["eh_frame_functions"] == referee_count

    # strip removes the symbol tables but the unwinder still needs its index:
    # the census must survive unchanged, on both sides.
    stripped = tmp_path / "stripped"
    shutil.copyfile(built, stripped)
    subprocess.run([strip, str(stripped)], check=True, capture_output=True, timeout=120)
    stripped_dump = subprocess.run(
        [dwarfdump, "--eh-frame", str(stripped)],
        check=True,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert len(_FDE_RE.findall(stripped_dump.stdout)) == referee_count
    stripped_facts = _session_facts(stripped, "native")
    assert stripped_facts["eh_frame_functions"] == referee_count
    assert "exported_symbols" not in stripped_facts


@pytest.mark.integration
def test_pe_runtime_function_count_agrees_with_pefile_and_survives_strip(
    tmp_path: Path,
) -> None:
    pefile_mod = _pefile()
    if pefile_mod is None:
        pytest.skip("pefile not installed — PE function-census gate not run (skip != pass)")
    gcc = shutil.which("x86_64-w64-mingw32-gcc")
    if gcc is None:
        pytest.skip("x86_64-w64-mingw32-gcc not installed — PE function-census gate not run"
                    " (skip != pass)")
    strip = shutil.which("x86_64-w64-mingw32-strip") or shutil.which("llvm-strip")
    if strip is None:
        pytest.skip("no PE-capable strip installed — PE function-census gate not run"
                    " (skip != pass)")

    source = tmp_path / "hello.c"
    source.write_text(
        "#include <stdio.h>\n"
        "int helper(int x) { return x * 2; }\n"
        "int main(void) { printf(\"%d\\n\", helper(21)); return 0; }\n"
    )
    built = tmp_path / "hello.exe"
    subprocess.run(
        [gcc, "-o", str(built), str(source)], check=True, capture_output=True, timeout=300
    )

    # pefile decodes each RUNTIME_FUNCTION struct out of the directory; the
    # session divides the directory size by the machine's entry width. Both
    # must land on the same count.
    pe = pefile_mod.PE(str(built))
    referee_count = len(getattr(pe, "DIRECTORY_ENTRY_EXCEPTION", []))
    assert referee_count > 0, "a MinGW x64 build should carry a .pdata table"
    assert _session_facts(built, "pe")["exception_functions"] == referee_count

    # The unwinder needs the table at runtime: strip must leave the census
    # intact while the COFF symbols vanish.
    stripped = tmp_path / "stripped.exe"
    shutil.copyfile(built, stripped)
    subprocess.run([strip, str(stripped)], check=True, capture_output=True, timeout=120)
    stripped_pe = pefile_mod.PE(str(stripped))
    assert len(getattr(stripped_pe, "DIRECTORY_ENTRY_EXCEPTION", [])) == referee_count
    stripped_facts = _session_facts(stripped, "pe")
    assert stripped_facts["exception_functions"] == referee_count
    assert stripped_facts["coff_symbol_count"] == 0


@pytest.mark.integration
def test_pe_fixture_counts_agree_with_pefile() -> None:
    pefile_mod = _pefile()
    if pefile_mod is None:
        pytest.skip("pefile not installed — PE fixture function-census gate not run"
                    " (skip != pass)")
    pairs = [
        _UPX_ROOT / f"console_fixture-x64.{stage}.exe" for stage in ("pre-upx", "upx")
    ]
    if not all(fixture.is_file() for fixture in pairs):
        pytest.skip(f"upx x64 fixtures missing under {_UPX_ROOT} (skip != pass)")

    # The MSVC build carries a real table; upx packs .pdata away. Both counts
    # must match pefile's decode -- including the packed zero.
    for fixture in pairs:
        pe = pefile_mod.PE(str(fixture))
        referee_count = len(getattr(pe, "DIRECTORY_ENTRY_EXCEPTION", []))
        assert _session_facts(fixture, "pe")["exception_functions"] == referee_count, (
            fixture.name
        )


def _uleb128(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        out.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(out)


def _macho_with_function_starts(offsets: list[int]) -> bytes:
    """A thin x86-64 Mach-O whose LC_FUNCTION_STARTS encodes ``offsets``.

    Independent of the reader: the header, the two segments and the
    linkedit_data_command are laid down byte for byte with struct.pack, and
    the ULEB128 run is built by the local encoder above. llvm-objdump
    resolves the deltas against __TEXT's vmaddr, so the segment spans mirror
    a real image's shape.
    """
    deltas = [offsets[0]] + [b - a for a, b in zip(offsets, offsets[1:], strict=False)]
    blob = b"".join(_uleb128(delta) for delta in deltas) + b"\x00"
    sizeofcmds = 72 + 72 + 16
    dataoff = 32 + sizeofcmds
    header = struct.pack(
        "<IIIIIIII", 0xFEEDFACF, 0x01000007, 3, 2, 3, sizeofcmds, 0, 0
    )
    seg_text = struct.pack(
        "<II16sQQQQiiII", 0x19, 72, b"__TEXT", 0, 0x4000, 0, dataoff, 7, 5, 0, 0
    )
    seg_linkedit = struct.pack(
        "<II16sQQQQiiII", 0x19, 72, b"__LINKEDIT", 0x4000, 0x1000, dataoff, len(blob), 1, 1, 0, 0
    )
    starts_cmd = struct.pack("<IIII", 0x26, 16, dataoff, len(blob))
    return header + seg_text + seg_linkedit + starts_cmd + blob


@pytest.mark.integration
def test_macho_function_starts_agree_with_llvm_objdump(tmp_path: Path) -> None:
    objdump = shutil.which("llvm-objdump")
    if objdump is None:
        pytest.skip("llvm-objdump not installed — Mach-O function-census gate not run"
                    " (skip != pass)")

    offsets = [0x1000, 0x1040, 0x1070, 0x10F0]
    image = tmp_path / "starts.macho"
    image.write_bytes(_macho_with_function_starts(offsets))

    # llvm-objdump decodes the same ULEB128 run against __TEXT's vmaddr: its
    # printed addresses must be exactly the planted offsets, and the session's
    # count the same number.
    dump = subprocess.run(
        [objdump, "--macho", "--function-starts", str(image)],
        check=True,
        capture_output=True,
        text=True,
        timeout=120,
    )
    printed = [int(line, 16) for line in dump.stdout.split() if re.fullmatch(r"[0-9a-f]{16}", line)]
    assert printed == offsets
    assert _session_facts(image, "native")["function_starts"] == len(offsets)
