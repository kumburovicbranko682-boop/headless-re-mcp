"""Cross-validate the native section-payload census against objcopy and file.

A session over an ELF or Mach-O now lists sections whose bytes open with
executable magic -- the native dropper's stash, a nested PE it writes out for a
Windows drop, an ELF loader, a zipped bundle, each parked in a custom section.
The section walk and the magic table are both ours, so two independent tools
referee them: objcopy (binutils, or llvm-objcopy for Mach-O) plants the payload
into a real binary and, crucially, extracts each section's bytes right back out
with ``--dump-section`` -- an entirely separate read of the same section table
-- and ``file`` (libmagic) classifies those extracted bytes. The reader's
census must name exactly the sections whose dumped bytes libmagic calls
executable, with the same kind and the same byte size, and stay silent on the
benign section both tools also see.

gcc/objcopy/readelf and file ship with the CI runner; the Mach-O arm needs
llvm-objcopy/llvm-objdump (LLVM) and the committed Mach-O fixture. skip != pass:
each arm skips, naming the missing tool, only when it is unavailable.
"""

from __future__ import annotations

import io
import shutil
import subprocess
import zipfile
from pathlib import Path
from typing import Any, cast

import pytest

from headless_re_mcp.core.service import AnalysisService

_MACHO_FIXTURE = Path(__file__).resolve().parents[2] / "fixtures" / "native" / "minimal.macho"

# A nested PE (a DOS-stub-sized MZ), a real ELF (a system binary) and a real
# ZIP -- the three payload kinds the census recognises, each a genuine file
# libmagic classifies without our help.
_NESTED_PE = b"MZ" + b"\x00" * 0x60


def _real_zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as archive:
        archive.writestr("stage2/config.txt", "second stage")
    return buf.getvalue()


def _real_elf() -> bytes | None:
    for candidate in ("/bin/true", "/bin/ls", "/usr/bin/python3"):
        path = Path(candidate)
        if path.is_file():
            return path.read_bytes()
    return None


def _kind_from_libmagic(description: str) -> str | None:
    """Map a libmagic description to the census's kind vocabulary, or None."""
    lowered = description.lower()
    if lowered.startswith("elf"):
        return "elf"
    if "ms-dos executable" in lowered or "pe32" in lowered:
        return "pe"
    if "zip archive" in lowered:
        return "zip"
    if "dalvik" in lowered:
        return "dex"
    if "mach-o" in lowered:
        return "macho"
    return None


def _libmagic(file_bin: str, data: bytes, scratch: Path) -> str:
    probe = scratch / "probe.bin"
    probe.write_bytes(data)
    result = subprocess.run(
        [file_bin, "--brief", str(probe)], capture_output=True, text=True, timeout=60
    )
    assert result.returncode == 0, result.stderr
    return result.stdout.strip()


def _session_sections(service: AnalysisService, binary: Path) -> list[dict[str, Any]]:
    created = service.create_session(str(binary))
    assert created.ok, created.error
    native = created.data["session"]["metadata"]["native"]
    return cast("list[dict[str, Any]]", native["section_payloads"])


@pytest.mark.integration
def test_elf_section_census_agrees_with_objcopy_and_file(tmp_path: Path) -> None:
    gcc = shutil.which("gcc") or shutil.which("cc")
    objcopy = shutil.which("objcopy")
    readelf = shutil.which("readelf")
    file_bin = shutil.which("file")
    if gcc is None:
        pytest.skip("no C compiler installed — section gate not run (skip != pass)")
    if objcopy is None or readelf is None:
        pytest.skip(
            "binutils (objcopy/readelf) not installed — section gate not run (skip != pass)"
        )
    if file_bin is None:
        pytest.skip("file (libmagic) not installed — section gate not run (skip != pass)")
    real_elf = _real_elf()
    if real_elf is None:
        pytest.skip("no system ELF to embed — section gate not run (skip != pass)")

    # A real ELF the tools built themselves, so the base binary is unimpeachable.
    source = tmp_path / "probe.c"
    source.write_text("int main(void){return 0;}\n")
    base = tmp_path / "base.elf"
    assert (
        subprocess.run(
            [gcc, str(source), "-o", str(base)], capture_output=True, text=True, timeout=120
        ).returncode
        == 0
    )

    planted = {
        ".payload": _NESTED_PE,
        ".loader": real_elf,
        ".bundle": _real_zip(),
        ".benign": b"a plain read-only note, nothing hidden here",
    }
    files = {}
    add_args: list[str] = []
    for name, data in planted.items():
        blob = tmp_path / f"{name.strip('.')}.bin"
        blob.write_bytes(data)
        files[name] = blob
        add_args += ["--add-section", f"{name}={blob}"]
    dropper = tmp_path / "dropper.elf"
    assert (
        subprocess.run(
            [objcopy, *add_args, str(base), str(dropper)],
            capture_output=True,
            text=True,
            timeout=60,
        ).returncode
        == 0
    )

    # readelf confirms the sections exist as an independent parser sees them.
    listing = subprocess.run(
        [readelf, "-S", str(dropper)], capture_output=True, text=True, timeout=60
    )
    assert listing.returncode == 0, listing.stderr
    for name in planted:
        assert name in listing.stdout, listing.stdout

    # Ground truth: objcopy dumps each section's bytes back out (a separate read
    # of the same section table) and libmagic classifies what it extracted.
    expected: dict[str, str] = {}
    dumped_size: dict[str, int] = {}
    for name in planted:
        out = tmp_path / f"dump{name}.bin"
        assert (
            subprocess.run(
                [objcopy, "--dump-section", f"{name}={out}", str(dropper)],
                capture_output=True,
                text=True,
                timeout=60,
            ).returncode
            == 0
        )
        blob = out.read_bytes()
        dumped_size[name] = len(blob)
        kind = _kind_from_libmagic(_libmagic(file_bin, blob, tmp_path))
        if kind is not None:
            expected[name] = kind
    assert expected == {".payload": "pe", ".loader": "elf", ".bundle": "zip"}

    service = AnalysisService()
    try:
        census = _session_sections(service, dropper)
    finally:
        service.close_all()

    reader = {entry["section"]: entry["kind"] for entry in census}
    assert reader == expected
    for entry in census:
        assert entry["size"] == dumped_size[entry["section"]]
    assert ".benign" not in reader


@pytest.mark.integration
def test_macho_section_census_agrees_with_llvm_objcopy_and_file(tmp_path: Path) -> None:
    if not _MACHO_FIXTURE.is_file():
        pytest.skip(f"Mach-O fixture missing: {_MACHO_FIXTURE} (skip != pass)")
    llvm_objcopy = shutil.which("llvm-objcopy") or shutil.which("llvm-objcopy-18")
    llvm_objdump = shutil.which("llvm-objdump") or shutil.which("llvm-objdump-18")
    file_bin = shutil.which("file")
    if llvm_objcopy is None or llvm_objdump is None:
        pytest.skip(
            "LLVM (llvm-objcopy/llvm-objdump) not installed — Mach-O arm skipped (skip != pass)"
        )
    if file_bin is None:
        pytest.skip("file (libmagic) not installed — Mach-O arm skipped (skip != pass)")

    # llvm-objcopy on this tiny fixture only lays down one added section cleanly
    # before header growth collides with the first segment's section offset, so
    # each kind gets its own dropper built from the pristine fixture -- every
    # one still refereed end to end by an independent extraction and libmagic.
    planted = {
        "__payload": (_NESTED_PE, "pe"),
        "__loader": (_real_elf() or b"\x7fELF" + b"\x00" * 0x40, "elf"),
        "__bundle": (_real_zip(), "zip"),
        "__benign": (b"a plain C string table, nothing hidden here", None),
    }
    for name, (data, want) in planted.items():
        blob = tmp_path / f"{name.strip('_')}.bin"
        blob.write_bytes(data)
        dropper = tmp_path / f"dropper{name}.macho"
        result = subprocess.run(
            [
                llvm_objcopy,
                "--add-section",
                f"__DATA,{name}={blob}",
                str(_MACHO_FIXTURE),
                str(dropper),
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert result.returncode == 0, result.stderr

        # An independent parser sees the section.
        headers = subprocess.run(
            [llvm_objdump, "--macho", "--section-headers", str(dropper)],
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert headers.returncode == 0, headers.stderr
        assert name in headers.stdout, headers.stdout

        # Ground truth: llvm-objcopy dumps the section back out (a separate read
        # of the same section table) and libmagic classifies what it extracted.
        out = tmp_path / f"dump_{name}.bin"
        dump = subprocess.run(
            [llvm_objcopy, "--dump-section", f"__DATA,{name}={out}", str(dropper)],
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert dump.returncode == 0, dump.stderr
        blob_out = out.read_bytes()
        kind = _kind_from_libmagic(_libmagic(file_bin, blob_out, tmp_path))
        assert kind == want, (name, kind, want)

        service = AnalysisService()
        try:
            census = _session_sections(service, dropper)
        finally:
            service.close_all()
        reader = {entry["section"]: entry["kind"] for entry in census}
        if want is None:
            # A benign section libmagic does not call executable is not flagged.
            assert name not in reader, reader
        else:
            # The one planted section reads under its name, kind and byte size.
            assert reader == {name: want}, reader
            assert census[0]["size"] == len(blob_out)
