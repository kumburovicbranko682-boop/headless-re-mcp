"""Cross-validate the overlay kind fact against file(1) -- libmagic's verdict.

A session over a PE, ELF or Mach-O (and the WASM/DEX readers through the same
helper) now names what an overlay's bytes self-declare as: zip is the
self-extractor classic, gzip/xz a compressed next stage, pe/elf an appended
executable, and None the honest no-magic answer an encrypted payload gives.
The sniff table is the reader's own, so the referee must carry its own magic
knowledge: file(1) is exactly that -- libmagic's database is maintained
entirely apart from this codebase.

The gate is one round-trip per format: glue a *real* container (built by
zipfile/gzip, not by echoing magic bytes) after a real binary, slice the file
at the offset the session reports, and hand the slice to file(1). libmagic
then referees both halves of the fact at once -- the offset (one byte early
or late and the slice no longer opens with the container's magic, so file
says "data") and the kind's name. A no-magic tail pins the honest None the
same way: file must also shrug.

gcc builds the ELF leg; the committed UPX and Mach-O fixtures anchor the PE
and Mach-O legs. skip != pass: each leg skips, naming the missing piece, only
when its own tool is absent.
"""

from __future__ import annotations

import gzip
import io
import shutil
import subprocess
import zipfile
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.core.service import AnalysisService

_UPX_ROOT = Path(__file__).resolve().parents[2] / "fixtures" / "upx"
_PE_FIXTURE = _UPX_ROOT / "console_fixture-x64.pre-upx.exe"
_MACHO_FIXTURE = Path(__file__).resolve().parents[2] / "fixtures" / "native" / "minimal.macho"


def _session_overlay(path: Path) -> dict[str, Any] | None:
    """The overlay fact off a session's pe/native metadata block."""
    service = AnalysisService()
    try:
        created = service.create_session(str(path))
        assert created.ok, created.error
        metadata = created.data["session"]["metadata"]
        facts = metadata.get("pe") or metadata.get("native") or {}
        return facts.get("overlay")
    finally:
        service.close_all()


def _file_verdict(payload: bytes, tmp_path: Path) -> str:
    """libmagic's name for the payload bytes, via file --brief."""
    slice_path = tmp_path / "overlay.slice"
    slice_path.write_bytes(payload)
    result = subprocess.run(
        ["file", "--brief", str(slice_path)],
        capture_output=True,
        text=True,
        timeout=60,
        check=True,
    )
    return result.stdout.strip().lower()


def _zip_payload() -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("payload.txt", "stage two")
    return buffer.getvalue()


@pytest.mark.integration
def test_elf_overlay_kind_agrees_with_file(tmp_path: Path) -> None:
    gcc = shutil.which("gcc")
    if gcc is None or shutil.which("file") is None:
        pytest.skip("gcc/file not installed — ELF overlay-kind gate not run (skip != pass)")

    source = tmp_path / "hello.c"
    source.write_text('#include <stdio.h>\nint main(void){puts("hi");return 0;}\n')
    binary = tmp_path / "hello"
    subprocess.run(
        [gcc, "-o", str(binary), str(source)], check=True, capture_output=True, timeout=120
    )
    assert _session_overlay(binary) is None, "a clean gcc build must trail nothing"
    base = binary.read_bytes()

    # The makeself/SFX shape: a real archive appended to a real binary.
    sfx = tmp_path / "hello.sfx"
    sfx.write_bytes(base + _zip_payload())
    overlay = _session_overlay(sfx)
    assert overlay is not None
    assert overlay["offset"] == len(base)
    assert overlay["kind"] == "zip"
    # libmagic referees offset and kind at once: the slice at the reported
    # offset must open with the archive's own magic for file to name it.
    assert "zip archive" in _file_verdict(sfx.read_bytes()[overlay["offset"] :], tmp_path)

    # The no-magic tail: the session must answer None and libmagic must
    # shrug the same way -- kind is a sniff, never a guess.
    plain = tmp_path / "hello.plain"
    plain.write_bytes(base + bytes(256))
    overlay = _session_overlay(plain)
    assert overlay is not None
    assert overlay["kind"] is None
    assert _file_verdict(plain.read_bytes()[overlay["offset"] :], tmp_path) == "data"


@pytest.mark.integration
def test_pe_overlay_kind_agrees_with_file(tmp_path: Path) -> None:
    if shutil.which("file") is None:
        pytest.skip("file not installed — PE overlay-kind gate not run (skip != pass)")
    if not _PE_FIXTURE.is_file():
        pytest.skip(f"fixture missing: {_PE_FIXTURE} (skip != pass)")

    base = _PE_FIXTURE.read_bytes()
    # A compressed next stage appended to a real Windows build. mtime=0 keeps
    # the gzip bytes deterministic run to run.
    staged = tmp_path / "staged.exe"
    staged.write_bytes(base + gzip.compress(b"stage two", mtime=0))
    overlay = _session_overlay(staged)
    assert overlay is not None
    assert overlay["offset"] == len(base)
    assert overlay["extra_size"] == overlay["size"]
    assert overlay["kind"] == "gzip"
    assert "gzip compressed" in _file_verdict(staged.read_bytes()[overlay["offset"] :], tmp_path)


@pytest.mark.integration
def test_macho_overlay_kind_agrees_with_file(tmp_path: Path) -> None:
    if shutil.which("file") is None:
        pytest.skip("file not installed — Mach-O overlay-kind gate not run (skip != pass)")
    if not _MACHO_FIXTURE.is_file():
        pytest.skip(f"fixture missing: {_MACHO_FIXTURE} (skip != pass)")

    base = _MACHO_FIXTURE.read_bytes()
    sfx = tmp_path / "staged.macho"
    sfx.write_bytes(base + _zip_payload())
    overlay = _session_overlay(sfx)
    assert overlay is not None
    assert overlay["offset"] == len(base)
    assert overlay["kind"] == "zip"
    assert "zip archive" in _file_verdict(sfx.read_bytes()[overlay["offset"] :], tmp_path)
