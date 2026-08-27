"""TOCTOU skips in the VMPDump PE-output scan.

``test_vmp_dumper_adapter_bounds.py`` pins ``_is_pe_file``'s header checks and
``_collect_output_pe``'s written-path / filter / newest / unreadable-root paths.
What it does not reach is the two ``except OSError`` arms that keep a file which
becomes unreadable *after* it was seen from crashing the whole scan: the second
open in ``_is_pe_file`` (reading the PE signature) and the per-candidate mtime
``stat`` in ``_collect_output_pe``. A dump directory is live storage the debuggee
is still writing, so a candidate can vanish between ``is_file`` and the read;
each arm must skip that entry rather than raise.
"""

from __future__ import annotations

import os
import struct
from pathlib import Path
from typing import Any

import pytest

import headless_re_mcp.unpack.vmp_dumper as vd


def _write_minimal_pe(path: Path) -> None:
    image = bytearray(0x400)
    pe_offset = 0x80
    image[:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, pe_offset)
    image[pe_offset : pe_offset + 4] = b"PE\0\0"
    path.write_bytes(bytes(image))


def test_is_pe_file_returns_false_when_the_signature_open_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The header open succeeds; the second open (for the signature) races.

    ``_is_pe_file`` opens the file twice -- once for the DOS header, once to
    read the PE signature at e_lfanew. If the file is unlinked between them the
    second open raises and the probe must answer False rather than propagate.
    """
    target = tmp_path / "race.exe"
    _write_minimal_pe(target)

    real_open = Path.open
    opens = {"n": 0}

    def flaky_open(
        self: Path,
        mode: str = "r",
        buffering: int = -1,
        encoding: str | None = None,
        errors: str | None = None,
        newline: str | None = None,
    ) -> Any:
        if self.name == "race.exe":
            opens["n"] += 1
            if opens["n"] >= 2:
                raise OSError("file vanished between the header and signature reads")
        return real_open(self, mode, buffering, encoding, errors, newline)

    monkeypatch.setattr(Path, "open", flaky_open)

    assert vd._is_pe_file(target) is False
    assert opens["n"] == 2, "the first open must have succeeded before the second failed"


def test_collect_output_pe_skips_a_candidate_whose_stat_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "root"
    root.mkdir()
    # A valid, correctly named PE that clears is_file and _is_pe_file, then loses
    # its mtime stat: the loop must skip it, not abort the whole collection.
    _write_minimal_pe(root / "trap.VMPDump.exe")
    produced = root / "good.VMPDump.exe"
    _write_minimal_pe(produced)
    os.utime(produced, (10_000.0, 10_000.0))

    armed = {"trap": False}
    real_is_pe = vd._is_pe_file

    def arming_is_pe(path: Path) -> bool:
        result = real_is_pe(path)
        if path.name == "trap.VMPDump.exe":
            armed["trap"] = True
        return result

    real_stat = Path.stat

    def flaky_stat(self: Path, *, follow_symlinks: bool = True) -> os.stat_result:
        # Only fail once the trap has passed is_file() and _is_pe_file(), so the
        # failure lands on the explicit mtime stat the guard protects.
        if self.name == "trap.VMPDump.exe" and armed["trap"]:
            raise OSError("file removed before its mtime could be read")
        return real_stat(self, follow_symlinks=follow_symlinks)

    monkeypatch.setattr(vd, "_is_pe_file", arming_is_pe)
    monkeypatch.setattr(Path, "stat", flaky_stat)

    got = vd._collect_output_pe(
        stdout="no path here", stderr="", mtime_floor=0.0, search_roots=[root]
    )
    assert got == produced
