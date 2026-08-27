"""TOCTOU skips in the Scylla PE-output scan.

``test_scylla_pe_helpers.py`` pins the ``_is_pe_file`` header checks and the
``_collect_newest_pe`` skips for directories, the input copy, and non-PE files.
What it does not reach is the three ``except OSError`` arms that keep a file
which becomes unreadable *after* it was seen from crashing the whole scan: the
second open in ``_is_pe_file``, and the ``resolve``/``stat`` calls per candidate
in ``_collect_newest_pe``. A dump directory is live storage a debugger is still
writing to, so a candidate can vanish between ``is_file`` and the read; each arm
must skip that entry, not raise.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest

import headless_re_mcp.unpack.scylla as scylla
from headless_re_mcp.unpack.scylla import _collect_newest_pe, _is_pe_file


def _pe_bytes(*, pe_offset: int = 0x40) -> bytes:
    header = bytearray(0x40)
    header[0:2] = b"MZ"
    header[0x3C:0x40] = pe_offset.to_bytes(4, "little")
    body = bytearray(pe_offset + 4)
    body[: len(header)] = header
    body[pe_offset : pe_offset + 4] = b"PE\0\0"
    return bytes(body)


def _write_pe(path: Path) -> Path:
    path.write_bytes(_pe_bytes())
    return path


def test_is_pe_file_returns_false_when_the_signature_read_open_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The header open succeeds; the second open (for the PE signature) races.

    ``_is_pe_file`` opens the file twice -- once for the DOS header, once to
    read the signature at e_lfanew. If the file is unlinked between the two,
    the second open raises and the probe must answer False, not propagate.
    """
    target = _write_pe(tmp_path / "race.exe")
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

    assert _is_pe_file(target) is False
    assert opens["n"] == 2, "the first open must have succeeded before the second failed"


def test_collect_newest_pe_skips_a_candidate_whose_path_cannot_be_resolved(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    work = tmp_path / "work"
    work.mkdir()
    work_input = _write_pe(work / "input.exe")
    # A plain file that is_file() accepts but whose resolve() raises: the loop
    # must skip it (it cannot even be compared against the input) rather than die.
    (work / "trap.exe").write_bytes(b"seen then unresolvable")
    produced = _write_pe(work / "dumped.exe")

    real_resolve = Path.resolve

    def flaky_resolve(self: Path, strict: bool = False) -> Path:
        if self.name == "trap.exe":
            raise OSError("path disappeared before it could be resolved")
        return real_resolve(self, strict)

    monkeypatch.setattr(Path, "resolve", flaky_resolve)

    assert _collect_newest_pe(work, work_input) == produced


def test_collect_newest_pe_skips_a_candidate_whose_stat_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    work = tmp_path / "work"
    work.mkdir()
    work_input = _write_pe(work / "input.exe")
    _write_pe(work / "trap.exe")  # a real PE, so it clears is_file and _is_pe_file
    produced = _write_pe(work / "dumped.exe")

    # Fail the mtime stat only once the candidate has already passed is_file and
    # _is_pe_file, so the failure lands on the explicit stat() at the mtime read
    # rather than on the is_file() probe that runs first.
    armed = {"trap": False}
    real_is_pe = scylla._is_pe_file

    def arming_is_pe(path: Path) -> bool:
        result = real_is_pe(path)
        if path.name == "trap.exe":
            armed["trap"] = True
        return result

    real_stat = Path.stat

    def flaky_stat(self: Path, *, follow_symlinks: bool = True) -> os.stat_result:
        if self.name == "trap.exe" and armed["trap"]:
            raise OSError("file removed before its mtime could be read")
        return real_stat(self, follow_symlinks=follow_symlinks)

    monkeypatch.setattr(scylla, "_is_pe_file", arming_is_pe)
    monkeypatch.setattr(Path, "stat", flaky_stat)

    assert _collect_newest_pe(work, work_input) == produced
