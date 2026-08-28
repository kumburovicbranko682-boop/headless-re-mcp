"""Direct coverage of the XVLKC output-collection helpers.

``run_xvlkc`` drives ``_is_pe_file`` and ``_collect_newest_pe`` only on the
happy path with a real (skipped) toolchain. These exercise the fail-closed
guards -- a second-open read error, non-file rglob entries, and stat/resolve
races on candidate paths -- directly against the module helpers.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.unpack import xvlkc as xvlkc_mod
from headless_re_mcp.unpack.xvlkc import XvlkcError, _collect_newest_pe, _is_pe_file


def _write_pe(path: Path) -> None:
    """A minimal file that ``_is_pe_file`` accepts (MZ + PE signature at 0x40)."""
    image = bytearray(0x44)
    image[:2] = b"MZ"
    image[0x3C:0x40] = (0x40).to_bytes(4, "little")
    image[0x40:0x44] = b"PE\0\0"
    path.write_bytes(bytes(image))


def test_is_pe_file_returns_false_when_the_signature_read_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "sample.exe"
    _write_pe(target)

    real_open: Any = Path.open
    calls = {"n": 0}

    def failing_second_open(self: Path, *args: Any, **kwargs: Any) -> Any:
        calls["n"] += 1
        if calls["n"] == 2:
            raise OSError("signature read failed")
        return real_open(self, *args, **kwargs)

    monkeypatch.setattr(Path, "open", failing_second_open)

    assert _is_pe_file(target) is False


def test_collect_newest_pe_skips_directories(tmp_path: Path) -> None:
    work = tmp_path / "work"
    work.mkdir()
    (work / "nested").mkdir()  # a non-file rglob entry
    work_input = work / "input.exe"
    _write_pe(work_input)
    produced = work / "unpacked.exe"
    _write_pe(produced)

    result = _collect_newest_pe(work, work_input)

    assert result == produced


def test_collect_newest_pe_skips_a_candidate_that_cannot_resolve(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    work = tmp_path / "work"
    work.mkdir()
    work_input = work / "input.exe"
    _write_pe(work_input)
    _write_pe(work / "boom.exe")
    good = work / "good.exe"
    _write_pe(good)

    real_resolve: Any = Path.resolve

    def failing_resolve(self: Path, *args: Any, **kwargs: Any) -> Any:
        if self.name == "boom.exe":
            raise OSError("cannot resolve")
        return real_resolve(self, *args, **kwargs)

    monkeypatch.setattr(Path, "resolve", failing_resolve)

    result = _collect_newest_pe(work, work_input)

    assert result == good


def test_collect_newest_pe_skips_a_candidate_that_cannot_stat(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    work = tmp_path / "work"
    work.mkdir()
    work_input = work / "input.exe"
    _write_pe(work_input)
    _write_pe(work / "statboom.exe")
    good = work / "good.exe"
    _write_pe(good)

    real_stat: Any = Path.stat
    stat_calls = {"n": 0}

    def failing_stat(self: Path, *args: Any, **kwargs: Any) -> Any:
        if self.name == "statboom.exe":
            stat_calls["n"] += 1
            # The first stat (is_file) succeeds; the explicit st_mtime read fails.
            if stat_calls["n"] >= 2:
                raise OSError("cannot stat")
        return real_stat(self, *args, **kwargs)

    monkeypatch.setattr(Path, "stat", failing_stat)

    result = _collect_newest_pe(work, work_input)

    assert result == good


def test_collect_newest_pe_fails_closed_without_candidates(tmp_path: Path) -> None:
    work = tmp_path / "work"
    work.mkdir()
    work_input = work / "input.exe"
    _write_pe(work_input)

    with pytest.raises(XvlkcError) as excinfo:
        _collect_newest_pe(work, work_input)

    assert excinfo.value.code == xvlkc_mod.XvlkcErrorCode.OUTPUT_MISSING
