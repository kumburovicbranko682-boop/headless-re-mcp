"""Cover the XVLKC adapter: PE sniffing, newest-output selection, the run
pipeline's guards and success path, and the best-effort probe."""

from __future__ import annotations

import io
import os
import stat
import struct
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import headless_re_mcp.unpack.xvlkc as xv
from headless_re_mcp.backends.common.bounded_run import BoundedCancelled
from headless_re_mcp.core.session import file_sha256
from headless_re_mcp.unpack.xvlkc import (
    XvlkcError,
    XvlkcErrorCode,
    XvlkcResult,
    _collect_newest_pe,
    _is_pe_file,
    probe_xvlkc,
    run_xvlkc,
)


def _write_pe(path: Path) -> None:
    image = bytearray(0x400)
    pe_offset = 0x80
    image[:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, pe_offset)
    image[pe_offset : pe_offset + 4] = b"PE\0\0"
    path.write_bytes(image)


def _script(path: Path, body: str) -> Path:
    path.write_text("#!/bin/sh\n" + body, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return path


# --- _is_pe_file --------------------------------------------------------------


def test_is_pe_file_accepts_a_real_pe(tmp_path: Path) -> None:
    binary = tmp_path / "ok.exe"
    _write_pe(binary)
    assert _is_pe_file(binary) is True


def test_is_pe_file_rejects_when_the_second_read_fails() -> None:
    header = bytearray(0x40)
    header[:2] = b"MZ"
    struct.pack_into("<I", header, 0x3C, 0x80)  # pe_offset >= 0x40

    class _SecondOpenFails:
        def __init__(self) -> None:
            self.calls = 0

        def open(self, _mode: str) -> io.BytesIO:
            self.calls += 1
            if self.calls == 1:
                return io.BytesIO(bytes(header))
            raise OSError("file vanished")

    assert _is_pe_file(_SecondOpenFails()) is False  # type: ignore[arg-type]


def test_is_pe_file_rejects_unreadable_and_malformed(tmp_path: Path) -> None:
    assert _is_pe_file(tmp_path) is False  # a directory raises OSError on open

    short = tmp_path / "short.bin"
    short.write_bytes(b"MZ")
    assert _is_pe_file(short) is False

    bad_offset = tmp_path / "bad_offset.bin"
    header = bytearray(0x40)
    header[:2] = b"MZ"
    struct.pack_into("<I", header, 0x3C, 0x10)  # pe_offset < 0x40
    bad_offset.write_bytes(header)
    assert _is_pe_file(bad_offset) is False

    bad_sig = tmp_path / "bad_sig.bin"
    image = bytearray(0x100)
    image[:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, 0x80)
    image[0x80:0x84] = b"XXXX"
    bad_sig.write_bytes(image)
    assert _is_pe_file(bad_sig) is False


# --- _collect_newest_pe -------------------------------------------------------


def test_collect_newest_pe_picks_the_lone_output(tmp_path: Path) -> None:
    work_dir = tmp_path / "work"
    work_dir.mkdir()
    work_input = work_dir / "input.exe"
    _write_pe(work_input)
    (work_dir / "notes.txt").write_text("not a pe", encoding="utf-8")
    (work_dir / "nested").mkdir()
    produced = work_dir / "unpacked.exe"
    _write_pe(produced)

    result = _collect_newest_pe(work_dir, work_input)
    assert result == produced


def test_collect_newest_pe_fails_closed_without_output(tmp_path: Path) -> None:
    work_dir = tmp_path / "work"
    work_dir.mkdir()
    work_input = work_dir / "input.exe"
    _write_pe(work_input)
    with pytest.raises(XvlkcError) as excinfo:
        _collect_newest_pe(work_dir, work_input)
    assert excinfo.value.code == XvlkcErrorCode.OUTPUT_MISSING


def test_collect_newest_pe_skips_unresolvable_and_unstatable_entries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class _Entry:
        def __init__(
            self,
            name: str,
            *,
            is_file: bool = True,
            resolve_raises: bool = False,
            stat_raises: bool = False,
            is_pe: bool = False,
            mtime: float = 1.0,
        ) -> None:
            self.name = name
            self._is_file = is_file
            self._resolve_raises = resolve_raises
            self._stat_raises = stat_raises
            self.is_pe = is_pe
            self._mtime = mtime

        def is_file(self) -> bool:
            return self._is_file

        def resolve(self) -> Any:
            if self._resolve_raises:
                raise OSError("cannot resolve")
            return self

        def stat(self) -> Any:
            if self._stat_raises:
                raise OSError("cannot stat")
            return SimpleNamespace(st_mtime=self._mtime)

        def __str__(self) -> str:
            return self.name

    winner = _Entry("winner", is_pe=True, mtime=9.0)
    entries = [
        _Entry("dir", is_file=False),
        _Entry("unresolvable", resolve_raises=True),
        _Entry("plain", is_pe=False),
        _Entry("unstatable", is_pe=True, stat_raises=True),
        winner,
    ]

    class _FakeWorkDir:
        def rglob(self, _pattern: str) -> Any:
            return iter(entries)

    monkeypatch.setattr(xv, "_is_pe_file", lambda entry: getattr(entry, "is_pe", False))
    result = _collect_newest_pe(_FakeWorkDir(), tmp_path / "work_input")  # type: ignore[arg-type]
    assert result is winner  # type: ignore[comparison-overlap]


def test_collect_newest_pe_refuses_ambiguous_outputs(tmp_path: Path) -> None:
    work_dir = tmp_path / "work"
    work_dir.mkdir()
    work_input = work_dir / "input.exe"
    _write_pe(work_input)
    first = work_dir / "a.exe"
    second = work_dir / "b.exe"
    _write_pe(first)
    _write_pe(second)
    os.utime(first, (1_000_000, 1_000_000))
    os.utime(second, (1_000_000, 1_000_000))
    with pytest.raises(XvlkcError) as excinfo:
        _collect_newest_pe(work_dir, work_input)
    assert excinfo.value.code == XvlkcErrorCode.OUTPUT_AMBIGUOUS


# --- run_xvlkc ----------------------------------------------------------------


def test_run_publishes_the_newest_pe_output(tmp_path: Path) -> None:
    source = tmp_path / "sample.exe"
    _write_pe(source)
    exe = _script(
        tmp_path / "xvlkc.sh",
        'dir=$(dirname "$1")\ncp "$1" "$dir/unpacked.exe"\necho ok\nexit 0\n',
    )
    destination = tmp_path / "out" / "unpacked.exe"
    sha = file_sha256(source)

    result = run_xvlkc(exe, source, destination, input_sha256=sha)
    assert result.returncode == 0
    assert Path(result.output_path).is_file()
    assert result.input_sha256 == sha


def test_run_refuses_a_missing_executable(tmp_path: Path) -> None:
    source = tmp_path / "sample.exe"
    _write_pe(source)
    with pytest.raises(XvlkcError) as excinfo:
        run_xvlkc(
            tmp_path / "absent",
            source,
            tmp_path / "out.exe",
            input_sha256=file_sha256(source),
        )
    assert excinfo.value.code == XvlkcErrorCode.EXECUTABLE_NOT_FOUND


def test_run_refuses_a_non_file_input(tmp_path: Path) -> None:
    exe = _script(tmp_path / "xvlkc.sh", "exit 0\n")
    a_dir = tmp_path / "input_dir"
    a_dir.mkdir()
    with pytest.raises(XvlkcError) as excinfo:
        run_xvlkc(exe, a_dir, tmp_path / "out.exe", input_sha256="x")
    assert excinfo.value.code == XvlkcErrorCode.INPUT_NOT_FOUND


def test_run_refuses_oversized_input(tmp_path: Path) -> None:
    source = tmp_path / "sample.exe"
    _write_pe(source)
    exe = _script(tmp_path / "xvlkc.sh", "exit 0\n")
    with pytest.raises(XvlkcError) as excinfo:
        run_xvlkc(
            exe,
            source,
            tmp_path / "out.exe",
            input_sha256=file_sha256(source),
            max_file_size=1,
        )
    assert excinfo.value.code == XvlkcErrorCode.INPUT_TOO_LARGE


def test_run_refuses_an_existing_destination(tmp_path: Path) -> None:
    source = tmp_path / "sample.exe"
    _write_pe(source)
    exe = _script(tmp_path / "xvlkc.sh", "exit 0\n")
    destination = tmp_path / "out.exe"
    destination.write_bytes(b"already here")
    with pytest.raises(XvlkcError) as excinfo:
        run_xvlkc(exe, source, destination, input_sha256=file_sha256(source))
    assert excinfo.value.code == XvlkcErrorCode.INVALID_ARGUMENT


def test_run_refuses_a_destination_that_resolves_to_the_input(tmp_path: Path) -> None:
    source = tmp_path / "sample.exe"
    _write_pe(source)
    exe = _script(tmp_path / "xvlkc.sh", "exit 0\n")
    # missing-dir does not exist, so exists() is False, but resolve() collapses
    # the '..' lexically back onto the source path.
    destination = tmp_path / "missing-dir" / ".." / "sample.exe"
    with pytest.raises(XvlkcError) as excinfo:
        run_xvlkc(exe, source, destination, input_sha256=file_sha256(source))
    assert excinfo.value.code == XvlkcErrorCode.INVALID_ARGUMENT


def test_run_refuses_a_changed_input_sha_up_front(tmp_path: Path) -> None:
    source = tmp_path / "sample.exe"
    _write_pe(source)
    exe = _script(tmp_path / "xvlkc.sh", "exit 0\n")
    with pytest.raises(XvlkcError) as excinfo:
        run_xvlkc(exe, source, tmp_path / "out.exe", input_sha256="deadbeef")
    assert excinfo.value.code == XvlkcErrorCode.INPUT_MUTATED


def test_run_maps_a_nonzero_exit_and_cleans_up_a_partial(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "sample.exe"
    _write_pe(source)
    exe = _script(tmp_path / "xvlkc.sh", "exit 0\n")
    destination = tmp_path / "out" / "unpacked.exe"

    def fake_capture(argv: list[str], **_kwargs: Any) -> Any:
        del argv
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(b"partial")
        return SimpleNamespace(
            stdout="boom",
            stderr="",
            returncode=3,
            stdout_exceeded=False,
            stderr_exceeded=False,
        )

    monkeypatch.setattr(xv, "_capture_process", fake_capture)
    with pytest.raises(XvlkcError) as excinfo:
        run_xvlkc(exe, source, destination, input_sha256=file_sha256(source))
    assert excinfo.value.code == XvlkcErrorCode.PROCESS_FAILED
    assert destination.is_file() is False


def test_run_reports_an_output_size_overrun(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "sample.exe"
    _write_pe(source)
    exe = _script(tmp_path / "xvlkc.sh", "exit 0\n")

    def fake_capture(argv: list[str], **_kwargs: Any) -> Any:
        del argv
        return SimpleNamespace(
            stdout="x",
            stderr="",
            returncode=0,
            stdout_exceeded=True,
            stderr_exceeded=False,
        )

    monkeypatch.setattr(xv, "_capture_process", fake_capture)
    with pytest.raises(XvlkcError) as excinfo:
        run_xvlkc(exe, source, tmp_path / "out.exe", input_sha256=file_sha256(source))
    assert excinfo.value.code == XvlkcErrorCode.OUTPUT_LIMIT


def test_run_detects_input_mutation_during_the_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "sample.exe"
    _write_pe(source)
    exe = _script(tmp_path / "xvlkc.sh", "exit 0\n")

    def fake_capture(argv: list[str], **_kwargs: Any) -> Any:
        del argv
        source.write_bytes(b"mutated after start")
        return SimpleNamespace(
            stdout="",
            stderr="",
            returncode=0,
            stdout_exceeded=False,
            stderr_exceeded=False,
        )

    monkeypatch.setattr(xv, "_capture_process", fake_capture)
    with pytest.raises(XvlkcError) as excinfo:
        run_xvlkc(exe, source, tmp_path / "out.exe", input_sha256=file_sha256(source))
    assert excinfo.value.code == XvlkcErrorCode.INPUT_MUTATED


def test_run_wraps_a_process_failure_from_the_capture(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "sample.exe"
    _write_pe(source)
    exe = _script(tmp_path / "xvlkc.sh", "exit 0\n")

    class _Boom(RuntimeError):
        code = "custom_code"
        details = {"k": "v"}
        stdout = "out"
        stderr = "err"
        returncode = 9
        retryable = True

    def fake_capture(argv: list[str], **_kwargs: Any) -> Any:
        del argv
        raise _Boom("capture fell over")

    monkeypatch.setattr(xv, "_capture_process", fake_capture)
    with pytest.raises(XvlkcError) as excinfo:
        run_xvlkc(exe, source, tmp_path / "out.exe", input_sha256=file_sha256(source))
    assert excinfo.value.code == "custom_code"
    assert excinfo.value.returncode == 9


def test_run_lets_a_cancellation_propagate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "sample.exe"
    _write_pe(source)
    exe = _script(tmp_path / "xvlkc.sh", "exit 0\n")

    def fake_capture(argv: list[str], **_kwargs: Any) -> Any:
        del argv
        raise BoundedCancelled()

    monkeypatch.setattr(xv, "_capture_process", fake_capture)
    with pytest.raises(BoundedCancelled):
        run_xvlkc(exe, source, tmp_path / "out.exe", input_sha256=file_sha256(source))


def test_result_to_dict_names_the_source_and_universal_flag() -> None:
    result = XvlkcResult(
        executable="xvlkc",
        input_path="in.exe",
        output_path="out.exe",
        input_sha256="a",
        output_sha256="b",
        returncode=0,
        stdout="ok",
        stderr="",
        duration_ms=12,
    )
    payload = result.to_dict()
    assert payload["source"] == "xvlkc"
    assert payload["claims_universal_unpack"] is False
    assert payload["duration_ms"] == 12


# --- probe_xvlkc --------------------------------------------------------------


def test_probe_reports_absent_for_a_missing_executable(tmp_path: Path) -> None:
    ok, text = probe_xvlkc(tmp_path / "nope")
    assert ok is False
    assert text == ""


def test_probe_reports_absent_for_an_unrunnable_file(tmp_path: Path) -> None:
    not_exec = tmp_path / "plain"
    not_exec.write_text("not executable", encoding="utf-8")
    ok, text = probe_xvlkc(not_exec)
    assert ok is False
    assert text == ""


def test_probe_recognises_a_usage_banner(tmp_path: Path) -> None:
    exe = _script(tmp_path / "xvlkc.sh", 'echo "Usage: xvlkc <input>"\nexit 1\n')
    ok, text = probe_xvlkc(exe)
    assert ok is True
    assert "Usage" in text


def test_probe_accepts_benign_return_codes_with_output(tmp_path: Path) -> None:
    exe = _script(tmp_path / "xvlkc.sh", 'echo "hello world"\nexit 0\n')
    ok, text = probe_xvlkc(exe)
    assert ok is True
    assert "hello world" in text


def test_probe_reports_absent_when_silent_and_failing(tmp_path: Path) -> None:
    exe = _script(tmp_path / "xvlkc.sh", "exit 2\n")
    ok, text = probe_xvlkc(exe)
    assert ok is False
    assert text == ""
