"""Edge coverage for the Scylla PE helpers and run guards.

``test_scylla_rebuild_integrity.py`` and ``test_scylla_closed_session.py`` drive
the end-to-end rebuild against a fake Scylla. These pin the pure helpers and the
run() guards the wider suite does not reach: ``_is_pe_file`` reading a header,
``_collect_newest_pe`` skipping non-candidates and refusing an empty or
ambiguous result, the output-equals-input guard, cancellation propagation, and
the cleanup that unlinks a published output when the run fails afterwards.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

import headless_re_mcp.unpack.scylla as scylla
from headless_re_mcp.backends.common.bounded_run import BoundedCancelled, TimedOut
from headless_re_mcp.core.session import file_sha256
from headless_re_mcp.dotnet.de4dot import _ProcessCapture
from headless_re_mcp.unpack.scylla import (
    ScyllaError,
    ScyllaErrorCode,
    ScyllaResult,
    _collect_newest_pe,
    _is_pe_file,
    probe_scylla,
    run_scylla,
)


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


# --------------------------------------------------------------------------- #
# _is_pe_file                                                                 #
# --------------------------------------------------------------------------- #
def test_is_pe_file_accepts_a_well_formed_pe(tmp_path: Path) -> None:
    assert _is_pe_file(_write_pe(tmp_path / "ok.exe")) is True


def test_is_pe_file_rejects_a_path_it_cannot_open(tmp_path: Path) -> None:
    # A directory opens as a directory, not a file: the read raises OSError and
    # the probe must answer False rather than propagate.
    assert _is_pe_file(tmp_path) is False


def test_is_pe_file_rejects_a_short_or_non_mz_header(tmp_path: Path) -> None:
    short = tmp_path / "short.bin"
    short.write_bytes(b"MZ")
    assert _is_pe_file(short) is False

    not_mz = tmp_path / "not_mz.bin"
    not_mz.write_bytes(b"ZM" + b"\0" * 0x40)
    assert _is_pe_file(not_mz) is False


def test_is_pe_file_rejects_a_pe_offset_inside_the_dos_header(tmp_path: Path) -> None:
    bad = tmp_path / "bad_offset.bin"
    header = bytearray(0x40)
    header[0:2] = b"MZ"
    header[0x3C:0x40] = (0x10).to_bytes(4, "little")  # points back into the DOS header
    bad.write_bytes(bytes(header))
    assert _is_pe_file(bad) is False


def test_is_pe_file_rejects_a_missing_pe_signature(tmp_path: Path) -> None:
    off = tmp_path / "no_sig.bin"
    body = bytearray(0x44)
    body[0:2] = b"MZ"
    body[0x3C:0x40] = (0x40).to_bytes(4, "little")
    body[0x40:0x44] = b"junk"  # right place, wrong signature
    off.write_bytes(bytes(body))
    assert _is_pe_file(off) is False


# --------------------------------------------------------------------------- #
# _collect_newest_pe                                                          #
# --------------------------------------------------------------------------- #
def test_collect_newest_pe_skips_dirs_the_input_and_non_pe_files(tmp_path: Path) -> None:
    work = tmp_path / "work"
    work.mkdir()
    (work / "subdir").mkdir()  # a directory rglob yields but is not a file
    work_input = _write_pe(work / "input.exe")  # the work copy itself is skipped
    (work / "notes.txt").write_bytes(b"plain text, not a PE")  # skipped as non-PE
    produced = _write_pe(work / "dumped.exe")

    assert _collect_newest_pe(work, work_input) == produced


def test_collect_newest_pe_raises_when_nothing_was_produced(tmp_path: Path) -> None:
    work = tmp_path / "work"
    work.mkdir()
    work_input = _write_pe(work / "input.exe")
    (work / "log.txt").write_bytes(b"only the log survived")

    with pytest.raises(ScyllaError) as excinfo:
        _collect_newest_pe(work, work_input)
    assert excinfo.value.code == ScyllaErrorCode.OUTPUT_MISSING


def test_collect_newest_pe_refuses_two_outputs_with_the_same_newest_mtime(
    tmp_path: Path,
) -> None:
    work = tmp_path / "work"
    work.mkdir()
    work_input = _write_pe(work / "input.exe")
    first = _write_pe(work / "a.exe")
    second = _write_pe(work / "b.exe")
    shared = 1_700_000_000.0
    os.utime(first, (shared, shared))
    os.utime(second, (shared, shared))

    with pytest.raises(ScyllaError) as excinfo:
        _collect_newest_pe(work, work_input)
    assert excinfo.value.code == ScyllaErrorCode.OUTPUT_AMBIGUOUS


# --------------------------------------------------------------------------- #
# run_scylla guards                                                           #
# --------------------------------------------------------------------------- #
def test_run_scylla_refuses_output_that_resolves_to_the_input(tmp_path: Path) -> None:
    exe = tmp_path / "scylla.exe"
    exe.write_bytes(b"MZ")
    source = _write_pe(tmp_path / "input.exe")
    # A different-looking path that normalizes back onto the input. Both guards
    # refuse the same danger -- an output that aliases the input -- but which
    # fires is platform-dependent: POSIX Path.exists() does not resolve a ".."
    # through the missing "nope" directory, so the path reads as not-yet-existing
    # and execution reaches the "must differ" guard; Windows collapses the ".."
    # lexically onto the existing input, so the earlier "must not already exist"
    # guard fires first. Since source must exist to get here, "must differ" is
    # unreachable on Windows, so accept either refusal.
    output = tmp_path / "nope" / ".." / "input.exe"

    with pytest.raises(ScyllaError) as excinfo:
        run_scylla(exe, source, output, input_sha256=file_sha256(source))
    assert excinfo.value.code == ScyllaErrorCode.INVALID_ARGUMENT
    message = str(excinfo.value)
    assert "differ" in message or "must not already exist" in message


def test_run_scylla_propagates_a_cancellation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exe = tmp_path / "scylla.exe"
    exe.write_bytes(b"MZ")
    source = _write_pe(tmp_path / "input.exe")
    output = tmp_path / "out" / "rebuilt.exe"

    def _cancel(*args: object, **kwargs: object) -> _ProcessCapture:
        raise BoundedCancelled([4321])

    monkeypatch.setattr(scylla, "_capture_process", _cancel)

    # Cancellation is not a Scylla failure: it must surface unwrapped so the
    # caller's cancel path is not disguised as a process error.
    with pytest.raises(BoundedCancelled):
        run_scylla(exe, source, output, input_sha256=file_sha256(source))


def test_run_scylla_unlinks_a_published_output_when_the_run_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exe = tmp_path / "scylla.exe"
    exe.write_bytes(b"MZ")
    source = _write_pe(tmp_path / "input.exe")
    output = tmp_path / "out" / "rebuilt.exe"

    def _write_output_then_fail(*args: object, **kwargs: object) -> _ProcessCapture:
        # A hostile/buggy Scylla writes straight to the output path and then
        # exits nonzero; the failure cleanup must not leave that file behind.
        output.write_bytes(_pe_bytes())
        return _ProcessCapture(
            stdout="",
            stderr="boom",
            returncode=1,
            stdout_exceeded=False,
            stderr_exceeded=False,
        )

    monkeypatch.setattr(scylla, "_capture_process", _write_output_then_fail)

    with pytest.raises(ScyllaError) as excinfo:
        run_scylla(exe, source, output, input_sha256=file_sha256(source))
    assert excinfo.value.code == ScyllaErrorCode.PROCESS_FAILED
    assert not output.exists(), "a failed run must not leave a published output behind"


def test_run_scylla_publishes_the_newest_output_and_serializes_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exe = tmp_path / "scylla.exe"
    exe.write_bytes(b"MZ")
    source = _write_pe(tmp_path / "input.exe")
    output = tmp_path / "out" / "rebuilt.exe"

    def _produce_pe(argv: list[str], **kwargs: object) -> _ProcessCapture:
        # argv[1] is the work copy inside the run's TemporaryDirectory; write a
        # fresh PE beside it so _collect_newest_pe has exactly one candidate.
        work_dir = Path(argv[1]).parent
        (work_dir / "dumped.exe").write_bytes(_pe_bytes())
        return _ProcessCapture(
            stdout="done",
            stderr="",
            returncode=0,
            stdout_exceeded=False,
            stderr_exceeded=False,
        )

    monkeypatch.setattr(scylla, "_capture_process", _produce_pe)

    result = run_scylla(exe, source, output, input_sha256=file_sha256(source))
    assert isinstance(result, ScyllaResult)
    assert output.is_file()

    payload = result.to_dict()
    assert payload["output_sha256"] == file_sha256(output)
    assert payload["returncode"] == 0
    assert payload["input_sha256"] == file_sha256(source)
    assert payload["source"] == scylla.SCYLLA_SOURCE


def test_probe_scylla_reports_unavailable_when_the_process_will_not_start(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exe = tmp_path / "scylla.exe"
    exe.write_bytes(b"MZ")

    def _refuse(*args: object, **kwargs: object) -> object:
        raise OSError("exec format error")

    monkeypatch.setattr(scylla, "run_bounded", _refuse)

    available, detail = probe_scylla(exe)
    assert available is False
    assert detail == ""


def test_probe_scylla_reports_a_gui_build_that_never_exits(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exe = tmp_path / "scylla.exe"
    exe.write_bytes(b"MZ")

    def _hang(*args: object, **kwargs: object) -> object:
        raise TimedOut(5.0, [])

    monkeypatch.setattr(scylla, "run_bounded", _hang)

    # A timeout means the process started but never returned (typical of a GUI
    # Scylla); the probe distinguishes that from a build that cannot launch.
    available, detail = probe_scylla(exe)
    assert available is False
    assert detail == "timeout_after_start"
