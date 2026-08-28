"""Fail-closed coverage for the Scylla rebuild adapter's own logic.

The service-level tests pin session lifecycle, and ``test_unpack_probes`` pins
the one probe timeout case. What is left untested is the part of ``scylla.py``
that decides whether a run may be called a success: the PE sniff, the
newest-output disambiguation, and the guard rails in ``run_scylla`` that refuse
to publish an output when the input was mutated, the tool failed, or the dump
is missing or ambiguous.

Everything here is platform-independent: the child process is faked by
substituting ``_capture_process`` (Scylla's launcher, imported from de4dot)
and ``run_bounded`` (the probe launcher), so no real Scylla binary is needed.
"""

from __future__ import annotations

import os
import struct
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.core.session import file_sha256
from headless_re_mcp.dotnet.de4dot import _ProcessCapture
from headless_re_mcp.unpack import scylla
from headless_re_mcp.unpack.scylla import ScyllaError, ScyllaErrorCode, run_scylla


def _min_pe() -> bytes:
    """Smallest byte string ``_is_pe_file`` accepts: MZ, e_lfanew, PE\\0\\0."""
    buf = bytearray(0x48)
    buf[:2] = b"MZ"
    struct.pack_into("<I", buf, 0x3C, 0x40)
    buf[0x40:0x44] = b"PE\x00\x00"
    return bytes(buf)


# --------------------------------------------------------------------------- #
# _is_pe_file                                                                 #
# --------------------------------------------------------------------------- #
def test_is_pe_file_accepts_a_well_formed_header(tmp_path: Path) -> None:
    pe = tmp_path / "ok.bin"
    pe.write_bytes(_min_pe())
    assert scylla._is_pe_file(pe) is True


def test_is_pe_file_rejects_a_non_mz_file(tmp_path: Path) -> None:
    plain = tmp_path / "plain.bin"
    plain.write_bytes(b"not a pe file at all" * 8)
    assert scylla._is_pe_file(plain) is False


def test_is_pe_file_rejects_an_e_lfanew_pointing_into_the_dos_header(tmp_path: Path) -> None:
    buf = bytearray(_min_pe())
    struct.pack_into("<I", buf, 0x3C, 0x10)  # inside the DOS header, below 0x40
    bad = tmp_path / "bad_offset.bin"
    bad.write_bytes(bytes(buf))
    assert scylla._is_pe_file(bad) is False


def test_is_pe_file_rejects_a_missing_pe_signature(tmp_path: Path) -> None:
    buf = bytearray(_min_pe())
    buf[0x40:0x44] = b"ZZ\x00\x00"
    bad = tmp_path / "no_sig.bin"
    bad.write_bytes(bytes(buf))
    assert scylla._is_pe_file(bad) is False


def test_is_pe_file_rejects_a_truncated_header(tmp_path: Path) -> None:
    short = tmp_path / "short.bin"
    short.write_bytes(b"MZ")
    assert scylla._is_pe_file(short) is False


# --------------------------------------------------------------------------- #
# _collect_newest_pe                                                          #
# --------------------------------------------------------------------------- #
def test_collect_newest_pe_returns_the_newest_and_skips_the_work_copy(
    tmp_path: Path,
) -> None:
    work_dir = tmp_path / "work"
    work_dir.mkdir()
    work_input = work_dir / "sample.exe"
    work_input.write_bytes(_min_pe())
    older = work_dir / "older.exe"
    older.write_bytes(_min_pe())
    newer = work_dir / "dump.exe"
    newer.write_bytes(_min_pe())
    os.utime(older, (1_000, 1_000))
    os.utime(newer, (2_000, 2_000))
    os.utime(work_input, (3_000, 3_000))  # newest, but must be excluded

    produced = scylla._collect_newest_pe(work_dir, work_input)
    assert produced == newer


def test_collect_newest_pe_raises_when_no_pe_is_beside_the_work_copy(
    tmp_path: Path,
) -> None:
    work_dir = tmp_path / "work"
    work_dir.mkdir()
    work_input = work_dir / "sample.exe"
    work_input.write_bytes(_min_pe())
    (work_dir / "notes.txt").write_bytes(b"just text")

    with pytest.raises(ScyllaError) as excinfo:
        scylla._collect_newest_pe(work_dir, work_input)
    assert excinfo.value.code == ScyllaErrorCode.OUTPUT_MISSING


def test_collect_newest_pe_refuses_a_tie_for_the_newest_mtime(tmp_path: Path) -> None:
    work_dir = tmp_path / "work"
    work_dir.mkdir()
    work_input = work_dir / "sample.exe"
    work_input.write_bytes(_min_pe())
    first = work_dir / "a.exe"
    second = work_dir / "b.exe"
    first.write_bytes(_min_pe())
    second.write_bytes(_min_pe())
    os.utime(first, (5_000, 5_000))
    os.utime(second, (5_000, 5_000))

    with pytest.raises(ScyllaError) as excinfo:
        scylla._collect_newest_pe(work_dir, work_input)
    assert excinfo.value.code == ScyllaErrorCode.OUTPUT_AMBIGUOUS


# --------------------------------------------------------------------------- #
# run_scylla: validation before the child ever starts                         #
# --------------------------------------------------------------------------- #
def test_run_scylla_refuses_a_missing_executable(tmp_path: Path) -> None:
    src = tmp_path / "in.exe"
    src.write_bytes(_min_pe())
    with pytest.raises(ScyllaError) as excinfo:
        run_scylla(
            tmp_path / "no-such-scylla.exe",
            src,
            tmp_path / "out.exe",
            input_sha256=file_sha256(src),
        )
    assert excinfo.value.code == ScyllaErrorCode.EXECUTABLE_NOT_FOUND


def test_run_scylla_refuses_an_input_that_is_not_a_regular_file(tmp_path: Path) -> None:
    exe = tmp_path / "scylla.exe"
    exe.write_bytes(b"fake")
    a_directory = tmp_path / "adir"
    a_directory.mkdir()
    with pytest.raises(ScyllaError) as excinfo:
        run_scylla(exe, a_directory, tmp_path / "out.exe", input_sha256="0" * 64)
    assert excinfo.value.code == ScyllaErrorCode.INPUT_NOT_FOUND


def test_run_scylla_refuses_an_oversize_input(tmp_path: Path) -> None:
    exe = tmp_path / "scylla.exe"
    exe.write_bytes(b"fake")
    src = tmp_path / "big.exe"
    src.write_bytes(_min_pe())
    with pytest.raises(ScyllaError) as excinfo:
        run_scylla(
            exe,
            src,
            tmp_path / "out.exe",
            input_sha256=file_sha256(src),
            max_file_size=8,
        )
    assert excinfo.value.code == ScyllaErrorCode.INPUT_TOO_LARGE


def test_run_scylla_refuses_a_preexisting_output(tmp_path: Path) -> None:
    exe = tmp_path / "scylla.exe"
    exe.write_bytes(b"fake")
    src = tmp_path / "in.exe"
    src.write_bytes(_min_pe())
    out = tmp_path / "out.exe"
    out.write_bytes(b"stale")
    with pytest.raises(ScyllaError) as excinfo:
        run_scylla(exe, src, out, input_sha256=file_sha256(src))
    assert excinfo.value.code == ScyllaErrorCode.INVALID_ARGUMENT


def test_run_scylla_detects_an_input_changed_before_the_run(tmp_path: Path) -> None:
    exe = tmp_path / "scylla.exe"
    exe.write_bytes(b"fake")
    src = tmp_path / "in.exe"
    src.write_bytes(_min_pe())
    with pytest.raises(ScyllaError) as excinfo:
        run_scylla(exe, src, tmp_path / "out.exe", input_sha256="f" * 64)
    assert excinfo.value.code == ScyllaErrorCode.INPUT_MUTATED
    assert "before" in str(excinfo.value)


# --------------------------------------------------------------------------- #
# run_scylla: outcomes once the (faked) child has run                         #
# --------------------------------------------------------------------------- #
def _prep(tmp_path: Path) -> tuple[Path, Path, Path, str]:
    exe = tmp_path / "scylla.exe"
    exe.write_bytes(b"fake")
    src = tmp_path / "in.exe"
    src.write_bytes(_min_pe())
    out = tmp_path / "dumps" / "rebuilt.exe"
    return exe, src, out, file_sha256(src)


def _ok_capture() -> _ProcessCapture:
    return _ProcessCapture(
        stdout="done", stderr="", returncode=0, stdout_exceeded=False, stderr_exceeded=False
    )


def test_run_scylla_publishes_the_newest_pe_on_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exe, src, out, sha = _prep(tmp_path)
    dumped = _min_pe() + b"UNPACKED"

    def _fake_capture(argv: list[str], *, timeout: float, max_output_size: int) -> _ProcessCapture:
        del timeout, max_output_size
        work_input = Path(argv[1])
        (work_input.parent / "scylla_dump.exe").write_bytes(dumped)
        return _ok_capture()

    monkeypatch.setattr(scylla, "_capture_process", _fake_capture)
    result = run_scylla(exe, src, out, input_sha256=sha)
    assert result.returncode == 0
    assert Path(result.output_path) == out.resolve()
    assert out.read_bytes() == dumped
    assert result.output_sha256 == file_sha256(out)
    # The original input is left byte-for-byte intact.
    assert file_sha256(src) == sha


def test_run_scylla_reports_output_missing_and_removes_a_stub_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exe, src, out, sha = _prep(tmp_path)

    def _fake_capture(argv: list[str], *, timeout: float, max_output_size: int) -> _ProcessCapture:
        del argv, timeout, max_output_size
        return _ok_capture()  # writes no PE beside the work copy

    monkeypatch.setattr(scylla, "_capture_process", _fake_capture)
    with pytest.raises(ScyllaError) as excinfo:
        run_scylla(exe, src, out, input_sha256=sha)
    assert excinfo.value.code == ScyllaErrorCode.OUTPUT_MISSING
    assert not out.exists()


def test_run_scylla_detects_an_input_mutated_during_the_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exe, src, out, sha = _prep(tmp_path)

    def _fake_capture(argv: list[str], *, timeout: float, max_output_size: int) -> _ProcessCapture:
        del argv, timeout, max_output_size
        src.write_bytes(_min_pe() + b"TAMPERED")
        return _ok_capture()

    monkeypatch.setattr(scylla, "_capture_process", _fake_capture)
    with pytest.raises(ScyllaError) as excinfo:
        run_scylla(exe, src, out, input_sha256=sha)
    assert excinfo.value.code == ScyllaErrorCode.INPUT_MUTATED


def test_run_scylla_reports_a_stdout_that_blew_the_bound(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exe, src, out, sha = _prep(tmp_path)

    def _fake_capture(argv: list[str], *, timeout: float, max_output_size: int) -> _ProcessCapture:
        del argv, timeout, max_output_size
        return _ProcessCapture(
            stdout="x", stderr="", returncode=0, stdout_exceeded=True, stderr_exceeded=False
        )

    monkeypatch.setattr(scylla, "_capture_process", _fake_capture)
    with pytest.raises(ScyllaError) as excinfo:
        run_scylla(exe, src, out, input_sha256=sha)
    assert excinfo.value.code == ScyllaErrorCode.OUTPUT_LIMIT


def test_run_scylla_reports_a_nonzero_exit_as_retryable_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exe, src, out, sha = _prep(tmp_path)

    def _fake_capture(argv: list[str], *, timeout: float, max_output_size: int) -> _ProcessCapture:
        del argv, timeout, max_output_size
        return _ProcessCapture(
            stdout="", stderr="crash", returncode=3, stdout_exceeded=False, stderr_exceeded=False
        )

    monkeypatch.setattr(scylla, "_capture_process", _fake_capture)
    with pytest.raises(ScyllaError) as excinfo:
        run_scylla(exe, src, out, input_sha256=sha)
    assert excinfo.value.code == ScyllaErrorCode.PROCESS_FAILED
    assert excinfo.value.returncode == 3
    assert excinfo.value.retryable is True


def test_run_scylla_maps_a_launcher_exception_to_its_code(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exe, src, out, sha = _prep(tmp_path)

    class _LauncherError(RuntimeError):
        code = ScyllaErrorCode.TIMEOUT
        stdout = "partial"
        stderr = "boom"
        returncode = None
        details = {"phase": "spawn"}
        retryable = True

    def _fake_capture(argv: list[str], *, timeout: float, max_output_size: int) -> _ProcessCapture:
        del argv, timeout, max_output_size
        raise _LauncherError("launch failed")

    monkeypatch.setattr(scylla, "_capture_process", _fake_capture)
    with pytest.raises(ScyllaError) as excinfo:
        run_scylla(exe, src, out, input_sha256=sha)
    assert excinfo.value.code == ScyllaErrorCode.TIMEOUT
    assert excinfo.value.stdout == "partial"
    assert excinfo.value.details == {"phase": "spawn"}


# --------------------------------------------------------------------------- #
# probe_scylla: readiness classification (non-timeout paths)                  #
# --------------------------------------------------------------------------- #
class _Completed:
    def __init__(self, *, stdout: bytes, stderr: bytes, returncode: int) -> None:
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode


def test_probe_missing_executable_is_not_ready(tmp_path: Path) -> None:
    ok, text = scylla.probe_scylla(tmp_path / "absent.exe")
    assert ok is False
    assert text == ""


def test_probe_recognises_a_scylla_banner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exe = tmp_path / "scylla.exe"
    exe.write_bytes(b"fake")

    def _fake_run(argv: Any, *, timeout: float, creationflags: int = 0) -> _Completed:
        del argv, timeout, creationflags
        return _Completed(stdout=b"Scylla IAT rebuild usage", stderr=b"", returncode=0)

    monkeypatch.setattr(scylla, "run_bounded", _fake_run)
    ok, text = scylla.probe_scylla(exe)
    assert ok is True
    assert "Scylla" in text


def test_probe_treats_a_clean_exit_without_output_as_started(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exe = tmp_path / "scylla.exe"
    exe.write_bytes(b"fake")

    def _fake_run(argv: Any, *, timeout: float, creationflags: int = 0) -> _Completed:
        del argv, timeout, creationflags
        return _Completed(stdout=b"", stderr=b"", returncode=1)

    monkeypatch.setattr(scylla, "run_bounded", _fake_run)
    ok, text = scylla.probe_scylla(exe)
    assert ok is True
    assert text == "started"


def test_probe_treats_an_unknown_exit_with_no_output_as_not_ready(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exe = tmp_path / "scylla.exe"
    exe.write_bytes(b"fake")

    def _fake_run(argv: Any, *, timeout: float, creationflags: int = 0) -> _Completed:
        del argv, timeout, creationflags
        return _Completed(stdout=b"", stderr=b"", returncode=42)

    monkeypatch.setattr(scylla, "run_bounded", _fake_run)
    ok, text = scylla.probe_scylla(exe)
    assert ok is False
    assert text == ""


def test_probe_reports_not_ready_when_the_launcher_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exe = tmp_path / "scylla.exe"
    exe.write_bytes(b"fake")

    def _fake_run(argv: Any, *, timeout: float, creationflags: int = 0) -> _Completed:
        del argv, timeout, creationflags
        raise OSError("cannot exec")

    monkeypatch.setattr(scylla, "run_bounded", _fake_run)
    ok, text = scylla.probe_scylla(exe)
    assert ok is False
    assert text == ""
