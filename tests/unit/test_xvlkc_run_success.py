"""Success path and post-run guards for ``run_xvlkc``.

The sibling ``test_xvlkc_closed_session`` file only covers the service-level
refusal on a closed session. ``run_xvlkc`` itself -- the bounded adapter that
copies the input, runs the CLI, and publishes the newest emitted PE -- is
otherwise untested, so its honesty-critical block runs at ~30%: the
input-mutated guards, the output-limit and non-zero-exit handling, and above all
``_collect_newest_pe`` (which must pick the single newest PE beside the work
copy and fail closed when the output is missing or ambiguous).

Each stand-in receives the whitelisted argv (``[exe, work_copy]``) and stands in
for the real CLI by writing whatever PE outputs the scenario needs into the work
directory, then returning a ``_ProcessCapture``. ``_collect_newest_pe`` only
accepts real PE files, so the stand-ins emit a minimal but valid PE image; no
real XVLKC binary is required and the whole surface runs on any platform.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.common.bounded_run import BoundedCancelled
from headless_re_mcp.core.session import file_sha256
from headless_re_mcp.dotnet.de4dot import _ProcessCapture
from headless_re_mcp.unpack import xvlkc as xvlkc_mod
from headless_re_mcp.unpack.xvlkc import (
    XvlkcError,
    XvlkcErrorCode,
    XvlkcResult,
    run_xvlkc,
)


def _write_min_pe(path: Path, extra: bytes = b"") -> None:
    """Write the smallest image ``_is_pe_file`` accepts (MZ + PE\\0\\0 at 0x40)."""
    buf = bytearray(0x44)
    buf[0:2] = b"MZ"
    buf[0x3C:0x40] = (0x40).to_bytes(4, "little")
    buf[0x40:0x44] = b"PE\0\0"
    path.write_bytes(bytes(buf) + extra)


def _capture(
    *,
    returncode: int = 0,
    stdout: str = "done",
    stderr: str = "",
    stdout_exceeded: bool = False,
    stderr_exceeded: bool = False,
) -> _ProcessCapture:
    return _ProcessCapture(
        stdout=stdout,
        stderr=stderr,
        returncode=returncode,
        stdout_exceeded=stdout_exceeded,
        stderr_exceeded=stderr_exceeded,
    )


def _prepare(tmp_path: Path) -> tuple[Path, Path, Path, str]:
    exe = tmp_path / "xvlkc.exe"
    exe.write_bytes(b"placeholder")
    source = tmp_path / "packed.exe"
    source.write_bytes(b"packed-input-bytes")
    destination = tmp_path / "out" / "unpacked.exe"
    return exe, source, destination, file_sha256(source)


def _install(monkeypatch: Any, writer: Callable[[Path], _ProcessCapture]) -> None:
    """Route ``_capture_process`` to ``writer(work_copy) -> _ProcessCapture``."""

    def fake(argv: list[str], **_: Any) -> _ProcessCapture:
        work_copy = Path(argv[1])
        return writer(work_copy)

    monkeypatch.setattr(xvlkc_mod, "_capture_process", fake)


def test_run_publishes_the_only_pe_output(tmp_path: Path, monkeypatch: Any) -> None:
    exe, source, destination, sha = _prepare(tmp_path)

    def writer(work_copy: Path) -> _ProcessCapture:
        _write_min_pe(work_copy.with_name("dumped.exe"), extra=b"unpacked-payload")
        return _capture()

    _install(monkeypatch, writer)
    result = run_xvlkc(exe, source, destination, input_sha256=sha)

    assert isinstance(result, XvlkcResult)
    assert destination.is_file()
    assert destination.read_bytes().endswith(b"unpacked-payload")
    assert result.returncode == 0
    assert result.input_sha256 == sha
    assert result.output_sha256 == file_sha256(destination)
    # The original session input must be untouched.
    assert file_sha256(source) == sha
    payload = result.to_dict()
    assert payload["source"] == "xvlkc"
    assert payload["claims_universal_unpack"] is False


def test_run_publishes_the_newest_pe_when_several_exist(tmp_path: Path, monkeypatch: Any) -> None:
    exe, source, destination, sha = _prepare(tmp_path)

    def writer(work_copy: Path) -> _ProcessCapture:
        older = work_copy.with_name("older.exe")
        newer = work_copy.with_name("newer.exe")
        _write_min_pe(older, extra=b"older-payload")
        _write_min_pe(newer, extra=b"newer-payload")
        # Deterministic ordering: distinct explicit mtimes, so the newest is
        # unambiguous rather than relying on filesystem timestamp resolution.
        os.utime(older, (1_000_000_000, 1_000_000_000))
        os.utime(newer, (2_000_000_000, 2_000_000_000))
        return _capture()

    _install(monkeypatch, writer)
    result = run_xvlkc(exe, source, destination, input_sha256=sha)

    assert destination.read_bytes().endswith(b"newer-payload")
    assert result.output_sha256 == file_sha256(destination)


def test_run_fails_closed_when_no_pe_output_appears(tmp_path: Path, monkeypatch: Any) -> None:
    exe, source, destination, sha = _prepare(tmp_path)

    def writer(work_copy: Path) -> _ProcessCapture:
        # A non-PE artifact must not be mistaken for the unpacked output.
        work_copy.with_name("notes.txt").write_bytes(b"not a pe file")
        return _capture()

    _install(monkeypatch, writer)

    with pytest.raises(XvlkcError) as excinfo:
        run_xvlkc(exe, source, destination, input_sha256=sha)

    assert excinfo.value.code == XvlkcErrorCode.OUTPUT_MISSING
    assert not destination.exists()


def test_run_rejects_a_malformed_mz_stub_as_output(tmp_path: Path, monkeypatch: Any) -> None:
    """An ``MZ`` file whose PE offset is bogus is not a PE and must be ignored."""
    exe, source, destination, sha = _prepare(tmp_path)

    def writer(work_copy: Path) -> _ProcessCapture:
        stub = bytearray(0x44)
        stub[0:2] = b"MZ"
        # e_lfanew below the DOS header floor: _is_pe_file must reject it.
        stub[0x3C:0x40] = (0x10).to_bytes(4, "little")
        work_copy.with_name("fake.exe").write_bytes(bytes(stub))
        return _capture()

    _install(monkeypatch, writer)

    with pytest.raises(XvlkcError) as excinfo:
        run_xvlkc(exe, source, destination, input_sha256=sha)

    assert excinfo.value.code == XvlkcErrorCode.OUTPUT_MISSING
    assert not destination.exists()


def test_run_fails_closed_when_pes_share_the_newest_mtime(tmp_path: Path, monkeypatch: Any) -> None:
    exe, source, destination, sha = _prepare(tmp_path)

    def writer(work_copy: Path) -> _ProcessCapture:
        first = work_copy.with_name("candidate_a.exe")
        second = work_copy.with_name("candidate_b.exe")
        _write_min_pe(first, extra=b"a")
        _write_min_pe(second, extra=b"b")
        # Same newest mtime on two PEs: the adapter cannot know which is the
        # real output and must refuse rather than guess.
        os.utime(first, (1_500_000_000, 1_500_000_000))
        os.utime(second, (1_500_000_000, 1_500_000_000))
        return _capture()

    _install(monkeypatch, writer)

    with pytest.raises(XvlkcError) as excinfo:
        run_xvlkc(exe, source, destination, input_sha256=sha)

    assert excinfo.value.code == XvlkcErrorCode.OUTPUT_AMBIGUOUS
    assert not destination.exists()


def test_run_reports_a_nonzero_exit_as_a_retryable_process_failure(
    tmp_path: Path, monkeypatch: Any
) -> None:
    exe, source, destination, sha = _prepare(tmp_path)

    def writer(work_copy: Path) -> _ProcessCapture:
        _write_min_pe(work_copy.with_name("dumped.exe"))
        return _capture(returncode=2, stderr="xvlkc failed")

    _install(monkeypatch, writer)

    with pytest.raises(XvlkcError) as excinfo:
        run_xvlkc(exe, source, destination, input_sha256=sha)

    assert excinfo.value.code == XvlkcErrorCode.PROCESS_FAILED
    assert excinfo.value.returncode == 2
    assert excinfo.value.retryable is True
    assert not destination.exists()


def test_run_reports_exceeded_output_as_output_limit(tmp_path: Path, monkeypatch: Any) -> None:
    exe, source, destination, sha = _prepare(tmp_path)

    def writer(work_copy: Path) -> _ProcessCapture:
        _write_min_pe(work_copy.with_name("dumped.exe"))
        return _capture(stderr_exceeded=True)

    _install(monkeypatch, writer)

    with pytest.raises(XvlkcError) as excinfo:
        run_xvlkc(exe, source, destination, input_sha256=sha)

    assert excinfo.value.code == XvlkcErrorCode.OUTPUT_LIMIT
    assert not destination.exists()


def test_run_detects_the_tool_mutating_the_original_input(tmp_path: Path, monkeypatch: Any) -> None:
    exe, source, destination, sha = _prepare(tmp_path)

    def writer(work_copy: Path) -> _ProcessCapture:
        # A tool that writes back to the original session input, not just the
        # isolated work copy, must be caught by the after-run hash re-check.
        source.write_bytes(b"packed-input-bytes-MUTATED")
        _write_min_pe(work_copy.with_name("dumped.exe"))
        return _capture()

    _install(monkeypatch, writer)

    with pytest.raises(XvlkcError) as excinfo:
        run_xvlkc(exe, source, destination, input_sha256=sha)

    assert excinfo.value.code == XvlkcErrorCode.INPUT_MUTATED
    assert not destination.exists()


def test_run_refuses_when_the_input_hash_changed_before_the_run(
    tmp_path: Path, monkeypatch: Any
) -> None:
    exe, source, destination, _sha = _prepare(tmp_path)

    def unreached(_work_copy: Path) -> _ProcessCapture:  # pragma: no cover
        raise AssertionError("capture must not run when the pre-hash mismatches")

    _install(monkeypatch, unreached)

    with pytest.raises(XvlkcError) as excinfo:
        run_xvlkc(exe, source, destination, input_sha256="0" * 64)

    assert excinfo.value.code == XvlkcErrorCode.INPUT_MUTATED


def test_run_propagates_a_caller_cancel(tmp_path: Path, monkeypatch: Any) -> None:
    """A caller cancel must surface as BoundedCancelled, not a tool failure.

    The scylla/vmp_dumper/net_reactor_slayer adapters re-raise BoundedCancelled
    before their generic remap; folding it into XvlkcError(process_failed) would
    report a cancel as a crash and diverge from every sibling adapter.
    """
    exe, source, destination, sha = _prepare(tmp_path)

    def cancel(_work_copy: Path) -> _ProcessCapture:
        raise BoundedCancelled()

    _install(monkeypatch, cancel)

    with pytest.raises(BoundedCancelled):
        run_xvlkc(exe, source, destination, input_sha256=sha)
    assert not destination.exists()


def test_run_remaps_a_generic_capture_failure(tmp_path: Path, monkeypatch: Any) -> None:
    exe, source, destination, sha = _prepare(tmp_path)

    def boom(_work_copy: Path) -> _ProcessCapture:
        raise RuntimeError("capture blew up")

    _install(monkeypatch, boom)

    with pytest.raises(XvlkcError) as excinfo:
        run_xvlkc(exe, source, destination, input_sha256=sha)

    assert excinfo.value.code == XvlkcErrorCode.PROCESS_FAILED
    assert not destination.exists()


def test_run_refuses_a_missing_executable(tmp_path: Path) -> None:
    _exe, source, destination, sha = _prepare(tmp_path)

    with pytest.raises(XvlkcError) as excinfo:
        run_xvlkc(tmp_path / "gone.exe", source, destination, input_sha256=sha)

    assert excinfo.value.code == XvlkcErrorCode.EXECUTABLE_NOT_FOUND


def test_run_refuses_an_input_that_is_not_a_regular_file(tmp_path: Path) -> None:
    exe, _source, destination, _sha = _prepare(tmp_path)
    a_directory = tmp_path / "a_dir"
    a_directory.mkdir()

    with pytest.raises(XvlkcError) as excinfo:
        run_xvlkc(exe, a_directory, destination, input_sha256="0" * 64)

    assert excinfo.value.code == XvlkcErrorCode.INPUT_NOT_FOUND


def test_run_refuses_an_input_over_the_size_cap(tmp_path: Path) -> None:
    exe, source, destination, sha = _prepare(tmp_path)

    with pytest.raises(XvlkcError) as excinfo:
        run_xvlkc(exe, source, destination, input_sha256=sha, max_file_size=1)

    assert excinfo.value.code == XvlkcErrorCode.INPUT_TOO_LARGE


def test_run_refuses_a_destination_that_already_exists(tmp_path: Path) -> None:
    exe, source, destination, sha = _prepare(tmp_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(b"pre-existing")

    with pytest.raises(XvlkcError) as excinfo:
        run_xvlkc(exe, source, destination, input_sha256=sha)

    assert excinfo.value.code == XvlkcErrorCode.INVALID_ARGUMENT
    assert destination.read_bytes() == b"pre-existing"


class _SecondOpenFails:
    """A path whose file vanishes between the header read and the PE-sig read."""

    def __init__(self, real: Path) -> None:
        self._real = real
        self._opens = 0

    def open(self, mode: str) -> Any:
        self._opens += 1
        if self._opens > 1:
            raise OSError("vanished mid-check")
        return self._real.open(mode)


def test_is_pe_file_reports_false_when_the_file_vanishes_mid_check(tmp_path: Path) -> None:
    real = tmp_path / "flaky.exe"
    _write_min_pe(real)

    assert xvlkc_mod._is_pe_file(_SecondOpenFails(real)) is False  # type: ignore[arg-type]


class _Entry:
    """A work-dir entry with injectable resolve/stat failures."""

    def __init__(
        self, real: Path, *, resolve_error: bool = False, stat_error: bool = False
    ) -> None:
        self._real = real
        self._resolve_error = resolve_error
        self._stat_error = stat_error

    def is_file(self) -> bool:
        return True

    def resolve(self) -> Path:
        if self._resolve_error:
            raise OSError("unresolvable")
        return self._real.resolve()

    def open(self, mode: str) -> Any:
        return self._real.open(mode)

    def stat(self) -> Any:
        if self._stat_error:
            raise OSError("no stat")
        return self._real.stat()

    def __str__(self) -> str:
        return str(self._real)


def test_collect_newest_pe_skips_directories_and_unreadable_entries(tmp_path: Path) -> None:
    """Entries that cannot be classified are skipped, not fatal, and not chosen."""
    work_input = tmp_path / "work-copy.exe"
    work_input.write_bytes(b"input")
    subdir = tmp_path / "extracted"
    subdir.mkdir()
    unresolvable = tmp_path / "unresolvable.exe"
    _write_min_pe(unresolvable)
    unstatable = tmp_path / "unstatable.exe"
    _write_min_pe(unstatable)
    good = tmp_path / "good.exe"
    _write_min_pe(good, extra=b"payload")
    entries: list[Any] = [
        subdir,
        _Entry(unresolvable, resolve_error=True),
        _Entry(unstatable, stat_error=True),
        good,
    ]
    from types import SimpleNamespace

    work_dir: Any = SimpleNamespace(rglob=lambda pattern: iter(entries))

    picked = xvlkc_mod._collect_newest_pe(work_dir, work_input)

    assert picked == good


def test_run_refuses_a_destination_that_resolves_to_the_input(tmp_path: Path) -> None:
    """A dest routed through a missing directory can still resolve onto the input."""
    exe, source, _destination, sha = _prepare(tmp_path)
    tricky = tmp_path / "missing-dir" / ".." / source.name

    with pytest.raises(XvlkcError) as excinfo:
        run_xvlkc(exe, source, tricky, input_sha256=sha)

    assert excinfo.value.code == XvlkcErrorCode.INVALID_ARGUMENT
    assert "must differ" in str(excinfo.value)


def test_run_removes_a_partial_destination_after_a_late_failure(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A tool that wrote to the final path before failing must not leave it behind."""
    exe, source, destination, sha = _prepare(tmp_path)

    def writer(work_copy: Path) -> _ProcessCapture:
        _write_min_pe(destination, extra=b"partial")
        return _capture(returncode=3, stderr="died late")

    _install(monkeypatch, writer)

    with pytest.raises(XvlkcError) as excinfo:
        run_xvlkc(exe, source, destination, input_sha256=sha)

    assert excinfo.value.code == XvlkcErrorCode.PROCESS_FAILED
    assert not destination.exists()


def test_probe_reports_absent_for_a_missing_executable(tmp_path: Path) -> None:
    ok, text = xvlkc_mod.probe_xvlkc(tmp_path / "nope.exe")
    assert ok is False
    assert text == ""


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission semantics")
def test_probe_reports_absent_for_an_unrunnable_executable(tmp_path: Path) -> None:
    exe = tmp_path / "not-executable.bin"
    exe.write_bytes(b"data, not a program")
    exe.chmod(0o644)

    ok, text = xvlkc_mod.probe_xvlkc(exe)

    assert ok is False
    assert text == ""


@pytest.mark.skipif(os.name == "nt", reason="POSIX shell stand-in for the CLI")
def test_probe_recognizes_usage_output(tmp_path: Path) -> None:
    exe = tmp_path / "xvlkc-stub.sh"
    exe.write_text("#!/bin/sh\necho 'xvlkc usage: <input> unpack'\n")
    exe.chmod(0o755)

    ok, text = xvlkc_mod.probe_xvlkc(exe)

    assert ok is True
    assert "xvlk" in text.casefold()
