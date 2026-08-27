"""Direct coverage for the de4dot adapter's runner, probe, and capture helpers.

The existing de4dot tests drive the service layer through a fake runner, so
``run_de4dot`` itself -- every fail-closed guard plus the whole post-capture
path -- was never exercised (67%). These tests call it directly with a mocked
``_capture_process`` that writes the ``-o`` output the way the real tool would,
and add the probe's remaining branches, the Windows console-hiding kwargs, and
the bounded output-stream reader's over-limit and error arms.
"""

from __future__ import annotations

import io
import os
import subprocess
from pathlib import Path
from threading import Event
from typing import Any

import pytest

from headless_re_mcp.backends.common.bounded_run import Completed, TimedOut
from headless_re_mcp.core.session import file_sha256
from headless_re_mcp.dotnet import de4dot as de4dot_mod
from headless_re_mcp.dotnet.de4dot import (
    De4dotError,
    De4dotErrorCode,
    De4dotResult,
    _CapturedStream,
    _creation_options,
    _ProcessCapture,
    probe_de4dot_version,
    run_de4dot,
)


def _prepare(tmp_path: Path) -> tuple[Path, Path, Path, str]:
    exe = tmp_path / "de4dot.exe"
    exe.write_bytes(b"placeholder")
    source = tmp_path / "managed.exe"
    source.write_bytes(b"managed-assembly-bytes")
    destination = tmp_path / "out" / "clean.exe"
    return exe, source, destination, file_sha256(source)


# --------------------------------------------------------------------------- #
# run_de4dot fail-closed guards                                               #
# --------------------------------------------------------------------------- #
def test_run_rejects_a_missing_executable(tmp_path: Path) -> None:
    _exe, source, destination, sha = _prepare(tmp_path)
    with pytest.raises(De4dotError) as excinfo:
        run_de4dot(tmp_path / "gone.exe", source, destination, input_sha256=sha)
    assert excinfo.value.code == De4dotErrorCode.EXECUTABLE_NOT_FOUND


def test_run_rejects_an_input_that_is_not_a_file(tmp_path: Path) -> None:
    exe, _source, destination, _sha = _prepare(tmp_path)
    a_dir = tmp_path / "adir"
    a_dir.mkdir()
    with pytest.raises(De4dotError) as excinfo:
        run_de4dot(exe, a_dir, destination, input_sha256="0" * 64)
    assert excinfo.value.code == De4dotErrorCode.INPUT_NOT_FOUND


def test_run_rejects_an_input_over_the_size_bound(tmp_path: Path) -> None:
    exe, source, destination, sha = _prepare(tmp_path)
    with pytest.raises(De4dotError) as excinfo:
        run_de4dot(exe, source, destination, input_sha256=sha, max_file_size=1)
    assert excinfo.value.code == De4dotErrorCode.INPUT_TOO_LARGE
    assert excinfo.value.details["max_file_size"] == 1


def test_run_refuses_to_overwrite_an_existing_output(tmp_path: Path) -> None:
    exe, source, destination, sha = _prepare(tmp_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(b"already here")
    with pytest.raises(De4dotError) as excinfo:
        run_de4dot(exe, source, destination, input_sha256=sha)
    assert excinfo.value.code == De4dotErrorCode.INVALID_ARGUMENT


def test_run_rejects_a_stale_input_hash(tmp_path: Path) -> None:
    exe, source, destination, _sha = _prepare(tmp_path)
    with pytest.raises(De4dotError) as excinfo:
        run_de4dot(exe, source, destination, input_sha256="dead" * 16)
    assert excinfo.value.code == De4dotErrorCode.INPUT_MUTATED


# --------------------------------------------------------------------------- #
# run_de4dot post-capture handling (mocked _capture_process)                  #
# --------------------------------------------------------------------------- #
def _capture_writing(destination_bytes: bytes) -> Any:
    def capture(argv: list[str], **_kwargs: Any) -> _ProcessCapture:
        # argv is [exe, "-f", <input>, "-o", <output>]; write the -o target.
        Path(argv[4]).write_bytes(destination_bytes)
        return _ProcessCapture("done", "", 0, False, False)

    return capture


def test_run_returns_the_deobfuscated_output_on_success(tmp_path: Path, monkeypatch: Any) -> None:
    exe, source, destination, sha = _prepare(tmp_path)
    monkeypatch.setattr(de4dot_mod, "_capture_process", _capture_writing(b"clean-bytes"))

    result = run_de4dot(exe, source, destination, input_sha256=sha)

    assert isinstance(result, De4dotResult)
    assert result.returncode == 0
    assert Path(result.output_path).read_bytes() == b"clean-bytes"
    assert result.output_sha256 == file_sha256(destination)
    assert result.input_sha256 == sha
    assert file_sha256(source) == sha  # original untouched


def test_run_flags_an_input_mutated_by_the_tool(tmp_path: Path, monkeypatch: Any) -> None:
    exe, source, destination, sha = _prepare(tmp_path)

    def capture(argv: list[str], **_kwargs: Any) -> _ProcessCapture:
        source.write_bytes(b"tool-rewrote-the-original")
        return _ProcessCapture("done", "", 0, False, False)

    monkeypatch.setattr(de4dot_mod, "_capture_process", capture)
    with pytest.raises(De4dotError) as excinfo:
        run_de4dot(exe, source, destination, input_sha256=sha)
    assert excinfo.value.code == De4dotErrorCode.INPUT_MUTATED


def test_run_flags_output_over_the_stream_bound_and_removes_partial(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """An over-limit run is rejected and any partial output is cleaned up."""
    exe, source, destination, sha = _prepare(tmp_path)

    def capture(argv: list[str], **_kwargs: Any) -> _ProcessCapture:
        Path(argv[4]).write_bytes(b"partial")
        return _ProcessCapture("noisy", "", 0, True, False)

    monkeypatch.setattr(de4dot_mod, "_capture_process", capture)
    with pytest.raises(De4dotError) as excinfo:
        run_de4dot(exe, source, destination, input_sha256=sha)
    assert excinfo.value.code == De4dotErrorCode.OUTPUT_LIMIT
    assert not destination.exists()


def test_run_flags_a_nonzero_exit_and_removes_partial(tmp_path: Path, monkeypatch: Any) -> None:
    exe, source, destination, sha = _prepare(tmp_path)

    def capture(argv: list[str], **_kwargs: Any) -> _ProcessCapture:
        Path(argv[4]).write_bytes(b"partial")
        return _ProcessCapture("", "boom", 5, False, False)

    monkeypatch.setattr(de4dot_mod, "_capture_process", capture)
    with pytest.raises(De4dotError) as excinfo:
        run_de4dot(exe, source, destination, input_sha256=sha)
    assert excinfo.value.code == De4dotErrorCode.PROCESS_FAILED
    assert excinfo.value.returncode == 5
    assert excinfo.value.retryable is True
    assert not destination.exists()


def test_run_flags_a_clean_exit_with_no_output(tmp_path: Path, monkeypatch: Any) -> None:
    exe, source, destination, sha = _prepare(tmp_path)

    def capture(argv: list[str], **_kwargs: Any) -> _ProcessCapture:
        return _ProcessCapture("said ok", "", 0, False, False)

    monkeypatch.setattr(de4dot_mod, "_capture_process", capture)
    with pytest.raises(De4dotError) as excinfo:
        run_de4dot(exe, source, destination, input_sha256=sha)
    assert excinfo.value.code == De4dotErrorCode.OUTPUT_MISSING


# --------------------------------------------------------------------------- #
# probe_de4dot_version                                                        #
# --------------------------------------------------------------------------- #
def test_probe_reports_missing_when_the_executable_is_absent(tmp_path: Path) -> None:
    ok, text = probe_de4dot_version(tmp_path / "nope.exe")
    assert ok is False
    assert text == ""


def test_probe_gives_up_when_the_binary_hangs(tmp_path: Path, monkeypatch: Any) -> None:
    exe = tmp_path / "de4dot.exe"
    exe.write_bytes(b"x")

    def hang(*_args: Any, **_kwargs: Any) -> Completed:
        raise TimedOut(timeout=0.8, killed=[])

    monkeypatch.setattr(de4dot_mod, "run_bounded", hang)
    ok, text = probe_de4dot_version(exe)
    assert ok is False
    assert text == ""


def test_probe_skips_a_failing_argv_then_recognizes_the_banner(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """An OSError on one argv form is skipped; a later form that works wins."""
    exe = tmp_path / "de4dot.exe"
    exe.write_bytes(b"x")
    calls = {"n": 0}

    def flaky(*_args: Any, **_kwargs: Any) -> Completed:
        calls["n"] += 1
        if calls["n"] == 1:
            raise OSError("first form not supported")
        return Completed(returncode=0, stdout=b"de4dot v3.1.41592\n", stderr=b"")

    monkeypatch.setattr(de4dot_mod, "run_bounded", flaky)
    ok, text = probe_de4dot_version(exe)
    assert ok is True
    assert "de4dot" in text
    assert calls["n"] == 2


def test_probe_reports_missing_when_no_argv_form_looks_like_de4dot(
    tmp_path: Path, monkeypatch: Any
) -> None:
    exe = tmp_path / "de4dot.exe"
    exe.write_bytes(b"x")

    def unknown(*_args: Any, **_kwargs: Any) -> Completed:
        return Completed(returncode=2, stdout=b"unrelated tool", stderr=b"")

    monkeypatch.setattr(de4dot_mod, "run_bounded", unknown)
    ok, text = probe_de4dot_version(exe)
    assert ok is False
    assert text == ""


# --------------------------------------------------------------------------- #
# _creation_options and _CapturedStream                                       #
# --------------------------------------------------------------------------- #
def test_creation_options_hide_the_console_on_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    class _FakeStartupInfo:
        def __init__(self) -> None:
            self.dwFlags = 0
            self.wShowWindow = 5

    monkeypatch.setattr(os, "name", "nt")
    monkeypatch.setattr(subprocess, "CREATE_NO_WINDOW", 0x08000000, raising=False)
    monkeypatch.setattr(subprocess, "STARTF_USESHOWWINDOW", 0x00000001, raising=False)
    monkeypatch.setattr(subprocess, "STARTUPINFO", _FakeStartupInfo, raising=False)

    options = _creation_options()

    assert options["creationflags"] == 0x08000000
    assert options["startupinfo"].dwFlags & 0x00000001
    assert options["startupinfo"].wShowWindow == 0
    assert "start_new_session" not in options


def test_captured_stream_keeps_output_under_the_limit() -> None:
    stream = _CapturedStream(max_size=1024)
    stream.read_from(io.BytesIO(b"hello world"), Event())
    assert stream.exceeded is False
    assert stream.text() == "hello world"


def test_captured_stream_stops_and_signals_when_over_the_limit() -> None:
    limit = Event()
    stream = _CapturedStream(max_size=4)
    stream.read_from(io.BytesIO(b"way too many bytes"), limit)
    assert stream.exceeded is True
    assert limit.is_set()


def test_captured_stream_swallows_a_broken_pipe() -> None:
    class _BoomPipe:
        def read(self, _size: int) -> bytes:
            raise OSError("pipe broke")

        def close(self) -> None:
            pass

    stream = _CapturedStream(max_size=64)
    stream.read_from(_BoomPipe(), Event())  # must not raise
    assert stream.exceeded is False
    assert stream.text() == ""


# --------------------------------------------------------------------------- #
# _capture_process guard and resource-bound arms                              #
# --------------------------------------------------------------------------- #
def test_capture_process_fails_closed_when_pipes_are_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A launch that yields no stdout/stderr pipes is refused, not read blindly."""

    class _NoPipeProcess:
        pid = 0  # falsy, so the process-group assignment is skipped

        def __init__(self) -> None:
            self.stdout = None
            self.stderr = None
            self.returncode: int | None = None

        def poll(self) -> int | None:
            return self.returncode

    monkeypatch.setattr(de4dot_mod.subprocess, "Popen", lambda *_a, **_k: _NoPipeProcess())
    # Neutralize the tree kill: the fake process has no real pid to signal.
    monkeypatch.setattr(de4dot_mod, "_terminate_process", lambda _proc: None)

    with pytest.raises(De4dotError) as excinfo:
        de4dot_mod._capture_process(
            ["de4dot", "-f", "in", "-o", "out"], timeout=1.0, max_output_size=1024
        )
    assert excinfo.value.code == De4dotErrorCode.PROCESS_FAILED
    assert "pipes" in str(excinfo.value)


def test_capture_process_terminates_a_run_that_floods_stdout() -> None:
    """When the reader trips the output bound, the loop kills the live process.

    The child writes far past the limit and then lingers, so the bound is hit
    while it is still running -- the arm that stops a runaway rather than
    waiting for it to exit on its own.
    """
    import sys

    script = "import sys, time; sys.stdout.write('x' * 200000); sys.stdout.flush(); time.sleep(5)"
    capture = de4dot_mod._capture_process(
        [sys.executable, "-c", script], timeout=10.0, max_output_size=1000
    )
    assert capture.stdout_exceeded is True
