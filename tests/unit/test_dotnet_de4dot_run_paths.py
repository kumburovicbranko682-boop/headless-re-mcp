"""run_de4dot guards, capture-loop arcs, and the version probe.

The service-level flow is tested elsewhere with a fake runner, so this file
drives ``run_de4dot`` itself with a mocked ``_capture_process``, exercises the
capture plumbing with real short-lived children, and walks the probe's argv
fallback chain with a mocked ``run_bounded``.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from threading import Event
from typing import Any

import pytest

import headless_re_mcp.core.process_tree as process_tree_module
import headless_re_mcp.process_group as process_group_module
from headless_re_mcp.backends.common.bounded_run import Completed
from headless_re_mcp.core.session import file_sha256
from headless_re_mcp.dotnet import de4dot
from headless_re_mcp.dotnet.de4dot import (
    De4dotError,
    De4dotErrorCode,
    probe_de4dot_version,
    run_de4dot,
)


class _OsProxy:
    """A stand-in ``os`` module with a pinned ``name``.

    Patching the global ``os.name`` would poison ``pathlib.Path`` on Python
    3.11, where ``Path()`` picks WindowsPath (uninstantiable on POSIX) from
    ``os.name``; a failing test would then crash pytest's own failure
    reporting. The proxy pins what ``de4dot`` reads and forwards the
    rest to the real module.
    """

    def __init__(self, name: str) -> None:
        self.name = name

    def __getattr__(self, attr: str) -> object:
        return getattr(os, attr)


def _capture(**overrides: Any) -> de4dot._ProcessCapture:
    kwargs: dict[str, Any] = {
        "stdout": "",
        "stderr": "",
        "returncode": 0,
        "stdout_exceeded": False,
        "stderr_exceeded": False,
    }
    kwargs.update(overrides)
    return de4dot._ProcessCapture(**kwargs)


def _sample(tmp_path: Path) -> tuple[Path, Path, Path, str]:
    exe = tmp_path / "de4dot.exe"
    exe.write_bytes(b"MZ")
    source = tmp_path / "input.exe"
    source.write_bytes(b"MZ managed assembly")
    destination = tmp_path / "out" / "clean.exe"
    return exe, source, destination, file_sha256(source)


# ------------------------------------------------------- run_de4dot guards


def test_run_rejects_a_missing_executable(tmp_path: Path) -> None:
    _, source, destination, sha = _sample(tmp_path)

    with pytest.raises(De4dotError) as exc:
        run_de4dot(tmp_path / "absent.exe", source, destination, input_sha256=sha)

    assert exc.value.code == De4dotErrorCode.EXECUTABLE_NOT_FOUND


def test_run_rejects_an_input_that_is_not_a_file(tmp_path: Path) -> None:
    exe, _, destination, sha = _sample(tmp_path)
    directory = tmp_path / "inputdir"
    directory.mkdir()

    with pytest.raises(De4dotError) as exc:
        run_de4dot(exe, directory, destination, input_sha256=sha)

    assert exc.value.code == De4dotErrorCode.INPUT_NOT_FOUND


def test_run_rejects_an_oversized_input(tmp_path: Path) -> None:
    exe, source, destination, sha = _sample(tmp_path)

    with pytest.raises(De4dotError) as exc:
        run_de4dot(exe, source, destination, input_sha256=sha, max_file_size=1)

    assert exc.value.code == De4dotErrorCode.INPUT_TOO_LARGE


def test_run_rejects_an_existing_output_path(tmp_path: Path) -> None:
    exe, source, destination, sha = _sample(tmp_path)
    destination.parent.mkdir(parents=True)
    destination.write_bytes(b"already here")

    with pytest.raises(De4dotError) as exc:
        run_de4dot(exe, source, destination, input_sha256=sha)

    assert exc.value.code == De4dotErrorCode.INVALID_ARGUMENT
    assert "already exist" in str(exc.value)


def test_run_rejects_an_output_path_aliasing_the_input(tmp_path: Path) -> None:
    """A dot-dot spelling that resolves onto the input must be rejected.

    On POSIX ``missing/../input.exe`` stats as absent (the missing/ segment
    cannot be traversed) yet ``resolve()`` collapses it onto the existing
    input, so the alias slips past the exists() guard and is caught by the
    resolve-equality guard ("differ from input_path"). Windows collapses the
    ``..`` lexically before the stat, so the same spelling stats as *present*
    and is rejected one guard earlier ("must not already exist"). Either guard
    rejecting the alias is correct, so assert on the shared outcome (the
    INVALID_ARGUMENT code) and accept either platform's message rather than
    the POSIX-only "stats as absent" premise.
    """
    exe, source, _, sha = _sample(tmp_path)
    aliased = tmp_path / "missing" / ".." / "input.exe"

    with pytest.raises(De4dotError) as exc:
        run_de4dot(exe, source, aliased, input_sha256=sha)

    assert exc.value.code == De4dotErrorCode.INVALID_ARGUMENT
    message = str(exc.value)
    assert "differ from input_path" in message or "must not already exist" in message


def test_run_rejects_a_stale_input_sha(tmp_path: Path) -> None:
    exe, source, destination, _ = _sample(tmp_path)

    with pytest.raises(De4dotError) as exc:
        run_de4dot(exe, source, destination, input_sha256="0" * 64)

    assert exc.value.code == De4dotErrorCode.INPUT_MUTATED
    assert "before de4dot" in str(exc.value)


def test_run_reports_an_input_mutated_by_the_tool(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exe, source, destination, sha = _sample(tmp_path)

    def mutating(argv: list[str], **_kwargs: Any) -> de4dot._ProcessCapture:
        source.write_bytes(b"rewritten in place")
        return _capture(stdout="done")

    monkeypatch.setattr(de4dot, "_capture_process", mutating)

    with pytest.raises(De4dotError) as exc:
        run_de4dot(exe, source, destination, input_sha256=sha)

    assert exc.value.code == De4dotErrorCode.INPUT_MUTATED
    assert "mutated the original" in str(exc.value)
    assert exc.value.stdout == "done"


def test_an_output_limit_discards_a_partial_output_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exe, source, destination, sha = _sample(tmp_path)

    def overflowing(argv: list[str], **_kwargs: Any) -> de4dot._ProcessCapture:
        destination.write_bytes(b"partial")
        return _capture(stdout_exceeded=True)

    monkeypatch.setattr(de4dot, "_capture_process", overflowing)

    with pytest.raises(De4dotError) as exc:
        run_de4dot(exe, source, destination, input_sha256=sha)

    assert exc.value.code == De4dotErrorCode.OUTPUT_LIMIT
    assert not destination.exists()


def test_an_output_limit_without_an_output_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exe, source, destination, sha = _sample(tmp_path)
    monkeypatch.setattr(
        de4dot,
        "_capture_process",
        lambda argv, **kwargs: _capture(stderr_exceeded=True),
    )

    with pytest.raises(De4dotError) as exc:
        run_de4dot(exe, source, destination, input_sha256=sha)

    assert exc.value.code == De4dotErrorCode.OUTPUT_LIMIT


def test_a_nonzero_exit_discards_the_partial_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exe, source, destination, sha = _sample(tmp_path)

    def failing(argv: list[str], **_kwargs: Any) -> de4dot._ProcessCapture:
        destination.write_bytes(b"partial")
        return _capture(returncode=3, stderr="boom")

    monkeypatch.setattr(de4dot, "_capture_process", failing)

    with pytest.raises(De4dotError) as exc:
        run_de4dot(exe, source, destination, input_sha256=sha)

    assert exc.value.code == De4dotErrorCode.PROCESS_FAILED
    assert exc.value.retryable is True
    assert not destination.exists()


def test_a_nonzero_exit_without_an_output_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exe, source, destination, sha = _sample(tmp_path)
    monkeypatch.setattr(
        de4dot,
        "_capture_process",
        lambda argv, **kwargs: _capture(returncode=3),
    )

    with pytest.raises(De4dotError) as exc:
        run_de4dot(exe, source, destination, input_sha256=sha)

    assert exc.value.code == De4dotErrorCode.PROCESS_FAILED


def test_success_without_an_output_file_is_output_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exe, source, destination, sha = _sample(tmp_path)
    monkeypatch.setattr(de4dot, "_capture_process", lambda argv, **kwargs: _capture())

    with pytest.raises(De4dotError) as exc:
        run_de4dot(exe, source, destination, input_sha256=sha)

    assert exc.value.code == De4dotErrorCode.OUTPUT_MISSING


def test_a_successful_run_reports_hashes_and_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exe, source, destination, sha = _sample(tmp_path)
    seen_argv: list[list[str]] = []

    def succeeding(argv: list[str], **_kwargs: Any) -> de4dot._ProcessCapture:
        seen_argv.append(argv)
        destination.write_bytes(b"deobfuscated")
        return _capture(stdout="ok")

    monkeypatch.setattr(de4dot, "_capture_process", succeeding)

    result = run_de4dot(exe, source, destination, input_sha256=sha)

    assert result.input_sha256 == sha
    assert result.output_sha256 == file_sha256(destination)
    assert result.output_path == str(destination.resolve())
    assert result.returncode == 0
    assert seen_argv[0][1:] == ["-f", str(source.resolve()), "-o", str(destination)]
    assert result.to_dict()["claims_universal_unpack"] is False


# --------------------------------------------------------- _CapturedStream


class _FakePipe:
    def __init__(self, chunks: list[bytes] | None = None, error: Exception | None = None):
        self._chunks = list(chunks or [])
        self._error = error
        self.closed = False

    def read(self, _size: int) -> bytes:
        if self._error is not None:
            raise self._error
        return self._chunks.pop(0) if self._chunks else b""

    def close(self) -> None:
        self.closed = True


def test_captured_stream_flags_output_beyond_the_cap() -> None:
    stream = de4dot._CapturedStream(max_size=10)
    limit = Event()
    pipe = _FakePipe(chunks=[b"x" * 64])

    stream.read_from(pipe, limit)

    assert stream.exceeded is True
    assert limit.is_set()
    assert stream.chunks == []
    assert pipe.closed is True


def test_captured_stream_survives_a_pipe_error() -> None:
    stream = de4dot._CapturedStream(max_size=10)
    limit = Event()
    pipe = _FakePipe(error=OSError("pipe gone"))

    stream.read_from(pipe, limit)

    assert stream.exceeded is False
    assert not limit.is_set()
    assert pipe.closed is True


# -------------------------------------------------------- _creation_options


def test_creation_options_on_windows_hide_the_console_window(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _FakeStartupInfo:
        def __init__(self) -> None:
            self.dwFlags = 0
            self.wShowWindow = 99

    monkeypatch.setattr(de4dot, "os", _OsProxy("nt"))
    monkeypatch.setattr(subprocess, "STARTUPINFO", _FakeStartupInfo, raising=False)

    options = de4dot._creation_options()

    assert "creationflags" in options
    assert "start_new_session" not in options
    startupinfo = options["startupinfo"]
    assert startupinfo.wShowWindow == 0
    assert startupinfo.dwFlags & getattr(subprocess, "STARTF_USESHOWWINDOW", 1)


def test_creation_options_on_windows_without_a_startupinfo_type(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(de4dot, "os", _OsProxy("nt"))
    monkeypatch.delattr(subprocess, "STARTUPINFO", raising=False)

    options = de4dot._creation_options()

    assert "creationflags" in options
    assert "startupinfo" not in options


# --------------------------------------------------------- _capture_process


def test_a_process_without_pipes_is_a_structured_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _PipelessProcess:
        pid = 0
        stdout = None
        stderr = None

    killed: list[object] = []
    monkeypatch.setattr(subprocess, "Popen", lambda argv, **options: _PipelessProcess())
    monkeypatch.setattr(de4dot, "_terminate_process", killed.append)

    with pytest.raises(De4dotError) as exc:
        de4dot._capture_process(["tool"], timeout=1.0, max_output_size=64)

    assert exc.value.code == De4dotErrorCode.PROCESS_FAILED
    assert "stdout/stderr pipes" in str(exc.value)
    assert len(killed) == 1


def test_the_capture_loop_kills_a_tool_beyond_the_output_cap() -> None:
    argv = [
        sys.executable,
        "-c",
        "import sys,time; sys.stdout.write('x'*200000); sys.stdout.flush(); time.sleep(30)",
    ]

    capture = de4dot._capture_process(argv, timeout=10.0, max_output_size=1000)

    assert capture.stdout_exceeded is True


def test_a_clean_exit_with_no_survivors_returns_the_capture() -> None:
    argv = [sys.executable, "-c", "print('hi')"]

    capture = de4dot._capture_process(argv, timeout=10.0, max_output_size=4096)

    assert capture.returncode == 0
    assert capture.stdout.strip() == "hi"
    assert capture.stdout_exceeded is False


def test_the_windows_exit_path_checks_descendants(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """With os.name faked to nt, a clean exit walks collect_descendants."""
    monkeypatch.setattr(de4dot, "os", _OsProxy("nt"))
    monkeypatch.setattr(process_group_module, "assign_to_process_group", lambda pid: False)
    walked: list[int] = []

    def fake_descendants(pid: int) -> list[int]:
        walked.append(pid)
        return []

    monkeypatch.setattr(process_tree_module, "collect_descendants", fake_descendants)
    argv = [sys.executable, "-c", "print('done')"]

    capture = de4dot._capture_process(argv, timeout=10.0, max_output_size=4096)

    assert capture.returncode == 0
    assert capture.stdout.strip() == "done"
    assert len(walked) == 1


def test_the_windows_exit_path_terminates_leftover_descendants(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """On nt a survivor triggers the tree kill but never the POSIX group kill."""
    monkeypatch.setattr(de4dot, "os", _OsProxy("nt"))
    monkeypatch.setattr(process_group_module, "assign_to_process_group", lambda pid: False)
    monkeypatch.setattr(process_tree_module, "collect_descendants", lambda pid: [999_999])
    killed: list[object] = []
    monkeypatch.setattr(de4dot, "_terminate_process", killed.append)
    argv = [sys.executable, "-c", "print('done')"]

    capture = de4dot._capture_process(argv, timeout=10.0, max_output_size=4096)

    assert capture.returncode == 0
    assert len(killed) == 1


# --------------------------------------------------- probe_de4dot_version


def test_probe_reports_a_missing_executable(tmp_path: Path) -> None:
    assert probe_de4dot_version(tmp_path / "absent.exe") == (False, "")


def test_probe_gives_up_when_no_argv_variant_launches(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exe = tmp_path / "de4dot.exe"
    exe.write_bytes(b"MZ")
    attempts: list[list[str]] = []

    def unlaunchable(argv: list[str], **_kwargs: Any) -> Completed:
        attempts.append(argv)
        raise OSError("exec format error")

    monkeypatch.setattr(de4dot, "run_bounded", unlaunchable)

    assert probe_de4dot_version(exe) == (False, "")
    assert len(attempts) == 3


def test_probe_accepts_a_later_argv_variant(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An unrecognisable first answer moves the probe on to -h."""
    exe = tmp_path / "de4dot.exe"
    exe.write_bytes(b"MZ")
    replies = [
        Completed(2, b"unknown option", b""),
        Completed(2, b"de4dot v3.1 GPL", b""),
    ]

    monkeypatch.setattr(de4dot, "run_bounded", lambda argv, **kwargs: replies.pop(0))

    ok, text = probe_de4dot_version(exe)

    assert ok is True
    assert "de4dot v3.1" in text
