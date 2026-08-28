"""Guard and capture-edge coverage for the bounded UPX adapter.

``test_upx.py`` covers the whitelisted-argv success paths, the pre-spawn sha
guard, the timeout/drain budget, and the stdout limit. This file covers the
paths that had no automated verification: the not-found guards in
``_validate_paths`` and ``probe_upx_version``, the post-run mutation raises for
both operations, the unpack failure branches that must delete a partial output
(nonzero exit, mutated input, oversized output), the missing-output raise, the
stderr limit, the missing-pipe and unkillable-process edges of
``_capture_process``, the overflow/OSError edges of ``_CapturedStream``, and
``copy_input_for_safe_pack``.
"""

from __future__ import annotations

import io
from pathlib import Path
from threading import Event
from typing import Any

import pytest

from headless_re_mcp.core.session import file_sha256
from headless_re_mcp.unpack import upx as upx_adapter
from headless_re_mcp.unpack.upx import (
    UpxErrorCode,
    UpxExecutableNotFoundError,
    UpxInputNotFoundError,
    UpxInputTooLargeError,
    UpxOutputLimitError,
    UpxProcessError,
    UpxScanError,
    UpxTimeoutError,
    copy_input_for_safe_pack,
    probe_upx_version,
    unpack_upx,
)

# Alias: production API is named test_upx; keep it out of pytest collection.
run_upx_test = upx_adapter.test_upx


def _fake_exe(tmp_path: Path) -> Path:
    executable = tmp_path / "upx.exe"
    executable.write_bytes(b"fake-upx")
    return executable


def _sample(tmp_path: Path, payload: bytes = b"MZ-packed-sample") -> Path:
    path = tmp_path / "packed.exe"
    path.write_bytes(payload)
    return path


def _capture(stdout: str = "", stderr: str = "", returncode: int = 0) -> Any:
    return upx_adapter._ProcessCapture(
        stdout=stdout,
        stderr=stderr,
        returncode=returncode,
        stdout_exceeded=False,
        stderr_exceeded=False,
    )


def _version_aware(unpack_behavior: Any) -> Any:
    """Build a fake _capture_process that answers --version then delegates."""

    def fake(argv: list[str], *, timeout: float, max_output_size: int) -> Any:
        del timeout, max_output_size
        if argv[1:] == ["--version"]:
            return _capture(stdout="upx 5.2.0\n")
        return unpack_behavior(argv)

    return fake


# ---------------------------------------------------------------------------
# Not-found guards


def test_missing_executable_is_reported_before_anything_runs(tmp_path: Path) -> None:
    sample = _sample(tmp_path)
    with pytest.raises(UpxExecutableNotFoundError) as caught:
        run_upx_test(tmp_path / "missing-upx", sample, input_sha256=file_sha256(sample))
    assert caught.value.code == UpxErrorCode.EXECUTABLE_NOT_FOUND


def test_missing_input_is_reported_before_anything_runs(tmp_path: Path) -> None:
    executable = _fake_exe(tmp_path)
    with pytest.raises(UpxInputNotFoundError) as caught:
        run_upx_test(executable, tmp_path / "missing.exe", input_sha256="0" * 64)
    assert caught.value.code == UpxErrorCode.INPUT_NOT_FOUND
    assert caught.value.details["path"].endswith("missing.exe")


def test_probe_refuses_a_missing_executable(tmp_path: Path) -> None:
    with pytest.raises(UpxExecutableNotFoundError):
        probe_upx_version(tmp_path / "missing-upx")


# ---------------------------------------------------------------------------
# Post-run integrity guards


def test_test_upx_reports_a_run_that_mutated_the_input(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable = _fake_exe(tmp_path)
    sample = _sample(tmp_path)
    digest = file_sha256(sample)

    def mutate(argv: list[str]) -> Any:
        assert argv[1] == "-t"
        sample.write_bytes(b"MZ-tampered")
        return _capture(stdout="testing... OK\n")

    monkeypatch.setattr(upx_adapter, "_capture_process", _version_aware(mutate))
    with pytest.raises(UpxScanError) as caught:
        run_upx_test(executable, sample, input_sha256=digest)
    assert caught.value.code == UpxErrorCode.INPUT_MUTATED
    assert caught.value.returncode == 0


def test_unpack_detects_mutated_input_before_spawn(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable = _fake_exe(tmp_path)
    sample = _sample(tmp_path)
    called = False

    def fail_if_spawned(*args: Any, **kwargs: Any) -> Any:
        nonlocal called
        called = True
        raise AssertionError("upx must not start when input sha mismatches")

    monkeypatch.setattr(upx_adapter, "_capture_process", fail_if_spawned)
    with pytest.raises(UpxScanError) as caught:
        unpack_upx(executable, sample, tmp_path / "out.exe", input_sha256="0" * 64)
    assert caught.value.code == UpxErrorCode.INPUT_MUTATED
    assert not called


def test_unpack_that_mutated_the_input_removes_the_partial_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable = _fake_exe(tmp_path)
    sample = _sample(tmp_path)
    digest = file_sha256(sample)
    output = tmp_path / "out" / "unpacked.exe"

    def mutate_and_write(argv: list[str]) -> Any:
        Path(argv[3]).write_bytes(b"MZ-partial")
        sample.write_bytes(b"MZ-tampered")
        return _capture(stdout="Unpacked 1 file.\n")

    monkeypatch.setattr(upx_adapter, "_capture_process", _version_aware(mutate_and_write))
    with pytest.raises(UpxScanError) as caught:
        unpack_upx(executable, sample, output, input_sha256=digest)
    assert caught.value.code == UpxErrorCode.INPUT_MUTATED
    assert not output.exists(), "a run that broke integrity must not leave output behind"


# ---------------------------------------------------------------------------
# Unpack failure branches


def test_failed_unpack_removes_the_partial_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable = _fake_exe(tmp_path)
    sample = _sample(tmp_path)
    digest = file_sha256(sample)
    output = tmp_path / "out" / "unpacked.exe"

    def fail_after_partial_write(argv: list[str]) -> Any:
        Path(argv[3]).write_bytes(b"MZ-partial")
        return _capture(stderr="CantUnpackException\n", returncode=2)

    monkeypatch.setattr(upx_adapter, "_capture_process", _version_aware(fail_after_partial_write))
    with pytest.raises(UpxProcessError) as caught:
        unpack_upx(executable, sample, output, input_sha256=digest)
    assert caught.value.code == UpxErrorCode.PROCESS_FAILED
    assert caught.value.returncode == 2
    assert not output.exists(), "a failed unpack must not leave a partial file behind"
    assert sample.read_bytes() == b"MZ-packed-sample"


def test_unpack_reporting_success_without_output_is_output_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable = _fake_exe(tmp_path)
    sample = _sample(tmp_path)
    output = tmp_path / "out" / "unpacked.exe"

    monkeypatch.setattr(
        upx_adapter,
        "_capture_process",
        _version_aware(lambda argv: _capture(stdout="Unpacked 1 file.\n")),
    )
    with pytest.raises(UpxScanError) as caught:
        unpack_upx(executable, sample, output, input_sha256=file_sha256(sample))
    assert caught.value.code == UpxErrorCode.OUTPUT_MISSING


def test_unpack_output_larger_than_the_file_limit_is_removed_and_reported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable = _fake_exe(tmp_path)
    sample = _sample(tmp_path, b"MZ-small")
    output = tmp_path / "out" / "unpacked.exe"

    def write_oversized(argv: list[str]) -> Any:
        Path(argv[3]).write_bytes(b"M" * 128)
        return _capture(stdout="Unpacked 1 file.\n")

    monkeypatch.setattr(upx_adapter, "_capture_process", _version_aware(write_oversized))
    with pytest.raises(UpxInputTooLargeError) as caught:
        unpack_upx(
            executable,
            sample,
            output,
            input_sha256=file_sha256(sample),
            max_file_size=64,
        )
    assert caught.value.code == UpxErrorCode.INPUT_TOO_LARGE
    assert caught.value.details["size"] == 128
    assert not output.exists(), "an over-limit output must not stay on disk"


def test_unpack_rejects_an_existing_destination(tmp_path: Path) -> None:
    executable = _fake_exe(tmp_path)
    sample = _sample(tmp_path)
    output = tmp_path / "already-there.exe"
    output.write_bytes(b"old")
    with pytest.raises(UpxScanError) as caught:
        unpack_upx(executable, sample, output, input_sha256=file_sha256(sample))
    assert caught.value.code == UpxErrorCode.INVALID_ARGUMENT
    assert output.read_bytes() == b"old", "an existing destination must never be overwritten"


# ---------------------------------------------------------------------------
# _capture_process edges


def test_capture_reports_a_stderr_flood_as_a_stderr_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _Process:
        def __init__(self) -> None:
            self.stdout = io.BytesIO(b"")
            self.stderr = io.BytesIO(b"y" * 64)
            self.killed = False

        def poll(self) -> int | None:
            return 0

        def wait(self, timeout: float | None = None) -> int:
            del timeout
            return 0

        def kill(self) -> None:
            self.killed = True

    monkeypatch.setattr(upx_adapter.subprocess, "Popen", lambda *a, **k: _Process())
    with pytest.raises(UpxOutputLimitError) as caught:
        upx_adapter._capture_process(["fake-upx"], timeout=1.0, max_output_size=8)
    assert caught.value.code == UpxErrorCode.OUTPUT_LIMIT
    assert caught.value.details["stream"] == "stderr"
    assert len(caught.value.stderr.encode()) <= 8


def test_capture_without_pipes_terminates_the_child_and_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _NoPipeProcess:
        stdout = None
        stderr = None

    terminated: list[Any] = []
    monkeypatch.setattr(upx_adapter.subprocess, "Popen", lambda *a, **k: _NoPipeProcess())
    monkeypatch.setattr(upx_adapter, "_terminate_process", terminated.append)
    with pytest.raises(UpxProcessError) as caught:
        upx_adapter._capture_process(["fake-upx"], timeout=1.0, max_output_size=32)
    assert caught.value.code == UpxErrorCode.PROCESS_FAILED
    assert len(terminated) == 1, "a pipe-less child must still be terminated"


def test_capture_of_an_unkillable_process_reports_returncode_minus_one(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A child that never dies must not wedge the adapter or report a fake rc."""

    class _ZombieProcess:
        def __init__(self) -> None:
            self.stdout = io.BytesIO(b"")
            self.stderr = io.BytesIO(b"")

        def poll(self) -> int | None:
            return None

    from headless_re_mcp.core import process_tree

    monkeypatch.setattr(upx_adapter.subprocess, "Popen", lambda *a, **k: _ZombieProcess())
    monkeypatch.setattr(upx_adapter, "_terminate_process", lambda process: None)
    monkeypatch.setattr(process_tree, "terminate_leftover_process_tree", lambda *a, **k: None)
    with pytest.raises(UpxTimeoutError) as caught:
        upx_adapter._capture_process(["fake-upx"], timeout=0.05, max_output_size=32)
    assert caught.value.code == UpxErrorCode.TIMEOUT
    assert caught.value.returncode == -1


# ---------------------------------------------------------------------------
# _CapturedStream edges


class _ScriptedPipe:
    """Pipe stub feeding fixed chunks, then EOF."""

    def __init__(self, chunks: list[bytes]) -> None:
        self._chunks = list(chunks)
        self.closed = False

    def read(self, size: int) -> bytes:
        del size
        if self._chunks:
            return self._chunks.pop(0)
        return b""

    def close(self) -> None:
        self.closed = True


def test_captured_stream_stops_storing_once_full_but_still_flags_overflow() -> None:
    stream = upx_adapter._CapturedStream(limit=4)
    exceeded = Event()
    pipe = _ScriptedPipe([b"abcd", b"ef"])

    stream.read_from(pipe, exceeded)  # type: ignore[arg-type]

    assert bytes(stream.data) == b"abcd", "data past the limit must not be stored"
    assert stream.exceeded is True
    assert exceeded.is_set()
    assert stream.finished.is_set()
    assert pipe.closed


def test_captured_stream_treats_a_broken_pipe_as_end_of_stream() -> None:
    class _BrokenPipe:
        closed = False

        def read(self, size: int) -> bytes:
            raise OSError("pipe burst")

        def close(self) -> None:
            self.closed = True

    stream = upx_adapter._CapturedStream(limit=16)
    pipe = _BrokenPipe()

    stream.read_from(pipe, Event())  # type: ignore[arg-type]

    assert bytes(stream.data) == b""
    assert stream.exceeded is False
    assert stream.finished.is_set(), "a broken pipe must still release the join"
    assert pipe.closed


# ---------------------------------------------------------------------------
# Fixture helper


def test_copy_input_for_safe_pack_copies_into_a_created_tree(tmp_path: Path) -> None:
    source = tmp_path / "orig.exe"
    source.write_bytes(b"MZ-fixture")
    destination = tmp_path / "nested" / "deeper" / "copy.exe"

    result = copy_input_for_safe_pack(source, destination)

    assert result == destination.resolve()
    assert result.read_bytes() == b"MZ-fixture"
    assert source.read_bytes() == b"MZ-fixture"
