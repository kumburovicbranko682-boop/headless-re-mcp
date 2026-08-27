"""Branch coverage for the UPX adapter helpers (unpack/upx.py).

Exercises the validation, capture, and unpack error branches directly with fake
processes and a scripted ``_capture_process`` so the paths the end-to-end tests
skip (mutation, output missing/oversized, stderr overflow, cancel) are covered
on a host without the official UPX CLI.
"""

from __future__ import annotations

import io
import os
import subprocess
from pathlib import Path
from threading import Event
from typing import Any

import pytest

import headless_re_mcp.core.process_tree as process_tree
import headless_re_mcp.process_group as process_group
from headless_re_mcp.core.session import file_sha256
from headless_re_mcp.unpack import upx as upx_adapter
from headless_re_mcp.unpack.upx import (
    UpxErrorCode,
    UpxExecutableNotFoundError,
    UpxInputNotFoundError,
    UpxInputTooLargeError,
    UpxOperation,
    UpxOutputLimitError,
    UpxProcessError,
    UpxScanError,
    copy_input_for_safe_pack,
    probe_upx_version,
    unpack_upx,
)

run_upx_test = upx_adapter.test_upx


def _cap(
    stdout: str = "",
    stderr: str = "",
    returncode: int = 0,
) -> upx_adapter._ProcessCapture:
    return upx_adapter._ProcessCapture(
        stdout=stdout,
        stderr=stderr,
        returncode=returncode,
        stdout_exceeded=False,
        stderr_exceeded=False,
    )


def _exe(tmp_path: Path) -> Path:
    exe = tmp_path / "upx.exe"
    exe.write_bytes(b"fake-upx")
    return exe


def _sample(tmp_path: Path, payload: bytes = b"MZ-packed-sample") -> Path:
    sample = tmp_path / "packed.exe"
    sample.write_bytes(payload)
    return sample


# --------------------------------------------------------------------------
# path validation
# --------------------------------------------------------------------------


def test_validate_paths_reports_a_missing_executable(tmp_path: Path) -> None:
    with pytest.raises(UpxExecutableNotFoundError):
        upx_adapter._validate_paths(tmp_path / "ghost.exe", tmp_path / "in.bin", max_file_size=1024)


def test_validate_paths_reports_a_missing_input(tmp_path: Path) -> None:
    with pytest.raises(UpxInputNotFoundError):
        upx_adapter._validate_paths(_exe(tmp_path), tmp_path / "missing.bin", max_file_size=1024)


def test_probe_version_requires_an_executable(tmp_path: Path) -> None:
    with pytest.raises(UpxExecutableNotFoundError):
        probe_upx_version(tmp_path / "ghost.exe")


# --------------------------------------------------------------------------
# _CapturedStream.read_from
# --------------------------------------------------------------------------


def test_captured_stream_flags_overflow_at_a_zero_limit() -> None:
    stream = upx_adapter._CapturedStream(limit=0)
    stream.read_from(io.BytesIO(b"abc"), Event())
    assert stream.exceeded is True
    assert bytes(stream.data) == b""
    assert stream.finished.is_set()


def test_captured_stream_swallows_a_failing_pipe() -> None:
    closed: list[bool] = []

    class _AngryPipe:
        def read(self, _size: int) -> bytes:
            raise OSError("pipe reset")

        def close(self) -> None:
            closed.append(True)

    stream = upx_adapter._CapturedStream(limit=16)
    stream.read_from(_AngryPipe(), Event())  # type: ignore[arg-type]
    assert closed == [True]
    assert stream.finished.is_set()


# --------------------------------------------------------------------------
# _creation_options windows branch
# --------------------------------------------------------------------------


def test_creation_options_hide_the_console_on_windows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _StartupInfo:
        def __init__(self) -> None:
            self.dwFlags = 0
            self.wShowWindow = 9

    monkeypatch.setattr(os, "name", "nt")
    monkeypatch.setattr(subprocess, "STARTUPINFO", _StartupInfo, raising=False)
    monkeypatch.setattr(subprocess, "CREATE_NO_WINDOW", 0x08000000, raising=False)
    monkeypatch.setattr(subprocess, "STARTF_USESHOWWINDOW", 1, raising=False)

    options = upx_adapter._creation_options()
    assert options["creationflags"] == 0x08000000
    assert options["startupinfo"].wShowWindow == 0
    assert "start_new_session" not in options


def test_creation_options_tolerate_a_missing_startupinfo(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(os, "name", "nt")
    monkeypatch.delattr(subprocess, "STARTUPINFO", raising=False)
    monkeypatch.setattr(subprocess, "CREATE_NO_WINDOW", 0x08000000, raising=False)

    options = upx_adapter._creation_options()
    assert options["creationflags"] == 0x08000000
    assert "startupinfo" not in options


# --------------------------------------------------------------------------
# _capture_process branches
# --------------------------------------------------------------------------


class _FakeProcess:
    def __init__(
        self,
        stdout: bytes = b"",
        stderr: bytes = b"",
        *,
        returncode: int | None = 0,
        poll_none: bool = False,
        pid: int = 4321,
    ) -> None:
        self.stdout: Any = io.BytesIO(stdout)
        self.stderr: Any = io.BytesIO(stderr)
        self._returncode = returncode
        self._poll_none = poll_none
        self.pid = pid
        self.killed = False

    def poll(self) -> int | None:
        if self._poll_none and not self.killed:
            return None
        return self._returncode

    def wait(self, timeout: float | None = None) -> int:
        if self._returncode is None:
            self._returncode = -9
        return self._returncode

    def kill(self) -> None:
        self.killed = True
        self._returncode = -9


def _quiet_cleanup(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(process_tree, "terminate_leftover_process_tree", lambda *a, **k: None)


def test_capture_process_assigns_a_process_group_and_returns_cleanly(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = _FakeProcess(stdout=b"ok", returncode=0)
    assigned: list[int] = []
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: process)
    monkeypatch.setattr(process_group, "assign_to_process_group", assigned.append)
    _quiet_cleanup(monkeypatch)
    capture = upx_adapter._capture_process(["fake-upx"], timeout=2.0, max_output_size=64)
    assert capture.stdout == "ok"
    assert capture.returncode == 0
    assert assigned == [4321]


def test_capture_process_maps_a_missing_executable(monkeypatch: pytest.MonkeyPatch) -> None:
    def missing(*_a: Any, **_k: Any) -> Any:
        raise FileNotFoundError("no such file")

    monkeypatch.setattr(subprocess, "Popen", missing)
    with pytest.raises(UpxExecutableNotFoundError):
        upx_adapter._capture_process(["ghost-upx"], timeout=1.0, max_output_size=32)


def test_capture_process_maps_a_spawn_oserror(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*_a: Any, **_k: Any) -> Any:
        raise OSError("exec format error")

    monkeypatch.setattr(subprocess, "Popen", boom)
    with pytest.raises(UpxProcessError, match="could not start upx"):
        upx_adapter._capture_process(["fake-upx"], timeout=1.0, max_output_size=32)


def test_capture_process_requires_stdout_and_stderr_pipes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = _FakeProcess(returncode=0)
    process.stdout = None
    process.stderr = None
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: process)
    monkeypatch.setattr(upx_adapter, "_terminate_process", lambda proc: None)
    with pytest.raises(UpxProcessError, match="stdout/stderr pipes"):
        upx_adapter._capture_process(["fake-upx"], timeout=1.0, max_output_size=32)


def test_capture_process_raises_bounded_cancelled(monkeypatch: pytest.MonkeyPatch) -> None:
    from headless_re_mcp.backends.common.bounded_run import BoundedCancelled

    process = _FakeProcess(stdout=b"", poll_none=True, returncode=None)
    cancel = Event()
    cancel.set()
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: process)
    monkeypatch.setattr(upx_adapter, "active_bound_cancel", lambda: cancel)
    monkeypatch.setattr(upx_adapter, "_terminate_process", lambda proc: None)
    _quiet_cleanup(monkeypatch)
    with pytest.raises(BoundedCancelled):
        upx_adapter._capture_process(["fake-upx"], timeout=2.0, max_output_size=32)


def test_capture_process_flags_a_stderr_overflow(monkeypatch: pytest.MonkeyPatch) -> None:
    process = _FakeProcess(stdout=b"ok", stderr=b"y" * 64, returncode=0)
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: process)
    monkeypatch.setattr(upx_adapter, "_terminate_process", lambda proc: None)
    _quiet_cleanup(monkeypatch)
    with pytest.raises(UpxOutputLimitError) as info:
        upx_adapter._capture_process(["fake-upx"], timeout=2.0, max_output_size=8)
    assert info.value.details["stream"] == "stderr"


# --------------------------------------------------------------------------
# UpxResult.to_dict
# --------------------------------------------------------------------------


def _test_result(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Any:
    exe = _exe(tmp_path)
    sample = _sample(tmp_path)
    digest = file_sha256(sample)

    def fake_capture(argv: list[str], *, timeout: float, max_output_size: int) -> Any:
        if argv[1:] == ["--version"]:
            return _cap(stdout="upx 5.2.0\n")
        return _cap(stdout="testing... OK\n")

    monkeypatch.setattr(upx_adapter, "_capture_process", fake_capture)
    return run_upx_test(exe, sample, input_sha256=digest)


def test_result_to_dict_serializes_to_an_object(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    result = _test_result(tmp_path, monkeypatch)
    payload = result.to_dict()
    assert payload["operation"] == UpxOperation.TEST.value
    assert payload["version"] == "5.2.0"


def test_result_to_dict_rejects_a_non_object_dump(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    result = _test_result(tmp_path, monkeypatch)
    monkeypatch.setattr(type(result), "model_dump", lambda self, **kwargs: "scalar")
    with pytest.raises(TypeError, match="did not serialize to an object"):
        result.to_dict()


# --------------------------------------------------------------------------
# test_upx mutation guard
# --------------------------------------------------------------------------


def test_test_upx_detects_input_mutated_during_the_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exe = _exe(tmp_path)
    sample = _sample(tmp_path)
    digest = file_sha256(sample)

    def fake_capture(argv: list[str], *, timeout: float, max_output_size: int) -> Any:
        if argv[1:] == ["--version"]:
            return _cap(stdout="upx 5.2.0\n")
        sample.write_bytes(b"MUTATED-by-a-misbehaving-upx")
        return _cap(stdout="ok\n")

    monkeypatch.setattr(upx_adapter, "_capture_process", fake_capture)
    with pytest.raises(UpxScanError) as info:
        run_upx_test(exe, sample, input_sha256=digest)
    assert info.value.code == UpxErrorCode.INPUT_MUTATED


# --------------------------------------------------------------------------
# unpack_upx guards
# --------------------------------------------------------------------------


def test_unpack_rejects_a_changed_input_before_spawning(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exe = _exe(tmp_path)
    sample = _sample(tmp_path)

    def fail(*_a: Any, **_k: Any) -> Any:
        raise AssertionError("upx must not run on a sha mismatch")

    monkeypatch.setattr(upx_adapter, "_capture_process", fail)
    with pytest.raises(UpxScanError) as info:
        unpack_upx(exe, sample, tmp_path / "out.exe", input_sha256="0" * 64)
    assert info.value.code == UpxErrorCode.INPUT_MUTATED


def test_unpack_rejects_an_existing_output_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exe = _exe(tmp_path)
    sample = _sample(tmp_path)
    output = tmp_path / "out.exe"
    output.write_bytes(b"already here")
    monkeypatch.setattr(
        upx_adapter,
        "_capture_process",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not spawn")),
    )
    with pytest.raises(UpxScanError, match="already exists"):
        unpack_upx(exe, sample, output, input_sha256=file_sha256(sample))


def test_unpack_rejects_output_equal_to_input(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exe = _exe(tmp_path)
    sample = _sample(tmp_path)
    # Force the exists() check to miss so the input/output identity guard runs.
    monkeypatch.setattr(Path, "exists", lambda self: False)
    with pytest.raises(UpxScanError, match="must differ from the input"):
        unpack_upx(exe, sample, sample, input_sha256=file_sha256(sample))


def _unpack_capture(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    on_unpack: Any,
) -> tuple[Path, Path, Path, str]:
    exe = _exe(tmp_path)
    sample = _sample(tmp_path, b"MZ-original-bytes")
    digest = file_sha256(sample)
    output = tmp_path / "artifacts" / "unpacked.exe"

    def fake_capture(argv: list[str], *, timeout: float, max_output_size: int) -> Any:
        if argv[1:] == ["--version"]:
            return _cap(stdout="upx 5.2.0\n")
        return on_unpack(argv)

    monkeypatch.setattr(upx_adapter, "_capture_process", fake_capture)
    return exe, sample, output, digest


def test_unpack_detects_input_mutation_and_deletes_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def on_unpack(argv: list[str]) -> Any:
        Path(argv[3]).parent.mkdir(parents=True, exist_ok=True)
        Path(argv[3]).write_bytes(b"unpacked")
        sample_path.write_bytes(b"MUTATED")
        return _cap(stdout="ok\n")

    exe, sample_path, output, digest = _unpack_capture(tmp_path, monkeypatch, on_unpack=on_unpack)
    with pytest.raises(UpxScanError) as info:
        unpack_upx(exe, sample_path, output, input_sha256=digest)
    assert info.value.code == UpxErrorCode.INPUT_MUTATED
    assert not output.resolve().exists()


def test_unpack_reports_mutation_when_no_output_was_written(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def on_unpack(argv: list[str]) -> Any:
        sample_path.write_bytes(b"MUTATED")
        return _cap(stdout="ok\n")

    exe, sample_path, output, digest = _unpack_capture(tmp_path, monkeypatch, on_unpack=on_unpack)
    with pytest.raises(UpxScanError) as info:
        unpack_upx(exe, sample_path, output, input_sha256=digest)
    assert info.value.code == UpxErrorCode.INPUT_MUTATED


def test_unpack_deletes_output_on_a_nonzero_exit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def on_unpack(argv: list[str]) -> Any:
        Path(argv[3]).parent.mkdir(parents=True, exist_ok=True)
        Path(argv[3]).write_bytes(b"partial")
        return _cap(stderr="broken\n", returncode=3)

    exe, sample_path, output, digest = _unpack_capture(tmp_path, monkeypatch, on_unpack=on_unpack)
    with pytest.raises(UpxProcessError) as info:
        unpack_upx(exe, sample_path, output, input_sha256=digest)
    assert info.value.code == UpxErrorCode.PROCESS_FAILED
    assert not output.resolve().exists()


def test_unpack_maps_a_nonzero_exit_when_no_output_was_written(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def on_unpack(argv: list[str]) -> Any:
        return _cap(stderr="broken\n", returncode=3)

    exe, sample_path, output, digest = _unpack_capture(tmp_path, monkeypatch, on_unpack=on_unpack)
    with pytest.raises(UpxProcessError) as info:
        unpack_upx(exe, sample_path, output, input_sha256=digest)
    assert info.value.code == UpxErrorCode.PROCESS_FAILED


def test_unpack_reports_a_missing_output(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def on_unpack(argv: list[str]) -> Any:
        return _cap(stdout="claims success\n")

    exe, sample_path, output, digest = _unpack_capture(tmp_path, monkeypatch, on_unpack=on_unpack)
    with pytest.raises(UpxScanError) as info:
        unpack_upx(exe, sample_path, output, input_sha256=digest)
    assert info.value.code == UpxErrorCode.OUTPUT_MISSING


def test_unpack_rejects_oversized_output(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def on_unpack(argv: list[str]) -> Any:
        Path(argv[3]).parent.mkdir(parents=True, exist_ok=True)
        Path(argv[3]).write_bytes(b"x" * 100)
        return _cap(stdout="ok\n")

    exe, sample_path, output, digest = _unpack_capture(tmp_path, monkeypatch, on_unpack=on_unpack)
    with pytest.raises(UpxInputTooLargeError):
        unpack_upx(exe, sample_path, output, input_sha256=digest, max_file_size=50)
    assert not output.resolve().exists()


# --------------------------------------------------------------------------
# copy_input_for_safe_pack
# --------------------------------------------------------------------------


def test_copy_input_for_safe_pack_duplicates_the_source(tmp_path: Path) -> None:
    source = _sample(tmp_path, b"packed-original")
    destination = tmp_path / "copies" / "safe.exe"
    result = copy_input_for_safe_pack(source, destination)
    assert result == destination.resolve()
    assert destination.read_bytes() == b"packed-original"
