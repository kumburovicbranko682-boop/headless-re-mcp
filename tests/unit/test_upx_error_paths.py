"""Validation, capture, and cleanup paths for the bounded UPX adapter.

The adapter drives an external CLI over untrusted inputs, so its contract is
that misconfiguration and process misbehavior surface as specific
``UpxScanError`` codes (never a raw exception or a leaked partial file). These
pin the caller-bound validation and the capture/cleanup branches the happy-path
suite skips.
"""

from __future__ import annotations

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
    _CapturedStream,
    _validate_paths,
    probe_upx_version,
    unpack_upx,
)

run_upx_test = upx_adapter.test_upx


def _write_sample(path: Path, payload: bytes = b"MZ-packed-sample") -> Path:
    path.write_bytes(payload)
    return path


class _FakePipe:
    def __init__(self, chunks: list[bytes], *, raises: bool = False) -> None:
        self._chunks = list(chunks)
        self._raises = raises
        self.closed = False

    def read(self, _size: int) -> bytes:
        if self._raises:
            raise OSError("pipe went away")
        return self._chunks.pop(0) if self._chunks else b""

    def close(self) -> None:
        self.closed = True


class _FakeProcess:
    def __init__(
        self,
        stdout: bytes = b"",
        stderr: bytes = b"",
        *,
        returncode: int | None = 0,
        hangs: bool = False,
        pipes: bool = True,
    ) -> None:
        import io

        self.stdout = io.BytesIO(stdout) if pipes else None
        self.stderr = io.BytesIO(stderr) if pipes else None
        self._returncode = None if hangs else returncode
        self._hangs = hangs
        # A falsy pid skips the real process-group assignment in _capture_process.
        self.pid = 0

    def poll(self) -> int | None:
        return self._returncode

    def kill(self) -> None:
        self._hangs = False
        self._returncode = -9


# --- caller-supplied bound validation ----------------------------------------


@pytest.mark.parametrize("bad", [0, -1, -0.5])
def test_test_upx_rejects_non_positive_timeout(tmp_path: Path, bad: float) -> None:
    with pytest.raises(UpxScanError) as caught:
        run_upx_test(tmp_path / "upx", tmp_path / "in", input_sha256="0" * 64, timeout=bad)
    assert caught.value.code == UpxErrorCode.INVALID_ARGUMENT
    assert "timeout" in str(caught.value)


@pytest.mark.parametrize("bad", [0, -8])
def test_test_upx_rejects_non_positive_byte_bounds(tmp_path: Path, bad: int) -> None:
    with pytest.raises(UpxScanError) as caught:
        run_upx_test(tmp_path / "upx", tmp_path / "in", input_sha256="0" * 64, max_file_size=bad)
    assert caught.value.code == UpxErrorCode.INVALID_ARGUMENT


def test_unpack_upx_rejects_non_positive_output_bound(tmp_path: Path) -> None:
    with pytest.raises(UpxScanError) as caught:
        unpack_upx(
            tmp_path / "upx",
            tmp_path / "in",
            tmp_path / "out",
            input_sha256="0" * 64,
            max_output_size=0,
        )
    assert caught.value.code == UpxErrorCode.INVALID_ARGUMENT
    assert "max_output_size" in str(caught.value)


def test_probe_upx_version_rejects_non_positive_timeout(tmp_path: Path) -> None:
    with pytest.raises(UpxScanError) as caught:
        probe_upx_version(tmp_path / "upx", timeout=-1)
    assert caught.value.code == UpxErrorCode.INVALID_ARGUMENT


# --- path validation ----------------------------------------------------------


def test_validate_paths_reports_missing_executable(tmp_path: Path) -> None:
    with pytest.raises(UpxExecutableNotFoundError):
        _validate_paths(tmp_path / "nope", tmp_path / "in", max_file_size=1024)


def test_validate_paths_reports_missing_input(tmp_path: Path) -> None:
    exe = tmp_path / "upx"
    exe.write_bytes(b"fake")
    with pytest.raises(UpxInputNotFoundError):
        _validate_paths(exe, tmp_path / "missing", max_file_size=1024)


def test_probe_version_reports_missing_executable(tmp_path: Path) -> None:
    with pytest.raises(UpxExecutableNotFoundError):
        probe_upx_version(tmp_path / "does-not-exist")


# --- _CapturedStream reader ---------------------------------------------------


def test_captured_stream_truncates_and_flags_exceeded() -> None:
    stream = _CapturedStream(limit=5)
    exceeded = Event()
    pipe = _FakePipe([b"x" * 10, b"y" * 10])
    stream.read_from(pipe, exceeded)
    assert stream.exceeded is True
    assert exceeded.is_set()
    assert len(stream.data) == 5
    assert pipe.closed and stream.finished.is_set()


def test_captured_stream_keeps_a_chunk_within_the_limit() -> None:
    stream = _CapturedStream(limit=100)
    exceeded = Event()
    stream.read_from(_FakePipe([b"abc"]), exceeded)
    assert stream.exceeded is False
    assert not exceeded.is_set()
    assert bytes(stream.data) == b"abc"


def test_captured_stream_survives_a_pipe_error() -> None:
    stream = _CapturedStream(limit=5)
    pipe = _FakePipe([], raises=True)
    stream.read_from(pipe, Event())
    assert stream.exceeded is False
    assert pipe.closed and stream.finished.is_set()


# --- _creation_options on Windows --------------------------------------------


def test_creation_options_configure_a_hidden_window(monkeypatch: pytest.MonkeyPatch) -> None:
    class _FakeStartupInfo:
        def __init__(self) -> None:
            self.dwFlags = 0
            self.wShowWindow = 7

    monkeypatch.setattr(upx_adapter.os, "name", "nt")
    monkeypatch.setattr(upx_adapter.subprocess, "STARTUPINFO", _FakeStartupInfo, raising=False)
    monkeypatch.setattr(upx_adapter.subprocess, "STARTF_USESHOWWINDOW", 1, raising=False)
    monkeypatch.setattr(upx_adapter.subprocess, "CREATE_NO_WINDOW", 0x08000000, raising=False)

    options = upx_adapter._creation_options()
    assert options["creationflags"] == 0x08000000
    startup = options["startupinfo"]
    assert isinstance(startup, _FakeStartupInfo)
    assert startup.dwFlags & 1
    assert startup.wShowWindow == 0


def test_creation_options_tolerate_missing_startupinfo(monkeypatch: pytest.MonkeyPatch) -> None:
    # A Windows name without a STARTUPINFO type (as on this Linux host) still
    # returns creationflags but no startupinfo entry.
    monkeypatch.setattr(upx_adapter.os, "name", "nt")
    monkeypatch.delattr(upx_adapter.subprocess, "STARTUPINFO", raising=False)
    options = upx_adapter._creation_options()
    assert "startupinfo" not in options
    assert options["creationflags"] == 0x08000000


# --- _capture_process error branches -----------------------------------------


def test_capture_process_rejects_a_process_without_pipes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        upx_adapter.subprocess, "Popen", lambda *a, **k: _FakeProcess(pipes=False)
    )
    monkeypatch.setattr(upx_adapter, "_terminate_process", lambda child: None)
    with pytest.raises(UpxProcessError) as caught:
        upx_adapter._capture_process(["fake-upx"], timeout=1.0, max_output_size=32)
    assert caught.value.code == UpxErrorCode.PROCESS_FAILED
    assert "pipes" in str(caught.value)


def test_capture_process_defaults_returncode_when_still_running(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = _FakeProcess(hangs=True)
    monkeypatch.setattr(upx_adapter.subprocess, "Popen", lambda *a, **k: process)
    # Leave the child "running" so the post-loop poll stays None and falls back to -1.
    monkeypatch.setattr(upx_adapter, "_terminate_process", lambda child: None)
    monkeypatch.setattr(
        "headless_re_mcp.core.process_tree.terminate_leftover_process_tree",
        lambda *a, **k: None,
    )
    with pytest.raises(upx_adapter.UpxTimeoutError) as caught:
        upx_adapter._capture_process(["fake-upx"], timeout=0.01, max_output_size=32)
    assert caught.value.returncode == -1


def test_capture_process_returns_a_clean_capture(monkeypatch: pytest.MonkeyPatch) -> None:
    process = _FakeProcess(stdout=b"testing OK\n", stderr=b"", returncode=0)
    monkeypatch.setattr(upx_adapter.subprocess, "Popen", lambda *a, **k: process)
    monkeypatch.setattr(
        "headless_re_mcp.core.process_tree.terminate_leftover_process_tree",
        lambda *a, **k: None,
    )
    capture = upx_adapter._capture_process(["fake-upx"], timeout=1.0, max_output_size=64)
    assert capture.returncode == 0
    assert capture.stdout == "testing OK\n"
    assert capture.stdout_exceeded is False


def test_capture_process_assigns_the_child_to_a_process_group(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = _FakeProcess(stdout=b"", returncode=0)
    process.pid = 1234  # a truthy pid triggers the process-group assignment
    assigned: list[int] = []
    monkeypatch.setattr(upx_adapter.subprocess, "Popen", lambda *a, **k: process)
    monkeypatch.setattr(
        "headless_re_mcp.process_group.assign_to_process_group", assigned.append
    )
    monkeypatch.setattr(
        "headless_re_mcp.core.process_tree.terminate_leftover_process_tree",
        lambda *a, **k: None,
    )
    upx_adapter._capture_process(["fake-upx"], timeout=1.0, max_output_size=32)
    assert assigned == [1234]


def test_capture_process_maps_a_missing_executable(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*_a: Any, **_k: Any) -> Any:
        raise FileNotFoundError(2, "no such file")

    monkeypatch.setattr(upx_adapter.subprocess, "Popen", boom)
    with pytest.raises(UpxExecutableNotFoundError):
        upx_adapter._capture_process(["missing-upx"], timeout=1.0, max_output_size=32)


def test_capture_process_maps_a_spawn_os_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*_a: Any, **_k: Any) -> Any:
        raise OSError("exec format error")

    monkeypatch.setattr(upx_adapter.subprocess, "Popen", boom)
    with pytest.raises(UpxProcessError) as caught:
        upx_adapter._capture_process(["bad-upx"], timeout=1.0, max_output_size=32)
    assert caught.value.code == UpxErrorCode.PROCESS_FAILED


def test_capture_process_flags_stderr_output_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = _FakeProcess(stdout=b"", stderr=b"z" * 64)
    monkeypatch.setattr(upx_adapter.subprocess, "Popen", lambda *a, **k: process)
    monkeypatch.setattr(
        "headless_re_mcp.core.process_tree.terminate_leftover_process_tree",
        lambda *a, **k: None,
    )
    with pytest.raises(UpxOutputLimitError) as caught:
        upx_adapter._capture_process(["fake-upx"], timeout=1.0, max_output_size=8)
    assert caught.value.details["stream"] == "stderr"


# --- test_upx / unpack_upx mid-run integrity and cleanup ---------------------


def _version_capture() -> upx_adapter._ProcessCapture:
    return upx_adapter._ProcessCapture(
        stdout="upx 5.2.0\n",
        stderr="",
        returncode=0,
        stdout_exceeded=False,
        stderr_exceeded=False,
    )


def test_test_upx_detects_input_mutated_during_the_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exe = tmp_path / "upx"
    exe.write_bytes(b"fake")
    sample = _write_sample(tmp_path / "packed.exe")
    digest = file_sha256(sample)

    def fake_capture(argv: list[str], **_kw: Any) -> upx_adapter._ProcessCapture:
        if argv[1:] == ["--version"]:
            return _version_capture()
        sample.write_bytes(b"tampered-during-run")
        return upx_adapter._ProcessCapture(
            stdout="OK", stderr="", returncode=0, stdout_exceeded=False, stderr_exceeded=False
        )

    monkeypatch.setattr(upx_adapter, "_capture_process", fake_capture)
    with pytest.raises(UpxScanError) as caught:
        run_upx_test(exe, sample, input_sha256=digest)
    assert caught.value.code == UpxErrorCode.INPUT_MUTATED


def test_unpack_upx_rejects_sha_mismatch_before_spawn(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exe = tmp_path / "upx"
    exe.write_bytes(b"fake")
    sample = _write_sample(tmp_path / "packed.exe")
    called = False

    def fail_if_spawned(*_a: Any, **_k: Any) -> Any:
        nonlocal called
        called = True
        raise AssertionError("must not spawn on sha mismatch")

    monkeypatch.setattr(upx_adapter, "_capture_process", fail_if_spawned)
    with pytest.raises(UpxScanError) as caught:
        unpack_upx(exe, sample, tmp_path / "out.exe", input_sha256="0" * 64)
    assert caught.value.code == UpxErrorCode.INPUT_MUTATED
    assert not called


def _unpack_fake(
    sample: Path,
    output: Path,
    *,
    returncode: int = 0,
    mutate_input: bool = False,
    write_output: bytes | None = b"MZ-unpacked",
):
    def fake_capture(argv: list[str], **_kw: Any) -> upx_adapter._ProcessCapture:
        if argv[1:] == ["--version"]:
            return _version_capture()
        if write_output is not None:
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_bytes(write_output)
        if mutate_input:
            sample.write_bytes(b"tampered")
        return upx_adapter._ProcessCapture(
            stdout="done",
            stderr="",
            returncode=returncode,
            stdout_exceeded=False,
            stderr_exceeded=False,
        )

    return fake_capture


def test_unpack_upx_cleans_output_when_input_mutated(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exe = tmp_path / "upx"
    exe.write_bytes(b"fake")
    sample = _write_sample(tmp_path / "packed.exe")
    output = tmp_path / "out" / "unpacked.exe"
    monkeypatch.setattr(
        upx_adapter, "_capture_process", _unpack_fake(sample, output, mutate_input=True)
    )
    with pytest.raises(UpxScanError) as caught:
        unpack_upx(exe, sample, output, input_sha256=file_sha256(sample))
    assert caught.value.code == UpxErrorCode.INPUT_MUTATED
    assert not output.exists()


def test_unpack_upx_cleans_output_on_process_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exe = tmp_path / "upx"
    exe.write_bytes(b"fake")
    sample = _write_sample(tmp_path / "packed.exe")
    output = tmp_path / "out" / "unpacked.exe"
    monkeypatch.setattr(
        upx_adapter, "_capture_process", _unpack_fake(sample, output, returncode=1)
    )
    with pytest.raises(UpxProcessError) as caught:
        unpack_upx(exe, sample, output, input_sha256=file_sha256(sample))
    assert caught.value.code == UpxErrorCode.PROCESS_FAILED
    assert not output.exists()


def test_unpack_upx_reports_missing_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exe = tmp_path / "upx"
    exe.write_bytes(b"fake")
    sample = _write_sample(tmp_path / "packed.exe")
    output = tmp_path / "out" / "unpacked.exe"
    monkeypatch.setattr(
        upx_adapter, "_capture_process", _unpack_fake(sample, output, write_output=None)
    )
    with pytest.raises(UpxScanError) as caught:
        unpack_upx(exe, sample, output, input_sha256=file_sha256(sample))
    assert caught.value.code == UpxErrorCode.OUTPUT_MISSING


def test_unpack_upx_rejects_oversized_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exe = tmp_path / "upx"
    exe.write_bytes(b"fake")
    sample = _write_sample(tmp_path / "packed.exe", b"MZ")  # 2 bytes, under the limit
    output = tmp_path / "out" / "unpacked.exe"
    monkeypatch.setattr(
        upx_adapter,
        "_capture_process",
        _unpack_fake(sample, output, write_output=b"Z" * 100),
    )
    with pytest.raises(UpxInputTooLargeError):
        unpack_upx(exe, sample, output, input_sha256=file_sha256(sample), max_file_size=8)
    assert not output.exists()


def test_unpack_upx_success_serializes_to_dict(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exe = tmp_path / "upx"
    exe.write_bytes(b"fake")
    sample = _write_sample(tmp_path / "packed.exe")
    output = tmp_path / "out" / "unpacked.exe"
    monkeypatch.setattr(upx_adapter, "_capture_process", _unpack_fake(sample, output))
    result = unpack_upx(exe, sample, output, input_sha256=file_sha256(sample))
    assert result.ok
    payload = result.to_dict()
    assert payload["operation"] == "unpack"
    assert payload["output_sha256"] == file_sha256(output)
    assert payload["returncode"] == 0


def test_copy_input_for_safe_pack_creates_parents(tmp_path: Path) -> None:
    source = _write_sample(tmp_path / "src.exe", b"payload")
    destination = tmp_path / "nested" / "copy.exe"
    result = upx_adapter.copy_input_for_safe_pack(source, destination)
    assert result == destination.resolve()
    assert destination.read_bytes() == b"payload"
