"""Error and cleanup paths for the bounded UPX adapter.

The main suite pins the happy paths and the pre-spawn refusals. These cover the
post-run guards: an input that changes under the tool, a nonzero exit, a success
with no output file, an output past the size limit, and the process-start
failures -- each of which must leave no partial file behind and surface a
specific error code rather than a bare exception.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

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

_VERSION = upx_adapter._ProcessCapture(
    stdout="upx 5.2.0\n",
    stderr="",
    returncode=0,
    stdout_exceeded=False,
    stderr_exceeded=False,
)


def _write_sample(path: Path, payload: bytes = b"MZ-packed-sample") -> Path:
    path.write_bytes(payload)
    return path


def _exe(tmp_path: Path) -> Path:
    executable = tmp_path / "upx.exe"
    executable.write_bytes(b"fake-upx")
    return executable


def test_missing_executable_is_a_typed_error(tmp_path: Path) -> None:
    sample = _write_sample(tmp_path / "packed.exe")
    with pytest.raises(UpxExecutableNotFoundError) as caught:
        run_upx_test(tmp_path / "not-there", sample, input_sha256=file_sha256(sample))
    assert caught.value.code == UpxErrorCode.EXECUTABLE_NOT_FOUND


def test_missing_input_is_a_typed_error(tmp_path: Path) -> None:
    with pytest.raises(UpxInputNotFoundError) as caught:
        run_upx_test(_exe(tmp_path), tmp_path / "gone.exe", input_sha256="0" * 64)
    assert caught.value.code == UpxErrorCode.INPUT_NOT_FOUND


def test_probe_version_reports_a_missing_executable(tmp_path: Path) -> None:
    with pytest.raises(UpxExecutableNotFoundError):
        probe_upx_version(tmp_path / "not-there")


def test_capture_enforces_the_stderr_output_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    """A quiet stdout with a runaway stderr must trip the stderr limit branch."""
    from tests.unit.test_upx import _FakeProcess

    process = _FakeProcess(b"", stderr=b"x" * 64)
    monkeypatch.setattr(upx_adapter.subprocess, "Popen", lambda *a, **k: process)
    with pytest.raises(UpxOutputLimitError) as caught:
        upx_adapter._capture_process(["fake-upx"], timeout=1.0, max_output_size=8)
    assert caught.value.details["stream"] == "stderr"


def test_capture_reports_a_process_without_pipes(monkeypatch: pytest.MonkeyPatch) -> None:
    class _NoPipes:
        pid = 0
        stdout = None
        stderr = None

        def poll(self) -> int:
            return 0

    monkeypatch.setattr(upx_adapter.subprocess, "Popen", lambda *a, **k: _NoPipes())
    monkeypatch.setattr(upx_adapter, "_terminate_process", lambda _child: None)
    with pytest.raises(UpxProcessError) as caught:
        upx_adapter._capture_process(["fake-upx"], timeout=1.0, max_output_size=8)
    assert caught.value.code == UpxErrorCode.PROCESS_FAILED


def test_test_upx_detects_input_mutated_during_the_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exe = _exe(tmp_path)
    sample = _write_sample(tmp_path / "packed.exe")
    digest = file_sha256(sample)

    def fake_capture(argv: list[str], *, timeout: float, max_output_size: int) -> Any:
        del timeout, max_output_size
        if argv[1:] == ["--version"]:
            return _VERSION
        sample.write_bytes(b"changed-mid-test")
        return upx_adapter._ProcessCapture(
            stdout="", stderr="", returncode=0, stdout_exceeded=False, stderr_exceeded=False
        )

    monkeypatch.setattr(upx_adapter, "_capture_process", fake_capture)
    with pytest.raises(UpxScanError) as caught:
        run_upx_test(exe, sample, input_sha256=digest)
    assert caught.value.code == UpxErrorCode.INPUT_MUTATED


def test_unpack_rejects_a_sha_mismatch_before_spawning(tmp_path: Path) -> None:
    exe = _exe(tmp_path)
    sample = _write_sample(tmp_path / "packed.exe")
    output = tmp_path / "out.exe"
    with pytest.raises(UpxScanError) as caught:
        unpack_upx(exe, sample, output, input_sha256="0" * 64)
    assert caught.value.code == UpxErrorCode.INPUT_MUTATED
    assert not output.exists()


def test_unpack_process_failure_removes_the_partial_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exe = _exe(tmp_path)
    sample = _write_sample(tmp_path / "packed.exe")
    digest = file_sha256(sample)
    output = tmp_path / "artifacts" / "out.exe"

    def fake_capture(argv: list[str], *, timeout: float, max_output_size: int) -> Any:
        del timeout, max_output_size
        if argv[1:] == ["--version"]:
            return _VERSION
        Path(argv[3]).parent.mkdir(parents=True, exist_ok=True)
        Path(argv[3]).write_bytes(b"partial")
        return upx_adapter._ProcessCapture(
            stdout="", stderr="boom", returncode=2, stdout_exceeded=False, stderr_exceeded=False
        )

    monkeypatch.setattr(upx_adapter, "_capture_process", fake_capture)
    with pytest.raises(UpxProcessError) as caught:
        unpack_upx(exe, sample, output, input_sha256=digest)
    assert caught.value.code == UpxErrorCode.PROCESS_FAILED
    assert not output.exists(), "a failed unpack must not leave a partial file"


def test_unpack_reports_success_with_no_output_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exe = _exe(tmp_path)
    sample = _write_sample(tmp_path / "packed.exe")
    digest = file_sha256(sample)
    output = tmp_path / "artifacts" / "out.exe"

    def fake_capture(argv: list[str], *, timeout: float, max_output_size: int) -> Any:
        del timeout, max_output_size
        if argv[1:] == ["--version"]:
            return _VERSION
        return upx_adapter._ProcessCapture(
            stdout="ok", stderr="", returncode=0, stdout_exceeded=False, stderr_exceeded=False
        )

    monkeypatch.setattr(upx_adapter, "_capture_process", fake_capture)
    with pytest.raises(UpxScanError) as caught:
        unpack_upx(exe, sample, output, input_sha256=digest)
    assert caught.value.code == UpxErrorCode.OUTPUT_MISSING


def test_unpack_rejects_an_output_larger_than_the_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exe = _exe(tmp_path)
    sample = _write_sample(tmp_path / "packed.exe")  # 16 bytes
    digest = file_sha256(sample)
    output = tmp_path / "artifacts" / "out.exe"

    def fake_capture(argv: list[str], *, timeout: float, max_output_size: int) -> Any:
        del timeout, max_output_size
        if argv[1:] == ["--version"]:
            return _VERSION
        Path(argv[3]).parent.mkdir(parents=True, exist_ok=True)
        Path(argv[3]).write_bytes(b"y" * 100)
        return upx_adapter._ProcessCapture(
            stdout="", stderr="", returncode=0, stdout_exceeded=False, stderr_exceeded=False
        )

    monkeypatch.setattr(upx_adapter, "_capture_process", fake_capture)
    with pytest.raises(UpxInputTooLargeError):
        unpack_upx(exe, sample, output, input_sha256=digest, max_file_size=50)
    assert not output.exists(), "an oversized output must be removed"


def test_unpack_detects_input_mutated_during_the_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exe = _exe(tmp_path)
    sample = _write_sample(tmp_path / "packed.exe")
    digest = file_sha256(sample)
    output = tmp_path / "artifacts" / "out.exe"

    def fake_capture(argv: list[str], *, timeout: float, max_output_size: int) -> Any:
        del timeout, max_output_size
        if argv[1:] == ["--version"]:
            return _VERSION
        Path(argv[3]).parent.mkdir(parents=True, exist_ok=True)
        Path(argv[3]).write_bytes(b"unpacked")
        sample.write_bytes(b"changed-mid-unpack")
        return upx_adapter._ProcessCapture(
            stdout="", stderr="", returncode=0, stdout_exceeded=False, stderr_exceeded=False
        )

    monkeypatch.setattr(upx_adapter, "_capture_process", fake_capture)
    with pytest.raises(UpxScanError) as caught:
        unpack_upx(exe, sample, output, input_sha256=digest)
    assert caught.value.code == UpxErrorCode.INPUT_MUTATED
    assert not output.exists(), "a mutation-during-unpack must remove the output"


def test_successful_unpack_result_serializes_to_a_dict(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exe = _exe(tmp_path)
    sample = _write_sample(tmp_path / "packed.exe")
    digest = file_sha256(sample)
    output = tmp_path / "artifacts" / "out.exe"

    def fake_capture(argv: list[str], *, timeout: float, max_output_size: int) -> Any:
        del timeout, max_output_size
        if argv[1:] == ["--version"]:
            return _VERSION
        Path(argv[3]).parent.mkdir(parents=True, exist_ok=True)
        Path(argv[3]).write_bytes(b"MZ-unpacked")
        return upx_adapter._ProcessCapture(
            stdout="Unpacked 1 file.\n",
            stderr="",
            returncode=0,
            stdout_exceeded=False,
            stderr_exceeded=False,
        )

    monkeypatch.setattr(upx_adapter, "_capture_process", fake_capture)
    result = unpack_upx(exe, sample, output, input_sha256=digest)
    payload = result.to_dict()
    assert isinstance(payload, dict)
    assert payload["operation"] == UpxOperation.UNPACK.value
    assert payload["ok"] is True
    assert payload["output_size"] == len(b"MZ-unpacked")


def test_copy_input_for_safe_pack_creates_parents_and_copies(tmp_path: Path) -> None:
    source = tmp_path / "sample.exe"
    source.write_bytes(b"MZ-body")
    destination = tmp_path / "nested" / "copy.exe"
    result = copy_input_for_safe_pack(source, destination)
    assert result == destination.resolve()
    assert destination.read_bytes() == b"MZ-body"
