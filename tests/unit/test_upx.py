from __future__ import annotations

import io
import os
import subprocess
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.core.session import file_sha256
from headless_re_mcp.unpack import upx as upx_adapter
from headless_re_mcp.unpack.upx import (
    UpxErrorCode,
    UpxInputTooLargeError,
    UpxOperation,
    UpxOutputLimitError,
    UpxProcessError,
    UpxScanError,
    UpxTimeoutError,
    probe_upx_version,
    unpack_upx,
)

# Alias: production API is named test_upx; keep it out of pytest collection.
run_upx_test = upx_adapter.test_upx


def _write_sample(path: Path, payload: bytes = b"MZ-packed-sample") -> Path:
    path.write_bytes(payload)
    return path


class _FakeProcess:
    def __init__(
        self,
        stdout: bytes,
        stderr: bytes = b"",
        *,
        returncode: int | None = 0,
        hangs: bool = False,
    ) -> None:
        self.stdout = io.BytesIO(stdout)
        self.stderr = io.BytesIO(stderr)
        self._returncode = None if hangs else returncode
        self._hangs = hangs
        self.killed = False

    def poll(self) -> int | None:
        return self._returncode

    def wait(self, timeout: float | None = None) -> int:
        del timeout
        if self._hangs and not self.killed:
            raise subprocess.TimeoutExpired("fake-upx", 0.01)
        if self._returncode is None:
            self._returncode = -9
        return self._returncode

    def kill(self) -> None:
        self.killed = True
        self._hangs = False
        self._returncode = -9


def test_test_upx_uses_whitelisted_argv_and_preserves_input(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable = tmp_path / "upx.exe"
    executable.write_bytes(b"fake-upx")
    sample = _write_sample(tmp_path / "packed.exe")
    digest = file_sha256(sample)
    seen: list[list[str]] = []

    def fake_capture(
        argv: list[str], *, timeout: float, max_output_size: int
    ) -> upx_adapter._ProcessCapture:
        del timeout, max_output_size
        seen.append(list(argv))
        if argv[1:] == ["--version"]:
            return upx_adapter._ProcessCapture(
                stdout="upx 5.2.0\n",
                stderr="",
                returncode=0,
                stdout_exceeded=False,
                stderr_exceeded=False,
            )
        assert argv[1:] == ["-t", str(sample.resolve())]
        return upx_adapter._ProcessCapture(
            stdout="testing... OK\n",
            stderr="",
            returncode=0,
            stdout_exceeded=False,
            stderr_exceeded=False,
        )

    monkeypatch.setattr(upx_adapter, "_capture_process", fake_capture)
    result = run_upx_test(executable, sample, input_sha256=digest)

    assert result.ok
    assert result.operation == UpxOperation.TEST
    assert result.version == "5.2.0"
    assert result.input_sha256 == digest
    assert file_sha256(sample) == digest
    assert all(argv[0] == str(executable.resolve()) for argv in seen)
    assert not any("-o" in argv or "--ultra-brute" in argv for argv in seen)
    assert [argv[1] for argv in seen] == ["--version", "-t"]


def test_unpack_upx_writes_output_without_mutating_input(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable = tmp_path / "upx.exe"
    executable.write_bytes(b"fake-upx")
    sample = _write_sample(tmp_path / "packed.exe", b"MZ-original-bytes")
    digest = file_sha256(sample)
    output = tmp_path / "artifacts" / "session" / "unpacked.exe"
    seen: list[list[str]] = []

    def fake_capture(
        argv: list[str], *, timeout: float, max_output_size: int
    ) -> upx_adapter._ProcessCapture:
        del timeout, max_output_size
        seen.append(list(argv))
        if argv[1:] == ["--version"]:
            return upx_adapter._ProcessCapture(
                stdout="upx 5.2.0\n",
                stderr="",
                returncode=0,
                stdout_exceeded=False,
                stderr_exceeded=False,
            )
        assert argv[1:3] == ["-d", "-o"]
        assert argv[3] == str(output.resolve())
        assert argv[4] == str(sample.resolve())
        Path(argv[3]).parent.mkdir(parents=True, exist_ok=True)
        Path(argv[3]).write_bytes(b"MZ-unpacked-bytes")
        return upx_adapter._ProcessCapture(
            stdout="Unpacked 1 file.\n",
            stderr="",
            returncode=0,
            stdout_exceeded=False,
            stderr_exceeded=False,
        )

    monkeypatch.setattr(upx_adapter, "_capture_process", fake_capture)
    result = unpack_upx(executable, sample, output, input_sha256=digest)

    assert result.ok
    assert result.operation == UpxOperation.UNPACK
    assert result.output_path == output.resolve()
    assert result.output_sha256 == file_sha256(output)
    assert sample.read_bytes() == b"MZ-original-bytes"
    assert file_sha256(sample) == digest
    assert [argv[1] for argv in seen] == ["--version", "-d"]
    assert not any(
        "--" in flag
        for argv in seen
        for flag in argv[1:]
        if flag.startswith("--") and flag != "--version"
    )


def test_unpack_rejects_same_output_path(tmp_path: Path) -> None:
    executable = tmp_path / "upx.exe"
    executable.write_bytes(b"fake")
    sample = _write_sample(tmp_path / "packed.exe")
    with pytest.raises(UpxScanError) as caught:
        unpack_upx(
            executable,
            sample,
            sample,
            input_sha256=file_sha256(sample),
        )
    assert caught.value.code == UpxErrorCode.INVALID_ARGUMENT


def test_test_upx_detects_mutated_input_before_spawn(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable = tmp_path / "upx.exe"
    executable.write_bytes(b"fake")
    sample = _write_sample(tmp_path / "packed.exe")
    called = False

    def fail_if_spawned(*args: Any, **kwargs: Any) -> Any:
        nonlocal called
        called = True
        raise AssertionError("upx must not start when input sha mismatches")

    monkeypatch.setattr(upx_adapter, "_capture_process", fail_if_spawned)
    with pytest.raises(UpxScanError) as caught:
        run_upx_test(executable, sample, input_sha256="0" * 64)
    assert caught.value.code == UpxErrorCode.INPUT_MUTATED
    assert not called


def test_process_capture_timeout_kills_child(monkeypatch: pytest.MonkeyPatch) -> None:
    process = _FakeProcess(b"", hangs=True)
    monkeypatch.setattr(upx_adapter.subprocess, "Popen", lambda *args, **kwargs: process)

    with pytest.raises(UpxTimeoutError) as caught:
        upx_adapter._capture_process(["fake-upx"], timeout=0.01, max_output_size=32)
    assert process.killed
    assert caught.value.code == UpxErrorCode.TIMEOUT


def test_process_capture_cleanup_shares_one_drain_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Stuck reader threads must not add four seconds of joins after a timeout."""
    clock = [0.0]
    join_timeouts: list[float] = []

    class _StuckThread:
        def __init__(self, *args: object, **kwargs: object) -> None:
            del args, kwargs

        def start(self) -> None:
            return None

        def is_alive(self) -> bool:
            # Model a reader wedged on an orphaned grandchild's pipe so the
            # cleanup path exercises every join instead of closing early.
            return True

        def join(self, timeout: float | None = None) -> None:
            budget = float(timeout or 0.0)
            join_timeouts.append(budget)
            clock[0] += budget

    def _advance_clock(seconds: float) -> None:
        clock[0] += seconds

    process = _FakeProcess(b"", hangs=True)
    monkeypatch.setattr(upx_adapter.subprocess, "Popen", lambda *a, **k: process)
    monkeypatch.setattr(upx_adapter, "Thread", _StuckThread)
    monkeypatch.setattr(upx_adapter, "monotonic", lambda: clock[0])
    monkeypatch.setattr(upx_adapter, "sleep", _advance_clock)
    monkeypatch.setattr(upx_adapter, "_terminate_process", lambda child: child.kill())

    with pytest.raises(UpxTimeoutError):
        upx_adapter._capture_process(["fake-upx"], timeout=0.1, max_output_size=32)

    assert join_timeouts, "cleanup should join the reader threads"
    assert sum(join_timeouts) <= 2.0


def test_process_capture_enforces_output_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    process = _FakeProcess(b"x" * 64)
    monkeypatch.setattr(upx_adapter.subprocess, "Popen", lambda *args, **kwargs: process)

    with pytest.raises(UpxOutputLimitError) as caught:
        upx_adapter._capture_process(["fake-upx"], timeout=1.0, max_output_size=8)
    assert caught.value.code == UpxErrorCode.OUTPUT_LIMIT
    assert caught.value.details["stream"] == "stdout"
    assert len(caught.value.stdout.encode()) <= 8


def test_test_upx_surfaces_process_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable = tmp_path / "upx.exe"
    executable.write_bytes(b"fake")
    sample = _write_sample(tmp_path / "packed.exe")
    digest = file_sha256(sample)

    def fake_capture(
        argv: list[str], *, timeout: float, max_output_size: int
    ) -> upx_adapter._ProcessCapture:
        del timeout, max_output_size
        if argv[1:] == ["--version"]:
            return upx_adapter._ProcessCapture(
                stdout="upx 5.2.0\n",
                stderr="",
                returncode=0,
                stdout_exceeded=False,
                stderr_exceeded=False,
            )
        return upx_adapter._ProcessCapture(
            stdout="",
            stderr="not packed by UPX",
            returncode=1,
            stdout_exceeded=False,
            stderr_exceeded=False,
        )

    monkeypatch.setattr(upx_adapter, "_capture_process", fake_capture)
    with pytest.raises(UpxProcessError) as caught:
        run_upx_test(executable, sample, input_sha256=digest)
    assert caught.value.code == UpxErrorCode.PROCESS_FAILED
    assert file_sha256(sample) == digest


def test_oversized_input_rejected_before_spawn(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable = tmp_path / "upx.exe"
    executable.write_bytes(b"fake")
    sample = _write_sample(tmp_path / "packed.exe", b"12345")
    called = False

    def fail_if_spawned(*args: Any, **kwargs: Any) -> Any:
        nonlocal called
        called = True
        raise AssertionError("upx must not start for oversized input")

    monkeypatch.setattr(upx_adapter, "_capture_process", fail_if_spawned)
    with pytest.raises(UpxInputTooLargeError) as caught:
        run_upx_test(
            executable,
            sample,
            input_sha256=file_sha256(sample),
            max_file_size=4,
        )
    assert caught.value.code == UpxErrorCode.INPUT_TOO_LARGE
    assert not called


def test_probe_upx_version_parses_stdout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable = tmp_path / "upx.exe"
    executable.write_bytes(b"fake")

    monkeypatch.setattr(
        upx_adapter,
        "_capture_process",
        lambda argv, *, timeout, max_output_size: upx_adapter._ProcessCapture(
            stdout="upx 4.2.4\nCopyright",
            stderr="",
            returncode=0,
            stdout_exceeded=False,
            stderr_exceeded=False,
        ),
    )
    assert probe_upx_version(executable) == "4.2.4"


def test_no_shell_and_no_window_options_are_explicit() -> None:
    options = upx_adapter._creation_options()
    assert options["shell"] is False
    assert options["stdin"] is subprocess.DEVNULL
    assert options["stdout"] is subprocess.PIPE
    assert options["stderr"] is subprocess.PIPE
    assert options["text"] is False
    if os.name == "nt":
        assert options["creationflags"] & getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
