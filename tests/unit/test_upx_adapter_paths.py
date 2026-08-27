"""Branch coverage for the UPX CLI adapter.

upx is absent on CI, so scan-level behaviour is driven through a stubbed
capture whose side effects (mutating the input, creating or withholding the
destination, failing exit codes) exercise the post-run guards, and
process-level edges through fake processes. Discovery-style validation and
the Windows creation options are covered directly.
"""

from __future__ import annotations

import io
import os
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from threading import Event
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
    UpxResult,
    UpxScanError,
    UpxTimeoutError,
    copy_input_for_safe_pack,
    probe_upx_version,
    unpack_upx,
)

# Alias: production API is named test_upx; keep it out of pytest collection.
run_upx_test = upx_adapter.test_upx


def _sample(tmp_path: Path) -> tuple[Path, Path, str]:
    executable = tmp_path / "upx"
    executable.write_bytes(b"fake-upx")
    packed = tmp_path / "packed.exe"
    packed.write_bytes(b"MZ-packed")
    return executable, packed, file_sha256(packed)


def _capture(stdout: str = "", stderr: str = "", returncode: int = 0) -> Any:
    return upx_adapter._ProcessCapture(stdout, stderr, returncode, False, False)


def _dispatching_run(on_run: Any) -> Any:
    """A _capture_process stub: version probes succeed, real runs delegate."""

    def fake(argv: list[str], *, timeout: float, max_output_size: int) -> Any:
        if "--version" in argv:
            return _capture(stdout="upx 4.2.1")
        return on_run(argv)

    return fake


# ---------------------------------------------------------------------------
# validation
# ---------------------------------------------------------------------------


def test_validate_paths_requires_executable_and_input(tmp_path: Path) -> None:
    executable, packed, _sha = _sample(tmp_path)
    with pytest.raises(UpxScanError) as no_exe:
        upx_adapter._validate_paths(tmp_path / "absent-upx", packed, max_file_size=1024)
    assert no_exe.value.code == UpxErrorCode.EXECUTABLE_NOT_FOUND
    with pytest.raises(UpxScanError) as no_input:
        upx_adapter._validate_paths(executable, tmp_path / "absent.exe", max_file_size=1024)
    assert no_input.value.code == UpxErrorCode.INPUT_NOT_FOUND


def test_probe_upx_version_requires_the_executable(tmp_path: Path) -> None:
    with pytest.raises(UpxScanError) as caught:
        probe_upx_version(tmp_path / "absent-upx")
    assert caught.value.code == UpxErrorCode.EXECUTABLE_NOT_FOUND


def test_to_dict_rejects_a_non_object_serialization(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable, packed, sha = _sample(tmp_path)
    now = datetime.now(UTC)
    result = UpxResult(
        operation=UpxOperation.TEST,
        executable=executable,
        input_path=packed,
        input_sha256=sha,
        input_size=9,
        ok=True,
        stdout="",
        stderr="",
        returncode=0,
        started_at=now,
        finished_at=now,
    )
    assert result.to_dict()["operation"] == "test"
    monkeypatch.setattr(upx_adapter.UpxResult, "model_dump", lambda self, **kw: [])
    with pytest.raises(TypeError):
        result.to_dict()


# ---------------------------------------------------------------------------
# test_upx / unpack_upx guards
# ---------------------------------------------------------------------------


def test_test_upx_detects_mutation_during_the_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable, packed, sha = _sample(tmp_path)

    def mutate(argv: list[str]) -> Any:
        Path(argv[-1]).write_bytes(b"MZ-tampered")
        return _capture(stdout="OK")

    monkeypatch.setattr(upx_adapter, "_capture_process", _dispatching_run(mutate))
    with pytest.raises(UpxScanError) as caught:
        run_upx_test(executable, packed, input_sha256=sha)
    assert caught.value.code == UpxErrorCode.INPUT_MUTATED
    assert "mutated the original input" in str(caught.value)


def test_unpack_rejects_an_input_that_changed_before_the_run(tmp_path: Path) -> None:
    executable, packed, _sha = _sample(tmp_path)
    with pytest.raises(UpxScanError) as caught:
        unpack_upx(executable, packed, tmp_path / "out.exe", input_sha256="0" * 64)
    assert caught.value.code == UpxErrorCode.INPUT_MUTATED
    assert "changed before unpack" in str(caught.value)


def test_unpack_rejects_a_destination_equal_to_the_input(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable, packed, sha = _sample(tmp_path)
    resolved = packed.resolve()
    real_exists = Path.exists

    # The exists() guard normally shadows the equality guard; pretend the
    # input vanished between the checks so the equality arm is reachable.
    def fake_exists(self: Path) -> bool:
        return False if self == resolved else real_exists(self)

    monkeypatch.setattr(Path, "exists", fake_exists)
    with pytest.raises(UpxScanError) as caught:
        unpack_upx(executable, packed, packed, input_sha256=sha)
    assert "must differ from the input path" in str(caught.value)


@pytest.mark.parametrize("emit_output", [True, False])
def test_unpack_discards_output_when_the_input_was_mutated(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, emit_output: bool
) -> None:
    executable, packed, sha = _sample(tmp_path)
    destination = tmp_path / "artifacts" / "out.exe"

    def mutate_and_emit(argv: list[str]) -> Any:
        if emit_output:
            Path(argv[3]).write_bytes(b"MZ-unpacked")
        Path(argv[4]).write_bytes(b"MZ-tampered")
        return _capture(stdout="Unpacked 1 file.")

    monkeypatch.setattr(upx_adapter, "_capture_process", _dispatching_run(mutate_and_emit))
    with pytest.raises(UpxScanError) as caught:
        unpack_upx(executable, packed, destination, input_sha256=sha)
    assert caught.value.code == UpxErrorCode.INPUT_MUTATED
    assert not destination.exists()


@pytest.mark.parametrize("emit_output", [True, False])
def test_unpack_discards_output_when_upx_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, emit_output: bool
) -> None:
    executable, packed, sha = _sample(tmp_path)
    destination = tmp_path / "artifacts" / "out.exe"

    def fail_but_emit(argv: list[str]) -> Any:
        if emit_output:
            Path(argv[3]).write_bytes(b"MZ-partial")
        return _capture(stderr="NotPackedException", returncode=2)

    monkeypatch.setattr(upx_adapter, "_capture_process", _dispatching_run(fail_but_emit))
    with pytest.raises(UpxProcessError) as caught:
        unpack_upx(executable, packed, destination, input_sha256=sha)
    assert caught.value.returncode == 2
    assert not destination.exists()


def test_unpack_reports_a_missing_output_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable, packed, sha = _sample(tmp_path)
    monkeypatch.setattr(
        upx_adapter,
        "_capture_process",
        _dispatching_run(lambda argv: _capture(stdout="Unpacked 1 file.")),
    )
    with pytest.raises(UpxScanError) as caught:
        unpack_upx(executable, packed, tmp_path / "out.exe", input_sha256=sha)
    assert caught.value.code == UpxErrorCode.OUTPUT_MISSING


def test_unpack_discards_an_oversized_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable, packed, sha = _sample(tmp_path)
    destination = tmp_path / "out.exe"

    def emit_large(argv: list[str]) -> Any:
        Path(argv[3]).write_bytes(b"X" * 64)
        return _capture(stdout="Unpacked 1 file.")

    monkeypatch.setattr(upx_adapter, "_capture_process", _dispatching_run(emit_large))
    with pytest.raises(UpxInputTooLargeError):
        unpack_upx(executable, packed, destination, input_sha256=sha, max_file_size=16)
    assert not destination.exists()


# ---------------------------------------------------------------------------
# stream capture edges
# ---------------------------------------------------------------------------


class _FakeProcess:
    def __init__(
        self,
        stdout: bytes,
        stderr: bytes = b"",
        *,
        returncode: int | None = 0,
    ) -> None:
        self.stdout: Any = io.BytesIO(stdout)
        self.stderr: Any = io.BytesIO(stderr)
        self.pid = 4242
        self._returncode = returncode
        self.killed = False

    def poll(self) -> int | None:
        return self._returncode

    def wait(self, timeout: float | None = None) -> int:
        del timeout
        if self._returncode is None:
            self._returncode = -9
        return self._returncode

    def kill(self) -> None:
        self.killed = True
        self._returncode = -9


def test_captured_stream_discards_bytes_past_a_zero_budget() -> None:
    stream = upx_adapter._CapturedStream(0)
    exceeded = Event()
    stream.read_from(io.BytesIO(b"abc"), exceeded)
    assert stream.exceeded is True
    assert exceeded.is_set()
    assert stream.text() == ""


def test_captured_stream_survives_a_pipe_error() -> None:
    class _ExplodingPipe:
        def read(self, size: int) -> bytes:
            raise OSError("gone")

        def close(self) -> None:
            raise OSError("also gone")

    stream = upx_adapter._CapturedStream(8)
    stream.read_from(_ExplodingPipe(), Event())  # type: ignore[arg-type]
    assert stream.text() == ""
    assert stream.finished.is_set()


def test_capture_process_rejects_missing_pipes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = _FakeProcess(b"")
    process.stdout = None
    terminated: list[Any] = []
    monkeypatch.setattr(upx_adapter, "_terminate_process", terminated.append)
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: process)
    with pytest.raises(UpxProcessError) as caught:
        upx_adapter._capture_process(["fake-upx"], timeout=1.0, max_output_size=8)
    assert "stdout/stderr pipes" in str(caught.value)
    assert terminated == [process]


def test_capture_process_reports_a_stderr_flood(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = _FakeProcess(b"{}", b"y" * 64)
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: process)
    with pytest.raises(UpxOutputLimitError) as caught:
        upx_adapter._capture_process(["fake-upx"], timeout=5.0, max_output_size=8)
    assert caught.value.details["stream"] == "stderr"


def test_capture_process_reports_an_unknowable_exit_code_after_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _NeverReports(_FakeProcess):
        def poll(self) -> int | None:
            return None

    process = _NeverReports(b"")
    from headless_re_mcp.core import process_tree

    monkeypatch.setattr(process_tree, "terminate_leftover_process_tree", lambda p, wait_s=1.0: None)
    monkeypatch.setattr(upx_adapter, "_terminate_process", lambda p: None)
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: process)
    with pytest.raises(UpxTimeoutError) as caught:
        upx_adapter._capture_process(["fake-upx"], timeout=0.01, max_output_size=8)
    assert caught.value.returncode == -1


def test_capture_process_returns_a_clean_exit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = _FakeProcess(b"upx ok", b"")
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: process)
    capture = upx_adapter._capture_process(["fake-upx"], timeout=5.0, max_output_size=64)
    assert capture.stdout == "upx ok"
    assert capture.returncode == 0


def test_capture_process_honours_a_bound_cancel(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from headless_re_mcp.backends.common.bounded_run import (
        BoundedCancelled,
        bound_cancel_scope,
    )

    cancel = Event()
    cancel.set()
    process = _FakeProcess(b"", returncode=None)
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: process)
    with bound_cancel_scope(cancel), pytest.raises(BoundedCancelled):
        upx_adapter._capture_process(["fake-upx"], timeout=5.0, max_output_size=64)
    assert process.killed


def test_creation_options_hide_the_windows_console(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _FakeStartupInfo:
        def __init__(self) -> None:
            self.dwFlags = 0
            self.wShowWindow = 99

    monkeypatch.setattr(os, "name", "nt")
    monkeypatch.setattr(subprocess, "STARTUPINFO", _FakeStartupInfo, raising=False)
    monkeypatch.setattr(subprocess, "STARTF_USESHOWWINDOW", 1, raising=False)
    options = upx_adapter._creation_options()
    assert options["creationflags"] != 0
    assert options["startupinfo"].wShowWindow == 0
    assert "start_new_session" not in options


def test_creation_options_skip_startupinfo_when_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(os, "name", "nt")
    monkeypatch.delattr(subprocess, "STARTUPINFO", raising=False)
    options = upx_adapter._creation_options()
    assert "startupinfo" not in options


# ---------------------------------------------------------------------------
# fixture helper
# ---------------------------------------------------------------------------


def test_copy_input_for_safe_pack_copies_into_a_new_tree(tmp_path: Path) -> None:
    source = tmp_path / "in" / "sample.exe"
    source.parent.mkdir()
    source.write_bytes(b"MZ")
    destination = tmp_path / "out" / "copy.exe"
    copied = copy_input_for_safe_pack(source, destination)
    assert copied == destination.resolve()
    assert copied.read_bytes() == b"MZ"
