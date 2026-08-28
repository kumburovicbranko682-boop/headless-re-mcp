"""Targeted coverage for :mod:`headless_re_mcp.detection.exeinfope` edge paths.

These exercise the validators, resolve/log helpers, parser branches, the two
Windows-only branches (via monkeypatch), the process-capture limit/cleanup
arcs, and the reusable CLI adapter that the happy-path suite does not reach.
"""

from __future__ import annotations

import ctypes
import io
import subprocess
from pathlib import Path
from threading import Event
from typing import Any

import pytest

from headless_re_mcp.detection import exeinfope as adapter
from headless_re_mcp.detection.exeinfope import (
    ExeinfopeCliAdapter,
    ExeinfopeErrorCode,
    ExeinfopeExecutableNotFoundError,
    ExeinfopeGuiWindowError,
    ExeinfopeInputNotFoundError,
    ExeinfopeOutputLimitError,
    ExeinfopeProcessError,
    ExeinfopeProtocolError,
    ExeinfopeScanError,
    scan_with_exeinfope,
)
from headless_re_mcp.detection.models import FindingCategory, ScanMode


def _real_binaries(tmp_path: Path) -> tuple[Path, Path]:
    executable = tmp_path / "Exeinfope.exe"
    executable.write_bytes(b"fake")
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ")
    return executable, sample


def _fake_capture(*, returncode: int = 0) -> adapter._ProcessCapture:
    return adapter._ProcessCapture(
        stdout="",
        stderr="",
        returncode=returncode,
        stdout_exceeded=False,
        stderr_exceeded=False,
        analyzer_windows=(),
    )


# --------------------------------------------------------------------------- #
# _CapturedStream.read_from                                                    #
# --------------------------------------------------------------------------- #


class _ChunkPipe:
    def __init__(self, chunks: list[bytes]) -> None:
        self._chunks = list(chunks)
        self.closed = False

    def read(self, _size: int) -> bytes:
        if self._chunks:
            return self._chunks.pop(0)
        return b""

    def close(self) -> None:
        self.closed = True


class _RaisingPipe:
    def read(self, _size: int) -> bytes:
        raise OSError("pipe exploded")

    def close(self) -> None:
        return None


def test_captured_stream_stops_extending_once_the_limit_is_reached() -> None:
    stream = adapter._CapturedStream(limit=4)
    pipe = _ChunkPipe([b"xxxx", b"yyyy"])

    stream.read_from(pipe, Event())  # type: ignore[arg-type]

    assert stream.text() == "xxxx"
    assert stream.exceeded is True
    assert pipe.closed is True
    assert stream.finished.is_set()


def test_captured_stream_swallows_pipe_errors() -> None:
    stream = adapter._CapturedStream(limit=16)

    stream.read_from(_RaisingPipe(), Event())  # type: ignore[arg-type]

    assert stream.text() == ""
    assert stream.exceeded is False
    assert stream.finished.is_set()


# --------------------------------------------------------------------------- #
# _creation_options / window helpers (Windows branches)                       #
# --------------------------------------------------------------------------- #


def test_creation_options_configures_a_hidden_window_on_windows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _FakeStartupInfo:
        def __init__(self) -> None:
            self.dwFlags = 0
            self.wShowWindow = 7

    monkeypatch.setattr(adapter.os, "name", "nt")
    monkeypatch.setattr(adapter.subprocess, "STARTUPINFO", _FakeStartupInfo, raising=False)

    options = adapter._creation_options()

    assert "start_new_session" not in options
    startupinfo = options["startupinfo"]
    assert isinstance(startupinfo, _FakeStartupInfo)
    assert startupinfo.wShowWindow == 0
    assert startupinfo.dwFlags == getattr(subprocess, "STARTF_USESHOWWINDOW", 1)


def test_creation_options_skips_startupinfo_when_the_sdk_lacks_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(adapter.os, "name", "nt")
    monkeypatch.delattr(adapter.subprocess, "STARTUPINFO", raising=False)

    options = adapter._creation_options()

    assert "startupinfo" not in options
    assert options["creationflags"] == getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)


def test_is_visible_window_treats_unparseable_handles_as_visible() -> None:
    assert adapter._is_visible_window("zzz:TForm1", visible_check=lambda _hwnd: False) is True


def test_is_visible_window_treats_os_errors_as_visible() -> None:
    def boom(_hwnd: int) -> bool:
        raise OSError("bad handle")

    assert adapter._is_visible_window("0x1:TForm1", visible_check=boom) is True


def test_visible_blocked_windows_uses_win32_visibility_on_windows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _User32:
        @staticmethod
        def IsWindowVisible(_hwnd: int) -> bool:
            return True

    class _Windll:
        user32 = _User32()

    monkeypatch.setattr(adapter.os, "name", "nt")
    monkeypatch.setattr(ctypes, "windll", _Windll(), raising=False)

    blocked = adapter._visible_blocked_windows({"0x1:TForm1:Exeinfo PE", "0x2:IME:noise"})

    assert blocked == ["0x1:TForm1:Exeinfo PE"]


# --------------------------------------------------------------------------- #
# _capture_process arcs                                                        #
# --------------------------------------------------------------------------- #


class _PidlessHang:
    """Poll never resolves and there is no pid, so the monitor and group-assign
    both take their no-pid branch until the deadline fires."""

    pid = None

    def __init__(self) -> None:
        self.stdout = io.BytesIO(b"")
        self.stderr = io.BytesIO(b"")

    def poll(self) -> int | None:
        return None

    def wait(self, timeout: float | None = None) -> int:
        raise subprocess.TimeoutExpired("fake", float(timeout or 0.0))

    def kill(self) -> None:
        return None


def test_capture_without_a_pid_times_out_through_the_no_pid_branches(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = _PidlessHang()
    monkeypatch.setattr(adapter.subprocess, "Popen", lambda *a, **k: process)
    monkeypatch.setattr(adapter, "_terminate_process", lambda child: None)
    monkeypatch.setattr(
        "headless_re_mcp.core.process_tree.terminate_leftover_process_tree",
        lambda *a, **k: None,
    )

    with pytest.raises(adapter.ExeinfopeTimeoutError):
        adapter._capture_process(
            ["fake"],
            timeout=0.15,
            max_output_size=32,
            window_observer=lambda _pid: set(),
        )


def test_capture_maps_a_missing_executable(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*_a: Any, **_k: Any) -> Any:
        raise FileNotFoundError("no such binary")

    monkeypatch.setattr(adapter.subprocess, "Popen", boom)

    with pytest.raises(ExeinfopeExecutableNotFoundError):
        adapter._capture_process(["/no/such/exe"], timeout=1.0, max_output_size=32)


def test_capture_wraps_a_spawn_oserror(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*_a: Any, **_k: Any) -> Any:
        raise OSError("spawn refused")

    monkeypatch.setattr(adapter.subprocess, "Popen", boom)

    with pytest.raises(ExeinfopeProcessError) as caught:
        adapter._capture_process(["exeinfope"], timeout=1.0, max_output_size=32)
    assert caught.value.code == ExeinfopeErrorCode.PROCESS_FAILED


class _WindowedHang:
    """Never resolves so the loop keeps the monitor thread alive."""

    pid = 4242

    def __init__(self) -> None:
        self.stdout = io.BytesIO(b"")
        self.stderr = io.BytesIO(b"")

    def poll(self) -> int | None:
        return None

    def wait(self, timeout: float | None = None) -> int:
        raise subprocess.TimeoutExpired("fake", float(timeout or 0.0))

    def kill(self) -> None:
        return None


def test_capture_monitor_records_windows_for_a_live_pid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(adapter.subprocess, "Popen", lambda *a, **k: _WindowedHang())
    monkeypatch.setattr(adapter, "_terminate_process", lambda child: None)
    monkeypatch.setattr(
        "headless_re_mcp.core.process_tree.terminate_leftover_process_tree",
        lambda *a, **k: None,
    )
    monkeypatch.setattr(adapter, "describe_process_windows", lambda _pid: {"0x1:TWinStat:x"})

    with pytest.raises(adapter.ExeinfopeTimeoutError) as caught:
        adapter._capture_process(["fake"], timeout=0.2, max_output_size=32)

    assert "0x1:TWinStat:x" in caught.value.details["analyzer_windows"]


def test_capture_honors_an_active_bound_cancel(monkeypatch: pytest.MonkeyPatch) -> None:
    signal = Event()
    signal.set()
    monkeypatch.setattr(adapter.subprocess, "Popen", lambda *a, **k: _WindowedHang())
    monkeypatch.setattr(adapter, "active_bound_cancel", lambda: signal)
    monkeypatch.setattr(adapter, "_terminate_process", lambda child: None)
    monkeypatch.setattr(
        "headless_re_mcp.core.process_tree.terminate_leftover_process_tree",
        lambda *a, **k: None,
    )
    monkeypatch.setattr(adapter, "describe_process_windows", lambda _pid: set())

    with pytest.raises(adapter.BoundedCancelled):
        adapter._capture_process(["fake"], timeout=5.0, max_output_size=32)


class _WaitSucceeds:
    pid = 4242

    def __init__(self) -> None:
        self.stdout = io.BytesIO(b"")
        self.stderr = io.BytesIO(b"")

    def poll(self) -> int | None:
        return None

    def wait(self, timeout: float | None = None) -> int:
        del timeout
        return 0

    def kill(self) -> None:
        return None


def test_capture_completes_through_a_successful_wait(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(adapter.subprocess, "Popen", lambda *a, **k: _WaitSucceeds())
    monkeypatch.setattr(adapter, "describe_process_windows", lambda _pid: set())
    monkeypatch.setattr(
        "headless_re_mcp.core.process_tree.terminate_leftover_process_tree",
        lambda *a, **k: None,
    )

    capture = adapter._capture_process(["fake"], timeout=1.0, max_output_size=32)

    assert capture.returncode == 0


class _NoPipeProcess:
    pid = 4242
    stdout = None
    stderr = None

    def poll(self) -> int | None:
        return 0

    def wait(self, timeout: float | None = None) -> int:
        del timeout
        return 0

    def kill(self) -> None:
        return None


def test_capture_rejects_a_process_without_pipes(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(adapter.subprocess, "Popen", lambda *a, **k: _NoPipeProcess())
    monkeypatch.setattr(adapter, "_terminate_process", lambda child: None)

    with pytest.raises(ExeinfopeProcessError) as caught:
        adapter._capture_process(["fake"], timeout=1.0, max_output_size=32)

    assert caught.value.code == ExeinfopeErrorCode.PROCESS_FAILED


class _HangingLimitProcess:
    pid = 4242

    def __init__(self) -> None:
        self.stdout = io.BytesIO(b"x" * 64)
        self.stderr = io.BytesIO(b"")
        self.killed = False

    def poll(self) -> int | None:
        return -9 if self.killed else None

    def wait(self, timeout: float | None = None) -> int:
        if self.killed:
            return -9
        raise subprocess.TimeoutExpired("fake", float(timeout or 0.0))

    def kill(self) -> None:
        self.killed = True


def test_capture_kills_the_process_when_output_limit_trips_mid_run(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = _HangingLimitProcess()
    monkeypatch.setattr(adapter.subprocess, "Popen", lambda *a, **k: process)
    monkeypatch.setattr(adapter, "describe_process_windows", lambda _pid: set())
    monkeypatch.setattr(adapter, "_terminate_process", lambda child: child.kill())
    monkeypatch.setattr(
        "headless_re_mcp.core.process_tree.terminate_leftover_process_tree",
        lambda *a, **k: None,
    )

    with pytest.raises(ExeinfopeOutputLimitError) as caught:
        adapter._capture_process(["fake"], timeout=5.0, max_output_size=8)

    assert process.killed is True
    assert caught.value.details["stream"] == "stdout"


class _WaitFlakesAfterExit:
    """poll() reports a clean exit, but the confirming wait() in the finally
    block still raises, driving the post-loop terminate branch."""

    pid = 4242

    def __init__(self) -> None:
        self.stdout = io.BytesIO(b"")
        self.stderr = io.BytesIO(b"")

    def poll(self) -> int | None:
        return 0

    def wait(self, timeout: float | None = None) -> int:
        raise subprocess.TimeoutExpired("fake", float(timeout or 0.0))

    def kill(self) -> None:
        return None


def test_capture_terminates_when_the_confirming_wait_times_out(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = _WaitFlakesAfterExit()
    monkeypatch.setattr(adapter.subprocess, "Popen", lambda *a, **k: process)
    monkeypatch.setattr(adapter, "describe_process_windows", lambda _pid: set())
    monkeypatch.setattr(adapter, "_terminate_process", lambda child: None)
    monkeypatch.setattr(
        "headless_re_mcp.core.process_tree.terminate_leftover_process_tree",
        lambda *a, **k: None,
    )

    capture = adapter._capture_process(["fake"], timeout=1.0, max_output_size=32)

    assert capture.returncode == 0


class _StderrFloodProcess:
    pid = 4242

    def __init__(self) -> None:
        self.stdout = io.BytesIO(b"")
        self.stderr = io.BytesIO(b"e" * 64)

    def poll(self) -> int | None:
        return 0

    def wait(self, timeout: float | None = None) -> int:
        del timeout
        return 0

    def kill(self) -> None:
        return None


def test_capture_reports_a_stderr_output_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(adapter.subprocess, "Popen", lambda *a, **k: _StderrFloodProcess())
    monkeypatch.setattr(adapter, "describe_process_windows", lambda _pid: set())
    monkeypatch.setattr(
        "headless_re_mcp.core.process_tree.terminate_leftover_process_tree",
        lambda *a, **k: None,
    )

    with pytest.raises(ExeinfopeOutputLimitError) as caught:
        adapter._capture_process(["fake"], timeout=1.0, max_output_size=8)

    assert caught.value.details["stream"] == "stderr"


class _QuietProcess:
    pid = 4242

    def __init__(self) -> None:
        self.stdout = io.BytesIO(b"")
        self.stderr = io.BytesIO(b"")

    def poll(self) -> int | None:
        return 0

    def wait(self, timeout: float | None = None) -> int:
        del timeout
        return 0

    def kill(self) -> None:
        return None


def test_capture_raises_when_a_visible_analyzer_window_is_seen(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(adapter.subprocess, "Popen", lambda *a, **k: _QuietProcess())
    monkeypatch.setattr(adapter, "describe_process_windows", lambda _pid: set())
    monkeypatch.setattr(
        "headless_re_mcp.core.process_tree.terminate_leftover_process_tree",
        lambda *a, **k: None,
    )
    monkeypatch.setattr(
        adapter,
        "_visible_blocked_windows",
        lambda _windows: ["0x1:TForm1:Exeinfo PE"],
    )

    with pytest.raises(ExeinfopeGuiWindowError) as caught:
        adapter._capture_process(["fake"], timeout=1.0, max_output_size=32)

    assert caught.value.details["analyzer_windows"] == ["0x1:TForm1:Exeinfo PE"]


# --------------------------------------------------------------------------- #
# Validators                                                                   #
# --------------------------------------------------------------------------- #


def test_coerce_mode_rejects_an_unknown_mode() -> None:
    with pytest.raises(ExeinfopeScanError) as caught:
        adapter._coerce_mode("does-not-exist")
    assert caught.value.code == ExeinfopeErrorCode.INVALID_ARGUMENT


@pytest.mark.parametrize("value", ["nope", True])
def test_validate_positive_number_rejects_non_numbers(value: Any) -> None:
    with pytest.raises(ExeinfopeScanError) as caught:
        adapter._validate_positive_number(value, "timeout")
    assert caught.value.code == ExeinfopeErrorCode.INVALID_ARGUMENT


@pytest.mark.parametrize("value", [0.0, float("inf")])
def test_validate_positive_number_rejects_non_finite_or_zero(value: float) -> None:
    with pytest.raises(ExeinfopeScanError):
        adapter._validate_positive_number(value, "timeout")


@pytest.mark.parametrize("value", [0, -3, True, "x"])
def test_validate_positive_integer_rejects_invalid_values(value: Any) -> None:
    with pytest.raises(ExeinfopeScanError) as caught:
        adapter._validate_positive_integer(value, "max_file_size")
    assert caught.value.code == ExeinfopeErrorCode.INVALID_ARGUMENT


# --------------------------------------------------------------------------- #
# Resolve helpers                                                              #
# --------------------------------------------------------------------------- #


def test_resolve_executable_reports_a_missing_binary(tmp_path: Path) -> None:
    with pytest.raises(ExeinfopeExecutableNotFoundError):
        adapter._resolve_executable(tmp_path / "absent.exe")


def test_resolve_executable_rejects_a_directory(tmp_path: Path) -> None:
    with pytest.raises(ExeinfopeExecutableNotFoundError):
        adapter._resolve_executable(tmp_path)


def test_resolve_input_reports_a_missing_file(tmp_path: Path) -> None:
    with pytest.raises(ExeinfopeInputNotFoundError) as caught:
        adapter._resolve_input(tmp_path / "gone.bin", 1024)
    assert caught.value.code == ExeinfopeErrorCode.INPUT_NOT_FOUND


def test_resolve_input_rejects_a_directory(tmp_path: Path) -> None:
    with pytest.raises(ExeinfopeInputNotFoundError):
        adapter._resolve_input(tmp_path, 1024)


def test_resolve_input_surfaces_a_stat_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"data")

    def boom(_self: Path, *args: Any, **kwargs: Any) -> Any:
        raise OSError("stat failed")

    monkeypatch.setattr(Path, "is_file", lambda _self: True)
    monkeypatch.setattr(Path, "stat", boom)

    with pytest.raises(ExeinfopeInputNotFoundError) as caught:
        adapter._resolve_input(sample, 1024)
    assert "could not stat" in str(caught.value)


def test_resolve_log_path_rejects_a_directory(tmp_path: Path) -> None:
    with pytest.raises(ExeinfopeScanError) as caught:
        adapter._resolve_log_path(tmp_path)
    assert caught.value.code == ExeinfopeErrorCode.INVALID_ARGUMENT


def test_resolve_log_path_reports_a_mkdir_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(_self: Path, *args: Any, **kwargs: Any) -> Any:
        raise OSError("cannot mkdir")

    monkeypatch.setattr(Path, "mkdir", boom)

    with pytest.raises(ExeinfopeScanError) as caught:
        adapter._resolve_log_path(tmp_path / "nested" / "out.log")
    assert caught.value.code == ExeinfopeErrorCode.INVALID_ARGUMENT


def test_log_flag_quotes_paths_with_spaces() -> None:
    flag = adapter._log_flag(Path("/tmp/with space/out.log"))
    assert flag.startswith('/log:"') and flag.endswith('"')


# --------------------------------------------------------------------------- #
# Parser branches                                                             #
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("text", "category"),
    [
        ("Themida protector", FindingCategory.PROTECTOR),
        ("ConfuserEx signature", FindingCategory.OBFUSCATOR),
        ("Inno Setup wrapper", FindingCategory.INSTALLER),
        ("Built with .NET clr", FindingCategory.RUNTIME),
        ("Portable executable image", FindingCategory.FILE_FORMAT),
        ("totally mysterious", FindingCategory.ANOMALY),
    ],
)
def test_category_for_maps_each_family(text: str, category: FindingCategory) -> None:
    assert adapter._category_for(text) == category


def test_name_for_falls_back_when_only_skip_tokens_remain() -> None:
    assert adapter._name_for("x64 exe dll") == "exeinfope"


def test_parse_log_uses_the_whole_line_when_there_is_no_dash() -> None:
    findings = adapter.parse_exeinfope_log("UPX packer signature")
    assert findings[0].summary == "UPX packer signature"


def test_parse_log_rejects_an_oversized_log() -> None:
    payload = "a" * (adapter.DEFAULT_MAX_LOG_SIZE + 1)
    with pytest.raises(ExeinfopeProtocolError) as caught:
        adapter.parse_exeinfope_log(payload)
    assert caught.value.details["max_log_size"] == adapter.DEFAULT_MAX_LOG_SIZE


def test_parse_log_rejects_too_many_lines() -> None:
    payload = "\n".join(f"line{i}" for i in range(adapter._MAX_LOG_LINES + 1))
    with pytest.raises(ExeinfopeProtocolError) as caught:
        adapter.parse_exeinfope_log(payload)
    assert caught.value.details["max"] == adapter._MAX_LOG_LINES


def test_parse_log_rejects_an_overlong_line() -> None:
    payload = "z" * (adapter._MAX_TEXT + 1)
    with pytest.raises(ExeinfopeProtocolError) as caught:
        adapter.parse_exeinfope_log(payload)
    assert caught.value.details["max_length"] == adapter._MAX_TEXT


# --------------------------------------------------------------------------- #
# _read_log                                                                    #
# --------------------------------------------------------------------------- #


def test_read_log_wraps_open_failures(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    log_path = tmp_path / "out.log"
    log_path.write_text("data", encoding="utf-8")

    def boom(_self: Path, *args: Any, **kwargs: Any) -> Any:
        raise OSError("cannot open")

    monkeypatch.setattr(Path, "open", boom)

    with pytest.raises(ExeinfopeProtocolError) as caught:
        adapter._read_log(log_path, 1024)
    assert caught.value.code == ExeinfopeErrorCode.PROTOCOL_ERROR


# --------------------------------------------------------------------------- #
# scan_with_exeinfope orchestration                                           #
# --------------------------------------------------------------------------- #


def test_scan_result_to_dict_round_trips(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable, sample = _real_binaries(tmp_path)
    log_path = tmp_path / "out.log"

    def fake_capture(*args: Any, **kwargs: Any) -> adapter._ProcessCapture:
        del args, kwargs
        log_path.write_text("sample.exe -  x64 UPX v3.9\n", encoding="utf-8")
        return _fake_capture()

    monkeypatch.setattr(adapter, "_capture_process", fake_capture)
    result = scan_with_exeinfope(executable, sample, log_path=log_path)

    payload = result.to_dict()
    assert isinstance(payload, dict)
    assert payload["source"]["name"] == "exeinfope"
    assert payload["returncode"] == 0


def test_scan_clears_a_stale_log_before_running(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable, sample = _real_binaries(tmp_path)
    log_path = tmp_path / "out.log"
    log_path.write_text("stale contents from a previous run\n", encoding="utf-8")
    seen_after_unlink: list[bool] = []

    def fake_capture(*args: Any, **kwargs: Any) -> adapter._ProcessCapture:
        del args, kwargs
        seen_after_unlink.append(log_path.exists())
        log_path.write_text("sample.exe -  x64 UPX v3.9\n", encoding="utf-8")
        return _fake_capture()

    monkeypatch.setattr(adapter, "_capture_process", fake_capture)
    result = scan_with_exeinfope(executable, sample, log_path=log_path)

    assert seen_after_unlink == [False]
    assert result.findings[0].name == "UPX"


def test_scan_reports_a_nonzero_exit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    executable, sample = _real_binaries(tmp_path)

    monkeypatch.setattr(
        adapter,
        "_capture_process",
        lambda *a, **k: _fake_capture(returncode=1),
    )

    with pytest.raises(ExeinfopeProcessError) as caught:
        scan_with_exeinfope(executable, sample, log_path=tmp_path / "out.log")
    assert caught.value.code == ExeinfopeErrorCode.PROCESS_FAILED
    assert caught.value.returncode == 1


def test_scan_preserves_error_streams_already_set_by_the_log_stage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable, sample = _real_binaries(tmp_path)

    monkeypatch.setattr(adapter, "_capture_process", lambda *a, **k: _fake_capture())

    def failing_read(*args: Any, **kwargs: Any) -> str:
        del args, kwargs
        raise ExeinfopeProtocolError(
            ExeinfopeErrorCode.PROTOCOL_ERROR,
            "log parse blew up",
            stdout="captured-out",
            stderr="captured-err",
            returncode=7,
        )

    monkeypatch.setattr(adapter, "_read_log", failing_read)

    with pytest.raises(ExeinfopeProtocolError) as caught:
        scan_with_exeinfope(executable, sample, log_path=tmp_path / "out.log")

    assert caught.value.stdout == "captured-out"
    assert caught.value.stderr == "captured-err"
    assert caught.value.returncode == 7
    assert caught.value.details["argv"][0] == str(executable.resolve())


# --------------------------------------------------------------------------- #
# ExeinfopeCliAdapter                                                          #
# --------------------------------------------------------------------------- #


def test_cli_adapter_forwards_its_configuration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable, sample = _real_binaries(tmp_path)
    log_path = tmp_path / "out.log"

    def fake_capture(*args: Any, **kwargs: Any) -> adapter._ProcessCapture:
        del args, kwargs
        log_path.write_text("sample.exe -  x64 UPX v3.9\n", encoding="utf-8")
        return _fake_capture()

    monkeypatch.setattr(adapter, "_capture_process", fake_capture)

    cli = ExeinfopeCliAdapter(executable, timeout=12.5, max_file_size=99)
    assert cli.timeout == 12.5
    assert cli.max_file_size == 99

    result = cli.scan(sample, log_path=log_path, mode=ScanMode.NORMAL)
    assert result.findings[0].name == "UPX"
    assert result.mode == ScanMode.NORMAL
