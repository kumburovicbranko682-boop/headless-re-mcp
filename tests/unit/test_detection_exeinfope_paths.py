"""Guard, error-mapping and process-plumbing coverage for the Exeinfo PE adapter.

``test_detection_exeinfope.py`` covers the whitelisted-argv happy path, the log
parser categories, the timeout/limit/GUI refusals at a high level and the two
window-visibility helpers. These drive the remaining branches:

* the structured error constructors and ``ExeinfopeScanResult.to_dict``;
* ``_CapturedStream.read_from`` limit/no-op/error arms;
* ``_creation_options`` Windows startupinfo branch and the visibility helpers'
  fail-open arms plus the ctypes / non-Windows fallbacks;
* every ``_capture_process`` control-flow arm (spawn failures, missing pipes,
  the window monitor body, cancel/limit/timeout-cleanup, the stderr-limit and
  in-process GUI refusals);
* the pure validators, resolvers, log-flag/category/name helpers, the
  ``parse_exeinfope_log`` size/line/length guards and ``_read_log`` OSError;
* ``scan_with_exeinfope`` pre-existing-log unlink, non-zero exit, and the
  error-enrichment arms; and ``ExeinfopeCliAdapter``.
"""

from __future__ import annotations

import io
import os
import subprocess
import threading
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.common.bounded_run import BoundedCancelled
from headless_re_mcp.detection import exeinfope as adapter
from headless_re_mcp.detection.exeinfope import (
    ExeinfopeErrorCode,
    ExeinfopeExecutableNotFoundError,
    ExeinfopeGuiWindowError,
    ExeinfopeInputNotFoundError,
    ExeinfopeOutputLimitError,
    ExeinfopeProcessError,
    ExeinfopeProtocolError,
    ExeinfopeScanError,
)
from headless_re_mcp.detection.models import FindingCategory

# --------------------------------------------------------------------------
# Structured error constructors and result serialisation.
# --------------------------------------------------------------------------


def test_executable_not_found_error_carries_details() -> None:
    error = ExeinfopeExecutableNotFoundError(Path("/opt/exeinfope.exe"))
    assert error.code == ExeinfopeErrorCode.EXECUTABLE_NOT_FOUND
    assert error.details["executable"] == "/opt/exeinfope.exe"


def test_input_not_found_error_carries_details() -> None:
    error = ExeinfopeInputNotFoundError(Path("/tmp/sample.exe"))
    assert error.code == ExeinfopeErrorCode.INPUT_NOT_FOUND
    assert error.details["path"] == "/tmp/sample.exe"


def _run_scan(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    log_body: str = "sample.exe -  x64 UPX v3.9\n",
    returncode: int = 0,
    pre_create_log: bool = False,
) -> adapter.ExeinfopeScanResult:
    executable = tmp_path / "Exeinfope.exe"
    executable.write_bytes(b"fake")
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ")
    log_path = tmp_path / "out.log"
    if pre_create_log:
        log_path.write_text("stale", encoding="utf-8")

    def fake_capture(*args: Any, **kwargs: Any) -> adapter._ProcessCapture:
        del args, kwargs
        log_path.write_text(log_body, encoding="utf-8")
        return adapter._ProcessCapture(
            stdout="out",
            stderr="err",
            returncode=returncode,
            stdout_exceeded=False,
            stderr_exceeded=False,
            analyzer_windows=(),
        )

    monkeypatch.setattr(adapter, "_capture_process", fake_capture)
    return adapter.scan_with_exeinfope(executable, sample, log_path=log_path)


def test_result_to_dict_serialises_to_object(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    result = _run_scan(tmp_path, monkeypatch)
    payload = result.to_dict()
    assert isinstance(payload, dict)
    assert payload["source"]["name"] == "exeinfope"


def test_result_to_dict_rejects_non_object_dump(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    result = _run_scan(tmp_path, monkeypatch)
    monkeypatch.setattr(type(result), "model_dump", lambda self, **kwargs: ["not", "a", "dict"])
    with pytest.raises(TypeError, match="did not serialize to an object"):
        result.to_dict()


# --------------------------------------------------------------------------
# _CapturedStream.read_from.
# --------------------------------------------------------------------------


class _ChunkPipe:
    def __init__(self, chunks: list[bytes]) -> None:
        self._chunks = list(chunks)
        self.closed = False

    def read(self, _size: int) -> bytes:
        return self._chunks.pop(0) if self._chunks else b""

    def close(self) -> None:
        self.closed = True


class _RaisingPipe:
    def read(self, _size: int) -> bytes:
        raise OSError("pipe boom")

    def close(self) -> None:
        return None


def test_captured_stream_appends_within_limit() -> None:
    stream = adapter._CapturedStream(limit=64)
    event = threading.Event()
    stream.read_from(_ChunkPipe([b"abc"]), event)  # type: ignore[arg-type]
    assert stream.text() == "abc"
    assert stream.exceeded is False
    assert not event.is_set()
    assert stream.finished.is_set()


def test_captured_stream_flags_overflow_when_full() -> None:
    stream = adapter._CapturedStream(limit=0)
    event = threading.Event()
    stream.read_from(_ChunkPipe([b"data"]), event)  # type: ignore[arg-type]
    assert stream.exceeded is True
    assert event.is_set()


def test_captured_stream_swallows_read_errors() -> None:
    stream = adapter._CapturedStream(limit=8)
    event = threading.Event()
    stream.read_from(_RaisingPipe(), event)  # type: ignore[arg-type]
    assert stream.text() == ""
    assert stream.finished.is_set()


# --------------------------------------------------------------------------
# _creation_options / visibility helpers.
# --------------------------------------------------------------------------


def test_creation_options_windows_with_startupinfo(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(os, "name", "nt")

    class _StartupInfo:
        def __init__(self) -> None:
            self.dwFlags = 0
            self.wShowWindow: int | None = None

    monkeypatch.setattr(subprocess, "STARTUPINFO", _StartupInfo, raising=False)
    monkeypatch.setattr(subprocess, "STARTF_USESHOWWINDOW", 0x1, raising=False)
    monkeypatch.setattr(subprocess, "CREATE_NO_WINDOW", 0x08000000, raising=False)

    options = adapter._creation_options()
    assert options["creationflags"] == 0x08000000
    startupinfo = options["startupinfo"]
    assert isinstance(startupinfo, _StartupInfo)
    assert startupinfo.dwFlags == 0x1
    assert startupinfo.wShowWindow == 0


def test_creation_options_windows_without_startupinfo(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(os, "name", "nt")
    monkeypatch.delattr(subprocess, "STARTUPINFO", raising=False)
    options = adapter._creation_options()
    assert "startupinfo" not in options


def test_is_visible_window_fails_open_on_bad_handle() -> None:
    assert adapter._is_visible_window("zz:TForm1:t", visible_check=lambda _h: True) is True


def test_is_visible_window_fails_open_on_oserror() -> None:
    def raises(_hwnd: int) -> bool:
        raise OSError("no window")

    assert adapter._is_visible_window("0x1:TForm1:t", visible_check=raises) is True


def test_visible_blocked_windows_returns_empty_without_check() -> None:
    # Non-Windows without a visibility check cannot verify anything, so it
    # tolerates rather than blocks.
    assert adapter._visible_blocked_windows({"0x1:TForm1:x"}) == []


def test_visible_blocked_windows_uses_windows_ctypes(monkeypatch: pytest.MonkeyPatch) -> None:
    import ctypes

    class _User32:
        @staticmethod
        def IsWindowVisible(_hwnd: int) -> int:
            return 1

    fake_windll = type("_WinDLL", (), {"user32": _User32()})()
    monkeypatch.setattr(ctypes, "windll", fake_windll, raising=False)
    monkeypatch.setattr(os, "name", "nt")

    blocked = adapter._visible_blocked_windows({"0x10:TForm1:Exeinfo PE"})
    assert blocked == ["0x10:TForm1:Exeinfo PE"]


# --------------------------------------------------------------------------
# _capture_process control flow.
# --------------------------------------------------------------------------


class _NoMonitorThread:
    """Runs reader targets synchronously; skips the window monitor loop."""

    def __init__(self, *, target: Any, name: str, daemon: bool = False, args: Any = ()) -> None:
        self._target = target
        self._args = args
        self.name = name
        self._alive = False

    def start(self) -> None:
        if self.name == "exeinfope-windows":
            return
        self._alive = True
        try:
            self._target(*self._args)
        finally:
            self._alive = False

    def is_alive(self) -> bool:
        return self._alive

    def join(self, timeout: float | None = None) -> None:
        return None


class _SyncThread(_NoMonitorThread):
    """Runs every target synchronously, including the window monitor."""

    def start(self) -> None:
        self._alive = True
        try:
            self._target(*self._args)
        finally:
            self._alive = False


class _OnceFalseEvent:
    """Event whose ``wait`` returns False once (run the body) then True."""

    def __init__(self) -> None:
        self._set = False
        self._wait_calls = 0

    def set(self) -> None:
        self._set = True

    def is_set(self) -> bool:
        return self._set

    def wait(self, timeout: float | None = None) -> bool:
        self._wait_calls += 1
        return self._wait_calls > 1


class _CaptureProc:
    def __init__(
        self,
        *,
        poll_value: int | None,
        wait_raises: bool = False,
        wait_value: int = 0,
        stdout: bytes = b"",
        stderr: bytes = b"",
        pid: int = 4242,
    ) -> None:
        self.stdout: Any = io.BytesIO(stdout)
        self.stderr: Any = io.BytesIO(stderr)
        self._poll = poll_value
        self._wait_raises = wait_raises
        self._wait_value = wait_value
        self.pid = pid
        self.killed = False

    def poll(self) -> int | None:
        return self._poll

    def wait(self, timeout: float | None = None) -> int:
        if self._wait_raises and not self.killed:
            raise subprocess.TimeoutExpired("fake", float(timeout or 0.0))
        return self._wait_value

    def kill(self) -> None:
        self.killed = True


def _install_capture_stubs(
    monkeypatch: pytest.MonkeyPatch,
    process: Any,
    *,
    thread_cls: type = _NoMonitorThread,
    event_cls: type | None = None,
) -> None:
    # adapter.subprocess is the shared stdlib module, so patching it here is what
    # _capture_process observes.
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: process)
    monkeypatch.setattr(adapter, "Thread", thread_cls)
    if event_cls is not None:
        monkeypatch.setattr(adapter, "Event", event_cls)
    monkeypatch.setattr(adapter, "_terminate_process", lambda proc: None)
    monkeypatch.setattr("headless_re_mcp.process_group.assign_to_process_group", lambda pid: True)
    monkeypatch.setattr(
        "headless_re_mcp.core.process_tree.terminate_leftover_process_tree",
        lambda proc, **k: [],
    )


def test_capture_process_raises_when_executable_is_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def boom(*_a: Any, **_k: Any) -> Any:
        raise FileNotFoundError("no exe")

    monkeypatch.setattr(subprocess, "Popen", boom)
    with pytest.raises(ExeinfopeExecutableNotFoundError):
        adapter._capture_process(["ghost.exe"], timeout=1.0, max_output_size=32)


def test_capture_process_wraps_a_generic_spawn_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def boom(*_a: Any, **_k: Any) -> Any:
        raise OSError("EPERM")

    monkeypatch.setattr(subprocess, "Popen", boom)
    with pytest.raises(ExeinfopeProcessError) as caught:
        adapter._capture_process(["x"], timeout=1.0, max_output_size=32)
    assert caught.value.code == ExeinfopeErrorCode.PROCESS_FAILED


def test_capture_process_requires_stdout_stderr_pipes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _NoPipeProc:
        def __init__(self) -> None:
            self.stdout = None
            self.stderr = None
            self.pid = 0  # falsy: skips the process-group assignment

    _install_capture_stubs(monkeypatch, _NoPipeProc())
    with pytest.raises(ExeinfopeProcessError, match="did not expose stdout/stderr"):
        adapter._capture_process(["x"], timeout=1.0, max_output_size=32)


def test_capture_process_runs_the_window_monitor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = _CaptureProc(poll_value=0)
    _install_capture_stubs(monkeypatch, process, thread_cls=_SyncThread, event_cls=_OnceFalseEvent)
    seen: list[int] = []

    def observer(pid: int) -> set[str]:
        seen.append(pid)
        return {"0xabc:IME:Default IME"}

    capture = adapter._capture_process(
        ["x"], timeout=1.0, max_output_size=32, window_observer=observer
    )
    assert capture.returncode == 0
    # The monitor body and the final sweep both queried the observer.
    assert seen and all(pid == 4242 for pid in seen)


def test_capture_process_monitor_tolerates_a_missing_pid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A process whose pid reads back falsy makes the monitor body skip the
    # observer call and loop again (407->404).
    process = _CaptureProc(poll_value=0, pid=0)
    _install_capture_stubs(monkeypatch, process, thread_cls=_SyncThread, event_cls=_OnceFalseEvent)
    seen: list[int] = []

    def record(pid: int) -> set[str]:
        seen.append(pid)
        return set()

    capture = adapter._capture_process(
        ["x"], timeout=1.0, max_output_size=32, window_observer=record
    )
    assert capture.returncode == 0
    # The monitor never queried the observer for a falsy pid; only the final
    # sweep (which passes process.pid directly) may have.
    assert seen in ([0], [])


def test_capture_process_completes_via_wait(monkeypatch: pytest.MonkeyPatch) -> None:
    process = _CaptureProc(poll_value=None, wait_raises=False, wait_value=0)
    _install_capture_stubs(monkeypatch, process)
    capture = adapter._capture_process(
        ["x"], timeout=1.0, max_output_size=32, window_observer=lambda pid: set()
    )
    assert capture.returncode == 0


def test_capture_process_terminates_when_cleanup_wait_times_out(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = _CaptureProc(poll_value=0, wait_raises=True)
    _install_capture_stubs(monkeypatch, process)
    capture = adapter._capture_process(
        ["x"], timeout=1.0, max_output_size=32, window_observer=lambda pid: set()
    )
    assert capture.returncode == 0


def test_capture_process_honours_a_bound_cancel(monkeypatch: pytest.MonkeyPatch) -> None:
    process = _CaptureProc(poll_value=None)
    _install_capture_stubs(monkeypatch, process)
    cancel = threading.Event()
    cancel.set()
    monkeypatch.setattr(adapter, "active_bound_cancel", lambda: cancel)
    with pytest.raises(BoundedCancelled):
        adapter._capture_process(
            ["x"], timeout=1.0, max_output_size=32, window_observer=lambda pid: set()
        )


def test_capture_process_breaks_on_the_stream_limit_event(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = _CaptureProc(poll_value=None, stdout=b"x" * 64)
    _install_capture_stubs(monkeypatch, process)
    with pytest.raises(ExeinfopeOutputLimitError) as caught:
        adapter._capture_process(
            ["x"], timeout=1.0, max_output_size=8, window_observer=lambda pid: set()
        )
    assert caught.value.details["stream"] == "stdout"


def test_capture_process_reports_a_stderr_overflow(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = _CaptureProc(poll_value=0, stderr=b"e" * 64)
    _install_capture_stubs(monkeypatch, process)
    with pytest.raises(ExeinfopeOutputLimitError) as caught:
        adapter._capture_process(
            ["x"], timeout=1.0, max_output_size=8, window_observer=lambda pid: set()
        )
    assert caught.value.details["stream"] == "stderr"


def test_capture_process_refuses_a_visible_analyzer_window(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = _CaptureProc(poll_value=0)
    _install_capture_stubs(monkeypatch, process)
    monkeypatch.setattr(adapter, "_visible_blocked_windows", lambda windows: ["0x1:TForm1:x"])
    with pytest.raises(ExeinfopeGuiWindowError):
        adapter._capture_process(
            ["x"],
            timeout=1.0,
            max_output_size=32,
            window_observer=lambda pid: {"0x1:TForm1:x"},
        )


# --------------------------------------------------------------------------
# Pure validators, resolvers and small formatters.
# --------------------------------------------------------------------------


def test_coerce_mode_rejects_unknown_mode() -> None:
    with pytest.raises(ExeinfopeScanError) as caught:
        adapter._coerce_mode("nonsense")
    assert caught.value.code == ExeinfopeErrorCode.INVALID_ARGUMENT


@pytest.mark.parametrize("value", ["x", True, float("inf"), -1.0, 0.0])
def test_validate_positive_number_rejects_bad_values(value: Any) -> None:
    with pytest.raises(ExeinfopeScanError):
        adapter._validate_positive_number(value, "timeout")


@pytest.mark.parametrize("value", [0, -3, True, "5"])
def test_validate_positive_integer_rejects_bad_values(value: Any) -> None:
    with pytest.raises(ExeinfopeScanError):
        adapter._validate_positive_integer(value, "max_file_size")


def test_resolve_executable_missing_path(tmp_path: Path) -> None:
    with pytest.raises(ExeinfopeExecutableNotFoundError):
        adapter._resolve_executable(tmp_path / "nope.exe")


def test_resolve_executable_rejects_a_directory(tmp_path: Path) -> None:
    with pytest.raises(ExeinfopeExecutableNotFoundError):
        adapter._resolve_executable(tmp_path)


def test_resolve_input_missing_path(tmp_path: Path) -> None:
    with pytest.raises(ExeinfopeInputNotFoundError):
        adapter._resolve_input(tmp_path / "nope.bin", 1024)


def test_resolve_input_rejects_a_directory(tmp_path: Path) -> None:
    with pytest.raises(ExeinfopeInputNotFoundError, match="explicit regular file"):
        adapter._resolve_input(tmp_path, 1024)


def test_resolve_input_wraps_a_stat_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"MZ")

    # Let resolution and the is_file gate pass, then fail the explicit stat call
    # so only the size-probe OSError arm runs (not the not-found arms).
    def fake_resolve(self: Path, *args: Any, **kwargs: Any) -> Path:
        return self

    def fake_is_file(self: Path) -> bool:
        return True

    def boom_stat(self: Path, *args: Any, **kwargs: Any) -> os.stat_result:
        raise OSError("stat failed")

    monkeypatch.setattr(Path, "resolve", fake_resolve)
    monkeypatch.setattr(Path, "is_file", fake_is_file)
    monkeypatch.setattr(Path, "stat", boom_stat)
    with pytest.raises(ExeinfopeInputNotFoundError, match="could not stat"):
        adapter._resolve_input(sample, 1024)


def test_resolve_log_path_rejects_a_directory(tmp_path: Path) -> None:
    with pytest.raises(ExeinfopeScanError, match="regular file path"):
        adapter._resolve_log_path(tmp_path)


def test_resolve_log_path_wraps_a_mkdir_error(tmp_path: Path) -> None:
    blocker = tmp_path / "blocker"
    blocker.write_bytes(b"file-not-dir")
    with pytest.raises(ExeinfopeScanError, match="could not create Exeinfo PE log directory"):
        adapter._resolve_log_path(blocker / "sub" / "out.log")


def test_log_flag_quotes_a_path_with_spaces() -> None:
    flag = adapter._log_flag(Path("/tmp/a b/out.log"))
    assert flag.startswith('/log:"') and flag.endswith('"')


@pytest.mark.parametrize(
    ("text", "category"),
    [
        ("Themida protector", FindingCategory.PROTECTOR),
        ("ConfuserEx obfuscator", FindingCategory.OBFUSCATOR),
        ("Nullsoft installer", FindingCategory.INSTALLER),
        (".NET assembly", FindingCategory.RUNTIME),
        ("generic PE executable", FindingCategory.FILE_FORMAT),
    ],
)
def test_category_for_hint_buckets(text: str, category: FindingCategory) -> None:
    assert adapter._category_for(text) == category


def test_name_for_falls_back_to_source_when_all_tokens_are_generic() -> None:
    assert adapter._name_for("x64 x86 exe dll pe") == "exeinfope"


# --------------------------------------------------------------------------
# parse_exeinfope_log guards and _read_log.
# --------------------------------------------------------------------------


def test_parse_log_rejects_oversized_log(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(adapter, "DEFAULT_MAX_LOG_SIZE", 4)
    with pytest.raises(ExeinfopeProtocolError, match="exceeds the configured size"):
        adapter.parse_exeinfope_log("sample - packed line\n")


def test_parse_log_rejects_too_many_lines(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(adapter, "_MAX_LOG_LINES", 2)
    with pytest.raises(ExeinfopeProtocolError, match="too many lines"):
        adapter.parse_exeinfope_log("a - 1\nb - 2\nc - 3\n")


def test_parse_log_rejects_an_overlong_line(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(adapter, "_MAX_TEXT", 5)
    with pytest.raises(ExeinfopeProtocolError, match="too long"):
        adapter.parse_exeinfope_log("abcdefghij\n")


def test_parse_log_handles_a_line_without_a_dash() -> None:
    findings = adapter.parse_exeinfope_log("UPXpacked\n")
    assert findings[0].summary == "UPXpacked"
    assert findings[0].category == FindingCategory.PACKER


def test_read_log_wraps_an_open_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    log_path = tmp_path / "out.log"
    log_path.write_text("data", encoding="utf-8")
    real_open = Path.open

    def boom_open(self: Path, *args: Any, **kwargs: Any) -> Any:
        if self == log_path:
            raise OSError("cannot open")
        return real_open(self, *args, **kwargs)

    monkeypatch.setattr(Path, "open", boom_open)
    with pytest.raises(ExeinfopeProtocolError, match="could not read Exeinfo PE log"):
        adapter._read_log(log_path, 1024)


# --------------------------------------------------------------------------
# scan_with_exeinfope wiring.
# --------------------------------------------------------------------------


def test_scan_unlinks_a_pre_existing_log(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    result = _run_scan(tmp_path, monkeypatch, pre_create_log=True)
    assert result.returncode == 0
    assert result.findings[0].name == "UPX"


def test_scan_raises_on_a_non_zero_exit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(ExeinfopeProcessError, match="exited with status 3"):
        _run_scan(tmp_path, monkeypatch, returncode=3)


def test_scan_preserves_error_streams_already_set(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable = tmp_path / "Exeinfope.exe"
    executable.write_bytes(b"fake")
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ")
    log_path = tmp_path / "out.log"

    def fake_capture(*args: Any, **kwargs: Any) -> adapter._ProcessCapture:
        del args, kwargs
        log_path.write_text("ok - line\n", encoding="utf-8")
        return adapter._ProcessCapture(
            stdout="capture-out",
            stderr="capture-err",
            returncode=0,
            stdout_exceeded=False,
            stderr_exceeded=False,
            analyzer_windows=(),
        )

    def boom_read(_path: Path, _max: int) -> str:
        raise ExeinfopeProtocolError(
            ExeinfopeErrorCode.PROTOCOL_ERROR,
            "already enriched",
            stdout="preset-out",
            stderr="preset-err",
            returncode=99,
        )

    monkeypatch.setattr(adapter, "_capture_process", fake_capture)
    monkeypatch.setattr(adapter, "_read_log", boom_read)

    with pytest.raises(ExeinfopeProtocolError) as caught:
        adapter.scan_with_exeinfope(executable, sample, log_path=log_path)
    # The pre-set stream/return fields survive: the enrichment arms are skipped.
    assert caught.value.stdout == "preset-out"
    assert caught.value.stderr == "preset-err"
    assert caught.value.returncode == 99
    assert caught.value.details["argv"][0] == str(executable.resolve())


# --------------------------------------------------------------------------
# ExeinfopeCliAdapter.
# --------------------------------------------------------------------------


def test_cli_adapter_delegates_to_scan(monkeypatch: pytest.MonkeyPatch) -> None:
    instance = adapter.ExeinfopeCliAdapter(
        Path("/opt/exeinfope.exe"),
        timeout=12.0,
        max_file_size=1234,
        max_output_size=5678,
        max_log_size=9012,
    )
    assert instance.timeout == 12.0
    assert instance.max_file_size == 1234

    captured: dict[str, Any] = {}

    def fake_scan(executable: Path, path: Path, **kwargs: Any) -> str:
        captured["executable"] = executable
        captured["path"] = path
        captured.update(kwargs)
        return "RESULT"

    monkeypatch.setattr(adapter, "scan_with_exeinfope", fake_scan)
    out: Any = instance.scan(Path("/tmp/in.exe"), log_path=Path("/tmp/out.log"))
    assert out == "RESULT"
    assert captured["executable"] == Path("/opt/exeinfope.exe")
    assert captured["timeout"] == 12.0
    assert captured["max_log_size"] == 9012
