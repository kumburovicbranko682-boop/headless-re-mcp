from __future__ import annotations

import io
import os
import subprocess
from pathlib import Path
from threading import Event
from typing import Any, cast

import pytest

from headless_re_mcp.detection import (
    ExeinfopeErrorCode,
    ExeinfopeExecutableNotFoundError,
    ExeinfopeGuiWindowError,
    ExeinfopeInputNotFoundError,
    ExeinfopeInputTooLargeError,
    ExeinfopeOutputLimitError,
    ExeinfopeProcessError,
    ExeinfopeProtocolError,
    ExeinfopeScanError,
    ExeinfopeTimeoutError,
    FindingCategory,
    parse_exeinfope_log,
    scan_with_exeinfope,
)
from headless_re_mcp.detection import exeinfope as adapter


def _exe_and_sample(tmp_path: Path) -> tuple[Path, Path]:
    executable = tmp_path / "Exeinfope.exe"
    executable.write_bytes(b"fake")
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ")
    return executable, sample


def _fake_capture(
    *,
    returncode: int = 0,
    windows: tuple[str, ...] = (),
) -> adapter._ProcessCapture:
    return adapter._ProcessCapture(
        stdout="",
        stderr="",
        returncode=returncode,
        stdout_exceeded=False,
        stderr_exceeded=False,
        analyzer_windows=windows,
    )


def test_parse_log_best_effort_categories() -> None:
    raw = "\n".join(
        [
            "sample.exe -  x64 UPX v3.9 - 5.0 - [ 5.20 ] - exe signature",
            "sample.exe -  x64 Microsoft Visual C++ v14.44 - 2025",
            "sample.exe -  Unknown mystery blob",
        ]
    )
    findings = parse_exeinfope_log(raw)
    assert [item.category for item in findings] == [
        FindingCategory.PACKER,
        FindingCategory.COMPILER,
        FindingCategory.ANOMALY,
    ]
    assert findings[0].source == "exeinfope"
    assert findings[0].name == "UPX"
    assert findings[0].confidence == 0.55
    assert findings[0].evidence[0].details["parser"] == "best_effort"


def test_parse_log_rejects_empty() -> None:
    with pytest.raises(ExeinfopeProtocolError) as caught:
        parse_exeinfope_log("\n\n")
    assert caught.value.code == ExeinfopeErrorCode.PROTOCOL_ERROR


def test_scan_builds_whitelisted_argv_and_reads_log(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable = tmp_path / "Exeinfope.exe"
    executable.write_bytes(b"fake")
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ")
    log_path = tmp_path / "out.log"
    seen: list[list[str]] = []

    def fake_capture(
        argv: list[str],
        *,
        timeout: float,
        max_output_size: int,
        window_observer: Any = None,
    ) -> adapter._ProcessCapture:
        del timeout, max_output_size, window_observer
        seen.append(argv)
        log_path.write_text(
            "sample.exe -  x64 UPX v3.9 - 5.0 - [ 5.20 ]\n",
            encoding="utf-8",
        )
        return _fake_capture()

    monkeypatch.setattr(adapter, "_capture_process", fake_capture)
    result = scan_with_exeinfope(executable, sample, log_path=log_path)

    assert len(seen) == 1
    assert seen[0][0] == str(executable.resolve())
    assert seen[0][1] == f"{sample.resolve()}*"
    assert seen[0][2] == "/s"
    assert seen[0][3] == f"/log:{log_path.resolve()}"
    assert "--" not in seen[0]
    assert "/un7zip" not in seen[0]
    assert result.findings[0].name == "UPX"
    assert result.claims_universal_unpack is False
    assert result.source.name == "exeinfope"


def test_scan_rejects_oversized_input_before_spawn(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable = tmp_path / "Exeinfope.exe"
    executable.write_bytes(b"fake")
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"12345")
    called = False

    def fail_if_spawned(*args: Any, **kwargs: Any) -> Any:
        nonlocal called
        called = True
        raise AssertionError("must not spawn for oversized input")

    monkeypatch.setattr(adapter.subprocess, "Popen", fail_if_spawned)
    with pytest.raises(ExeinfopeInputTooLargeError) as caught:
        scan_with_exeinfope(
            executable,
            sample,
            log_path=tmp_path / "x.log",
            max_file_size=4,
        )
    assert caught.value.code == ExeinfopeErrorCode.INPUT_TOO_LARGE
    assert not called


def test_scan_fails_when_log_missing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable = tmp_path / "Exeinfope.exe"
    executable.write_bytes(b"fake")
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ")
    monkeypatch.setattr(
        adapter,
        "_capture_process",
        lambda *args, **kwargs: _fake_capture(),
    )
    with pytest.raises(ExeinfopeProtocolError) as caught:
        scan_with_exeinfope(executable, sample, log_path=tmp_path / "missing.log")
    assert caught.value.code == ExeinfopeErrorCode.LOG_MISSING


def test_log_read_is_bounded_even_when_file_metadata_is_stale(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    log_path = tmp_path / "growing.log"
    log_path.write_bytes(b"0123456789")
    real_stat = Path.stat

    def stale_stat(path: Path, *args: Any, **kwargs: Any) -> os.stat_result:
        result = real_stat(path, *args, **kwargs)
        if path == log_path:
            fields = list(result)
            fields[6] = 1
            return os.stat_result(fields)
        return result

    monkeypatch.setattr(Path, "stat", stale_stat)

    with pytest.raises(ExeinfopeOutputLimitError) as caught:
        adapter._read_log(log_path, 4)

    assert caught.value.details["size_at_least"] == 5


def test_scan_fails_on_bad_log(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable = tmp_path / "Exeinfope.exe"
    executable.write_bytes(b"fake")
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ")
    log_path = tmp_path / "bad.log"

    def fake_capture(*args: Any, **kwargs: Any) -> adapter._ProcessCapture:
        del args, kwargs
        log_path.write_text("\n\n", encoding="utf-8")
        return _fake_capture()

    monkeypatch.setattr(adapter, "_capture_process", fake_capture)
    with pytest.raises(ExeinfopeProtocolError):
        scan_with_exeinfope(executable, sample, log_path=log_path)


def test_visible_blocked_window_raises(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    executable = tmp_path / "Exeinfope.exe"
    executable.write_bytes(b"fake")
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ")

    def fake_capture(*args: Any, **kwargs: Any) -> adapter._ProcessCapture:
        del args, kwargs
        raise ExeinfopeGuiWindowError(
            ["0x1:TForm1:Exeinfo PE - ver.0.0.9.3"],
            returncode=0,
        )

    monkeypatch.setattr(adapter, "_capture_process", fake_capture)
    with pytest.raises(ExeinfopeGuiWindowError) as caught:
        scan_with_exeinfope(executable, sample, log_path=tmp_path / "x.log")
    assert caught.value.code == ExeinfopeErrorCode.GUI_WINDOW_DETECTED


def test_visible_window_helper_ignores_invisible_forms() -> None:
    windows = {
        "0x1:TForm1:Exeinfo PE",
        "0x2:TApplication:BIN ... Please wait",
        "0x3:IME:Default IME",
    }
    blocked = adapter._visible_blocked_windows(
        windows,
        visible_check=lambda hwnd: hwnd == 0x2,
    )
    assert blocked == []


def test_visible_window_helper_flags_visible_main_form() -> None:
    windows = {"0x10:TForm1:Exeinfo PE", "0x11:TApplication:wait"}
    blocked = adapter._visible_blocked_windows(
        windows,
        visible_check=lambda hwnd: hwnd == 0x10,
    )
    assert blocked == ["0x10:TForm1:Exeinfo PE"]


class _FakeProcess:
    def __init__(self, hangs: bool = False) -> None:
        self.stdout = io.BytesIO(b"")
        self.stderr = io.BytesIO(b"")
        self._returncode = None if hangs else 0
        self._hangs = hangs
        self.killed = False
        self.pid = 4242

    def poll(self) -> int | None:
        return self._returncode

    def wait(self, timeout: float | None = None) -> int:
        del timeout
        if self._hangs and not self.killed:
            raise subprocess.TimeoutExpired("fake", 0.01)
        if self._returncode is None:
            self._returncode = -9
        return self._returncode

    def kill(self) -> None:
        self.killed = True
        self._hangs = False
        self._returncode = -9


def test_process_capture_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    process = _FakeProcess(hangs=True)
    monkeypatch.setattr(adapter.subprocess, "Popen", lambda *args, **kwargs: process)
    monkeypatch.setattr(adapter, "describe_process_windows", lambda pid: set())
    with pytest.raises(ExeinfopeTimeoutError) as caught:
        adapter._capture_process(["fake"], timeout=0.01, max_output_size=32)
    assert process.killed
    assert caught.value.code == ExeinfopeErrorCode.TIMEOUT


def test_process_capture_cleanup_threads_share_one_drain_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The three stuck cleanup threads must not add three seconds after a timeout."""
    clock = [0.0]
    join_timeouts: list[float] = []

    class _TimedOutProcess(_FakeProcess):
        def wait(self, timeout: float | None = None) -> int:
            budget = float(timeout or 0.0)
            clock[0] += budget
            if self.killed:
                self._returncode = -9
                return self._returncode
            raise subprocess.TimeoutExpired("fake", budget)

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

    process = _TimedOutProcess(hangs=True)
    monkeypatch.setattr(adapter.subprocess, "Popen", lambda *a, **k: process)
    monkeypatch.setattr(adapter, "Thread", _StuckThread)
    monkeypatch.setattr(adapter, "monotonic", lambda: clock[0])
    monkeypatch.setattr(adapter, "_terminate_process", lambda child: child.kill())
    monkeypatch.setattr(adapter, "describe_process_windows", lambda pid: set())

    with pytest.raises(ExeinfopeTimeoutError):
        adapter._capture_process(["fake"], timeout=0.1, max_output_size=32)

    assert len(join_timeouts) == 3
    assert sum(join_timeouts) <= 1.0


def test_process_capture_stream_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    process = _FakeProcess()
    process.stdout = io.BytesIO(b"x" * 64)
    monkeypatch.setattr(adapter.subprocess, "Popen", lambda *args, **kwargs: process)
    monkeypatch.setattr(adapter, "describe_process_windows", lambda pid: set())
    with pytest.raises(ExeinfopeOutputLimitError) as caught:
        adapter._capture_process(["fake"], timeout=1.0, max_output_size=8)
    assert caught.value.code == ExeinfopeErrorCode.OUTPUT_LIMIT


def test_no_shell_options() -> None:
    options = adapter._creation_options()
    assert options["shell"] is False
    assert options["stdin"] is subprocess.DEVNULL
    if os.name == "nt":
        assert options["creationflags"] & getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)


@pytest.mark.parametrize(
    "kwargs",
    [
        pytest.param({"mode": "bogus"}, id="unknown-mode"),
        pytest.param({"timeout": "soon"}, id="timeout-string"),
        pytest.param({"timeout": float("nan")}, id="timeout-nan"),
        pytest.param({"timeout": 0}, id="timeout-zero"),
        pytest.param({"timeout": True}, id="timeout-bool"),
        pytest.param({"max_file_size": -1}, id="file-size-negative"),
        pytest.param({"max_file_size": 1.5}, id="file-size-float"),
        pytest.param({"max_output_size": True}, id="output-size-bool"),
        pytest.param({"max_log_size": 0}, id="log-size-zero"),
    ],
)
def test_invalid_scan_arguments_are_refused_before_spawning(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kwargs: dict[str, Any]
) -> None:
    executable, sample = _exe_and_sample(tmp_path)

    def fail_if_spawned(*args: Any, **kw: Any) -> Any:
        raise AssertionError("must not spawn for invalid arguments")

    monkeypatch.setattr(subprocess, "Popen", fail_if_spawned)
    with pytest.raises(ExeinfopeScanError) as caught:
        scan_with_exeinfope(executable, sample, log_path=tmp_path / "x.log", **kwargs)
    assert caught.value.code == ExeinfopeErrorCode.INVALID_ARGUMENT


def test_missing_or_nonfile_executable_and_input_are_rejected(tmp_path: Path) -> None:
    executable, sample = _exe_and_sample(tmp_path)
    directory = tmp_path / "adir"
    directory.mkdir()
    log_path = tmp_path / "x.log"

    with pytest.raises(ExeinfopeExecutableNotFoundError):
        scan_with_exeinfope(tmp_path / "nope.exe", sample, log_path=log_path)
    with pytest.raises(ExeinfopeExecutableNotFoundError):
        scan_with_exeinfope(directory, sample, log_path=log_path)
    with pytest.raises(ExeinfopeInputNotFoundError):
        scan_with_exeinfope(executable, tmp_path / "nope.bin", log_path=log_path)
    with pytest.raises(ExeinfopeInputNotFoundError) as caught:
        scan_with_exeinfope(executable, directory, log_path=log_path)
    assert "regular file" in str(caught.value)


def test_log_path_must_be_a_creatable_regular_file(tmp_path: Path) -> None:
    executable, sample = _exe_and_sample(tmp_path)
    directory = tmp_path / "adir"
    directory.mkdir()

    with pytest.raises(ExeinfopeScanError) as caught:
        scan_with_exeinfope(executable, sample, log_path=directory)
    assert caught.value.code == ExeinfopeErrorCode.INVALID_ARGUMENT

    # The log directory cannot be created when a path component is a file.
    plain = tmp_path / "plainfile"
    plain.write_bytes(b"x")
    with pytest.raises(ExeinfopeScanError) as caught:
        scan_with_exeinfope(executable, sample, log_path=plain / "sub" / "x.log")
    assert caught.value.code == ExeinfopeErrorCode.INVALID_ARGUMENT


def test_argv_helpers_quote_spaces_and_keep_an_existing_mask() -> None:
    assert adapter._log_flag(Path("/tmp/has space/x.log")) == '/log:"/tmp/has space/x.log"'
    assert adapter._log_flag(Path("/tmp/x.log")) == "/log:/tmp/x.log"
    assert adapter._input_mask(Path("/tmp/foo*")) == "/tmp/foo*"
    assert adapter._input_mask(Path("/tmp/foo.exe")) == "/tmp/foo.exe*"


@pytest.mark.parametrize(
    ("description", "expected"),
    [
        pytest.param("Themida 3.x", FindingCategory.PROTECTOR, id="protector"),
        pytest.param("ConfuserEx assembly", FindingCategory.OBFUSCATOR, id="obfuscator"),
        pytest.param("Inno Setup module", FindingCategory.INSTALLER, id="installer"),
        pytest.param(".NET CLR v4 assembly", FindingCategory.RUNTIME, id="runtime"),
        pytest.param("PE32 executable", FindingCategory.FILE_FORMAT, id="file-format"),
    ],
)
def test_exeinfope_descriptions_map_to_finding_categories(
    description: str, expected: FindingCategory
) -> None:
    assert adapter._category_for(description) is expected


def test_name_extraction_falls_back_when_no_token_survives() -> None:
    # Every token is an architecture/extension noise word, and the whitespace
    # line has no tokens at all; both must yield the honest source name.
    assert adapter._name_for("x64 exe dll pe") == "exeinfope"
    assert adapter._name_for("   ") == "exeinfope"
    assert adapter._name_for("Something [x64] weird") == "Something"


@pytest.mark.parametrize(
    ("raw_log", "fragment"),
    [
        pytest.param(
            "\n".join(f"line {index}" for index in range(adapter._MAX_LOG_LINES + 1)),
            "too many lines",
            id="too-many-lines",
        ),
        pytest.param("x" * (adapter._MAX_TEXT + 1), "is too long", id="line-too-long"),
        pytest.param(
            "y" * (adapter.DEFAULT_MAX_LOG_SIZE + 1),
            "size limit",
            id="log-over-byte-budget",
        ),
    ],
)
def test_parse_log_bounds_hostile_logs(raw_log: str, fragment: str) -> None:
    with pytest.raises(ExeinfopeProtocolError) as caught:
        parse_exeinfope_log(raw_log)
    assert caught.value.code == ExeinfopeErrorCode.PROTOCOL_ERROR
    assert fragment in str(caught.value)


def test_parse_log_keeps_a_line_without_the_dash_separator() -> None:
    findings = parse_exeinfope_log("UPX packed blob without file prefix")
    assert findings[0].summary == "UPX packed blob without file prefix"
    assert findings[0].category is FindingCategory.PACKER


def test_scan_removes_a_stale_log_and_serialises_the_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable, sample = _exe_and_sample(tmp_path)
    log_path = tmp_path / "out.log"
    log_path.write_text("STALE - leftovers from a previous run\n", encoding="utf-8")

    def fake_capture(*args: Any, **kwargs: Any) -> adapter._ProcessCapture:
        del args, kwargs
        assert not log_path.exists(), "the stale log must be unlinked before the run"
        log_path.write_text("sample.exe -  UPX v3.9\n", encoding="utf-8")
        return _fake_capture()

    monkeypatch.setattr(adapter, "_capture_process", fake_capture)
    result = scan_with_exeinfope(executable, sample, log_path=log_path)
    assert result.findings[0].name == "UPX"
    serialized = result.to_dict()
    assert serialized["claims_universal_unpack"] is False
    assert serialized["source"]["name"] == "exeinfope"


def test_nonzero_exit_is_a_process_error_with_captured_streams(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable, sample = _exe_and_sample(tmp_path)

    def fake_capture(*args: Any, **kwargs: Any) -> adapter._ProcessCapture:
        del args, kwargs
        return adapter._ProcessCapture("so", "se", 3, False, False, ("0x1:TApplication:wait",))

    monkeypatch.setattr(adapter, "_capture_process", fake_capture)
    with pytest.raises(ExeinfopeProcessError) as caught:
        scan_with_exeinfope(executable, sample, log_path=tmp_path / "x.log")
    assert caught.value.code == ExeinfopeErrorCode.PROCESS_FAILED
    assert caught.value.returncode == 3
    assert caught.value.stdout == "so"
    assert caught.value.stderr == "se"
    assert caught.value.details["analyzer_windows"] == ["0x1:TApplication:wait"]


def test_log_errors_are_enriched_with_the_captured_process_context(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable, sample = _exe_and_sample(tmp_path)

    def fake_capture(*args: Any, **kwargs: Any) -> adapter._ProcessCapture:
        del args, kwargs
        return adapter._ProcessCapture("captured-out", "captured-err", 0, False, False, ())

    monkeypatch.setattr(adapter, "_capture_process", fake_capture)
    with pytest.raises(ExeinfopeProtocolError) as caught:
        scan_with_exeinfope(executable, sample, log_path=tmp_path / "missing.log")
    assert caught.value.code == ExeinfopeErrorCode.LOG_MISSING
    assert "argv" in caught.value.details
    assert caught.value.stdout == "captured-out"
    assert caught.value.stderr == "captured-err"
    assert caught.value.returncode == 0


def test_read_log_maps_an_os_read_error_to_protocol_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    log_path = tmp_path / "l.log"
    log_path.write_text("x", encoding="utf-8")

    def deny(*args: Any, **kwargs: Any) -> Any:
        raise OSError("denied")

    monkeypatch.setattr(Path, "open", deny)
    with pytest.raises(ExeinfopeProtocolError) as caught:
        adapter._read_log(log_path, 100)
    assert caught.value.code == ExeinfopeErrorCode.PROTOCOL_ERROR
    assert "denied" in str(caught.value)


def test_window_probe_fails_closed_on_malformed_or_unqueryable_handles() -> None:
    # A description whose handle does not parse, and one whose visibility query
    # fails, must both count as visible so a leaked GUI is never missed.
    assert adapter._is_visible_window("nothex:TForm1:t", visible_check=lambda hwnd: False)

    def boom(hwnd: int) -> bool:
        raise OSError("query failed")

    assert adapter._is_visible_window("0x1:TForm1:t", visible_check=boom)


@pytest.mark.skipif(os.name == "nt", reason="POSIX default visibility path")
def test_window_scan_declines_without_a_visibility_probe() -> None:
    # Off Windows there is no IsWindowVisible; the helper must decline rather
    # than guess and block a scan on invisible transient forms.
    assert adapter._visible_blocked_windows({"0x1:TForm1:t"}) == []


def test_hanging_process_is_terminated_when_a_stream_hits_its_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = _FakeProcess(hangs=True)
    process.stdout = io.BytesIO(b"x" * 64)
    monkeypatch.setattr(subprocess, "Popen", lambda *args, **kwargs: process)
    monkeypatch.setattr(adapter, "describe_process_windows", lambda pid: set())
    with pytest.raises(ExeinfopeOutputLimitError) as caught:
        adapter._capture_process(["fake"], timeout=30.0, max_output_size=8)
    assert process.killed
    assert caught.value.details["stream"] == "stdout"


def test_stderr_over_limit_is_reported_by_stream_name(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = _FakeProcess()
    process.stderr = io.BytesIO(b"y" * 64)
    monkeypatch.setattr(subprocess, "Popen", lambda *args, **kwargs: process)
    monkeypatch.setattr(adapter, "describe_process_windows", lambda pid: set())
    with pytest.raises(ExeinfopeOutputLimitError) as caught:
        adapter._capture_process(["fake"], timeout=1.0, max_output_size=8)
    assert caught.value.details["stream"] == "stderr"


def test_capture_raises_when_the_analyzer_gui_became_visible(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = _FakeProcess()
    monkeypatch.setattr(subprocess, "Popen", lambda *args, **kwargs: process)
    monkeypatch.setattr(adapter, "describe_process_windows", lambda pid: {"0x1:TForm1:Exeinfo PE"})
    monkeypatch.setattr(
        adapter, "_visible_blocked_windows", lambda descriptions: sorted(descriptions)
    )
    with pytest.raises(ExeinfopeGuiWindowError) as caught:
        adapter._capture_process(["fake"], timeout=1.0, max_output_size=1024)
    assert caught.value.details["analyzer_windows"] == ["0x1:TForm1:Exeinfo PE"]


def test_missing_pipes_terminate_the_process(monkeypatch: pytest.MonkeyPatch) -> None:
    # hangs=True models the real failure: the process is still alive when the
    # missing pipes are noticed, so the guard must kill it before raising.
    process = _FakeProcess(hangs=True)
    process.stdout = cast(Any, None)
    monkeypatch.setattr(subprocess, "Popen", lambda *args, **kwargs: process)
    with pytest.raises(ExeinfopeProcessError) as caught:
        adapter._capture_process(["fake"], timeout=1.0, max_output_size=8)
    assert caught.value.code == ExeinfopeErrorCode.PROCESS_FAILED
    assert process.killed


def test_process_that_exits_during_the_wait_slice_returns_a_clean_capture(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # poll() keeps reporting "still running" so the loop reaches wait(); when
    # the wait slice observes the exit, the capture must come back complete
    # and untouched -- a normally exiting scanner is never killed.
    class _SleepyProcess:
        def __init__(self) -> None:
            self.stdout = io.BytesIO(b"hello")
            self.stderr = io.BytesIO(b"")
            self.pid = 4242
            self.wait_calls = 0

        def poll(self) -> int | None:
            return None if self.wait_calls == 0 else 0

        def wait(self, timeout: float | None = None) -> int:
            del timeout
            self.wait_calls += 1
            return 0

        def kill(self) -> None:
            raise AssertionError("a cleanly exiting process must not be killed")

    process = _SleepyProcess()
    monkeypatch.setattr(subprocess, "Popen", lambda *args, **kwargs: process)
    monkeypatch.setattr(adapter, "describe_process_windows", lambda pid: set())
    capture = adapter._capture_process(["fake"], timeout=5.0, max_output_size=64)
    assert capture.returncode == 0
    assert capture.stdout == "hello"
    assert not capture.stdout_exceeded


def test_stream_reader_survives_a_broken_pipe() -> None:
    class _BrokenPipe:
        closed = False

        def read(self, size: int) -> bytes:
            raise OSError("io fail")

        def close(self) -> None:
            self.closed = True

    capture = adapter._CapturedStream(16)
    pipe = _BrokenPipe()
    capture.read_from(cast(Any, pipe), Event())
    assert capture.finished.is_set()
    assert pipe.closed
    assert bytes(capture.data) == b""


def test_cli_adapter_delegates_with_its_configuration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable, sample = _exe_and_sample(tmp_path)
    seen: dict[str, Any] = {}

    def spy(exe: Path, path: Path, **kwargs: Any) -> Any:
        seen.update(kwargs, executable=exe, path=path)
        return "sentinel"

    monkeypatch.setattr(adapter, "scan_with_exeinfope", spy)
    cli = adapter.ExeinfopeCliAdapter(
        executable, timeout=7.0, max_file_size=11, max_output_size=22, max_log_size=33
    )
    result = cli.scan(sample, log_path=tmp_path / "x.log", mode="normal")
    assert cast(object, result) == "sentinel"
    assert seen["executable"] == executable
    assert seen["path"] == sample
    assert seen["mode"] == "normal"
    assert seen["timeout"] == 7.0
    assert seen["max_file_size"] == 11
    assert seen["max_output_size"] == 22
    assert seen["max_log_size"] == 33
