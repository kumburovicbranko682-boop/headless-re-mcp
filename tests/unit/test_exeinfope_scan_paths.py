"""Focused coverage for Exeinfo PE adapter helpers and scan orchestration.

The existing suite exercises the happy path, timeout, stream-limit-on-exit
and the GUI helper, but leaves the pure decoders (category/name mapping,
log parsing bounds), the argument validators and path resolvers, the
mid-run output-limit kill, the log-read I/O error, and the scan
orchestration edges (pre-existing log unlink, non-zero exit, to_dict, the
CLI adapter) unrun. These drive those arms directly with fakes, matching
the fake-process style already in ``test_detection_exeinfope``.
"""

from __future__ import annotations

import io
import subprocess
import time
from datetime import UTC, datetime
from pathlib import Path
from threading import Event
from typing import Any

import pytest

from headless_re_mcp.detection import exeinfope as adapter
from headless_re_mcp.detection.exeinfope import (
    DEFAULT_MAX_LOG_SIZE,
    EXEINFOPE_SOURCE,
    ExeinfopeCliAdapter,
    ExeinfopeErrorCode,
    ExeinfopeExecutableNotFoundError,
    ExeinfopeInputNotFoundError,
    ExeinfopeOutputLimitError,
    ExeinfopeProcessError,
    ExeinfopeProtocolError,
    ExeinfopeScanError,
    _build_argv,
    _category_for,
    _coerce_mode,
    _is_visible_window,
    _log_flag,
    _name_for,
    _read_log,
    _resolve_executable,
    _resolve_input,
    _resolve_log_path,
    _validate_positive_integer,
    _validate_positive_number,
    parse_exeinfope_log,
    scan_with_exeinfope,
)
from headless_re_mcp.detection.models import FindingCategory, ScanMode


def _fake_capture(
    *,
    returncode: int = 0,
    stdout: str = "",
    stderr: str = "",
    windows: tuple[str, ...] = (),
) -> adapter._ProcessCapture:
    return adapter._ProcessCapture(
        stdout=stdout,
        stderr=stderr,
        returncode=returncode,
        stdout_exceeded=False,
        stderr_exceeded=False,
        analyzer_windows=windows,
    )


class TestCategoryFor:
    @pytest.mark.parametrize(
        "text, expected",
        [
            ("Themida / WinLicense protector", FindingCategory.PROTECTOR),
            ("ConfuserEx obfuscator", FindingCategory.OBFUSCATOR),
            ("UPX packer", FindingCategory.PACKER),
            ("Nullsoft installer", FindingCategory.INSTALLER),
            ("Microsoft Visual C++ linker", FindingCategory.COMPILER),
            (".NET / CLR assembly", FindingCategory.RUNTIME),
            ("PE32 executable", FindingCategory.FILE_FORMAT),
            ("total mystery", FindingCategory.ANOMALY),
        ],
    )
    def test_each_hint_family_maps_to_its_category(
        self, text: str, expected: FindingCategory
    ) -> None:
        assert _category_for(text) == expected

    def test_protector_beats_a_generic_pack_substring(self) -> None:
        # "protect" (protector hint) must win over "pack"/"compress" ordering.
        assert _category_for("VMProtect packed binary") == FindingCategory.PROTECTOR


class TestNameFor:
    def test_a_known_tool_token_is_pulled_out(self) -> None:
        assert _name_for("x64 Themida 3.x heavy") == "Themida"

    def test_the_first_meaningful_token_wins_when_no_tool_matches(self) -> None:
        assert _name_for("Frobnicator custom stub") == "Frobnicator"

    def test_only_stopword_tokens_fall_back_to_the_source_name(self) -> None:
        assert _name_for("x64 x86 exe dll pe") == "exeinfope"


class TestParseLogBounds:
    def test_a_line_without_a_separator_is_kept_whole(self) -> None:
        findings = parse_exeinfope_log("SingleTokenNoSeparator")
        assert len(findings) == 1
        assert findings[0].summary == "SingleTokenNoSeparator"

    def test_an_oversized_log_is_a_protocol_error(self) -> None:
        with pytest.raises(ExeinfopeProtocolError) as exc:
            parse_exeinfope_log("a" * (DEFAULT_MAX_LOG_SIZE + 1))
        assert exc.value.details["max_log_size"] == DEFAULT_MAX_LOG_SIZE

    def test_too_many_lines_is_a_protocol_error(self) -> None:
        with pytest.raises(ExeinfopeProtocolError) as exc:
            parse_exeinfope_log("\n".join("x" for _ in range(adapter._MAX_LOG_LINES + 1)))
        assert exc.value.details["max"] == adapter._MAX_LOG_LINES

    def test_a_single_absurdly_long_line_is_a_protocol_error(self) -> None:
        with pytest.raises(ExeinfopeProtocolError) as exc:
            parse_exeinfope_log("z" * (adapter._MAX_TEXT + 1))
        assert exc.value.details["max_length"] == adapter._MAX_TEXT
        assert exc.value.details["index"] == 0


class TestValidators:
    def test_coerce_mode_accepts_enum_and_string(self) -> None:
        assert _coerce_mode(ScanMode.NORMAL) == ScanMode.NORMAL
        assert _coerce_mode("normal") == ScanMode.NORMAL

    def test_coerce_mode_rejects_a_bad_string(self) -> None:
        with pytest.raises(ExeinfopeScanError) as exc:
            _coerce_mode("does-not-exist")
        assert exc.value.code == ExeinfopeErrorCode.INVALID_ARGUMENT
        assert "allowed" in exc.value.details

    @pytest.mark.parametrize("bad", [True, "5", None, [1]])
    def test_positive_number_rejects_non_numbers(self, bad: Any) -> None:
        with pytest.raises(ExeinfopeScanError) as exc:
            _validate_positive_number(bad, "timeout")
        assert exc.value.code == ExeinfopeErrorCode.INVALID_ARGUMENT

    @pytest.mark.parametrize("bad", [0.0, -1.0, float("inf"), float("nan")])
    def test_positive_number_rejects_non_positive_or_non_finite(self, bad: float) -> None:
        with pytest.raises(ExeinfopeScanError):
            _validate_positive_number(bad, "timeout")

    def test_positive_number_accepts_a_finite_positive(self) -> None:
        assert _validate_positive_number(3, "timeout") == 3.0

    @pytest.mark.parametrize("bad", [True, 0, -4, 2.5, "3"])
    def test_positive_integer_rejects_bad_values(self, bad: Any) -> None:
        with pytest.raises(ExeinfopeScanError) as exc:
            _validate_positive_integer(bad, "max_file_size")
        assert exc.value.code == ExeinfopeErrorCode.INVALID_ARGUMENT

    def test_positive_integer_accepts_a_positive_int(self) -> None:
        assert _validate_positive_integer(7, "max_file_size") == 7


class TestResolvers:
    def test_missing_executable_resolves_to_not_found(self, tmp_path: Path) -> None:
        with pytest.raises(ExeinfopeExecutableNotFoundError):
            _resolve_executable(tmp_path / "nope.exe")

    def test_a_directory_executable_is_not_a_file(self, tmp_path: Path) -> None:
        with pytest.raises(ExeinfopeExecutableNotFoundError):
            _resolve_executable(tmp_path)

    def test_missing_input_resolves_to_not_found(self, tmp_path: Path) -> None:
        with pytest.raises(ExeinfopeInputNotFoundError):
            _resolve_input(tmp_path / "absent.bin", 1024)

    def test_a_directory_input_is_not_a_regular_file(self, tmp_path: Path) -> None:
        with pytest.raises(ExeinfopeInputNotFoundError) as exc:
            _resolve_input(tmp_path, 1024)
        assert "regular file" in str(exc.value)

    def test_a_directory_log_path_is_invalid(self, tmp_path: Path) -> None:
        with pytest.raises(ExeinfopeScanError) as exc:
            _resolve_log_path(tmp_path)
        assert exc.value.code == ExeinfopeErrorCode.INVALID_ARGUMENT

    def test_a_log_parent_that_is_a_file_cannot_be_made(self, tmp_path: Path) -> None:
        blocker = tmp_path / "blocker"
        blocker.write_bytes(b"not a directory")
        with pytest.raises(ExeinfopeScanError) as exc:
            _resolve_log_path(blocker / "sub" / "out.log")
        assert exc.value.code == ExeinfopeErrorCode.INVALID_ARGUMENT

    def test_a_clean_log_path_is_created_and_returned(self, tmp_path: Path) -> None:
        target = tmp_path / "logs" / "out.log"
        resolved = _resolve_log_path(target)
        assert resolved == target.resolve()
        assert resolved.parent.is_dir()


class TestLogFlagAndArgv:
    def test_a_plain_path_is_unquoted(self, tmp_path: Path) -> None:
        assert _log_flag(tmp_path / "out.log") == f"/log:{tmp_path / 'out.log'}"

    def test_a_spaced_path_is_quoted(self) -> None:
        assert _log_flag(Path("/tmp/with space/out.log")) == '/log:"/tmp/with space/out.log"'

    def test_argv_is_the_fixed_whitelist(self, tmp_path: Path) -> None:
        argv = _build_argv(tmp_path / "e.exe", tmp_path / "s.bin", tmp_path / "o.log")
        assert argv[0] == str(tmp_path / "e.exe")
        assert argv[1].endswith("*")
        assert argv[2] == "/s"
        assert argv[3].startswith("/log:")


class TestIsVisibleWindow:
    def test_an_unparseable_handle_is_treated_as_visible(self) -> None:
        # Fail-closed: a description we cannot read a hwnd from must not be
        # dismissed as invisible.
        assert _is_visible_window("notahex:TForm1:x", visible_check=lambda h: False) is True

    def test_a_visible_check_that_raises_is_treated_as_visible(self) -> None:
        def boom(_hwnd: int) -> bool:
            raise OSError("USER32 said no")

        assert _is_visible_window("0x10:TForm1:x", visible_check=boom) is True

    def test_a_readable_invisible_window_is_reported_invisible(self) -> None:
        assert _is_visible_window("0x10:TForm1:x", visible_check=lambda h: False) is False


class TestCapturedStreamReadErrors:
    def test_a_reader_error_keeps_prior_bytes_and_closes(self) -> None:
        class _Pipe:
            def __init__(self) -> None:
                self.reads = [b"kept", ValueError("stream closed under us")]
                self.closed = False

            def read(self, _n: int) -> bytes:
                item = self.reads.pop(0)
                if isinstance(item, Exception):
                    raise item
                return item

            def close(self) -> None:
                self.closed = True

        stream = adapter._CapturedStream(limit=1024)
        pipe = _Pipe()
        stream.read_from(pipe, Event())  # type: ignore[arg-type]
        assert stream.text() == "kept"
        assert stream.exceeded is False
        assert pipe.closed is True
        assert stream.finished.is_set()


class _FakeProcess:
    def __init__(self, *, stdout: bytes = b"", stderr: bytes = b"") -> None:
        self.stdout: Any = io.BytesIO(stdout)
        self.stderr: Any = io.BytesIO(stderr)
        self.pid = 4242
        self.killed = False
        self._returncode: int | None = 0

    def poll(self) -> int | None:
        return self._returncode

    def wait(self, timeout: float | None = None) -> int:
        del timeout
        return self._returncode if self._returncode is not None else -9

    def kill(self) -> None:
        self.killed = True
        self._returncode = -9


class TestCaptureProcessEdges:
    def test_a_process_without_pipes_is_a_process_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        process = _FakeProcess()
        process.stdout = None
        process.pid = None  # skip the (Linux no-op) process-group assignment
        monkeypatch.setattr(adapter.subprocess, "Popen", lambda *a, **k: process)
        monkeypatch.setattr(adapter, "_terminate_process", lambda child: None)
        with pytest.raises(ExeinfopeProcessError) as exc:
            adapter._capture_process(
                ["fake"], timeout=1.0, max_output_size=32, window_observer=lambda pid: set()
            )
        assert "stdout/stderr pipes" in str(exc.value)

    def test_a_stderr_flood_is_output_limit(self, monkeypatch: pytest.MonkeyPatch) -> None:
        process = _FakeProcess(stderr=b"e" * 64)
        monkeypatch.setattr(adapter.subprocess, "Popen", lambda *a, **k: process)
        with pytest.raises(ExeinfopeOutputLimitError) as exc:
            adapter._capture_process(
                ["fake"], timeout=1.0, max_output_size=8, window_observer=lambda pid: set()
            )
        assert exc.value.details["stream"] == "stderr"

    def test_a_mid_run_flood_kills_before_the_deadline(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The output-limit arm must terminate a still-running process."""

        class _LingerFlood(_FakeProcess):
            def __init__(self) -> None:
                super().__init__(stdout=b"x" * 200_000)
                self._returncode = None  # stays alive until killed

        process = _LingerFlood()
        monkeypatch.setattr(adapter.subprocess, "Popen", lambda *a, **k: process)
        with pytest.raises(ExeinfopeOutputLimitError) as exc:
            adapter._capture_process(
                ["fake"], timeout=30.0, max_output_size=512, window_observer=lambda pid: set()
            )
        assert exc.value.details["stream"] == "stdout"
        assert process.killed is True

    def test_a_clean_exit_that_stalls_on_the_final_wait_is_force_terminated(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A final reap wait that times out must fall through to a terminate."""

        class _StallOnFinalWait(_FakeProcess):
            def wait(self, timeout: float | None = None) -> int:
                raise subprocess.TimeoutExpired("fake", timeout or 0.0)

        process = _StallOnFinalWait()
        terminated: list[object] = []
        monkeypatch.setattr(adapter.subprocess, "Popen", lambda *a, **k: process)
        monkeypatch.setattr(adapter, "_terminate_process", lambda child: terminated.append(child))
        capture = adapter._capture_process(
            ["fake"], timeout=5.0, max_output_size=64, window_observer=lambda pid: set()
        )
        # The loop broke on a clean poll(); the finally wait then timed out, so
        # the force-terminate fallback must have run before returning.
        assert terminated == [process]
        assert capture.returncode == 0

    def test_a_launch_oserror_becomes_a_process_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def boom(*_a: Any, **_k: Any) -> Any:
            raise OSError("exec format error")

        monkeypatch.setattr(adapter.subprocess, "Popen", boom)
        with pytest.raises(ExeinfopeProcessError) as exc:
            adapter._capture_process(
                ["fake"], timeout=1.0, max_output_size=32, window_observer=lambda pid: set()
            )
        assert exc.value.code == ExeinfopeErrorCode.PROCESS_FAILED
        assert "exec format error" in exc.value.details["os_error"]

    def test_a_missing_binary_becomes_executable_not_found(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def boom(*_a: Any, **_k: Any) -> Any:
            raise FileNotFoundError("no such file")

        monkeypatch.setattr(adapter.subprocess, "Popen", boom)
        with pytest.raises(ExeinfopeExecutableNotFoundError):
            adapter._capture_process(
                ["/no/such/exe"], timeout=1.0, max_output_size=32, window_observer=lambda pid: set()
            )

    def test_a_bound_cancel_stops_the_run_and_raises_cancelled(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        class _AliveProcess(_FakeProcess):
            def __init__(self) -> None:
                super().__init__()
                self._returncode = None

            def wait(self, timeout: float | None = None) -> int:
                if self.killed:
                    return -9
                raise subprocess.TimeoutExpired("fake", timeout or 0.0)

        cancel = Event()
        cancel.set()
        process = _AliveProcess()
        monkeypatch.setattr(adapter.subprocess, "Popen", lambda *a, **k: process)
        monkeypatch.setattr(adapter, "active_bound_cancel", lambda: cancel)
        with pytest.raises(adapter.BoundedCancelled):
            adapter._capture_process(
                ["fake"], timeout=30.0, max_output_size=64, window_observer=lambda pid: set()
            )
        assert process.killed is True

    def test_a_wait_that_returns_ends_the_loop(self, monkeypatch: pytest.MonkeyPatch) -> None:
        class _ExitsOnWait(_FakeProcess):
            def __init__(self) -> None:
                super().__init__()
                self._first = True

            def poll(self) -> int | None:
                # None on the first look so the loop reaches the wait() branch.
                if self._first:
                    self._first = False
                    return None
                return 0

            def wait(self, timeout: float | None = None) -> int:
                return 0

        process = _ExitsOnWait()
        monkeypatch.setattr(adapter.subprocess, "Popen", lambda *a, **k: process)
        capture = adapter._capture_process(
            ["fake"], timeout=5.0, max_output_size=64, window_observer=lambda pid: set()
        )
        assert capture.returncode == 0

    def test_the_window_monitor_polls_a_still_running_process(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A benign (non-blocked) window class is observed but does not fail."""

        class _BrieflyAlive(_FakeProcess):
            def __init__(self) -> None:
                super().__init__()
                self._polls = 0

            def poll(self) -> int | None:
                self._polls += 1
                return None if self._polls <= 3 else 0

            def wait(self, timeout: float | None = None) -> int:
                if self._polls > 3:
                    return 0
                # Pace the loop for real so the 0.05s window monitor tick fires
                # at least once before the process "exits".
                time.sleep(timeout or 0.0)
                raise subprocess.TimeoutExpired("fake", timeout or 0.0)

        observed_pids: list[int] = []

        def observer(pid: int) -> set[str]:
            observed_pids.append(pid)
            return {"0x1:TApplication:BIN ... Please wait"}

        process = _BrieflyAlive()
        monkeypatch.setattr(adapter.subprocess, "Popen", lambda *a, **k: process)
        capture = adapter._capture_process(
            ["fake"], timeout=5.0, max_output_size=64, window_observer=observer
        )
        assert observed_pids, "the monitor thread must have polled the live process"
        # A tolerated TApplication form is not a blocked class, so it is
        # recorded without turning into a GUI failure.
        assert "0x1:TApplication:BIN ... Please wait" in capture.analyzer_windows


class TestReadLog:
    def test_an_io_error_reading_the_log_is_a_protocol_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        log_path = tmp_path / "present.log"
        log_path.write_bytes(b"data")
        real_open = Path.open

        def boom(self: Path, *args: Any, **kwargs: Any) -> Any:
            if self == log_path:
                raise OSError("disk fell over")
            return real_open(self, *args, **kwargs)

        monkeypatch.setattr(Path, "open", boom)
        with pytest.raises(ExeinfopeProtocolError) as exc:
            _read_log(log_path, 1024)
        assert exc.value.code == ExeinfopeErrorCode.PROTOCOL_ERROR


class TestScanOrchestration:
    def _exe_and_sample(self, tmp_path: Path) -> tuple[Path, Path]:
        exe = tmp_path / "Exeinfope.exe"
        exe.write_bytes(b"fake")
        sample = tmp_path / "sample.exe"
        sample.write_bytes(b"MZ")
        return exe, sample

    def test_a_pre_existing_log_is_removed_before_the_scan(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        exe, sample = self._exe_and_sample(tmp_path)
        log_path = tmp_path / "out.log"
        log_path.write_text("stale content from a previous run\n", encoding="utf-8")

        def fake_capture(argv: list[str], **_kw: Any) -> adapter._ProcessCapture:
            # If the stale log had survived, this fresh write would append to
            # it; the parser would then see both runs.
            log_path.write_text("sample.exe -  x64 UPX v3.9\n", encoding="utf-8")
            return _fake_capture()

        monkeypatch.setattr(adapter, "_capture_process", fake_capture)
        result = scan_with_exeinfope(exe, sample, log_path=log_path)
        assert len(result.findings) == 1
        assert result.findings[0].name == "UPX"

        payload = result.to_dict()
        assert payload["source"]["name"] == EXEINFOPE_SOURCE
        assert payload["claims_universal_unpack"] is False
        assert payload["returncode"] == 0

    def test_a_non_zero_exit_is_process_failed_with_argv(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        exe, sample = self._exe_and_sample(tmp_path)
        monkeypatch.setattr(
            adapter,
            "_capture_process",
            lambda *a, **k: _fake_capture(returncode=2, stderr="exeinfope: boom"),
        )
        with pytest.raises(ExeinfopeProcessError) as exc:
            scan_with_exeinfope(exe, sample, log_path=tmp_path / "x.log")
        assert exc.value.code == ExeinfopeErrorCode.PROCESS_FAILED
        assert exc.value.returncode == 2
        assert exc.value.details["argv"][2] == "/s"
        assert exc.value.stderr == "exeinfope: boom"

    def test_a_parse_failure_is_annotated_with_capture_context(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        exe, sample = self._exe_and_sample(tmp_path)
        log_path = tmp_path / "empty.log"

        def fake_capture(*a: Any, **k: Any) -> adapter._ProcessCapture:
            log_path.write_text("\n\n", encoding="utf-8")
            return _fake_capture(stdout="ran", stderr="warn")

        monkeypatch.setattr(adapter, "_capture_process", fake_capture)
        with pytest.raises(ExeinfopeProtocolError) as exc:
            scan_with_exeinfope(exe, sample, log_path=log_path)
        # The empty-log protocol error carries the argv and streams the parser
        # itself never saw, so a caller can still diagnose the run.
        assert "argv" in exc.value.details
        assert exc.value.stdout == "ran"
        assert exc.value.stderr == "warn"
        assert exc.value.returncode == 0


class TestCliAdapter:
    def test_the_adapter_forwards_its_configured_bounds(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        exe = tmp_path / "Exeinfope.exe"
        exe.write_bytes(b"fake")
        sample = tmp_path / "sample.exe"
        sample.write_bytes(b"MZ")
        log_path = tmp_path / "out.log"
        seen: dict[str, Any] = {}

        def fake_scan(executable: Path, path: Path, **kwargs: Any) -> Any:
            seen["executable"] = executable
            seen["path"] = path
            seen.update(kwargs)
            return "sentinel-result"

        monkeypatch.setattr(adapter, "scan_with_exeinfope", fake_scan)
        cli = ExeinfopeCliAdapter(
            exe, timeout=12.0, max_file_size=99, max_output_size=88, max_log_size=77
        )
        assert cli.executable == exe
        assert cli.timeout == 12.0
        assert cli.max_file_size == 99

        out = cli.scan(sample, log_path=log_path, mode=ScanMode.DEEP)
        assert out == "sentinel-result"
        assert seen["executable"] == exe
        assert seen["path"] == sample
        assert seen["timeout"] == 12.0
        assert seen["max_file_size"] == 99
        assert seen["max_output_size"] == 88
        assert seen["max_log_size"] == 77
        assert seen["mode"] == ScanMode.DEEP


def test_scan_result_to_dict_round_trips(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    result = adapter.ExeinfopeScanResult(
        path=tmp_path / "s.exe",
        size=3,
        mode=ScanMode.NORMAL,
        findings=(),
        source=adapter.DetectionSource(name=EXEINFOPE_SOURCE, status="completed", duration_ms=1),
        raw_log="log",
        log_path=tmp_path / "s.log",
        stdout="",
        stderr="",
        returncode=0,
        scanned_at=datetime.now(UTC),
    )
    value = result.to_dict()
    assert isinstance(value, dict)
    assert value["source"]["name"] == EXEINFOPE_SOURCE
    assert value["claims_universal_unpack"] is False
