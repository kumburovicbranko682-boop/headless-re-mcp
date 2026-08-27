from __future__ import annotations

import io
import os
import subprocess
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.detection import (
    ExeinfopeErrorCode,
    ExeinfopeGuiWindowError,
    ExeinfopeInputTooLargeError,
    ExeinfopeOutputLimitError,
    ExeinfopeProtocolError,
    ExeinfopeTimeoutError,
    FindingCategory,
    parse_exeinfope_log,
    scan_with_exeinfope,
)
from headless_re_mcp.detection import exeinfope as adapter
from headless_re_mcp.detection.models import FindingSeverity


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


def test_parse_log_maps_every_category_bucket() -> None:
    """Each classifier branch has to land in its own bucket in priority order.

    Only packer/compiler/anomaly were exercised, so a regression in the
    protector, obfuscator, installer, runtime, or file-format arms -- or in the
    order they are tried -- would have gone unnoticed. Anomaly is the only
    category that downgrades severity to a hint; the rest stay informational.
    """
    raw = "\n".join(
        [
            "s.exe -  Themida / WinLicense protector",
            "s.exe -  Confuser .NET obfuscator",
            "s.exe -  Inno Setup installer",
            "s.exe -  Microsoft .NET Framework assembly",
            "s.exe -  PE32 executable",
            "s.exe -  totally unknown blob",
        ]
    )
    findings = parse_exeinfope_log(raw)
    assert [item.category for item in findings] == [
        FindingCategory.PROTECTOR,
        FindingCategory.OBFUSCATOR,
        FindingCategory.INSTALLER,
        FindingCategory.RUNTIME,
        FindingCategory.FILE_FORMAT,
        FindingCategory.ANOMALY,
    ]
    assert findings[-1].severity == FindingSeverity.HINT
    assert all(item.severity == FindingSeverity.INFO for item in findings[:-1])


def test_name_for_handles_multiword_names_and_token_fallbacks() -> None:
    """The product regex, the token scan, and the last-resort literal all matter.

    A two-word product name must survive as one token, a description with no
    known product falls back to the first meaningful token (skipping arch/format
    noise), and a description that is nothing but noise yields the literal
    ``exeinfope`` rather than an empty name.
    """
    assert adapter._name_for("x64 Inno Setup installer") == "Inno Setup"
    assert adapter._name_for("x64 exe SuperWidget blob") == "SuperWidget"
    assert adapter._name_for("x64 exe dll pe") == "exeinfope"


def test_parse_log_rejects_oversized_log() -> None:
    with pytest.raises(ExeinfopeProtocolError) as caught:
        parse_exeinfope_log("x" * (adapter.DEFAULT_MAX_LOG_SIZE + 1))
    assert caught.value.code == ExeinfopeErrorCode.PROTOCOL_ERROR
    assert caught.value.details["max_log_size"] == adapter.DEFAULT_MAX_LOG_SIZE


def test_parse_log_rejects_too_many_lines() -> None:
    raw = "\n".join(["a"] * (adapter._MAX_LOG_LINES + 1))
    with pytest.raises(ExeinfopeProtocolError) as caught:
        parse_exeinfope_log(raw)
    assert caught.value.code == ExeinfopeErrorCode.PROTOCOL_ERROR
    assert caught.value.details["max"] == adapter._MAX_LOG_LINES


def test_parse_log_rejects_overlong_line() -> None:
    with pytest.raises(ExeinfopeProtocolError) as caught:
        parse_exeinfope_log("y" * (adapter._MAX_TEXT + 1))
    assert caught.value.code == ExeinfopeErrorCode.PROTOCOL_ERROR
    assert caught.value.details["index"] == 0


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
