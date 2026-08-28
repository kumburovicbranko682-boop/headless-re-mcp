"""Cover the Exeinfo PE adapter's argument validators, path resolvers, log
parser bounds, category/name heuristics, and the capture arms that only the
poll loop reaches (stdout/stderr limits, a leaked GUI form, a wedged wait, and
missing stdio pipes)."""

from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path
from threading import Event
from typing import Any

import pytest

import headless_re_mcp.detection.exeinfope as adapter
from headless_re_mcp.detection import (
    ExeinfopeErrorCode,
    ExeinfopeExecutableNotFoundError,
    ExeinfopeGuiWindowError,
    ExeinfopeInputNotFoundError,
    ExeinfopeOutputLimitError,
    ExeinfopeProcessError,
    ExeinfopeProtocolError,
    ExeinfopeScanError,
    FindingCategory,
    ScanMode,
    parse_exeinfope_log,
    scan_with_exeinfope,
)


def _script(path: Path, body: str) -> Path:
    path.write_text("#!/bin/sh\n" + body, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return path


# Most tests fake the capture or the process object outright. The ones marked
# below launch a real child from a "#!/bin/sh" script, which cannot run on
# Windows (WinError 193).
_EXECUTES_SH_SCRIPT = pytest.mark.skipif(
    os.name == "nt", reason="the fake tool is a POSIX sh script"
)


def _fake_capture(**kwargs: Any) -> adapter._ProcessCapture:
    defaults: dict[str, Any] = {
        "stdout": "",
        "stderr": "",
        "returncode": 0,
        "stdout_exceeded": False,
        "stderr_exceeded": False,
        "analyzer_windows": (),
    }
    defaults.update(kwargs)
    return adapter._ProcessCapture(**defaults)


# --- argument validators ------------------------------------------------------


def test_coerce_mode_rejects_an_unknown_mode() -> None:
    with pytest.raises(ExeinfopeScanError) as caught:
        adapter._coerce_mode("nonsense")
    assert caught.value.code == ExeinfopeErrorCode.INVALID_ARGUMENT


def test_positive_number_rejects_bool_and_nonpositive() -> None:
    with pytest.raises(ExeinfopeScanError):
        adapter._validate_positive_number(True, "timeout")
    with pytest.raises(ExeinfopeScanError):
        adapter._validate_positive_number(0.0, "timeout")
    assert adapter._validate_positive_number(1.5, "timeout") == 1.5


def test_positive_integer_rejects_bool_and_nonpositive() -> None:
    with pytest.raises(ExeinfopeScanError):
        adapter._validate_positive_integer(True, "max_file_size")
    with pytest.raises(ExeinfopeScanError):
        adapter._validate_positive_integer(0, "max_file_size")
    assert adapter._validate_positive_integer(7, "max_file_size") == 7


# --- path resolvers -----------------------------------------------------------


def test_resolve_executable_reports_missing_and_nonfile(tmp_path: Path) -> None:
    with pytest.raises(ExeinfopeExecutableNotFoundError):
        adapter._resolve_executable(tmp_path / "nope.exe")
    a_dir = tmp_path / "dir"
    a_dir.mkdir()
    with pytest.raises(ExeinfopeExecutableNotFoundError):
        adapter._resolve_executable(a_dir)


def test_resolve_input_reports_missing_nonfile_and_stat_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with pytest.raises(ExeinfopeInputNotFoundError):
        adapter._resolve_input(tmp_path / "gone.bin", 1024)
    a_dir = tmp_path / "adir"
    a_dir.mkdir()
    with pytest.raises(ExeinfopeInputNotFoundError):
        adapter._resolve_input(a_dir, 1024)

    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"MZ")
    resolved_sample = sample.resolve()
    real_stat = Path.stat
    calls = {"n": 0}

    def flaky_stat(self: Path, *args: Any, **kwargs: Any) -> Any:
        # resolve(strict=True) stats the target first; fail only the explicit
        # size probe that follows so we exercise the stat-failure arm, not the
        # resolve-failure arm.
        if self == resolved_sample:
            calls["n"] += 1
            if calls["n"] >= 2:
                raise OSError("stat exploded")
        return real_stat(self, *args, **kwargs)

    monkeypatch.setattr(Path, "stat", flaky_stat)
    with pytest.raises(ExeinfopeInputNotFoundError):
        adapter._resolve_input(sample, 1024)


def test_resolve_log_path_rejects_directory_and_unmakeable_parent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    a_dir = tmp_path / "logdir"
    a_dir.mkdir()
    with pytest.raises(ExeinfopeScanError) as caught:
        adapter._resolve_log_path(a_dir)
    assert caught.value.code == ExeinfopeErrorCode.INVALID_ARGUMENT

    def boom_mkdir(self: Path, *args: Any, **kwargs: Any) -> None:
        raise OSError("read-only")

    monkeypatch.setattr(Path, "mkdir", boom_mkdir)
    with pytest.raises(ExeinfopeScanError) as caught:
        adapter._resolve_log_path(tmp_path / "sub" / "out.log")
    assert caught.value.code == ExeinfopeErrorCode.INVALID_ARGUMENT


def test_log_flag_quotes_paths_with_spaces() -> None:
    assert adapter._log_flag(Path("/tmp/plain.log")) == "/log:/tmp/plain.log"
    quoted = adapter._log_flag(Path("/tmp/with space.log"))
    assert quoted.startswith('/log:"') and quoted.endswith('"')


# --- category / name heuristics ----------------------------------------------


def test_category_for_covers_each_family() -> None:
    assert adapter._category_for("VMProtect 3.x") == FindingCategory.PROTECTOR
    assert adapter._category_for("ConfuserEx") == FindingCategory.OBFUSCATOR
    assert adapter._category_for("Nullsoft") == FindingCategory.INSTALLER
    assert adapter._category_for(".NET Framework") == FindingCategory.RUNTIME
    assert adapter._category_for("Portable Executable") == FindingCategory.FILE_FORMAT


def test_name_for_falls_back_to_the_source_name() -> None:
    assert adapter._name_for("x64 exe dll pe") == "exeinfope"


# --- log parser bounds --------------------------------------------------------


def test_parse_log_rejects_oversized_payload(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(adapter, "DEFAULT_MAX_LOG_SIZE", 8)
    with pytest.raises(ExeinfopeProtocolError) as caught:
        parse_exeinfope_log("x" * 32)
    assert caught.value.code == ExeinfopeErrorCode.PROTOCOL_ERROR


def test_parse_log_rejects_too_many_lines(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(adapter, "_MAX_LOG_LINES", 3)
    raw = "\n".join(f"file - hint {n}" for n in range(10))
    with pytest.raises(ExeinfopeProtocolError):
        parse_exeinfope_log(raw)


def test_parse_log_rejects_an_overlong_line(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(adapter, "_MAX_TEXT", 4)
    with pytest.raises(ExeinfopeProtocolError):
        parse_exeinfope_log("this line is much longer than four")


def test_parse_log_accepts_lines_without_a_dash_separator() -> None:
    findings = parse_exeinfope_log("UPX standalone banner")
    assert findings[0].summary == "UPX standalone banner"
    assert findings[0].name == "UPX"


# --- capture stream helpers ---------------------------------------------------


def test_captured_stream_survives_a_broken_pipe() -> None:
    class _BoomPipe:
        def read(self, _n: int) -> bytes:
            raise OSError("pipe went away")

        def close(self) -> None:
            return None

    captured = adapter._CapturedStream(limit=16)
    captured.read_from(_BoomPipe(), Event())  # type: ignore[arg-type]
    assert captured.finished.is_set()
    assert captured.text() == ""


def test_is_visible_window_fails_open_on_bad_input_and_errors() -> None:
    assert adapter._is_visible_window("not-hex:cls:t", visible_check=lambda h: False) is True

    def raiser(_hwnd: int) -> bool:
        raise OSError("winapi down")

    assert adapter._is_visible_window("0x10:cls:t", visible_check=raiser) is True


# --- _read_log unreadable file ------------------------------------------------


def test_read_log_wraps_an_os_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    log_path = tmp_path / "present.log"
    log_path.write_text("data", encoding="utf-8")
    real_open = Path.open

    def boom_open(self: Path, *args: Any, **kwargs: Any) -> Any:
        if self == log_path:
            raise OSError("cannot read")
        return real_open(self, *args, **kwargs)

    monkeypatch.setattr(Path, "open", boom_open)
    with pytest.raises(ExeinfopeProtocolError) as caught:
        adapter._read_log(log_path, 1024)
    assert caught.value.code == ExeinfopeErrorCode.PROTOCOL_ERROR


# --- capture process arms via real child processes ---------------------------


@_EXECUTES_SH_SCRIPT
def test_capture_terminates_when_stdout_exceeds_the_limit_mid_run(tmp_path: Path) -> None:
    script = _script(tmp_path / "flood.sh", "head -c 200000 /dev/zero\nsleep 5\n")
    with pytest.raises(ExeinfopeOutputLimitError) as caught:
        adapter._capture_process(
            [str(script)],
            timeout=5.0,
            max_output_size=8,
            window_observer=lambda _pid: set(),
        )
    assert caught.value.details["stream"] == "stdout"


@_EXECUTES_SH_SCRIPT
def test_capture_reports_a_stderr_overrun(tmp_path: Path) -> None:
    script = _script(tmp_path / "floode.sh", "head -c 200000 /dev/zero 1>&2\nexit 0\n")
    with pytest.raises(ExeinfopeOutputLimitError) as caught:
        adapter._capture_process(
            [str(script)],
            timeout=5.0,
            max_output_size=8,
            window_observer=lambda _pid: set(),
        )
    assert caught.value.details["stream"] == "stderr"


@_EXECUTES_SH_SCRIPT
def test_capture_raises_when_a_blocked_gui_form_appears(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    script = _script(tmp_path / "quiet.sh", "exit 0\n")
    monkeypatch.setattr(
        adapter, "_visible_blocked_windows", lambda descriptions: ["0x10:TForm1:leak"]
    )
    with pytest.raises(ExeinfopeGuiWindowError) as caught:
        adapter._capture_process(
            [str(script)],
            timeout=5.0,
            max_output_size=4096,
            window_observer=lambda _pid: {"0x10:TForm1:leak"},
        )
    assert caught.value.code == ExeinfopeErrorCode.GUI_WINDOW_DETECTED


def test_capture_maps_launch_failures(monkeypatch: pytest.MonkeyPatch) -> None:
    def missing(*_a: Any, **_k: Any) -> Any:
        raise FileNotFoundError("no such binary")

    monkeypatch.setattr(subprocess, "Popen", missing)
    with pytest.raises(ExeinfopeExecutableNotFoundError):
        adapter._capture_process(["nope"], timeout=1.0, max_output_size=8)

    def denied(*_a: Any, **_k: Any) -> Any:
        raise OSError("permission denied")

    monkeypatch.setattr(subprocess, "Popen", denied)
    with pytest.raises(ExeinfopeProcessError) as caught:
        adapter._capture_process(["nope"], timeout=1.0, max_output_size=8)
    assert caught.value.code == ExeinfopeErrorCode.PROCESS_FAILED


@_EXECUTES_SH_SCRIPT
def test_capture_polls_windows_while_the_child_runs(tmp_path: Path) -> None:
    script = _script(tmp_path / "slow.sh", "sleep 0.3\nexit 0\n")
    seen: list[int] = []

    def observer(pid: int) -> set[str]:
        seen.append(pid)
        # A tolerated transient form -- not one of the blocked classes.
        return {"0x1:TApplication:BIN ... Please wait"}

    capture = adapter._capture_process(
        [str(script)], timeout=5.0, max_output_size=4096, window_observer=observer
    )
    assert capture.returncode == 0
    assert "0x1:TApplication:BIN ... Please wait" in capture.analyzer_windows
    assert seen


@_EXECUTES_SH_SCRIPT
def test_capture_honors_an_active_cancellation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from headless_re_mcp.backends.common.bounded_run import BoundedCancelled

    stop = Event()
    stop.set()
    monkeypatch.setattr(adapter, "active_bound_cancel", lambda: stop)
    monkeypatch.setattr(adapter, "describe_process_windows", lambda pid: set())
    script = _script(tmp_path / "sleepy.sh", "sleep 5\n")
    with pytest.raises(BoundedCancelled):
        adapter._capture_process(
            [str(script)],
            timeout=5.0,
            max_output_size=4096,
            window_observer=lambda _pid: set(),
        )


def test_capture_defaults_returncode_when_a_cancelled_child_never_reaps(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import io

    from headless_re_mcp.backends.common.bounded_run import BoundedCancelled

    class _NeverReaps:
        pid = 4242

        def __init__(self) -> None:
            self.stdout = io.BytesIO(b"")
            self.stderr = io.BytesIO(b"")

        def poll(self) -> int | None:
            return None

        def wait(self, timeout: float | None = None) -> int:
            raise subprocess.TimeoutExpired("fake", timeout or 0.0)

    stop = Event()
    stop.set()
    monkeypatch.setattr(adapter, "active_bound_cancel", lambda: stop)
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: _NeverReaps())
    monkeypatch.setattr(adapter, "_terminate_process", lambda process: None)
    monkeypatch.setattr(adapter, "describe_process_windows", lambda pid: set())
    with pytest.raises(BoundedCancelled):
        adapter._capture_process(["fake"], timeout=1.0, max_output_size=8)


def test_capture_reports_missing_stdio_pipes(monkeypatch: pytest.MonkeyPatch) -> None:
    class _NoPipeProcess:
        pid = 0
        stdout = None
        stderr = None

        def poll(self) -> int:
            return 0

    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: _NoPipeProcess())
    monkeypatch.setattr(adapter, "_terminate_process", lambda process: None)
    with pytest.raises(ExeinfopeProcessError) as caught:
        adapter._capture_process(["fake"], timeout=1.0, max_output_size=8)
    assert caught.value.code == ExeinfopeErrorCode.PROCESS_FAILED


def test_capture_terminates_a_child_that_wedges_the_final_wait(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import io

    class _WedgingProcess:
        pid = 0

        def __init__(self) -> None:
            self.stdout = io.BytesIO(b"")
            self.stderr = io.BytesIO(b"")
            self._returncode: int | None = None
            self._waits = 0
            self.killed = False

        def poll(self) -> int | None:
            return self._returncode

        def wait(self, timeout: float | None = None) -> int:
            self._waits += 1
            if self._waits == 1:
                self._returncode = 0
                return 0
            raise subprocess.TimeoutExpired("fake", timeout or 0.0)

        def kill(self) -> None:
            self.killed = True
            self._returncode = -9

    process = _WedgingProcess()
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: process)
    monkeypatch.setattr(adapter, "_terminate_process", lambda child: child.kill())
    monkeypatch.setattr(adapter, "describe_process_windows", lambda pid: set())
    capture = adapter._capture_process(["fake"], timeout=1.0, max_output_size=32)
    assert process.killed
    assert capture.returncode == -9


# --- scan_with_exeinfope arms -------------------------------------------------


def test_scan_unlinks_a_stale_log_and_reports_to_dict(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable = tmp_path / "Exeinfope.exe"
    executable.write_bytes(b"fake")
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ")
    log_path = tmp_path / "out.log"
    log_path.write_text("stale contents that must be replaced", encoding="utf-8")

    def fake_capture(argv: list[str], **kwargs: Any) -> adapter._ProcessCapture:
        # The stale log must have been unlinked before we write the fresh one.
        assert not log_path.exists()
        log_path.write_text("sample.exe - UPX packer\n", encoding="utf-8")
        return _fake_capture()

    monkeypatch.setattr(adapter, "_capture_process", fake_capture)
    result = scan_with_exeinfope(executable, sample, log_path=log_path, mode=ScanMode.NORMAL)
    payload = result.to_dict()
    assert payload["source"]["name"] == "exeinfope"
    assert payload["findings"][0]["name"] == "UPX"


def test_scan_maps_a_nonzero_exit_to_process_failed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable = tmp_path / "Exeinfope.exe"
    executable.write_bytes(b"fake")
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ")

    monkeypatch.setattr(
        adapter, "_capture_process", lambda *a, **k: _fake_capture(returncode=3)
    )
    with pytest.raises(ExeinfopeProcessError) as caught:
        scan_with_exeinfope(executable, sample, log_path=tmp_path / "x.log")
    assert caught.value.code == ExeinfopeErrorCode.PROCESS_FAILED
    assert caught.value.returncode == 3


# --- ExeinfopeCliAdapter ------------------------------------------------------


def test_cli_adapter_forwards_its_configuration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: dict[str, Any] = {}

    def fake_scan(executable: Path, path: Path, **kwargs: Any) -> str:
        seen["executable"] = executable
        seen["path"] = path
        seen.update(kwargs)
        return "scanned"

    monkeypatch.setattr(adapter, "scan_with_exeinfope", fake_scan)
    cli = adapter.ExeinfopeCliAdapter(
        tmp_path / "Exeinfope.exe",
        timeout=12.0,
        max_file_size=111,
        max_output_size=222,
        max_log_size=333,
    )
    out = cli.scan(tmp_path / "sample.exe", log_path=tmp_path / "out.log")
    assert out == "scanned"  # type: ignore[comparison-overlap]
    assert seen["timeout"] == 12.0
    assert seen["max_file_size"] == 111
    assert seen["max_output_size"] == 222
    assert seen["max_log_size"] == 333
