"""Coverage for ``detection.exeinfope`` validation, parsing, and capture arms.

Pure helpers (mode/number/path validation, window filtering, log parsing and
category/name mapping) are called directly; ``scan_with_exeinfope`` and the
adapter run against a real fake Exeinfo PE shell script that honours the
``/log:`` switch, so the capture machinery runs for real on this host.
"""

from __future__ import annotations

import ctypes
import os
import subprocess
from pathlib import Path
from threading import Event
from types import SimpleNamespace
from typing import BinaryIO, cast

import pytest

import headless_re_mcp.detection.exeinfope as ei
from headless_re_mcp.backends.common.bounded_run import BoundedCancelled, bound_cancel_scope
from headless_re_mcp.detection.exeinfope import (
    ExeinfopeCliAdapter,
    ExeinfopeExecutableNotFoundError,
    ExeinfopeGuiWindowError,
    ExeinfopeInputNotFoundError,
    ExeinfopeInputTooLargeError,
    ExeinfopeOutputLimitError,
    ExeinfopeProcessError,
    ExeinfopeProtocolError,
    ExeinfopeScanError,
    parse_exeinfope_log,
    scan_with_exeinfope,
)
from headless_re_mcp.detection.models import FindingCategory, ScanMode

pytestmark = pytest.mark.skipif(os.name == "nt", reason="fake analyzer is a POSIX shell script")


def _fake_exeinfope(tmp_path: Path, *, body: str, name: str = "exeinfope.sh") -> Path:
    script = tmp_path / name
    script.write_text(f"#!/bin/sh\n{body}\n")
    script.chmod(0o755)
    return script


def _log_writer(tmp_path: Path, line: str = "input.exe - UPX 3.96 [packer]") -> Path:
    body = f"log_path=\"${{3#/log:}}\"\nprintf '%s\\n' '{line}' > \"$log_path\""
    return _fake_exeinfope(tmp_path, body=body)


def _sample(tmp_path: Path) -> Path:
    path = tmp_path / "input.exe"
    path.write_bytes(b"MZ\x90\x00")
    return path


# ---------------------------------------------------------------------------
# exceptions / validators / resolvers
# ---------------------------------------------------------------------------


def test_input_not_found_error_uses_the_default_message() -> None:
    assert "does not exist" in str(ExeinfopeInputNotFoundError(Path("/x")))
    assert str(ExeinfopeInputNotFoundError(Path("/x"), "custom")) == "custom"


def test_coerce_mode_rejects_junk() -> None:
    assert ei._coerce_mode("deep") is ScanMode.DEEP
    with pytest.raises(ExeinfopeScanError, match="unsupported Exeinfo PE scan mode"):
        ei._coerce_mode("sideways")


@pytest.mark.parametrize("bad", [True, "x", float("inf"), 0])
def test_validate_positive_number_rejects_bad_values(bad: object) -> None:
    with pytest.raises(ExeinfopeScanError, match="positive finite number"):
        ei._validate_positive_number(bad, "timeout")  # type: ignore[arg-type]


def test_validate_positive_integer_rejects_bad_values() -> None:
    with pytest.raises(ExeinfopeScanError, match="positive integer"):
        ei._validate_positive_integer(0, "max_log_size")


def test_resolve_executable_and_input_guards(tmp_path: Path) -> None:
    with pytest.raises(ExeinfopeExecutableNotFoundError):
        ei._resolve_executable(tmp_path / "nope")
    with pytest.raises(ExeinfopeExecutableNotFoundError):
        ei._resolve_executable(tmp_path)
    with pytest.raises(ExeinfopeInputNotFoundError):
        ei._resolve_input(tmp_path / "nope", 1024)
    with pytest.raises(ExeinfopeInputNotFoundError):
        ei._resolve_input(tmp_path, 1024)
    with pytest.raises(ExeinfopeInputTooLargeError):
        ei._resolve_input(_sample(tmp_path), 1)


def test_resolve_log_path_guards(tmp_path: Path) -> None:
    with pytest.raises(ExeinfopeScanError, match="regular file path"):
        ei._resolve_log_path(tmp_path)

    blocker = tmp_path / "blocker"
    blocker.write_text("flat file")
    with pytest.raises(ExeinfopeScanError, match="log directory"):
        ei._resolve_log_path(blocker / "sub" / "log.txt")


def test_log_flag_quotes_paths_with_whitespace(tmp_path: Path) -> None:
    assert ei._log_flag(Path("/tmp/plain.log")) == "/log:/tmp/plain.log"
    assert ei._log_flag(Path("/tmp/with space.log")) == '/log:"/tmp/with space.log"'


# ---------------------------------------------------------------------------
# window helpers
# ---------------------------------------------------------------------------


def test_is_visible_window_fails_open_on_bad_input() -> None:
    def boom(hwnd: int) -> bool:
        raise OSError("gone")

    assert ei._is_visible_window("nothex:TForm1:x", visible_check=lambda h: False)
    assert ei._is_visible_window("0x10:TForm1:x", visible_check=boom)
    assert ei._is_visible_window("0x10:TForm1:x", visible_check=lambda h: False) is False


def test_visible_blocked_windows_filters_classes_and_visibility() -> None:
    descriptions = {
        "0x1:TForm1:main window",
        "0x2:TForm1:hidden window",
        "0x3:SomethingElse:ignored",
        "malformed",
    }
    blocked = ei._visible_blocked_windows(descriptions, visible_check=lambda hwnd: hwnd != 0x2)
    assert blocked == ["0x1:TForm1:main window"]


def test_visible_blocked_windows_uses_ctypes_on_windows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(os, "name", "nt")
    fake_user32 = SimpleNamespace(IsWindowVisible=lambda hwnd: 1)
    monkeypatch.setattr(ctypes, "windll", SimpleNamespace(user32=fake_user32), raising=False)
    blocked = ei._visible_blocked_windows({"0x10:TForm1:Exeinfo PE"})
    assert blocked == ["0x10:TForm1:Exeinfo PE"]


# ---------------------------------------------------------------------------
# category / name mapping and log parsing
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("Themida 3.x protection", FindingCategory.PROTECTOR),
        ("ConfuserEx obfuscated", FindingCategory.OBFUSCATOR),
        ("Inno Setup installer", FindingCategory.INSTALLER),
        (".NET CLR assembly", FindingCategory.RUNTIME),
        ("plain pe executable", FindingCategory.FILE_FORMAT),
    ],
)
def test_category_for_maps_hint_families(text: str, expected: FindingCategory) -> None:
    assert ei._category_for(text) is expected


def test_name_for_falls_back_when_only_noise_tokens_remain() -> None:
    assert ei._name_for("x64 exe pe") == "exeinfope"
    assert ei._name_for("UPX 3.96") == "UPX"


def test_parse_log_size_and_line_guards() -> None:
    with pytest.raises(ExeinfopeProtocolError, match="size limit"):
        parse_exeinfope_log("a" * (ei.DEFAULT_MAX_LOG_SIZE + 1))
    with pytest.raises(ExeinfopeProtocolError, match="too many lines"):
        parse_exeinfope_log("x\n" * (ei._MAX_LOG_LINES + 1))
    with pytest.raises(ExeinfopeProtocolError, match="is too long"):
        parse_exeinfope_log("b" * (ei._MAX_TEXT + 1))


def test_parse_log_handles_lines_without_a_file_separator() -> None:
    findings = parse_exeinfope_log("UPX packer detected here")
    assert findings[0].summary == "UPX packer detected here"
    assert findings[0].category is FindingCategory.PACKER


# ---------------------------------------------------------------------------
# _read_log / _CapturedStream / _creation_options
# ---------------------------------------------------------------------------


@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores file permissions")
def test_read_log_wraps_an_unreadable_file(tmp_path: Path) -> None:
    log = tmp_path / "log.txt"
    log.write_text("data")
    log.chmod(0o000)
    try:
        with pytest.raises(ExeinfopeProtocolError, match="could not read"):
            ei._read_log(log, 1024)
    finally:
        log.chmod(0o644)


class _ChunkPipe:
    def __init__(self, chunks: list[bytes]) -> None:
        self._chunks = list(chunks)

    def read(self, size: int) -> bytes:
        return self._chunks.pop(0) if self._chunks else b""

    def close(self) -> None:
        return None


class _ExplodingPipe:
    def read(self, size: int) -> bytes:
        raise OSError("torn down")

    def close(self) -> None:
        return None


def test_captured_stream_limit_and_error_arms() -> None:
    stream = ei._CapturedStream(4)
    exceeded = Event()
    stream.read_from(cast(BinaryIO, _ChunkPipe([b"abcdef", b"gh", b""])), exceeded)
    assert bytes(stream.data) == b"abcd"
    assert stream.exceeded and exceeded.is_set()

    other = ei._CapturedStream(4)
    other.read_from(cast(BinaryIO, _ExplodingPipe()), Event())
    assert other.finished.is_set()


def test_creation_options_hides_the_console_on_windows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _StartupInfo:
        def __init__(self) -> None:
            self.dwFlags = 0
            self.wShowWindow = -1

    monkeypatch.setattr(os, "name", "nt")
    monkeypatch.setattr(subprocess, "STARTUPINFO", _StartupInfo, raising=False)
    options = ei._creation_options()
    assert options["startupinfo"].wShowWindow == 0
    assert "start_new_session" not in options


def test_capture_process_rejects_a_process_without_pipes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _NoPipes:
        stdout = None
        stderr = None
        pid = None

        def __init__(self, argv: object, **options: object) -> None:
            pass

        def poll(self) -> int:
            return 0

        def wait(self, timeout: float | None = None) -> int:
            return 0

    monkeypatch.setattr(subprocess, "Popen", _NoPipes)
    with pytest.raises(ExeinfopeProcessError, match="did not expose stdout/stderr"):
        ei._capture_process(["exeinfope"], timeout=1.0, max_output_size=1024)


def test_capture_process_maps_a_start_failure(tmp_path: Path) -> None:
    not_executable = tmp_path / "flat"
    not_executable.write_text("#!/bin/sh\n")
    with pytest.raises(ExeinfopeProcessError, match="could not start"):
        ei._capture_process([str(not_executable)], timeout=1.0, max_output_size=1024)


def test_capture_process_honours_an_active_bound_cancel(tmp_path: Path) -> None:
    exe = _fake_exeinfope(tmp_path, body="sleep 5", name="hung.sh")
    cancel = Event()
    cancel.set()
    with bound_cancel_scope(cancel), pytest.raises(BoundedCancelled):
        ei._capture_process([str(exe)], timeout=5.0, max_output_size=1024)


def test_capture_process_kills_flooding_scanners(tmp_path: Path) -> None:
    stdout_flood = _fake_exeinfope(
        tmp_path, body="head -c 200000 /dev/zero; sleep 2", name="flood_out.sh"
    )
    with pytest.raises(ExeinfopeOutputLimitError) as out_info:
        ei._capture_process([str(stdout_flood)], timeout=5.0, max_output_size=1024)
    assert out_info.value.details["stream"] == "stdout"

    stderr_flood = _fake_exeinfope(
        tmp_path, body="head -c 200000 /dev/zero 1>&2; sleep 2", name="flood_err.sh"
    )
    with pytest.raises(ExeinfopeOutputLimitError) as err_info:
        ei._capture_process([str(stderr_flood)], timeout=5.0, max_output_size=1024)
    assert err_info.value.details["stream"] == "stderr"


# ---------------------------------------------------------------------------
# scan_with_exeinfope / adapter (real subprocess)
# ---------------------------------------------------------------------------


def test_scan_parses_a_real_log_and_replaces_stale_ones(tmp_path: Path) -> None:
    exe = _log_writer(tmp_path)
    log_path = tmp_path / "logs" / "scan.log"
    log_path.parent.mkdir()
    log_path.write_text("stale content from a previous run")
    result = scan_with_exeinfope(exe, _sample(tmp_path), log_path=log_path)
    assert result.returncode == 0
    assert any(f.category is FindingCategory.PACKER for f in result.findings)
    payload = result.to_dict()
    assert payload["claims_universal_unpack"] is False
    assert "UPX" in result.raw_log


def test_scan_maps_a_nonzero_exit(tmp_path: Path) -> None:
    exe = _fake_exeinfope(tmp_path, body="exit 3")
    with pytest.raises(ExeinfopeProcessError, match="status 3"):
        scan_with_exeinfope(exe, _sample(tmp_path), log_path=tmp_path / "scan.log")


def test_scan_enriches_a_missing_log_error_with_process_context(tmp_path: Path) -> None:
    exe = _fake_exeinfope(tmp_path, body="echo scanned; exit 0")
    with pytest.raises(ExeinfopeProtocolError) as excinfo:
        scan_with_exeinfope(exe, _sample(tmp_path), log_path=tmp_path / "scan.log")
    assert excinfo.value.code == "log_missing"
    assert "argv" in excinfo.value.details
    assert "scanned" in excinfo.value.stdout
    assert excinfo.value.returncode == 0


def test_scan_rejects_a_leaked_gui_window(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        ei, "_visible_blocked_windows", lambda descriptions: ["0x1:TForm1:Exeinfo PE"]
    )
    exe = _log_writer(tmp_path)
    with pytest.raises(ExeinfopeGuiWindowError) as excinfo:
        scan_with_exeinfope(exe, _sample(tmp_path), log_path=tmp_path / "scan.log")
    assert excinfo.value.details["analyzer_windows"] == ["0x1:TForm1:Exeinfo PE"]


def test_cli_adapter_delegates_to_scan(tmp_path: Path) -> None:
    exe = _log_writer(tmp_path, line="input.exe - VMProtect 3.5")
    adapter = ExeinfopeCliAdapter(exe, timeout=10.0)
    result = adapter.scan(_sample(tmp_path), log_path=tmp_path / "scan.log", mode="deep")
    assert result.mode is ScanMode.DEEP
    assert result.findings[0].category is FindingCategory.PROTECTOR
