"""Branch coverage for the DIE (``diec``) adapter helpers.

These exercise the private validation, parsing, and process helpers directly so
the error and platform branches that the end-to-end scan tests never reach are
covered on a non-Windows host.
"""

from __future__ import annotations

import io
import json
import subprocess
from pathlib import Path
from threading import Event
from typing import Any

import pytest

import headless_re_mcp.core.process_tree as process_tree
from headless_re_mcp.detection import FindingCategory, ScanMode
from headless_re_mcp.detection import die as die_adapter
from headless_re_mcp.detection.die import (
    DieCliAdapter,
    DieExecutableNotFoundError,
    DieInputNotFoundError,
    DieInputTooLargeError,
    DieProtocolError,
    DieScanError,
    scan_with_die,
)


def _capture(stdout: str) -> die_adapter._ProcessCapture:
    return die_adapter._ProcessCapture(
        stdout=stdout,
        stderr="",
        returncode=0,
        stdout_exceeded=False,
        stderr_exceeded=False,
    )


def _payload() -> dict[str, Any]:
    return {
        "detects": [
            {
                "filetype": "PE64",
                "values": [
                    {
                        "info": "",
                        "name": "UPX",
                        "string": "Packer: UPX",
                        "type": "packer",
                        "version": "4.2",
                    }
                ],
            }
        ]
    }


# --------------------------------------------------------------------------
# argument validation
# --------------------------------------------------------------------------


def test_coerce_mode_rejects_an_unknown_mode() -> None:
    with pytest.raises(DieScanError) as info:
        die_adapter._coerce_mode("sideways")
    assert info.value.code == die_adapter.DieErrorCode.INVALID_ARGUMENT


@pytest.mark.parametrize("value", ["ten", True, float("inf"), float("nan"), 0, -1.0])
def test_validate_positive_number_rejects_bad_values(value: Any) -> None:
    with pytest.raises(DieScanError, match="positive finite number"):
        die_adapter._validate_positive_number(value, "timeout")


def test_validate_positive_number_accepts_a_real_number() -> None:
    assert die_adapter._validate_positive_number(2, "timeout") == 2.0


@pytest.mark.parametrize("value", [0, -3, True, "5"])
def test_validate_positive_integer_rejects_bad_values(value: Any) -> None:
    with pytest.raises(DieScanError, match="positive integer"):
        die_adapter._validate_positive_integer(value, "max_file_size")


def test_resolve_executable_reports_a_missing_path(tmp_path: Path) -> None:
    with pytest.raises(DieExecutableNotFoundError):
        die_adapter._resolve_executable(tmp_path / "nope.exe")


def test_resolve_executable_rejects_a_directory(tmp_path: Path) -> None:
    with pytest.raises(DieExecutableNotFoundError):
        die_adapter._resolve_executable(tmp_path)


def test_resolve_input_reports_a_missing_file(tmp_path: Path) -> None:
    with pytest.raises(DieInputNotFoundError):
        die_adapter._resolve_input(tmp_path / "ghost.bin", 1024)


def test_resolve_input_rejects_a_directory(tmp_path: Path) -> None:
    with pytest.raises(DieInputNotFoundError, match="regular file"):
        die_adapter._resolve_input(tmp_path, 1024)


def test_resolve_input_maps_a_stat_failure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"MZ")
    resolved = sample.resolve()
    real_stat = Path.stat
    hits = {"n": 0}

    def flaky_stat(self: Path, *args: Any, **kwargs: Any) -> Any:
        # is_file() stats first; fail only the explicit size-check stat after it.
        if self == resolved:
            hits["n"] += 1
            if hits["n"] >= 2:
                raise OSError("stat denied")
        return real_stat(self, *args, **kwargs)

    monkeypatch.setattr(Path, "stat", flaky_stat)
    with pytest.raises(DieInputNotFoundError, match="could not stat"):
        die_adapter._resolve_input(sample, 1024)


def test_resolve_input_enforces_the_size_ceiling(tmp_path: Path) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"123456")
    with pytest.raises(DieInputTooLargeError):
        die_adapter._resolve_input(sample, 4)


# --------------------------------------------------------------------------
# category mapping
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("type_name", "expected"),
    [
        ("Linker", FindingCategory.LINKER),
        ("installer", FindingCategory.INSTALLER),
        ("Obfuscator", FindingCategory.OBFUSCATOR),
        ("protection", FindingCategory.PROTECTOR),
        ("virtual machine", FindingCategory.RUNTIME),
        ("binary format", FindingCategory.FILE_FORMAT),
        ("something else", FindingCategory.ANOMALY),
    ],
)
def test_category_for_maps_each_family(type_name: str, expected: FindingCategory) -> None:
    assert die_adapter._category_for(type_name) is expected


# --------------------------------------------------------------------------
# JSON normalization guards
# --------------------------------------------------------------------------


def test_normalize_rejects_too_many_detects() -> None:
    payload = {"detects": [{"filetype": "PE", "values": []}] * (die_adapter._MAX_DETECTS + 1)}
    with pytest.raises(DieProtocolError, match="too many detect records"):
        die_adapter._normalize_json(payload)


def test_normalize_rejects_a_blank_filetype() -> None:
    with pytest.raises(DieProtocolError, match="must not be blank"):
        die_adapter._normalize_json({"detects": [{"filetype": "   ", "values": []}]})


def test_normalize_rejects_too_many_values() -> None:
    payload = {
        "detects": [
            {
                "filetype": "PE",
                "values": [{"type": "x", "name": "y", "string": "", "info": "", "version": ""}]
                * (die_adapter._MAX_VALUES_PER_DETECT + 1),
            }
        ]
    }
    with pytest.raises(DieProtocolError, match="too many records"):
        die_adapter._normalize_json(payload)


def test_normalize_rejects_a_non_string_field() -> None:
    payload = {"detects": [{"filetype": 123, "values": []}]}
    with pytest.raises(DieProtocolError, match="must be a string"):
        die_adapter._normalize_json(payload)


def test_normalize_rejects_an_overlong_field() -> None:
    payload = {"detects": [{"filetype": "x" * (die_adapter._MAX_TEXT + 1), "values": []}]}
    with pytest.raises(DieProtocolError, match="too long"):
        die_adapter._normalize_json(payload)


# --------------------------------------------------------------------------
# _parse_json branches
# --------------------------------------------------------------------------


def test_parse_json_rejects_empty_stdout() -> None:
    with pytest.raises(DieProtocolError, match="no JSON on stdout"):
        die_adapter._parse_json("   ")


def test_parse_json_rejects_non_standard_constants() -> None:
    with pytest.raises(DieProtocolError, match="invalid JSON"):
        die_adapter._parse_json('{"x": NaN}')


def test_parse_json_maps_a_normalizer_type_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def broken(_payload: object) -> Any:
        raise ValueError("boom")

    monkeypatch.setattr(die_adapter, "_normalize_json", broken)
    with pytest.raises(DieProtocolError, match="could not normalize"):
        die_adapter._parse_json(json.dumps(_payload()))


def test_parse_json_reraises_a_structured_protocol_error() -> None:
    # A decodable object that _normalize_json rejects must surface as-is.
    with pytest.raises(DieProtocolError, match="must not be blank"):
        die_adapter._parse_json(json.dumps({"detects": [{"filetype": " ", "values": []}]}))


# --------------------------------------------------------------------------
# _CapturedStream.read_from
# --------------------------------------------------------------------------


def test_captured_stream_marks_overflow_when_the_limit_is_zero() -> None:
    stream = die_adapter._CapturedStream(limit=0)
    stream.read_from(io.BytesIO(b"abc"), Event())
    assert stream.exceeded is True
    assert bytes(stream.data) == b""
    assert stream.finished.is_set()


def test_captured_stream_survives_a_pipe_that_raises() -> None:
    closed: list[bool] = []

    class _AngryPipe:
        def read(self, _size: int) -> bytes:
            raise OSError("pipe reset")

        def close(self) -> None:
            closed.append(True)

    stream = die_adapter._CapturedStream(limit=16)
    stream.read_from(_AngryPipe(), Event())  # type: ignore[arg-type]
    assert closed == [True]
    assert stream.finished.is_set()


# --------------------------------------------------------------------------
# _creation_options platform branch
# --------------------------------------------------------------------------


def test_creation_options_hides_the_console_on_windows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _StartupInfo:
        def __init__(self) -> None:
            self.dwFlags = 0
            self.wShowWindow = 9

    monkeypatch.setattr(die_adapter.os, "name", "nt")
    monkeypatch.setattr(subprocess, "STARTUPINFO", _StartupInfo, raising=False)
    monkeypatch.setattr(subprocess, "CREATE_NO_WINDOW", 0x08000000, raising=False)
    monkeypatch.setattr(subprocess, "STARTF_USESHOWWINDOW", 1, raising=False)

    options = die_adapter._creation_options()
    assert options["creationflags"] == 0x08000000
    assert isinstance(options["startupinfo"], _StartupInfo)
    assert options["startupinfo"].wShowWindow == 0
    assert "start_new_session" not in options


def test_creation_options_tolerates_a_missing_startupinfo(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(die_adapter.os, "name", "nt")
    monkeypatch.setattr(subprocess, "CREATE_NO_WINDOW", 0x08000000, raising=False)
    monkeypatch.delattr(subprocess, "STARTUPINFO", raising=False)

    options = die_adapter._creation_options()
    assert options["creationflags"] == 0x08000000
    assert "startupinfo" not in options


# --------------------------------------------------------------------------
# _capture_process branches
# --------------------------------------------------------------------------


class _FakeProcess:
    def __init__(
        self,
        stdout: bytes = b"",
        stderr: bytes = b"",
        *,
        returncode: int | None = 0,
        poll_none: bool = False,
        wait_raises: bool = False,
    ) -> None:
        self.stdout: Any = io.BytesIO(stdout) if stdout is not None else None
        self.stderr: Any = io.BytesIO(stderr) if stderr is not None else None
        self._returncode = returncode
        self._poll_none = poll_none
        self._wait_raises = wait_raises
        self.pid = 4321
        self.killed = False

    def poll(self) -> int | None:
        if self._poll_none and not self.killed:
            return None
        return self._returncode

    def wait(self, timeout: float | None = None) -> int:
        if self._wait_raises and not self.killed:
            raise subprocess.TimeoutExpired("fake-diec", timeout or 0.0)
        if self._returncode is None:
            self._returncode = -9
        return self._returncode

    def kill(self) -> None:
        self.killed = True
        self._returncode = -9


def test_capture_process_requires_stdout_and_stderr_pipes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = _FakeProcess(returncode=0)
    process.stdout = None
    process.stderr = None
    monkeypatch.setattr(die_adapter.subprocess, "Popen", lambda *a, **k: process)
    monkeypatch.setattr(die_adapter, "_terminate_process", lambda proc: None)
    with pytest.raises(die_adapter.DieProcessError, match="stdout/stderr pipes"):
        die_adapter._capture_process(["fake-diec"], timeout=1.0, max_output_size=32)


def test_capture_process_maps_a_missing_executable(monkeypatch: pytest.MonkeyPatch) -> None:
    def missing(*_a: Any, **_k: Any) -> Any:
        raise FileNotFoundError("no such file")

    monkeypatch.setattr(die_adapter.subprocess, "Popen", missing)
    with pytest.raises(DieExecutableNotFoundError):
        die_adapter._capture_process(["ghost-diec"], timeout=1.0, max_output_size=32)


def test_capture_process_maps_a_spawn_oserror(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*_a: Any, **_k: Any) -> Any:
        raise OSError("exec format error")

    monkeypatch.setattr(die_adapter.subprocess, "Popen", boom)
    with pytest.raises(die_adapter.DieProcessError, match="could not start diec"):
        die_adapter._capture_process(["fake-diec"], timeout=1.0, max_output_size=32)


def test_capture_process_terminates_when_the_limit_trips_before_exit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = _FakeProcess(stdout=b"x" * 64, poll_none=True)
    monkeypatch.setattr(die_adapter.subprocess, "Popen", lambda *a, **k: process)
    monkeypatch.setattr(die_adapter, "_terminate_process", lambda proc: proc.kill())
    monkeypatch.setattr(process_tree, "terminate_leftover_process_tree", lambda *a, **k: None)
    with pytest.raises(die_adapter.DieOutputLimitError) as info:
        die_adapter._capture_process(["fake-diec"], timeout=2.0, max_output_size=8)
    assert info.value.details["stream"] == "stdout"
    assert process.killed


def test_capture_process_flags_a_stderr_overflow(monkeypatch: pytest.MonkeyPatch) -> None:
    process = _FakeProcess(stdout=b"{}", stderr=b"y" * 64, returncode=0)
    monkeypatch.setattr(die_adapter.subprocess, "Popen", lambda *a, **k: process)
    monkeypatch.setattr(die_adapter, "_terminate_process", lambda proc: None)
    monkeypatch.setattr(process_tree, "terminate_leftover_process_tree", lambda *a, **k: None)
    with pytest.raises(die_adapter.DieOutputLimitError) as info:
        die_adapter._capture_process(["fake-diec"], timeout=2.0, max_output_size=8)
    assert info.value.details["stream"] == "stderr"


def test_capture_process_breaks_out_when_the_child_is_cancelled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from headless_re_mcp.backends.common.bounded_run import BoundedCancelled

    process = _FakeProcess(stdout=b"", poll_none=True)
    # poll() stays None even after kill so the end-of-run returncode is None too.
    process._returncode = None
    cancel = Event()
    cancel.set()
    monkeypatch.setattr(die_adapter.subprocess, "Popen", lambda *a, **k: process)
    monkeypatch.setattr(die_adapter, "active_bound_cancel", lambda: cancel)
    monkeypatch.setattr(die_adapter, "_terminate_process", lambda proc: None)
    monkeypatch.setattr(process_tree, "terminate_leftover_process_tree", lambda *a, **k: None)
    with pytest.raises(BoundedCancelled):
        die_adapter._capture_process(["fake-diec"], timeout=2.0, max_output_size=32)


def test_capture_process_returns_a_clean_wait_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _PollNoneWaitZero(_FakeProcess):
        def poll(self) -> int | None:
            return None if not self.killed else self._returncode

        def wait(self, timeout: float | None = None) -> int:
            return 0

    process = _PollNoneWaitZero(stdout=b"{}", returncode=0)
    monkeypatch.setattr(die_adapter.subprocess, "Popen", lambda *a, **k: process)
    monkeypatch.setattr(die_adapter, "_terminate_process", lambda proc: None)
    monkeypatch.setattr(process_tree, "terminate_leftover_process_tree", lambda *a, **k: None)
    capture = die_adapter._capture_process(["fake-diec"], timeout=2.0, max_output_size=64)
    assert capture.returncode == 0
    assert capture.stdout == "{}"


def test_capture_process_handles_a_slow_final_wait(monkeypatch: pytest.MonkeyPatch) -> None:
    process = _FakeProcess(stdout=b"{}", returncode=0, wait_raises=True)
    monkeypatch.setattr(die_adapter.subprocess, "Popen", lambda *a, **k: process)
    monkeypatch.setattr(die_adapter, "_terminate_process", lambda proc: proc.kill())
    monkeypatch.setattr(process_tree, "terminate_leftover_process_tree", lambda *a, **k: None)
    capture = die_adapter._capture_process(["fake-diec"], timeout=2.0, max_output_size=64)
    assert capture.stdout == "{}"
    assert process.killed


# --------------------------------------------------------------------------
# DieScanResult.to_dict + DieCliAdapter
# --------------------------------------------------------------------------


def _result(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Any:
    executable = tmp_path / "diec.exe"
    executable.write_bytes(b"fake")
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"MZ")
    monkeypatch.setattr(
        die_adapter,
        "_capture_process",
        lambda argv, *, timeout, max_output_size: _capture(json.dumps(_payload())),
    )
    return scan_with_die(executable, sample)


def test_result_to_dict_serializes_to_an_object(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    result = _result(tmp_path, monkeypatch)
    payload = result.to_dict()
    assert payload["mode"] == ScanMode.NORMAL.value
    assert payload["returncode"] == 0


def test_result_to_dict_rejects_a_non_object_dump(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    result = _result(tmp_path, monkeypatch)
    monkeypatch.setattr(type(result), "model_dump", lambda self, **kwargs: "scalar")
    with pytest.raises(TypeError, match="did not serialize to an object"):
        result.to_dict()


def test_cli_adapter_forwards_configuration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable = tmp_path / "diec.exe"
    executable.write_bytes(b"fake")
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"MZ")
    seen: dict[str, Any] = {}

    def fake_scan(exe: Path, path: Path, **kwargs: Any) -> str:
        seen["exe"] = exe
        seen["path"] = path
        seen["kwargs"] = kwargs
        return "scanned"

    monkeypatch.setattr(die_adapter, "scan_with_die", fake_scan)
    adapter = DieCliAdapter(executable, timeout=7.0, max_file_size=99, max_output_size=100)
    returned: Any = adapter.scan(sample, mode=ScanMode.DEEP)
    assert returned == "scanned"
    assert seen["kwargs"]["timeout"] == 7.0
    assert seen["kwargs"]["mode"] is ScanMode.DEEP
    assert seen["kwargs"]["max_file_size"] == 99
