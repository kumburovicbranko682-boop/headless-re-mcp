"""Branch coverage for the Detect It Easy (diec) adapter.

diec is absent on CI, so process-level behaviour is driven through fake
process objects whose pipes are in-memory buffers, and scan-level behaviour
through a stubbed capture. That reaches the validation arms, the JSON
protocol guards, the category mapping, the stream-capture edges and the
configured adapter wrapper without a real scanner.
"""

from __future__ import annotations

import io
import json
import os
import subprocess
from pathlib import Path
from threading import Event
from typing import Any

import pytest

from headless_re_mcp.detection import (
    DieCliAdapter,
    DieErrorCode,
    DieOutputLimitError,
    DieProcessError,
    DieProtocolError,
    DieScanError,
    FindingCategory,
    ScanMode,
)
from headless_re_mcp.detection import die as die_adapter


def _capture(stdout: str) -> Any:
    def fake(argv: list[str], *, timeout: float, max_output_size: int) -> Any:
        return die_adapter._ProcessCapture(stdout, "", 0, False, False)

    return fake


def _files(tmp_path: Path) -> tuple[Path, Path]:
    executable = tmp_path / "diec"
    executable.write_bytes(b"fake")
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"MZ")
    return executable, sample


class _FakeProcess:
    def __init__(
        self,
        stdout: bytes,
        stderr: bytes = b"",
        *,
        returncode: int | None = 0,
        hangs: bool = False,
    ) -> None:
        self.stdout: Any = io.BytesIO(stdout)
        self.stderr: Any = io.BytesIO(stderr)
        # A truthy pid routes through assign_to_process_group, which is a
        # documented no-op off Windows.
        self.pid = 4242
        self._returncode = None if hangs else returncode
        self._hangs = hangs
        self.killed = False

    def poll(self) -> int | None:
        return self._returncode

    def wait(self, timeout: float | None = None) -> int:
        del timeout
        if self._hangs and not self.killed:
            raise subprocess.TimeoutExpired("fake-diec", 0.01)
        if self._returncode is None:
            self._returncode = -9
        return self._returncode

    def kill(self) -> None:
        self.killed = True
        self._hangs = False
        self._returncode = -9


# ---------------------------------------------------------------------------
# argument validation
# ---------------------------------------------------------------------------


def test_coerce_mode_rejects_an_unknown_mode() -> None:
    assert die_adapter._coerce_mode(ScanMode.DEEP) is ScanMode.DEEP
    with pytest.raises(DieScanError) as caught:
        die_adapter._coerce_mode("turbo")
    assert caught.value.code == DieErrorCode.INVALID_ARGUMENT


def test_validate_positive_number_rejects_bad_values() -> None:
    assert die_adapter._validate_positive_number(2, "timeout") == 2.0
    for bad in (True, "soon", None):
        with pytest.raises(DieScanError):
            die_adapter._validate_positive_number(bad, "timeout")  # type: ignore[arg-type]
    for bad_value in (-1, 0, float("nan"), float("inf")):
        with pytest.raises(DieScanError):
            die_adapter._validate_positive_number(bad_value, "timeout")


def test_validate_positive_integer_rejects_bad_values() -> None:
    assert die_adapter._validate_positive_integer(7, "max_file_size") == 7
    for bad in (True, 0, -5, 1.5):
        with pytest.raises(DieScanError):
            die_adapter._validate_positive_integer(bad, "max_file_size")  # type: ignore[arg-type]


def test_resolve_executable_requires_an_existing_file(tmp_path: Path) -> None:
    with pytest.raises(DieScanError) as missing:
        die_adapter._resolve_executable(tmp_path / "absent")
    assert missing.value.code == DieErrorCode.EXECUTABLE_NOT_FOUND
    with pytest.raises(DieScanError) as directory:
        die_adapter._resolve_executable(tmp_path)
    assert directory.value.code == DieErrorCode.EXECUTABLE_NOT_FOUND


def test_resolve_input_requires_a_regular_file(tmp_path: Path) -> None:
    with pytest.raises(DieScanError) as missing:
        die_adapter._resolve_input(tmp_path / "absent.bin", 1024)
    assert missing.value.code == DieErrorCode.INPUT_NOT_FOUND
    with pytest.raises(DieScanError) as directory:
        die_adapter._resolve_input(tmp_path, 1024)
    assert "explicit regular file" in str(directory.value)


def test_resolve_input_reports_a_failing_stat(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "sample.bin"
    target.write_bytes(b"MZ")
    resolved = target.resolve()
    real_is_file = Path.is_file
    real_stat = Path.stat

    def fake_is_file(self: Path) -> bool:
        return True if self == resolved else real_is_file(self)

    def fake_stat(self: Path, **kwargs: Any) -> Any:
        if self == resolved:
            raise OSError("stat denied")
        return real_stat(self, **kwargs)

    monkeypatch.setattr(Path, "is_file", fake_is_file)
    monkeypatch.setattr(Path, "stat", fake_stat)
    with pytest.raises(DieScanError) as caught:
        die_adapter._resolve_input(target, 1024)
    assert "could not stat" in str(caught.value)


# ---------------------------------------------------------------------------
# JSON protocol guards
# ---------------------------------------------------------------------------


def test_bounded_text_rejects_non_string_and_oversized_values() -> None:
    with pytest.raises(DieProtocolError) as wrong_type:
        die_adapter._bounded_text(5, field_name="root.x")
    assert wrong_type.value.details["actual_type"] == "int"
    with pytest.raises(DieProtocolError) as too_long:
        die_adapter._bounded_text("x" * (die_adapter._MAX_TEXT + 1), field_name="root.x")
    assert too_long.value.details["max_length"] == die_adapter._MAX_TEXT


def test_normalize_rejects_too_many_detects(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(die_adapter, "_MAX_DETECTS", 1)
    payload = {"detects": [{"filetype": "PE", "values": []}] * 2}
    with pytest.raises(DieProtocolError) as caught:
        die_adapter._normalize_json(payload)
    assert "too many detect records" in str(caught.value)


def test_normalize_rejects_a_blank_filetype() -> None:
    payload = {"detects": [{"filetype": "   ", "values": []}]}
    with pytest.raises(DieProtocolError) as caught:
        die_adapter._normalize_json(payload)
    assert "must not be blank" in str(caught.value)


def test_normalize_rejects_too_many_values(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(die_adapter, "_MAX_VALUES_PER_DETECT", 1)
    payload = {"detects": [{"filetype": "PE", "values": [{}, {}]}]}
    with pytest.raises(DieProtocolError) as caught:
        die_adapter._normalize_json(payload)
    assert "too many records" in str(caught.value)


def test_parse_json_rejects_empty_stdout() -> None:
    with pytest.raises(DieProtocolError) as caught:
        die_adapter._parse_json("   \n")
    assert "no JSON" in str(caught.value)


def test_parse_json_rejects_nonstandard_constants() -> None:
    with pytest.raises(DieProtocolError) as caught:
        die_adapter._parse_json('{"detects": NaN}')
    assert "non-standard JSON constant" in str(caught.value)


def test_parse_json_passes_protocol_errors_through() -> None:
    with pytest.raises(DieProtocolError) as caught:
        die_adapter._parse_json('{"detects": {}}')
    assert "must be an array" in str(caught.value)


def test_parse_json_wraps_an_unexpected_normalize_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def explode(payload: object) -> Any:
        raise ValueError("boom")

    monkeypatch.setattr(die_adapter, "_normalize_json", explode)
    with pytest.raises(DieProtocolError) as caught:
        die_adapter._parse_json('{"detects": []}')
    assert "could not normalize DIE JSON: boom" in str(caught.value)


def test_category_mapping_covers_every_bucket() -> None:
    cases = {
        "Linker": FindingCategory.LINKER,
        "Installer": FindingCategory.INSTALLER,
        "Obfuscator": FindingCategory.OBFUSCATOR,
        "Protector": FindingCategory.PROTECTOR,
        "Virtual Machine": FindingCategory.RUNTIME,
        "File format": FindingCategory.FILE_FORMAT,
        "Packer": FindingCategory.PACKER,
        "Compiler": FindingCategory.COMPILER,
        "Something new": FindingCategory.ANOMALY,
    }
    for label, expected in cases.items():
        assert die_adapter._category_for(label) is expected


# ---------------------------------------------------------------------------
# stream capture edges
# ---------------------------------------------------------------------------


def test_captured_stream_discards_bytes_past_a_zero_budget() -> None:
    stream = die_adapter._CapturedStream(0)
    exceeded = Event()
    stream.read_from(io.BytesIO(b"abc"), exceeded)
    assert stream.exceeded is True
    assert exceeded.is_set()
    assert stream.text() == ""
    assert stream.finished.is_set()


def test_captured_stream_survives_a_pipe_error() -> None:
    class _ExplodingPipe:
        def read(self, size: int) -> bytes:
            raise OSError("gone")

        def close(self) -> None:
            raise OSError("also gone")

    stream = die_adapter._CapturedStream(8)
    stream.read_from(_ExplodingPipe(), Event())  # type: ignore[arg-type]
    assert stream.text() == ""
    assert stream.finished.is_set()


def test_capture_process_rejects_missing_pipes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = _FakeProcess(b"")
    process.stdout = None
    terminated: list[Any] = []
    monkeypatch.setattr(die_adapter, "_terminate_process", terminated.append)
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: process)
    with pytest.raises(DieProcessError) as caught:
        die_adapter._capture_process(["fake-diec"], timeout=1.0, max_output_size=8)
    assert "stdout/stderr pipes" in str(caught.value)
    assert terminated == [process]


def test_capture_process_stops_a_running_child_at_the_output_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = _FakeProcess(b"x" * 64, hangs=True)
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: process)
    with pytest.raises(DieOutputLimitError) as caught:
        die_adapter._capture_process(["fake-diec"], timeout=5.0, max_output_size=8)
    assert process.killed
    assert caught.value.details["stream"] == "stdout"


def test_capture_process_reports_a_stderr_flood(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = _FakeProcess(b"{}", b"y" * 64)
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: process)
    with pytest.raises(DieOutputLimitError) as caught:
        die_adapter._capture_process(["fake-diec"], timeout=5.0, max_output_size=8)
    assert caught.value.details["stream"] == "stderr"


def test_capture_process_tolerates_a_wait_that_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _ExitedButUnwaitable(_FakeProcess):
        def wait(self, timeout: float | None = None) -> int:
            raise OSError("already reaped")

    process = _ExitedButUnwaitable(b"ok")
    from headless_re_mcp.core import process_tree

    monkeypatch.setattr(process_tree, "terminate_leftover_process_tree", lambda p, wait_s=1.0: None)
    monkeypatch.setattr(die_adapter, "_terminate_process", lambda p: None)
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: process)
    capture = die_adapter._capture_process(["fake-diec"], timeout=1.0, max_output_size=64)
    assert capture.stdout == "ok"
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
    process = _FakeProcess(b"", hangs=True)
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: process)
    with bound_cancel_scope(cancel), pytest.raises(BoundedCancelled):
        die_adapter._capture_process(["fake-diec"], timeout=5.0, max_output_size=64)
    assert process.killed


def test_capture_process_picks_up_an_exit_reported_by_wait(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _ExitsDuringWait:
        def __init__(self) -> None:
            self.stdout: Any = io.BytesIO(b"done")
            self.stderr: Any = io.BytesIO(b"")
            self.pid = 4242
            self._exited = False

        def poll(self) -> int | None:
            return 0 if self._exited else None

        def wait(self, timeout: float | None = None) -> int:
            self._exited = True
            return 0

        def kill(self) -> None:
            self._exited = True

    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: _ExitsDuringWait())
    capture = die_adapter._capture_process(["fake-diec"], timeout=1.0, max_output_size=64)
    assert capture.stdout == "done"
    assert capture.returncode == 0


def test_capture_process_reports_an_unknowable_exit_code_after_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _NeverReports(_FakeProcess):
        def poll(self) -> int | None:
            return None

    process = _NeverReports(b"", hangs=True)
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: process)
    with pytest.raises(die_adapter.DieTimeoutError) as caught:
        die_adapter._capture_process(["fake-diec"], timeout=0.01, max_output_size=64)
    assert caught.value.returncode == -1


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
    options = die_adapter._creation_options()
    assert options["creationflags"] != 0
    assert options["startupinfo"].wShowWindow == 0
    assert options["startupinfo"].dwFlags & 1
    assert "start_new_session" not in options


def test_creation_options_skip_startupinfo_when_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(os, "name", "nt")
    monkeypatch.delattr(subprocess, "STARTUPINFO", raising=False)
    options = die_adapter._creation_options()
    assert "startupinfo" not in options


# ---------------------------------------------------------------------------
# configured adapter + result serialization
# ---------------------------------------------------------------------------


def test_die_cli_adapter_scans_with_its_stored_configuration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable, sample = _files(tmp_path)
    seen: dict[str, Any] = {}

    def fake(argv: list[str], *, timeout: float, max_output_size: int) -> Any:
        seen["timeout"] = timeout
        seen["max_output_size"] = max_output_size
        return die_adapter._ProcessCapture(json.dumps({"detects": []}), "", 0, False, False)

    monkeypatch.setattr(die_adapter, "_capture_process", fake)
    adapter = DieCliAdapter(executable, timeout=5.0, max_file_size=1024, max_output_size=2048)
    result = adapter.scan(sample, mode="deep")
    assert result.mode is ScanMode.DEEP
    assert result.findings == ()
    assert seen == {"timeout": 5.0, "max_output_size": 2048}

    as_dict = result.to_dict()
    assert as_dict["mode"] == "deep"
    assert as_dict["path"].endswith("sample.bin")


def test_to_dict_rejects_a_non_object_serialization(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable, sample = _files(tmp_path)
    monkeypatch.setattr(die_adapter, "_capture_process", _capture(json.dumps({"detects": []})))
    result = die_adapter.scan_with_die(executable, sample)
    monkeypatch.setattr(
        die_adapter.DieScanResult, "model_dump", lambda self, **kwargs: ["not an object"]
    )
    with pytest.raises(TypeError):
        result.to_dict()
