from __future__ import annotations

import io
import json
import os
import subprocess
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.detection import (
    DieErrorCode,
    DieInputTooLargeError,
    DieOutputLimitError,
    DieProcessError,
    DieProtocolError,
    DieTimeoutError,
    FindingCategory,
    ScanMode,
    scan_with_die,
)
from headless_re_mcp.detection import die as die_adapter


def _payload() -> dict[str, Any]:
    return {
        "detects": [
            {
                "filetype": "PE64",
                "info": "",
                "offset": "0",
                "parentfilepart": "Header",
                "size": "1234",
                "values": [
                    {
                        "info": "",
                        "name": "UPX",
                        "string": "Packer: UPX(4.2)",
                        "type": "packer",
                        "version": "4.2",
                    },
                    {
                        "info": "x86",
                        "name": "Microsoft C/C++",
                        "string": "Compiler: Microsoft C/C++(19)",
                        "type": "Compiler",
                        "version": "19",
                    },
                    {
                        "info": "",
                        "name": "Mystery",
                        "string": "Mystery: Mystery",
                        "type": "new official category",
                        "version": "",
                    },
                ],
            }
        ],
        "future_field": {"kept": True},
    }


def _fake_capture(stdout: str) -> die_adapter._ProcessCapture:
    return die_adapter._ProcessCapture(
        stdout=stdout,
        stderr="diagnostic\n",
        returncode=0,
        stdout_exceeded=False,
        stderr_exceeded=False,
    )


def test_scan_tolerates_diec_notice_prefix_before_json(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable = tmp_path / "fake-diec.exe"
    executable.write_bytes(b"fake")
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"MZ")

    def fake_capture(
        argv: list[str], *, timeout: float, max_output_size: int
    ) -> die_adapter._ProcessCapture:
        del argv, timeout, max_output_size
        notice = "[!] Heuristic scan is disabled. Use '--heuristicscan' to enable\n"
        return _fake_capture(notice + json.dumps(_payload()))

    monkeypatch.setattr(die_adapter, "_capture_process", fake_capture)
    result = scan_with_die(executable, sample)
    assert any(finding.name == "UPX" for finding in result.findings)


@pytest.mark.parametrize(
    ("mode", "flag"),
    [
        (ScanMode.NORMAL, None),
        (ScanMode.DEEP, "-d"),
        (ScanMode.HEURISTIC, "-u"),
        (ScanMode.AGGRESSIVE, "-g"),
    ],
)
def test_scan_builds_only_whitelisted_die_command(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: ScanMode,
    flag: str | None,
) -> None:
    executable = tmp_path / "fake-diec.exe"
    executable.write_bytes(b"fake")
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"MZ")
    seen: list[list[str]] = []

    def fake_capture(
        argv: list[str], *, timeout: float, max_output_size: int
    ) -> die_adapter._ProcessCapture:
        del timeout, max_output_size
        seen.append(argv)
        return _fake_capture(json.dumps(_payload()))

    monkeypatch.setattr(die_adapter, "_capture_process", fake_capture)
    result = scan_with_die(executable, sample, mode=mode)

    assert len(seen) == 1
    assert seen[0][0] == str(executable.resolve())
    assert seen[0][-2] == "-j"
    assert seen[0][-1] == str(sample.resolve())
    assert seen[0][1:-2] == ([] if flag is None else [flag])
    assert "--" not in seen[0]
    assert result.mode == mode


def test_scan_normalizes_categories_and_preserves_raw_payload(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable = tmp_path / "fake-diec.exe"
    executable.write_bytes(b"fake")
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"sample")
    payload = _payload()
    monkeypatch.setattr(
        die_adapter,
        "_capture_process",
        lambda argv, *, timeout, max_output_size: _fake_capture(json.dumps(payload)),
    )

    result = scan_with_die(executable, sample, mode="deep")

    assert result.mode is ScanMode.DEEP
    assert result.raw == payload
    assert json.loads(result.raw_json) == payload
    assert [finding.category for finding in result.findings] == [
        FindingCategory.FILE_FORMAT,
        FindingCategory.PACKER,
        FindingCategory.COMPILER,
        FindingCategory.ANOMALY,
    ]
    assert result.findings[-1].evidence[0].details["type"] == "new official category"


def test_scan_rejects_non_json_protocol_and_keeps_bounded_diagnostics(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable = tmp_path / "fake-diec.exe"
    executable.write_bytes(b"fake")
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"sample")
    monkeypatch.setattr(
        die_adapter,
        "_capture_process",
        lambda argv, *, timeout, max_output_size: _fake_capture("not json"),
    )

    with pytest.raises(DieProtocolError) as caught:
        scan_with_die(executable, sample)
    assert caught.value.code == DieErrorCode.PROTOCOL_ERROR
    assert caught.value.stdout == "not json"
    assert caught.value.stderr == "diagnostic\n"


def test_scan_rejects_oversized_input_before_spawning(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable = tmp_path / "fake-diec.exe"
    executable.write_bytes(b"fake")
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"12345")
    called = False

    def fail_if_spawned(*args: Any, **kwargs: Any) -> Any:
        nonlocal called
        called = True
        raise AssertionError("diec must not start for an oversized input")

    monkeypatch.setattr(die_adapter.subprocess, "Popen", fail_if_spawned)
    with pytest.raises(DieInputTooLargeError) as caught:
        scan_with_die(executable, sample, max_file_size=4)
    assert caught.value.code == DieErrorCode.INPUT_TOO_LARGE
    assert not called


class _FakeProcess:
    def __init__(
        self,
        stdout: bytes,
        stderr: bytes = b"",
        *,
        returncode: int | None = 0,
        hangs: bool = False,
    ) -> None:
        self.stdout = io.BytesIO(stdout)
        self.stderr = io.BytesIO(stderr)
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


def test_process_capture_enforces_each_stream_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    process = _FakeProcess(b"x" * 64)
    monkeypatch.setattr(die_adapter.subprocess, "Popen", lambda *args, **kwargs: process)

    with pytest.raises(DieOutputLimitError) as caught:
        die_adapter._capture_process(
            ["fake-diec"], timeout=1.0, max_output_size=8
        )
    assert caught.value.code == DieErrorCode.OUTPUT_LIMIT
    assert caught.value.details["stream"] == "stdout"
    assert len(caught.value.stdout.encode()) <= 8


def test_process_capture_timeout_kills_child(monkeypatch: pytest.MonkeyPatch) -> None:
    process = _FakeProcess(b"", hangs=True)
    monkeypatch.setattr(die_adapter.subprocess, "Popen", lambda *args, **kwargs: process)

    with pytest.raises(DieTimeoutError) as caught:
        die_adapter._capture_process(
            ["fake-diec"], timeout=0.01, max_output_size=32
        )
    assert process.killed
    assert caught.value.code == DieErrorCode.TIMEOUT


def test_process_failure_is_structured(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable = tmp_path / "fake-diec.exe"
    sample = tmp_path / "sample.bin"
    executable.write_bytes(b"fake")
    sample.write_bytes(b"sample")
    process = _FakeProcess(b"{}", b"bad", returncode=7)
    monkeypatch.setattr(die_adapter.subprocess, "Popen", lambda *args, **kwargs: process)
    with pytest.raises(DieProcessError) as caught:
        scan_with_die(executable, sample)
    assert caught.value.code == DieErrorCode.PROCESS_FAILED


def test_no_shell_and_no_window_options_are_explicit() -> None:
    options = die_adapter._creation_options()
    assert options["shell"] is False
    assert options["stdin"] is subprocess.DEVNULL
    assert options["stdout"] is subprocess.PIPE
    assert options["stderr"] is subprocess.PIPE
    assert options["text"] is False
    if os.name == "nt":
        assert options["creationflags"] & getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
