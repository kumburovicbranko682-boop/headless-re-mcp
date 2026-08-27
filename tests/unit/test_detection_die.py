from __future__ import annotations

import io
import json
import os
import subprocess
from pathlib import Path
from typing import Any, cast

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


def test_a_brace_heavy_reply_is_refused_without_going_quadratic(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The JSON scan runs after capture, outside the subprocess timeout.

    _parse_json walks stdout trying to decode an object at each '{'. Every
    failed attempt costs O(len) -- ``text[index:]`` copies the tail, and the
    index form instead pays for the line/column count JSONDecodeError runs
    from the buffer start -- so trying every brace is O(n^2). stdout is only
    bounded (4 MiB), not small, and its bytes are influenced by the sample, so
    a reply that is almost all '{' turned a bounded capture into minutes of
    work with no deadline. Capping the number of decode attempts makes the
    flood linear: one megabyte of braces was ~100s on the old path and is
    milliseconds now, and a reply whose only object hides behind a megabyte of
    junk is refused rather than chased. The 20s bound separates the two
    without being flaky.
    """
    import time

    executable = tmp_path / "fake-diec.exe"
    executable.write_bytes(b"fake")
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"MZ")

    flood = "{" * (1024 * 1024) + json.dumps(_payload())

    def fake_capture(
        argv: list[str], *, timeout: float, max_output_size: int
    ) -> die_adapter._ProcessCapture:
        del argv, timeout, max_output_size
        return _fake_capture(flood)

    monkeypatch.setattr(die_adapter, "_capture_process", fake_capture)
    started = time.perf_counter()
    with pytest.raises(DieProtocolError):
        scan_with_die(executable, sample)
    elapsed = time.perf_counter() - started
    assert elapsed < 20.0, f"brace-heavy JSON scan took {elapsed:.1f}s"


def test_json_object_is_still_found_after_a_notice_line_with_a_stray_brace(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The attempt cap must not break the reason the scan tries many braces.

    A notice line can carry its own '{' before the real document, so the scan
    still has to walk past a false brace to the object. The cap sits far above
    any real preamble, so this keeps working.
    """
    executable = tmp_path / "fake-diec.exe"
    executable.write_bytes(b"fake")
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"MZ")

    notice = "[!] Heuristic scan is disabled; try '{--flag}' to enable\n"

    def fake_capture(
        argv: list[str], *, timeout: float, max_output_size: int
    ) -> die_adapter._ProcessCapture:
        del argv, timeout, max_output_size
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


def test_process_capture_cleanup_shares_one_drain_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Stuck reader threads must not add seconds of joins after a timeout."""
    clock = [0.0]
    join_timeouts: list[float] = []

    class _TimedOutProcess(_FakeProcess):
        def wait(self, timeout: float | None = None) -> int:
            budget = float(timeout or 0.0)
            clock[0] += budget
            if self.killed:
                self._returncode = -9
                return self._returncode
            raise subprocess.TimeoutExpired("fake-diec", budget)

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

    process = _TimedOutProcess(b"", hangs=True)
    monkeypatch.setattr(die_adapter.subprocess, "Popen", lambda *a, **k: process)
    monkeypatch.setattr(die_adapter, "Thread", _StuckThread)
    monkeypatch.setattr(die_adapter, "monotonic", lambda: clock[0])
    monkeypatch.setattr(die_adapter, "_terminate_process", lambda child: child.kill())

    with pytest.raises(DieTimeoutError):
        die_adapter._capture_process(
            ["fake-diec"], timeout=0.1, max_output_size=32
        )

    assert join_timeouts, "cleanup should join the reader threads"
    assert sum(join_timeouts) <= 1.0


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


def _exe_and_sample(tmp_path: Path) -> tuple[Path, Path]:
    executable = tmp_path / "fake-diec.exe"
    executable.write_bytes(b"fake")
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"MZ")
    return executable, sample


@pytest.mark.parametrize(
    "kwargs",
    [
        {"mode": "bogus-mode"},
        {"timeout": 0},
        {"timeout": "soon"},
        {"timeout": float("inf")},
        {"max_file_size": 0},
        {"max_output_size": 0},
    ],
)
def test_invalid_scan_arguments_are_refused_before_spawning(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    kwargs: dict[str, Any],
) -> None:
    """Every argument gate raises invalid_argument, and none reaches a process.

    mode, timeout, max_file_size, and max_output_size are validated up front, so
    an unsupported mode, a non-positive or non-finite timeout, or a non-positive
    byte budget tells the caller exactly what was wrong -- with diec never
    started.
    """
    executable, sample = _exe_and_sample(tmp_path)

    def must_not_spawn(*args: Any, **kw: Any) -> Any:
        raise AssertionError("diec must not start when an argument is invalid")

    monkeypatch.setattr(die_adapter, "_capture_process", must_not_spawn)
    with pytest.raises(die_adapter.DieScanError) as caught:
        scan_with_die(executable, sample, **kwargs)
    assert caught.value.code == DieErrorCode.INVALID_ARGUMENT


def test_missing_or_nonfile_executable_and_input_are_rejected(tmp_path: Path) -> None:
    """The executable and the input must each resolve to an existing file.

    A missing or non-file executable (here a directory) is
    executable_not_found; a missing or non-file input is input_not_found. The
    input check runs only after the executable resolves, so a valid executable
    is supplied for the input cases, and the directory case carries the explicit
    "regular file" message.
    """
    executable, sample = _exe_and_sample(tmp_path)

    with pytest.raises(die_adapter.DieExecutableNotFoundError):
        scan_with_die(tmp_path / "absent-diec", sample)
    with pytest.raises(die_adapter.DieExecutableNotFoundError):
        scan_with_die(tmp_path, sample)

    with pytest.raises(die_adapter.DieInputNotFoundError):
        scan_with_die(executable, tmp_path / "absent.bin")
    with pytest.raises(die_adapter.DieInputNotFoundError) as caught:
        scan_with_die(executable, tmp_path)
    assert "regular file" in str(caught.value)


@pytest.mark.parametrize(
    ("type_name", "expected"),
    [
        ("packer", FindingCategory.PACKER),
        ("Compression", FindingCategory.PACKER),
        ("compiler", FindingCategory.COMPILER),
        ("linker", FindingCategory.LINKER),
        ("installer", FindingCategory.INSTALLER),
        ("setup", FindingCategory.INSTALLER),
        ("obfuscator", FindingCategory.OBFUSCATOR),
        ("protector", FindingCategory.PROTECTOR),
        ("runtime", FindingCategory.RUNTIME),
        ("Virtual Machine", FindingCategory.RUNTIME),
        ("file format", FindingCategory.FILE_FORMAT),
        ("Binary format", FindingCategory.FILE_FORMAT),
        ("brand new bucket", FindingCategory.ANOMALY),
    ],
)
def test_die_type_names_map_to_finding_categories(
    type_name: str,
    expected: FindingCategory,
) -> None:
    """DIE's free-form ``type`` strings normalize into fixed categories.

    The mapping is case- and separator-insensitive, and an unmapped or novel
    string must fall through to ANOMALY rather than be dropped -- so a category
    diec adds later still surfaces as a finding.
    """
    assert die_adapter._category_for(type_name) is expected


@pytest.mark.parametrize(
    ("payload", "match"),
    [
        (
            {"detects": [{"filetype": "PE", "values": []}] * (die_adapter._MAX_DETECTS + 1)},
            "too many detect records",
        ),
        ({"detects": [{"filetype": "   ", "values": []}]}, "must not be blank"),
        (
            {
                "detects": [
                    {
                        "filetype": "PE",
                        "values": [
                            {"type": "packer", "name": "x", "string": "", "info": "", "version": ""}
                        ]
                        * (die_adapter._MAX_VALUES_PER_DETECT + 1),
                    }
                ]
            },
            "too many records",
        ),
        (
            {
                "detects": [
                    {
                        "filetype": "PE",
                        "values": [
                            {"type": "packer", "name": 123, "string": "", "info": "", "version": ""}
                        ],
                    }
                ]
            },
            "must be a string",
        ),
        (
            {
                "detects": [
                    {
                        "filetype": "PE",
                        "values": [
                            {
                                "type": "packer",
                                "name": "x" * (die_adapter._MAX_TEXT + 1),
                                "string": "",
                                "info": "",
                                "version": "",
                            }
                        ],
                    }
                ]
            },
            "is too long",
        ),
    ],
)
def test_normalize_rejects_hostile_json_shapes(payload: dict[str, Any], match: str) -> None:
    """DIE JSON is untrusted, so oversized or ill-typed shapes are bounded.

    The detect and value counts are capped so a hostile reply cannot balloon
    the finding list, a blank filetype is refused, and every text field must be
    a bounded string rather than a number or a megabyte of characters.
    """
    with pytest.raises(DieProtocolError, match=match):
        die_adapter._normalize_json(payload)


def test_parse_json_rejects_empty_output_and_nonstandard_constants() -> None:
    """Empty stdout and JSON with NaN/Infinity are both protocol errors.

    diec must emit a JSON document; blank stdout is refused outright, and the
    decoder rejects the non-standard constants that would otherwise parse into
    values the model never expects, so such a reply reads as invalid JSON
    rather than a silent NaN.
    """
    with pytest.raises(DieProtocolError, match="no JSON"):
        die_adapter._parse_json("   ")
    with pytest.raises(DieProtocolError, match="invalid JSON"):
        die_adapter._parse_json('{"score": NaN}')


def test_die_cli_adapter_delegates_with_its_configuration(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The adapter is a thin, configured wrapper around scan_with_die.

    Its stored executable and the three bounds are forwarded unchanged and the
    per-call mode passed through, so configuring an adapter once behaves exactly
    like calling the function with those arguments.
    """
    executable, sample = _exe_and_sample(tmp_path)
    seen: dict[str, Any] = {}

    def fake_scan(
        exe: Path,
        path: Path,
        *,
        mode: Any,
        timeout: float,
        max_file_size: int,
        max_output_size: int,
    ) -> str:
        seen.update(
            executable=exe,
            path=path,
            mode=mode,
            timeout=timeout,
            max_file_size=max_file_size,
            max_output_size=max_output_size,
        )
        return "sentinel"

    monkeypatch.setattr(die_adapter, "scan_with_die", fake_scan)
    adapter = die_adapter.DieCliAdapter(
        executable, timeout=12.0, max_file_size=99, max_output_size=77
    )

    result = adapter.scan(sample, mode=ScanMode.DEEP)

    # scan is typed to return DieScanResult; the fake returns a sentinel to
    # prove the return value is forwarded verbatim, so widen for the compare.
    assert cast(object, result) == "sentinel"
    assert seen["executable"] == executable
    assert seen["path"] == sample
    assert seen["mode"] is ScanMode.DEEP
    assert seen["timeout"] == 12.0
    assert seen["max_file_size"] == 99
    assert seen["max_output_size"] == 77
