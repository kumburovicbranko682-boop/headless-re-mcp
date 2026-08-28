"""Coverage for ``detection.die`` parsing, validation, and capture arms.

Pure helpers (mode/number/path validation, JSON normalisation, category
mapping) are called directly; the subprocess capture, ``scan_with_die`` and the
adapter are driven by a real fake ``diec`` shell script so the concurrent
stream draining and process cleanup run for real on this host.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from threading import Event
from typing import BinaryIO, cast

import pytest

import headless_re_mcp.detection.die as die
from headless_re_mcp.backends.common.bounded_run import BoundedCancelled, bound_cancel_scope
from headless_re_mcp.detection.die import (
    DieCliAdapter,
    DieExecutableNotFoundError,
    DieInputNotFoundError,
    DieInputTooLargeError,
    DieProcessError,
    DieProtocolError,
    DieScanError,
    _bounded_text,
    _build_argv,
    _category_for,
    _coerce_mode,
    _normalize_json,
    _parse_json,
    _resolve_executable,
    _resolve_input,
    _validate_positive_integer,
    _validate_positive_number,
    scan_with_die,
)
from headless_re_mcp.detection.models import FindingCategory, ScanMode

_VALID_JSON = (
    '{"detects":[{"filetype":"PE32","values":['
    '{"type":"packer","name":"UPX","string":"UPX 3.96","info":"packer","version":"3.96"}'
    "]}]}"
)


def _fake_diec(tmp_path: Path, *, body: str) -> Path:
    script = tmp_path / "diec.sh"
    script.write_text(f"#!/bin/sh\n{body}\n")
    script.chmod(0o755)
    return script


def _sample(tmp_path: Path) -> Path:
    path = tmp_path / "sample.bin"
    path.write_bytes(b"MZ\x90\x00")
    return path


# ---------------------------------------------------------------------------
# exception helpers
# ---------------------------------------------------------------------------


def test_input_not_found_error_uses_a_custom_message() -> None:
    default = DieInputNotFoundError(Path("/x"))
    assert "does not exist" in str(default)
    custom = DieInputNotFoundError(Path("/x"), "must be a regular file")
    assert str(custom) == "must be a regular file"


def test_input_too_large_error_records_sizes() -> None:
    err = DieInputTooLargeError(Path("/big"), 100, 10)
    assert err.details["size"] == 100
    assert err.details["max_file_size"] == 10


# ---------------------------------------------------------------------------
# _coerce_mode / validators
# ---------------------------------------------------------------------------


def test_coerce_mode_accepts_enum_and_string_and_rejects_junk() -> None:
    assert _coerce_mode(ScanMode.DEEP) is ScanMode.DEEP
    assert _coerce_mode("normal") is ScanMode.NORMAL
    with pytest.raises(DieScanError, match="unsupported DIE scan mode"):
        _coerce_mode("sideways")


@pytest.mark.parametrize("bad", [True, "x", float("inf"), 0, -1.0])
def test_validate_positive_number_rejects_bad_values(bad: object) -> None:
    with pytest.raises(DieScanError, match="positive finite number"):
        _validate_positive_number(bad, "timeout")  # type: ignore[arg-type]


def test_validate_positive_number_accepts_a_finite_positive() -> None:
    assert _validate_positive_number(2, "timeout") == 2.0


@pytest.mark.parametrize("bad", [True, "x", 0, -3])
def test_validate_positive_integer_rejects_bad_values(bad: object) -> None:
    with pytest.raises(DieScanError, match="positive integer"):
        _validate_positive_integer(bad, "max_output_size")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# _resolve_executable / _resolve_input
# ---------------------------------------------------------------------------


def test_resolve_executable_rejects_missing_and_non_files(tmp_path: Path) -> None:
    with pytest.raises(DieExecutableNotFoundError):
        _resolve_executable(tmp_path / "nope")
    with pytest.raises(DieExecutableNotFoundError):
        _resolve_executable(tmp_path)


def test_resolve_input_validates_existence_and_size(tmp_path: Path) -> None:
    with pytest.raises(DieInputNotFoundError):
        _resolve_input(tmp_path / "nope", 1024)
    with pytest.raises(DieInputNotFoundError):
        _resolve_input(tmp_path, 1024)

    sample = _sample(tmp_path)
    with pytest.raises(DieInputTooLargeError):
        _resolve_input(sample, 1)

    resolved, size = _resolve_input(sample, 1024)
    assert resolved == sample.resolve()
    assert size == 4


# ---------------------------------------------------------------------------
# _bounded_text
# ---------------------------------------------------------------------------


def test_bounded_text_rejects_non_strings_and_overlong(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(DieProtocolError, match="must be a string"):
        _bounded_text(123, field_name="name")

    monkeypatch.setattr(die, "_MAX_TEXT", 4)
    with pytest.raises(DieProtocolError, match="too long"):
        _bounded_text("abcdef", field_name="name")


# ---------------------------------------------------------------------------
# _category_for
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("type_name", "expected"),
    [
        ("Packer", FindingCategory.PACKER),
        ("Compiler", FindingCategory.COMPILER),
        ("Linker", FindingCategory.LINKER),
        ("Installer", FindingCategory.INSTALLER),
        ("Obfuscator", FindingCategory.OBFUSCATOR),
        ("Protector", FindingCategory.PROTECTOR),
        ("Virtual machine", FindingCategory.RUNTIME),
        ("Format", FindingCategory.FILE_FORMAT),
        ("something odd", FindingCategory.ANOMALY),
    ],
)
def test_category_for_maps_known_type_names(type_name: str, expected: FindingCategory) -> None:
    assert _category_for(type_name) is expected


# ---------------------------------------------------------------------------
# _normalize_json
# ---------------------------------------------------------------------------


def test_normalize_json_builds_format_and_value_findings() -> None:
    payload = {
        "detects": [
            {
                "filetype": "PE32",
                "values": [
                    {
                        "type": "packer",
                        "name": "UPX",
                        "string": "UPX 3.96",
                        "info": "",
                        "version": "3.96",
                    }
                ],
            }
        ]
    }
    findings, raw = _normalize_json(payload)
    assert findings[0].category is FindingCategory.FILE_FORMAT
    assert findings[1].category is FindingCategory.PACKER
    assert raw == payload


def test_normalize_json_rejects_bad_shapes() -> None:
    with pytest.raises(DieProtocolError, match="root must be an object"):
        _normalize_json(["not a dict"])
    with pytest.raises(DieProtocolError, match="root.detects must be an array"):
        _normalize_json({"detects": {}})
    with pytest.raises(DieProtocolError, match="filetype must not be blank"):
        _normalize_json({"detects": [{"filetype": "  ", "values": []}]})


def test_normalize_json_enforces_detect_and_value_ceilings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(die, "_MAX_DETECTS", 1)
    with pytest.raises(DieProtocolError, match="too many detect records"):
        _normalize_json({"detects": [{"filetype": "PE"}, {"filetype": "ELF"}]})

    monkeypatch.setattr(die, "_MAX_DETECTS", 4096)
    monkeypatch.setattr(die, "_MAX_VALUES_PER_DETECT", 1)
    payload = {"detects": [{"filetype": "PE", "values": [{}, {}]}]}
    with pytest.raises(DieProtocolError, match="too many records"):
        _normalize_json(payload)


# ---------------------------------------------------------------------------
# _parse_json
# ---------------------------------------------------------------------------


def test_parse_json_rejects_empty_output() -> None:
    with pytest.raises(DieProtocolError, match="no JSON on stdout"):
        _parse_json("   ")


def test_parse_json_skips_notice_lines_before_the_object() -> None:
    findings, _ = _parse_json('[!] loading signatures\n{"detects":[]}')
    assert findings == ()


def test_parse_json_rejects_nonstandard_constants() -> None:
    with pytest.raises(DieProtocolError, match="invalid JSON"):
        _parse_json('{"x": NaN}')


def test_parse_json_reraises_protocol_errors_from_the_normalizer() -> None:
    with pytest.raises(DieProtocolError, match="must not be blank"):
        _parse_json('{"detects":[{"filetype":"  ","values":[]}]}')


def test_parse_json_wraps_normalizer_value_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(payload: object) -> object:
        raise ValueError("bad shape")

    monkeypatch.setattr(die, "_normalize_json", boom)
    with pytest.raises(DieProtocolError, match="could not normalize DIE JSON"):
        _parse_json('{"detects":[]}')


# ---------------------------------------------------------------------------
# _build_argv
# ---------------------------------------------------------------------------


def test_build_argv_adds_the_mode_flag_and_json_switch(tmp_path: Path) -> None:
    argv = _build_argv(tmp_path / "diec", tmp_path / "sample", ScanMode.DEEP)
    assert argv[1] == "-d"
    assert argv[-2:] == ["-j", str(tmp_path / "sample")]

    normal = _build_argv(tmp_path / "diec", tmp_path / "sample", ScanMode.NORMAL)
    assert "-d" not in normal


# ---------------------------------------------------------------------------
# _CapturedStream / _creation_options
# ---------------------------------------------------------------------------


class _ChunkPipe:
    def __init__(self, chunks: list[bytes]) -> None:
        self._chunks = list(chunks)
        self.closed = False

    def read(self, size: int) -> bytes:
        return self._chunks.pop(0) if self._chunks else b""

    def close(self) -> None:
        self.closed = True


class _ExplodingPipe:
    def read(self, size: int) -> bytes:
        raise OSError("pipe torn down")

    def close(self) -> None:
        raise OSError("already closed")


def test_captured_stream_discards_bytes_beyond_the_limit() -> None:
    stream = die._CapturedStream(4)
    exceeded = Event()
    pipe = _ChunkPipe([b"abcdef", b"gh", b""])
    stream.read_from(cast(BinaryIO, pipe), exceeded)
    assert bytes(stream.data) == b"abcd"
    assert stream.exceeded and exceeded.is_set()
    assert pipe.closed and stream.finished.is_set()


def test_captured_stream_survives_a_pipe_error_during_read() -> None:
    stream = die._CapturedStream(4)
    stream.read_from(cast(BinaryIO, _ExplodingPipe()), Event())
    assert not stream.exceeded
    assert stream.finished.is_set()


def test_creation_options_hides_the_console_on_windows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _StartupInfo:
        def __init__(self) -> None:
            self.dwFlags = 0
            self.wShowWindow = -1

    monkeypatch.setattr(os, "name", "nt")
    monkeypatch.setattr(subprocess, "STARTUPINFO", _StartupInfo, raising=False)
    options = die._creation_options()
    assert options["creationflags"] != 0
    assert options["startupinfo"].wShowWindow == 0


# ---------------------------------------------------------------------------
# _capture_process failure arms (real subprocesses where possible)
# ---------------------------------------------------------------------------


def test_capture_process_maps_a_missing_executable(tmp_path: Path) -> None:
    with pytest.raises(DieExecutableNotFoundError):
        die._capture_process([str(tmp_path / "missing")], timeout=1.0, max_output_size=1024)


@pytest.mark.skipif(os.name == "nt", reason="permission bits are POSIX behaviour")
def test_capture_process_maps_a_start_os_error(tmp_path: Path) -> None:
    not_executable = tmp_path / "tool"
    not_executable.write_text("#!/bin/sh\n")
    with pytest.raises(DieProcessError, match="could not start diec"):
        die._capture_process([str(not_executable)], timeout=1.0, max_output_size=1024)


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
    with pytest.raises(DieProcessError, match="did not expose stdout/stderr"):
        die._capture_process(["diec"], timeout=1.0, max_output_size=1024)


@pytest.mark.skipif(os.name == "nt", reason="fake diec is a POSIX shell script")
def test_capture_process_times_out_a_hung_scanner(tmp_path: Path) -> None:
    diec = _fake_diec(tmp_path, body="sleep 5")
    with pytest.raises(die.DieTimeoutError):
        die._capture_process([str(diec)], timeout=0.2, max_output_size=1024)


@pytest.mark.skipif(os.name == "nt", reason="fake diec is a POSIX shell script")
def test_capture_process_kills_a_scanner_flooding_stdout(tmp_path: Path) -> None:
    diec = _fake_diec(tmp_path, body="head -c 200000 /dev/zero; sleep 5")
    with pytest.raises(die.DieOutputLimitError) as excinfo:
        die._capture_process([str(diec)], timeout=5.0, max_output_size=1024)
    assert excinfo.value.details["stream"] == "stdout"


@pytest.mark.skipif(os.name == "nt", reason="fake diec is a POSIX shell script")
def test_capture_process_kills_a_scanner_flooding_stderr(tmp_path: Path) -> None:
    diec = _fake_diec(tmp_path, body="head -c 200000 /dev/zero 1>&2; sleep 5")
    with pytest.raises(die.DieOutputLimitError) as excinfo:
        die._capture_process([str(diec)], timeout=5.0, max_output_size=1024)
    assert excinfo.value.details["stream"] == "stderr"


@pytest.mark.skipif(os.name == "nt", reason="fake diec is a POSIX shell script")
def test_capture_process_honours_an_active_bound_cancel(tmp_path: Path) -> None:
    diec = _fake_diec(tmp_path, body="sleep 5")
    cancel = Event()
    cancel.set()
    with bound_cancel_scope(cancel), pytest.raises(BoundedCancelled):
        die._capture_process([str(diec)], timeout=5.0, max_output_size=1024)


# ---------------------------------------------------------------------------
# scan_with_die / DieCliAdapter (real subprocess)
# ---------------------------------------------------------------------------


@pytest.mark.skipif(os.name == "nt", reason="fake diec is a POSIX shell script")
def test_scan_with_die_parses_a_real_process(tmp_path: Path) -> None:
    diec = _fake_diec(tmp_path, body=f"echo '{_VALID_JSON}'")
    result = scan_with_die(diec, _sample(tmp_path))
    assert result.returncode == 0
    assert any(f.category is FindingCategory.PACKER for f in result.findings)
    payload = result.to_dict()
    assert payload["mode"] == "normal"
    assert payload["returncode"] == 0


@pytest.mark.skipif(os.name == "nt", reason="fake diec is a POSIX shell script")
def test_scan_with_die_raises_on_a_nonzero_exit(tmp_path: Path) -> None:
    diec = _fake_diec(tmp_path, body="echo oops 1>&2; exit 3")
    with pytest.raises(DieProcessError, match="status 3"):
        scan_with_die(diec, _sample(tmp_path))


@pytest.mark.skipif(os.name == "nt", reason="fake diec is a POSIX shell script")
def test_scan_with_die_raises_on_non_json_output(tmp_path: Path) -> None:
    diec = _fake_diec(tmp_path, body="echo not-json-here")
    with pytest.raises(DieProtocolError):
        scan_with_die(diec, _sample(tmp_path))


@pytest.mark.skipif(os.name == "nt", reason="fake diec is a POSIX shell script")
def test_die_cli_adapter_delegates_to_scan(tmp_path: Path) -> None:
    # The short sleep keeps the child alive past the first poll so the scan
    # exercises the wait-based exit arm of the capture loop.
    diec = _fake_diec(tmp_path, body=f"sleep 0.2; echo '{_VALID_JSON}'")
    adapter = DieCliAdapter(diec)
    result = adapter.scan(_sample(tmp_path), mode="deep")
    assert result.mode is ScanMode.DEEP
    assert result.findings
