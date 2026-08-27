"""Lock in the XVLKC adapter's pure validation, output selection, and parsing.

The service-layer tests drive :func:`unpack_xvlkc_unpack` through a fake
runner, so ``run_xvlkc`` itself, the PE sniffing in ``_is_pe_file``, the
fail-closed newest-output selection in ``_collect_newest_pe``, and the
best-effort ``probe_xvlkc`` were unexercised. This file pins those hostile-
input-facing branches without spawning a real process.
"""

from __future__ import annotations

import os
import struct
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from headless_re_mcp.backends.common.bounded_run import TimedOut
from headless_re_mcp.core.session import file_sha256
from headless_re_mcp.dotnet.de4dot import _ProcessCapture
from headless_re_mcp.unpack import xvlkc
from headless_re_mcp.unpack.xvlkc import XvlkcError, XvlkcErrorCode, run_xvlkc


def _write_pe(path: Path, *, tail: bytes = b"") -> None:
    image = bytearray(0x100)
    image[:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, 0x80)
    image[0x80:0x84] = b"PE\0\0"
    path.write_bytes(bytes(image) + tail)


def _capture(
    *,
    returncode: int = 0,
    stdout: str = "out",
    stderr: str = "err",
    stdout_exceeded: bool = False,
    stderr_exceeded: bool = False,
) -> _ProcessCapture:
    return _ProcessCapture(stdout, stderr, returncode, stdout_exceeded, stderr_exceeded)


def _exe_and_input(tmp_path: Path) -> tuple[Path, Path, str]:
    executable = tmp_path / "xvlkc.exe"
    executable.write_bytes(b"fake")
    source = tmp_path / "input.exe"
    _write_pe(source)
    return executable, source, file_sha256(source)


def test_is_pe_file_accepts_a_well_formed_header(tmp_path: Path) -> None:
    good = tmp_path / "good.exe"
    _write_pe(good)
    assert xvlkc._is_pe_file(good) is True


@pytest.mark.parametrize(
    "make",
    [
        pytest.param(lambda p: p.write_bytes(b"XX" + b"\0" * 0x40), id="not-mz"),
        pytest.param(lambda p: p.write_bytes(b"MZ"), id="too-short"),
        pytest.param(
            lambda p: p.write_bytes(
                bytes(bytearray(b"MZ" + b"\0" * 0x3A) + struct.pack("<I", 0x10) + b"\0" * 0xB0)
            ),
            id="pe-offset-inside-header",
        ),
    ],
)
def test_is_pe_file_rejects_malformed_headers(tmp_path: Path, make: Any) -> None:
    candidate = tmp_path / "candidate.bin"
    make(candidate)
    assert xvlkc._is_pe_file(candidate) is False


def test_is_pe_file_rejects_a_bad_nt_signature(tmp_path: Path) -> None:
    bad = tmp_path / "bad.exe"
    image = bytearray(0x100)
    image[:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, 0x80)
    image[0x80:0x84] = b"XX\0\0"
    bad.write_bytes(bytes(image))
    assert xvlkc._is_pe_file(bad) is False


def test_is_pe_file_returns_false_for_a_missing_path(tmp_path: Path) -> None:
    assert xvlkc._is_pe_file(tmp_path / "nope.exe") is False


def test_collect_newest_pe_requires_an_output_beside_the_work_copy(tmp_path: Path) -> None:
    work_input = tmp_path / "input.exe"
    _write_pe(work_input)
    with pytest.raises(XvlkcError) as caught:
        xvlkc._collect_newest_pe(tmp_path, work_input)
    assert caught.value.code == XvlkcErrorCode.OUTPUT_MISSING


def test_collect_newest_pe_ignores_the_work_copy_and_non_pe_files(tmp_path: Path) -> None:
    work_input = tmp_path / "input.exe"
    _write_pe(work_input)
    produced = tmp_path / "unpacked.exe"
    _write_pe(produced, tail=b"X")
    os.utime(produced, (1000, 1000))
    # A newer non-PE file must never win the selection.
    junk = tmp_path / "log.txt"
    junk.write_bytes(b"not a pe at all")
    os.utime(junk, (9999, 9999))
    assert xvlkc._collect_newest_pe(tmp_path, work_input) == produced


def test_collect_newest_pe_fails_closed_on_a_tie(tmp_path: Path) -> None:
    work_input = tmp_path / "input.exe"
    _write_pe(work_input)
    first = tmp_path / "one.exe"
    second = tmp_path / "two.exe"
    _write_pe(first, tail=b"1")
    _write_pe(second, tail=b"2")
    os.utime(first, (2000, 2000))
    os.utime(second, (2000, 2000))
    with pytest.raises(XvlkcError) as caught:
        xvlkc._collect_newest_pe(tmp_path, work_input)
    assert caught.value.code == XvlkcErrorCode.OUTPUT_AMBIGUOUS
    assert len(caught.value.details["candidates"]) == 2


def test_run_publishes_the_newest_pe_and_never_claims_universal_unpack(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable, source, sha = _exe_and_input(tmp_path)
    destination = tmp_path / "out" / "unpacked.exe"

    def fake_capture(argv: list[str], *, timeout: float, max_output_size: int) -> _ProcessCapture:
        del timeout, max_output_size
        work_input = Path(argv[1])
        produced = work_input.parent / "dumped.exe"
        _write_pe(produced, tail=b"payload")
        os.utime(produced, (5000, 5000))
        return _capture()

    monkeypatch.setattr(xvlkc, "_capture_process", fake_capture)
    result = run_xvlkc(executable, source, destination, input_sha256=sha)
    assert result.returncode == 0
    assert destination.is_file()
    assert result.output_sha256 == file_sha256(destination)
    assert result.to_dict()["claims_universal_unpack"] is False


def test_missing_input_is_a_structured_not_found_not_a_raw_oserror(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # resolve(strict=True) raised FileNotFoundError before this guard, so a
    # missing input surfaced as a generic internal_error at the agent
    # transport instead of the INPUT_NOT_FOUND this taxonomy already raises
    # for a directory. Both shapes must now be the same structured error.
    executable, source, sha = _exe_and_input(tmp_path)

    def no_spawn(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("must not spawn when the input is missing")

    monkeypatch.setattr(xvlkc, "_capture_process", no_spawn)
    with pytest.raises(XvlkcError) as caught:
        run_xvlkc(executable, tmp_path / "nope.bin", tmp_path / "o.exe", input_sha256=sha)
    assert caught.value.code == XvlkcErrorCode.INPUT_NOT_FOUND
    assert caught.value.details["input_path"].endswith("nope.bin")

    directory = tmp_path / "adir"
    directory.mkdir()
    with pytest.raises(XvlkcError) as caught:
        run_xvlkc(executable, directory, tmp_path / "o2.exe", input_sha256=sha)
    assert caught.value.code == XvlkcErrorCode.INPUT_NOT_FOUND


@pytest.mark.parametrize("timeout", [0, -1.0, float("nan"), float("inf"), "soon", True])
def test_run_refuses_a_non_positive_or_non_finite_timeout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, timeout: Any
) -> None:
    executable, source, sha = _exe_and_input(tmp_path)

    def no_spawn(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("must not spawn for an invalid timeout")

    monkeypatch.setattr(xvlkc, "_capture_process", no_spawn)
    with pytest.raises(XvlkcError) as caught:
        run_xvlkc(executable, source, tmp_path / "o.exe", input_sha256=sha, timeout=timeout)
    assert caught.value.code == XvlkcErrorCode.INVALID_ARGUMENT


def test_run_rejects_a_missing_executable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _, source, sha = _exe_and_input(tmp_path)

    def no_spawn(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("must not spawn")

    monkeypatch.setattr(xvlkc, "_capture_process", no_spawn)
    with pytest.raises(XvlkcError) as caught:
        run_xvlkc(tmp_path / "nope.exe", source, tmp_path / "o.exe", input_sha256=sha)
    assert caught.value.code == XvlkcErrorCode.EXECUTABLE_NOT_FOUND


def test_run_rejects_input_larger_than_the_budget(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable, source, sha = _exe_and_input(tmp_path)

    def no_spawn(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("must not spawn for oversized input")

    monkeypatch.setattr(xvlkc, "_capture_process", no_spawn)
    with pytest.raises(XvlkcError) as caught:
        run_xvlkc(executable, source, tmp_path / "o.exe", input_sha256=sha, max_file_size=4)
    assert caught.value.code == XvlkcErrorCode.INPUT_TOO_LARGE


def test_run_refuses_a_preexisting_or_aliased_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable, source, sha = _exe_and_input(tmp_path)

    def no_spawn(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("must not spawn")

    monkeypatch.setattr(xvlkc, "_capture_process", no_spawn)

    existing = tmp_path / "already.exe"
    existing.write_bytes(b"x")
    with pytest.raises(XvlkcError) as caught:
        run_xvlkc(executable, source, existing, input_sha256=sha)
    assert caught.value.code == XvlkcErrorCode.INVALID_ARGUMENT

    with pytest.raises(XvlkcError) as caught:
        run_xvlkc(executable, source, source, input_sha256=sha)
    assert caught.value.code == XvlkcErrorCode.INVALID_ARGUMENT


def test_run_detects_a_pre_run_sha_mismatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable, source, _ = _exe_and_input(tmp_path)

    def no_spawn(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("must not spawn when the input already changed")

    monkeypatch.setattr(xvlkc, "_capture_process", no_spawn)
    with pytest.raises(XvlkcError) as caught:
        run_xvlkc(executable, source, tmp_path / "o.exe", input_sha256="deadbeef")
    assert caught.value.code == XvlkcErrorCode.INPUT_MUTATED


def test_run_reports_a_nonzero_exit_as_retryable_process_failed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable, source, sha = _exe_and_input(tmp_path)
    destination = tmp_path / "out" / "unpacked.exe"

    def fake_capture(argv: list[str], *, timeout: float, max_output_size: int) -> _ProcessCapture:
        del argv, timeout, max_output_size
        return _capture(returncode=3)

    monkeypatch.setattr(xvlkc, "_capture_process", fake_capture)
    with pytest.raises(XvlkcError) as caught:
        run_xvlkc(executable, source, destination, input_sha256=sha)
    assert caught.value.code == XvlkcErrorCode.PROCESS_FAILED
    assert caught.value.retryable is True
    assert not destination.exists()


def test_run_reports_an_output_cap_overrun(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    executable, source, sha = _exe_and_input(tmp_path)

    def fake_capture(argv: list[str], *, timeout: float, max_output_size: int) -> _ProcessCapture:
        del argv, timeout, max_output_size
        return _capture(stdout_exceeded=True)

    monkeypatch.setattr(xvlkc, "_capture_process", fake_capture)
    with pytest.raises(XvlkcError) as caught:
        run_xvlkc(executable, source, tmp_path / "o.exe", input_sha256=sha)
    assert caught.value.code == XvlkcErrorCode.OUTPUT_LIMIT


def test_run_reports_missing_output_when_the_tool_emits_no_pe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable, source, sha = _exe_and_input(tmp_path)

    def fake_capture(argv: list[str], *, timeout: float, max_output_size: int) -> _ProcessCapture:
        del argv, timeout, max_output_size
        return _capture()

    monkeypatch.setattr(xvlkc, "_capture_process", fake_capture)
    with pytest.raises(XvlkcError) as caught:
        run_xvlkc(executable, source, tmp_path / "o.exe", input_sha256=sha)
    assert caught.value.code == XvlkcErrorCode.OUTPUT_MISSING


def test_run_detects_the_tool_mutating_the_original_input(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable, source, sha = _exe_and_input(tmp_path)

    def fake_capture(argv: list[str], *, timeout: float, max_output_size: int) -> _ProcessCapture:
        del timeout, max_output_size
        # A well-behaved tool works on the copy; here it tampers the original.
        source.write_bytes(source.read_bytes() + b"MUTATED")
        work_input = Path(argv[1])
        _write_pe(work_input.parent / "dumped.exe", tail=b"z")
        return _capture()

    monkeypatch.setattr(xvlkc, "_capture_process", fake_capture)
    with pytest.raises(XvlkcError) as caught:
        run_xvlkc(executable, source, tmp_path / "o.exe", input_sha256=sha)
    assert caught.value.code == XvlkcErrorCode.INPUT_MUTATED


def test_probe_returns_false_for_a_missing_executable(tmp_path: Path) -> None:
    assert xvlkc.probe_xvlkc(tmp_path / "nope.exe") == (False, "")


def test_probe_recognises_a_usage_banner(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    executable = tmp_path / "xvlkc.exe"
    executable.write_bytes(b"fake")
    monkeypatch.setattr(
        xvlkc,
        "run_bounded",
        lambda *a, **k: SimpleNamespace(stdout=b"XVLKC usage: <input>", stderr=b"", returncode=0),
    )
    ok, text = xvlkc.probe_xvlkc(executable)
    assert ok is True
    assert "usage" in text


def test_probe_accepts_a_benign_returncode_with_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable = tmp_path / "xvlkc.exe"
    executable.write_bytes(b"fake")
    monkeypatch.setattr(
        xvlkc,
        "run_bounded",
        lambda *a, **k: SimpleNamespace(stdout=b"some banner", stderr=b"", returncode=1),
    )
    ok, text = xvlkc.probe_xvlkc(executable)
    assert ok is True
    assert text == "some banner"


def test_probe_reports_false_on_silent_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable = tmp_path / "xvlkc.exe"
    executable.write_bytes(b"fake")
    monkeypatch.setattr(
        xvlkc,
        "run_bounded",
        lambda *a, **k: SimpleNamespace(stdout=b"", stderr=b"", returncode=2),
    )
    assert xvlkc.probe_xvlkc(executable) == (False, "")


def test_probe_swallows_a_launch_timeout(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    executable = tmp_path / "xvlkc.exe"
    executable.write_bytes(b"fake")

    def boom(*args: Any, **kwargs: Any) -> Any:
        raise TimedOut(5.0, [])

    monkeypatch.setattr(xvlkc, "run_bounded", boom)
    assert xvlkc.probe_xvlkc(executable) == (False, "")
