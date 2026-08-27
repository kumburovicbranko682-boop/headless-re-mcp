"""Guards, publish path, capture machinery, and probe of the de4dot adapter.

``test_dotnet_de4dot.py`` drives the service seam with a fake runner, so the
adapter's own body -- the argument-validation envelope, the honesty branches
after the tool returns, the bounded ``_capture_process`` that owns the child and
its pipes, and the version probe -- was never exercised directly. This does that:
the envelope with a faked capture, the capture itself against short-lived
``sys.executable`` children (a clean exit, a missing binary, a deadline, a blown
output bound, a caller cancel), and the probe with a faked ``run_bounded``.
"""

from __future__ import annotations

import sys
from pathlib import Path
from threading import Event
from types import SimpleNamespace
from typing import Any

import pytest

from headless_re_mcp.backends.common.bounded_run import (
    BoundedCancelled,
    TimedOut,
    bound_cancel_scope,
)
from headless_re_mcp.core.session import file_sha256
from headless_re_mcp.dotnet import de4dot as de4dot_mod
from headless_re_mcp.dotnet.de4dot import (
    De4dotError,
    De4dotErrorCode,
    _capture_process,
    _ProcessCapture,
    probe_de4dot_version,
    run_de4dot,
)


def _inputs(tmp_path: Path) -> tuple[Path, Path, Path, str]:
    exe = tmp_path / "de4dot.exe"
    exe.write_bytes(b"placeholder")
    source = tmp_path / "managed.exe"
    source.write_bytes(b"managed-assembly-bytes")
    destination = tmp_path / "out" / "clean.exe"
    return exe, source, destination, file_sha256(source)


def _clean(returncode: int = 0) -> _ProcessCapture:
    return _ProcessCapture(
        stdout="ok", stderr="", returncode=returncode, stdout_exceeded=False, stderr_exceeded=False
    )


def _py(code: str) -> list[str]:
    return [sys.executable, "-c", code]


# ---------------------------------------------------------------------------
# run_de4dot envelope
# ---------------------------------------------------------------------------
def test_missing_executable_is_reported(tmp_path: Path) -> None:
    _, source, destination, sha = _inputs(tmp_path)
    with pytest.raises(De4dotError) as caught:
        run_de4dot(tmp_path / "absent.exe", source, destination, input_sha256=sha)
    assert caught.value.code == De4dotErrorCode.EXECUTABLE_NOT_FOUND


def test_a_directory_input_is_not_a_file(tmp_path: Path) -> None:
    exe, _, destination, _ = _inputs(tmp_path)
    a_dir = tmp_path / "adir"
    a_dir.mkdir()
    with pytest.raises(De4dotError) as caught:
        run_de4dot(exe, a_dir, destination, input_sha256="0" * 64)
    assert caught.value.code == De4dotErrorCode.INPUT_NOT_FOUND


def test_oversized_input_is_refused(tmp_path: Path) -> None:
    exe, source, destination, sha = _inputs(tmp_path)
    with pytest.raises(De4dotError) as caught:
        run_de4dot(exe, source, destination, input_sha256=sha, max_file_size=1)
    assert caught.value.code == De4dotErrorCode.INPUT_TOO_LARGE


def test_an_existing_destination_is_refused(tmp_path: Path) -> None:
    exe, source, destination, sha = _inputs(tmp_path)
    destination.parent.mkdir(parents=True)
    destination.write_bytes(b"keep me")
    with pytest.raises(De4dotError) as caught:
        run_de4dot(exe, source, destination, input_sha256=sha)
    assert caught.value.code == De4dotErrorCode.INVALID_ARGUMENT


def test_a_changed_input_sha_before_run_is_refused(tmp_path: Path) -> None:
    exe, source, destination, _ = _inputs(tmp_path)
    with pytest.raises(De4dotError) as caught:
        run_de4dot(exe, source, destination, input_sha256="beef" * 16)
    assert caught.value.code == De4dotErrorCode.INPUT_MUTATED


def test_happy_path_publishes_the_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exe, source, destination, sha = _inputs(tmp_path)

    def fake_capture(argv: list[str], **kwargs: Any) -> _ProcessCapture:
        Path(argv[4]).write_bytes(b"deobfuscated")
        return _clean()

    monkeypatch.setattr(de4dot_mod, "_capture_process", fake_capture)
    result = run_de4dot(exe, source, destination, input_sha256=sha)
    assert destination.read_bytes() == b"deobfuscated"
    assert result.output_sha256 == file_sha256(destination)
    assert result.to_dict()["source"] == de4dot_mod.DE4DOT_SOURCE


def test_a_mutated_original_after_run_is_reported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exe, source, destination, sha = _inputs(tmp_path)

    def mutate(argv: list[str], **kwargs: Any) -> _ProcessCapture:
        source.write_bytes(b"tool rewrote the input")
        return _clean()

    monkeypatch.setattr(de4dot_mod, "_capture_process", mutate)
    with pytest.raises(De4dotError) as caught:
        run_de4dot(exe, source, destination, input_sha256=sha)
    assert caught.value.code == De4dotErrorCode.INPUT_MUTATED


def test_a_blown_output_bound_removes_the_partial_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exe, source, destination, sha = _inputs(tmp_path)

    def overflow(argv: list[str], **kwargs: Any) -> _ProcessCapture:
        Path(argv[4]).write_bytes(b"partial")
        return _ProcessCapture(
            stdout="x", stderr="", returncode=0, stdout_exceeded=True, stderr_exceeded=False
        )

    monkeypatch.setattr(de4dot_mod, "_capture_process", overflow)
    with pytest.raises(De4dotError) as caught:
        run_de4dot(exe, source, destination, input_sha256=sha)
    assert caught.value.code == De4dotErrorCode.OUTPUT_LIMIT
    assert not destination.exists()


def test_a_nonzero_exit_removes_output_and_is_retryable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exe, source, destination, sha = _inputs(tmp_path)

    def failed(argv: list[str], **kwargs: Any) -> _ProcessCapture:
        Path(argv[4]).write_bytes(b"junk")
        return _clean(returncode=3)

    monkeypatch.setattr(de4dot_mod, "_capture_process", failed)
    with pytest.raises(De4dotError) as caught:
        run_de4dot(exe, source, destination, input_sha256=sha)
    assert caught.value.code == De4dotErrorCode.PROCESS_FAILED
    assert caught.value.retryable is True
    assert not destination.exists()


def test_a_clean_exit_without_output_is_reported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exe, source, destination, sha = _inputs(tmp_path)
    monkeypatch.setattr(de4dot_mod, "_capture_process", lambda *a, **k: _clean())
    with pytest.raises(De4dotError) as caught:
        run_de4dot(exe, source, destination, input_sha256=sha)
    assert caught.value.code == De4dotErrorCode.OUTPUT_MISSING


# ---------------------------------------------------------------------------
# _capture_process against real short-lived children
# ---------------------------------------------------------------------------
def test_capture_collects_streams_of_a_clean_exit() -> None:
    capture = _capture_process(
        _py("import sys; sys.stdout.write('out'); sys.stderr.write('err')"),
        timeout=30.0,
        max_output_size=1 << 20,
    )
    assert capture.returncode == 0
    assert capture.stdout == "out"
    assert capture.stderr == "err"
    assert capture.stdout_exceeded is False


def test_capture_maps_a_missing_binary() -> None:
    with pytest.raises(De4dotError) as caught:
        _capture_process(
            ["this-de4dot-binary-does-not-exist-xyz"], timeout=5.0, max_output_size=1 << 20
        )
    assert caught.value.code == De4dotErrorCode.EXECUTABLE_NOT_FOUND


def test_capture_enforces_the_deadline() -> None:
    with pytest.raises(De4dotError) as caught:
        _capture_process(_py("import time; time.sleep(30)"), timeout=0.3, max_output_size=1 << 20)
    assert caught.value.code == De4dotErrorCode.TIMEOUT
    assert caught.value.retryable is True


def test_capture_flags_a_blown_output_bound() -> None:
    capture = _capture_process(
        _py("import sys; sys.stdout.write('x' * 200000)"),
        timeout=30.0,
        max_output_size=1024,
    )
    assert capture.stdout_exceeded is True


def test_capture_honours_a_caller_cancel() -> None:
    cancel = Event()
    cancel.set()
    with bound_cancel_scope(cancel), pytest.raises(BoundedCancelled):
        _capture_process(
            _py("import time; time.sleep(30)"), timeout=30.0, max_output_size=1 << 20
        )


# ---------------------------------------------------------------------------
# probe_de4dot_version
# ---------------------------------------------------------------------------
def test_probe_returns_false_without_an_executable(tmp_path: Path) -> None:
    ok, text = probe_de4dot_version(tmp_path / "nope.exe")
    assert ok is False
    assert text == ""


def test_probe_gives_up_when_the_binary_hangs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exe = tmp_path / "de4dot.exe"
    exe.write_bytes(b"x")

    def hang(*args: Any, **kwargs: Any) -> Any:
        raise TimedOut(5.0, [])

    monkeypatch.setattr(de4dot_mod, "run_bounded", hang)
    ok, text = probe_de4dot_version(exe)
    assert ok is False
    assert text == ""


def test_probe_skips_a_launch_error_then_recognises_the_banner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exe = tmp_path / "de4dot.exe"
    exe.write_bytes(b"x")
    calls: list[list[str]] = []

    def run(args: list[str], **kwargs: Any) -> Any:
        calls.append(args)
        if len(calls) == 1:
            # The bare invocation cannot start; the probe should try -h next.
            raise OSError("exec format error")
        return SimpleNamespace(stdout=b"de4dot v3.1.41592", stderr=b"", returncode=1)

    monkeypatch.setattr(de4dot_mod, "run_bounded", run)
    ok, text = probe_de4dot_version(exe)
    assert ok is True
    assert "de4dot" in text
    assert len(calls) == 2


def test_probe_reports_false_when_no_variant_answers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exe = tmp_path / "de4dot.exe"
    exe.write_bytes(b"x")
    monkeypatch.setattr(
        de4dot_mod,
        "run_bounded",
        lambda *a, **k: SimpleNamespace(stdout=b"unrelated", stderr=b"", returncode=5),
    )
    ok, text = probe_de4dot_version(exe)
    assert ok is False
    assert text == ""
