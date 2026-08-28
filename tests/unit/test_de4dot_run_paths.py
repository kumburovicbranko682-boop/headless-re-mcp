"""Cover the de4dot adapter's run pipeline, output-limit handling via a real
capture, and the version/help probe."""

from __future__ import annotations

import stat
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import headless_re_mcp.dotnet.de4dot as de4dot
from headless_re_mcp.core.session import file_sha256
from headless_re_mcp.dotnet.de4dot import (
    De4dotError,
    De4dotErrorCode,
    probe_de4dot_version,
    run_de4dot,
)


def _script(path: Path, body: str) -> Path:
    path.write_text("#!/bin/sh\n" + body, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return path


def _source(tmp_path: Path) -> Path:
    source = tmp_path / "managed.exe"
    source.write_bytes(b"managed-assembly-bytes")
    return source


# --- run_de4dot guards --------------------------------------------------------


def test_run_writes_the_output_and_reports_success(tmp_path: Path) -> None:
    source = _source(tmp_path)
    # argv is: exe -f <source> -o <destination>; $2=source, $4=destination.
    exe = _script(tmp_path / "de4dot.sh", 'cp "$2" "$4"\necho cleaned\nexit 0\n')
    destination = tmp_path / "out" / "clean.exe"
    result = run_de4dot(exe, source, destination, input_sha256=file_sha256(source))
    assert result.returncode == 0
    assert Path(result.output_path).is_file()
    assert result.input_sha256 == file_sha256(source)


def test_run_refuses_a_missing_executable(tmp_path: Path) -> None:
    source = _source(tmp_path)
    with pytest.raises(De4dotError) as excinfo:
        run_de4dot(
            tmp_path / "absent",
            source,
            tmp_path / "out.exe",
            input_sha256=file_sha256(source),
        )
    assert excinfo.value.code == De4dotErrorCode.EXECUTABLE_NOT_FOUND


def test_run_refuses_a_non_file_input(tmp_path: Path) -> None:
    exe = _script(tmp_path / "de4dot.sh", "exit 0\n")
    a_dir = tmp_path / "input_dir"
    a_dir.mkdir()
    with pytest.raises(De4dotError) as excinfo:
        run_de4dot(exe, a_dir, tmp_path / "out.exe", input_sha256="x")
    assert excinfo.value.code == De4dotErrorCode.INPUT_NOT_FOUND


def test_run_refuses_oversized_input(tmp_path: Path) -> None:
    source = _source(tmp_path)
    exe = _script(tmp_path / "de4dot.sh", "exit 0\n")
    with pytest.raises(De4dotError) as excinfo:
        run_de4dot(
            exe,
            source,
            tmp_path / "out.exe",
            input_sha256=file_sha256(source),
            max_file_size=1,
        )
    assert excinfo.value.code == De4dotErrorCode.INPUT_TOO_LARGE


def test_run_refuses_an_existing_destination(tmp_path: Path) -> None:
    source = _source(tmp_path)
    exe = _script(tmp_path / "de4dot.sh", "exit 0\n")
    destination = tmp_path / "out.exe"
    destination.write_bytes(b"already here")
    with pytest.raises(De4dotError) as excinfo:
        run_de4dot(exe, source, destination, input_sha256=file_sha256(source))
    assert excinfo.value.code == De4dotErrorCode.INVALID_ARGUMENT


def test_run_refuses_a_destination_that_resolves_to_the_input(tmp_path: Path) -> None:
    source = _source(tmp_path)
    exe = _script(tmp_path / "de4dot.sh", "exit 0\n")
    destination = tmp_path / "missing-dir" / ".." / "managed.exe"
    with pytest.raises(De4dotError) as excinfo:
        run_de4dot(exe, source, destination, input_sha256=file_sha256(source))
    assert excinfo.value.code == De4dotErrorCode.INVALID_ARGUMENT


def test_run_refuses_a_changed_input_sha_up_front(tmp_path: Path) -> None:
    source = _source(tmp_path)
    exe = _script(tmp_path / "de4dot.sh", "exit 0\n")
    with pytest.raises(De4dotError) as excinfo:
        run_de4dot(exe, source, tmp_path / "out.exe", input_sha256="deadbeef")
    assert excinfo.value.code == De4dotErrorCode.INPUT_MUTATED


def test_run_detects_input_mutation_during_the_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = _source(tmp_path)
    exe = _script(tmp_path / "de4dot.sh", "exit 0\n")

    def capture(argv: list[str], **_kwargs: Any) -> Any:
        del argv
        source.write_bytes(b"mutated during run")
        return SimpleNamespace(
            stdout="", stderr="", returncode=0,
            stdout_exceeded=False, stderr_exceeded=False,
        )

    monkeypatch.setattr(de4dot, "_capture_process", capture)
    with pytest.raises(De4dotError) as excinfo:
        run_de4dot(exe, source, tmp_path / "out.exe", input_sha256=file_sha256(source))
    assert excinfo.value.code == De4dotErrorCode.INPUT_MUTATED


def test_run_maps_a_nonzero_exit_and_cleans_up_a_partial(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = _source(tmp_path)
    exe = _script(tmp_path / "de4dot.sh", "exit 0\n")
    destination = tmp_path / "out" / "clean.exe"

    def capture(argv: list[str], **_kwargs: Any) -> Any:
        del argv
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(b"partial")
        return SimpleNamespace(
            stdout="boom", stderr="", returncode=7,
            stdout_exceeded=False, stderr_exceeded=False,
        )

    monkeypatch.setattr(de4dot, "_capture_process", capture)
    with pytest.raises(De4dotError) as excinfo:
        run_de4dot(exe, source, destination, input_sha256=file_sha256(source))
    assert excinfo.value.code == De4dotErrorCode.PROCESS_FAILED
    assert destination.is_file() is False


def test_run_maps_a_nonzero_exit_without_a_partial(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = _source(tmp_path)
    exe = _script(tmp_path / "de4dot.sh", "exit 0\n")

    def capture(argv: list[str], **_kwargs: Any) -> Any:
        del argv
        return SimpleNamespace(
            stdout="boom", stderr="", returncode=9,
            stdout_exceeded=False, stderr_exceeded=False,
        )

    monkeypatch.setattr(de4dot, "_capture_process", capture)
    with pytest.raises(De4dotError) as excinfo:
        run_de4dot(exe, source, tmp_path / "out.exe", input_sha256=file_sha256(source))
    assert excinfo.value.code == De4dotErrorCode.PROCESS_FAILED


def test_run_reports_missing_output_after_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = _source(tmp_path)
    exe = _script(tmp_path / "de4dot.sh", "exit 0\n")

    def capture(argv: list[str], **_kwargs: Any) -> Any:
        del argv
        return SimpleNamespace(
            stdout="ok", stderr="", returncode=0,
            stdout_exceeded=False, stderr_exceeded=False,
        )

    monkeypatch.setattr(de4dot, "_capture_process", capture)
    with pytest.raises(De4dotError) as excinfo:
        run_de4dot(exe, source, tmp_path / "out.exe", input_sha256=file_sha256(source))
    assert excinfo.value.code == De4dotErrorCode.OUTPUT_MISSING


def test_run_cleans_up_when_output_exceeds_the_bound(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = _source(tmp_path)
    exe = _script(tmp_path / "de4dot.sh", "exit 0\n")
    destination = tmp_path / "out" / "clean.exe"

    def capture(argv: list[str], **_kwargs: Any) -> Any:
        del argv
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(b"partial")
        return SimpleNamespace(
            stdout="x", stderr="", returncode=0,
            stdout_exceeded=True, stderr_exceeded=False,
        )

    monkeypatch.setattr(de4dot, "_capture_process", capture)
    with pytest.raises(De4dotError) as excinfo:
        run_de4dot(exe, source, destination, input_sha256=file_sha256(source))
    assert excinfo.value.code == De4dotErrorCode.OUTPUT_LIMIT
    assert destination.is_file() is False


# --- real capture: the output limiter fires -----------------------------------


def test_capture_enforces_the_output_ceiling_on_a_live_child(tmp_path: Path) -> None:
    source = _source(tmp_path)
    # Emit far more than the tiny ceiling, then linger so the limiter, not the
    # child's own exit, is what ends the run.
    exe = _script(
        tmp_path / "de4dot.sh",
        'printf "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"\nsleep 3\n',
    )
    with pytest.raises(De4dotError) as excinfo:
        run_de4dot(
            exe,
            source,
            tmp_path / "out.exe",
            input_sha256=file_sha256(source),
            timeout=10.0,
            max_output_size=4,
        )
    assert excinfo.value.code == De4dotErrorCode.OUTPUT_LIMIT


# --- probe_de4dot_version -----------------------------------------------------


def test_probe_reports_absent_for_a_missing_executable(tmp_path: Path) -> None:
    ok, text = probe_de4dot_version(tmp_path / "nope")
    assert ok is False
    assert text == ""


def test_probe_skips_unrunnable_argforms_then_gives_up(tmp_path: Path) -> None:
    not_exec = tmp_path / "plain"
    not_exec.write_text("not executable", encoding="utf-8")
    ok, text = probe_de4dot_version(not_exec)
    assert ok is False
    assert text == ""


def test_probe_recognises_a_de4dot_banner(tmp_path: Path) -> None:
    exe = _script(tmp_path / "de4dot.sh", 'echo "de4dot v3.1.41592"\nexit 0\n')
    ok, text = probe_de4dot_version(exe)
    assert ok is True
    assert "de4dot" in text


def test_probe_gives_up_when_a_form_times_out(tmp_path: Path) -> None:
    exe = _script(tmp_path / "de4dot.sh", "sleep 2\n")
    ok, text = probe_de4dot_version(exe, timeout=0.3)
    assert ok is False
    assert text == ""


def test_probe_keeps_trying_forms_that_never_match(tmp_path: Path) -> None:
    exe = _script(tmp_path / "de4dot.sh", 'echo "irrelevant"\nexit 2\n')
    ok, text = probe_de4dot_version(exe)
    assert ok is False
    assert text == ""
