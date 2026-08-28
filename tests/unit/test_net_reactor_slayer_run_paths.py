"""Cover the NETReactorSlayer adapter guards, output selection, cleanup, and
the best-effort probe."""

from __future__ import annotations

import os
import stat
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import headless_re_mcp.dotnet.net_reactor_slayer as nrs
from headless_re_mcp.core.session import file_sha256
from headless_re_mcp.dotnet.net_reactor_slayer import (
    NetReactorSlayerError,
    NetReactorSlayerErrorCode,
    NetReactorSlayerResult,
    probe_net_reactor_slayer,
    run_net_reactor_slayer,
)

# Most tests only need the fake tool to exist on disk: the guard under test
# refuses before anything is launched, or _capture_process is monkeypatched.
# The ones marked below actually execute it, and a "#!/bin/sh" script cannot
# run on Windows (WinError 193).
_EXECUTES_SH_SCRIPT = pytest.mark.skipif(
    os.name == "nt", reason="the fake NETReactorSlayer is a POSIX sh script"
)


def _script(path: Path, body: str) -> Path:
    path.write_text("#!/bin/sh\n" + body, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return path


def _source(tmp_path: Path) -> Path:
    source = tmp_path / "managed.exe"
    source.write_bytes(b"managed-assembly-bytes")
    return source


def _fake_capture(**overrides: Any) -> Any:
    defaults = dict(
        stdout="",
        stderr="",
        returncode=0,
        stdout_exceeded=False,
        stderr_exceeded=False,
    )
    defaults.update(overrides)

    def capture(argv: list[str], **_kwargs: Any) -> Any:
        del argv
        return SimpleNamespace(**defaults)

    return capture


# --- run guards ---------------------------------------------------------------


@_EXECUTES_SH_SCRIPT
def test_run_publishes_the_exact_slayed_output(tmp_path: Path) -> None:
    source = _source(tmp_path)
    exe = _script(
        tmp_path / "nrs.sh",
        'in="$1"\ndir=$(dirname "$in")\nbase=$(basename "$in")\n'
        'stem="${base%.*}"\next="${base##*.}"\n'
        'cp "$in" "$dir/${stem}_Slayed.${ext}"\necho done\nexit 0\n',
    )
    destination = tmp_path / "out" / "slayed.exe"
    result = run_net_reactor_slayer(
        exe, source, destination, input_sha256=file_sha256(source)
    )
    assert result.returncode == 0
    assert Path(result.output_path).is_file()


@_EXECUTES_SH_SCRIPT
def test_run_accepts_a_single_slayed_file_by_glob(tmp_path: Path) -> None:
    source = _source(tmp_path)
    exe = _script(
        tmp_path / "nrs.sh",
        'dir=$(dirname "$1")\ncp "$1" "$dir/weird_Slayed.bin"\nexit 0\n',
    )
    destination = tmp_path / "out" / "slayed.exe"
    result = run_net_reactor_slayer(
        exe, source, destination, input_sha256=file_sha256(source)
    )
    assert Path(result.output_path).is_file()


@_EXECUTES_SH_SCRIPT
def test_run_fails_closed_when_no_slayed_output_appears(tmp_path: Path) -> None:
    source = _source(tmp_path)
    exe = _script(tmp_path / "nrs.sh", "exit 0\n")
    with pytest.raises(NetReactorSlayerError) as excinfo:
        run_net_reactor_slayer(
            exe, source, tmp_path / "out.exe", input_sha256=file_sha256(source)
        )
    assert excinfo.value.code == NetReactorSlayerErrorCode.OUTPUT_MISSING


def test_run_refuses_a_missing_executable(tmp_path: Path) -> None:
    source = _source(tmp_path)
    with pytest.raises(NetReactorSlayerError) as excinfo:
        run_net_reactor_slayer(
            tmp_path / "absent",
            source,
            tmp_path / "out.exe",
            input_sha256=file_sha256(source),
        )
    assert excinfo.value.code == NetReactorSlayerErrorCode.EXECUTABLE_NOT_FOUND


def test_run_refuses_a_non_file_input(tmp_path: Path) -> None:
    exe = _script(tmp_path / "nrs.sh", "exit 0\n")
    a_dir = tmp_path / "input_dir"
    a_dir.mkdir()
    with pytest.raises(NetReactorSlayerError) as excinfo:
        run_net_reactor_slayer(exe, a_dir, tmp_path / "out.exe", input_sha256="x")
    assert excinfo.value.code == NetReactorSlayerErrorCode.INPUT_NOT_FOUND


def test_run_refuses_oversized_input(tmp_path: Path) -> None:
    source = _source(tmp_path)
    exe = _script(tmp_path / "nrs.sh", "exit 0\n")
    with pytest.raises(NetReactorSlayerError) as excinfo:
        run_net_reactor_slayer(
            exe,
            source,
            tmp_path / "out.exe",
            input_sha256=file_sha256(source),
            max_file_size=1,
        )
    assert excinfo.value.code == NetReactorSlayerErrorCode.INPUT_TOO_LARGE


def test_run_refuses_an_existing_destination(tmp_path: Path) -> None:
    source = _source(tmp_path)
    exe = _script(tmp_path / "nrs.sh", "exit 0\n")
    destination = tmp_path / "out.exe"
    destination.write_bytes(b"already here")
    with pytest.raises(NetReactorSlayerError) as excinfo:
        run_net_reactor_slayer(
            exe, source, destination, input_sha256=file_sha256(source)
        )
    assert excinfo.value.code == NetReactorSlayerErrorCode.INVALID_ARGUMENT


def test_run_refuses_a_destination_that_resolves_to_the_input(tmp_path: Path) -> None:
    source = _source(tmp_path)
    exe = _script(tmp_path / "nrs.sh", "exit 0\n")
    destination = tmp_path / "missing-dir" / ".." / "managed.exe"
    with pytest.raises(NetReactorSlayerError) as excinfo:
        run_net_reactor_slayer(
            exe, source, destination, input_sha256=file_sha256(source)
        )
    assert excinfo.value.code == NetReactorSlayerErrorCode.INVALID_ARGUMENT


def test_run_refuses_a_changed_input_sha_up_front(tmp_path: Path) -> None:
    source = _source(tmp_path)
    exe = _script(tmp_path / "nrs.sh", "exit 0\n")
    with pytest.raises(NetReactorSlayerError) as excinfo:
        run_net_reactor_slayer(
            exe, source, tmp_path / "out.exe", input_sha256="deadbeef"
        )
    assert excinfo.value.code == NetReactorSlayerErrorCode.INPUT_MUTATED


def test_run_detects_input_mutation_during_the_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = _source(tmp_path)
    exe = _script(tmp_path / "nrs.sh", "exit 0\n")

    def capture(argv: list[str], **_kwargs: Any) -> Any:
        del argv
        source.write_bytes(b"mutated after start")
        return SimpleNamespace(
            stdout="", stderr="", returncode=0,
            stdout_exceeded=False, stderr_exceeded=False,
        )

    monkeypatch.setattr(nrs, "_capture_process", capture)
    with pytest.raises(NetReactorSlayerError) as excinfo:
        run_net_reactor_slayer(
            exe, source, tmp_path / "out.exe", input_sha256=file_sha256(source)
        )
    assert excinfo.value.code == NetReactorSlayerErrorCode.INPUT_MUTATED


def test_run_reports_an_output_size_overrun(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = _source(tmp_path)
    exe = _script(tmp_path / "nrs.sh", "exit 0\n")
    monkeypatch.setattr(nrs, "_capture_process", _fake_capture(stdout_exceeded=True))
    with pytest.raises(NetReactorSlayerError) as excinfo:
        run_net_reactor_slayer(
            exe, source, tmp_path / "out.exe", input_sha256=file_sha256(source)
        )
    assert excinfo.value.code == NetReactorSlayerErrorCode.OUTPUT_LIMIT


def test_run_maps_a_nonzero_exit_and_cleans_up_a_partial(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = _source(tmp_path)
    exe = _script(tmp_path / "nrs.sh", "exit 0\n")
    destination = tmp_path / "out" / "slayed.exe"

    def capture(argv: list[str], **_kwargs: Any) -> Any:
        del argv
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(b"partial")
        return SimpleNamespace(
            stdout="boom", stderr="", returncode=5,
            stdout_exceeded=False, stderr_exceeded=False,
        )

    monkeypatch.setattr(nrs, "_capture_process", capture)
    with pytest.raises(NetReactorSlayerError) as excinfo:
        run_net_reactor_slayer(
            exe, source, destination, input_sha256=file_sha256(source)
        )
    assert excinfo.value.code == NetReactorSlayerErrorCode.PROCESS_FAILED
    assert destination.is_file() is False


def test_result_to_dict_carries_the_authorized_target(tmp_path: Path) -> None:
    result = NetReactorSlayerResult(
        executable="nrs",
        input_path="in.exe",
        output_path="out.exe",
        input_sha256="a",
        output_sha256="b",
        returncode=0,
        stdout="ok",
        stderr="",
        duration_ms=3,
    )
    payload = result.to_dict()
    assert payload["source"] == "net_reactor_slayer"
    assert payload["target"] == "authorized_reactor_samples_only"
    assert payload["claims_universal_unpack"] is False


# --- probe --------------------------------------------------------------------


def test_probe_reports_absent_for_a_missing_executable(tmp_path: Path) -> None:
    ok, text = probe_net_reactor_slayer(tmp_path / "nope")
    assert ok is False
    assert text == ""


def test_probe_reports_absent_for_an_unrunnable_file(tmp_path: Path) -> None:
    not_exec = tmp_path / "plain"
    not_exec.write_text("not executable", encoding="utf-8")
    ok, text = probe_net_reactor_slayer(not_exec)
    assert ok is False
    assert text == ""


@_EXECUTES_SH_SCRIPT
def test_probe_recognises_a_tool_banner(tmp_path: Path) -> None:
    exe = _script(tmp_path / "nrs.sh", 'echo "NETReactorSlayer 1.0"\nexit 1\n')
    ok, text = probe_net_reactor_slayer(exe)
    assert ok is True
    assert "NETReactorSlayer" in text


@_EXECUTES_SH_SCRIPT
def test_probe_accepts_usage_output_with_a_benign_return_code(tmp_path: Path) -> None:
    exe = _script(tmp_path / "nrs.sh", 'echo "Usage: give an assembly"\nexit 0\n')
    ok, text = probe_net_reactor_slayer(exe)
    assert ok is True
    assert "Usage" in text


def test_probe_reports_absent_when_silent_and_failing(tmp_path: Path) -> None:
    exe = _script(tmp_path / "nrs.sh", "exit 2\n")
    ok, text = probe_net_reactor_slayer(exe)
    assert ok is False
    assert text == ""
