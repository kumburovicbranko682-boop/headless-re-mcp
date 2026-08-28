"""``run_de4dot`` honesty guards and the bounded ``_capture_process`` machinery.

The sibling ``test_dotnet_de4dot`` file covers the service-level deobfuscate/
verify/doctor surface with the runner mocked. ``run_de4dot`` itself -- the
adapter that runs ``de4dot -f <in> -o <out>`` and refuses to report success it
cannot back up -- and the shared ``_capture_process`` subprocess lifecycle are
otherwise untested (~66%).

Two styles are used. ``run_de4dot`` is driven with a stand-in ``_capture_process``
that writes the ``-o`` output the scenario needs and returns a ``_ProcessCapture``,
so every guard runs deterministically without a subprocess. ``_capture_process``
and the version probe are exercised against real POSIX shell scripts, because
their whole point is bounded process I/O (stream capture, output ceiling,
timeout kill, cancel).
"""

from __future__ import annotations

import os
from collections.abc import Callable
from pathlib import Path
from threading import Event
from typing import Any

import pytest

from headless_re_mcp.backends.common.bounded_run import (
    BoundedCancelled,
    bound_cancel_scope,
)
from headless_re_mcp.core.session import file_sha256
from headless_re_mcp.dotnet import de4dot as de4dot_mod
from headless_re_mcp.dotnet.de4dot import (
    De4dotError,
    De4dotErrorCode,
    De4dotResult,
    _ProcessCapture,
    run_de4dot,
)

posix_only = pytest.mark.skipif(os.name == "nt", reason="POSIX shell stand-in for the CLI")


def _capture(
    *,
    returncode: int = 0,
    stdout: str = "done",
    stderr: str = "",
    stdout_exceeded: bool = False,
    stderr_exceeded: bool = False,
) -> _ProcessCapture:
    return _ProcessCapture(
        stdout=stdout,
        stderr=stderr,
        returncode=returncode,
        stdout_exceeded=stdout_exceeded,
        stderr_exceeded=stderr_exceeded,
    )


def _prepare(tmp_path: Path) -> tuple[Path, Path, Path, str]:
    exe = tmp_path / "de4dot.exe"
    exe.write_bytes(b"placeholder")
    source = tmp_path / "obf.exe"
    source.write_bytes(b"obfuscated-assembly-bytes")
    destination = tmp_path / "out" / "clean.exe"
    return exe, source, destination, file_sha256(source)


def _install(monkeypatch: Any, writer: Callable[[Path], _ProcessCapture]) -> None:
    """Route ``_capture_process`` to ``writer(destination) -> _ProcessCapture``.

    ``run_de4dot`` invokes ``de4dot -f <src> -o <dst>``, so the output path the
    real CLI would write is ``argv[4]``.
    """

    def fake(argv: list[str], **_: Any) -> _ProcessCapture:
        destination = Path(argv[4])
        return writer(destination)

    monkeypatch.setattr(de4dot_mod, "_capture_process", fake)


def _write_script(path: Path, body: str) -> Path:
    path.write_text(f"#!/bin/sh\n{body}\n")
    path.chmod(0o755)
    return path


# --------------------------------------------------------------------------- #
# run_de4dot: success and post-run guards (deterministic, no subprocess)       #
# --------------------------------------------------------------------------- #
def test_run_publishes_the_deobfuscated_output(
    tmp_path: Path, monkeypatch: Any
) -> None:
    exe, source, destination, sha = _prepare(tmp_path)

    def writer(dst: Path) -> _ProcessCapture:
        dst.write_bytes(b"cleaned-payload")
        return _capture(stdout="Cleaning obf.exe\nSaving clean.exe")

    _install(monkeypatch, writer)
    result = run_de4dot(exe, source, destination, input_sha256=sha)

    assert isinstance(result, De4dotResult)
    assert destination.read_bytes() == b"cleaned-payload"
    assert result.returncode == 0
    assert result.input_sha256 == sha
    assert result.output_sha256 == file_sha256(destination)
    assert file_sha256(source) == sha  # original untouched
    payload = result.to_dict()
    assert payload["source"] == "de4dot"
    assert payload["claims_universal_unpack"] is False


def test_run_reports_output_missing_when_success_leaves_no_file(
    tmp_path: Path, monkeypatch: Any
) -> None:
    exe, source, destination, sha = _prepare(tmp_path)

    _install(monkeypatch, lambda _dst: _capture())  # rc 0 but writes nothing

    with pytest.raises(De4dotError) as excinfo:
        run_de4dot(exe, source, destination, input_sha256=sha)

    assert excinfo.value.code == De4dotErrorCode.OUTPUT_MISSING


def test_run_reports_a_nonzero_exit_and_removes_a_partial_output(
    tmp_path: Path, monkeypatch: Any
) -> None:
    exe, source, destination, sha = _prepare(tmp_path)

    def writer(dst: Path) -> _ProcessCapture:
        dst.write_bytes(b"half-written")  # a partial file must not survive
        return _capture(returncode=1, stderr="de4dot error")

    _install(monkeypatch, writer)

    with pytest.raises(De4dotError) as excinfo:
        run_de4dot(exe, source, destination, input_sha256=sha)

    assert excinfo.value.code == De4dotErrorCode.PROCESS_FAILED
    assert excinfo.value.returncode == 1
    assert excinfo.value.retryable is True
    assert not destination.exists()


def test_run_reports_output_limit_and_removes_a_partial_output(
    tmp_path: Path, monkeypatch: Any
) -> None:
    exe, source, destination, sha = _prepare(tmp_path)

    def writer(dst: Path) -> _ProcessCapture:
        dst.write_bytes(b"half-written")
        return _capture(stdout_exceeded=True)

    _install(monkeypatch, writer)

    with pytest.raises(De4dotError) as excinfo:
        run_de4dot(exe, source, destination, input_sha256=sha)

    assert excinfo.value.code == De4dotErrorCode.OUTPUT_LIMIT
    assert not destination.exists()


def test_run_detects_the_tool_mutating_the_original_input(
    tmp_path: Path, monkeypatch: Any
) -> None:
    exe, source, destination, sha = _prepare(tmp_path)

    def writer(dst: Path) -> _ProcessCapture:
        source.write_bytes(b"obfuscated-assembly-bytes-MUTATED")
        dst.write_bytes(b"cleaned-payload")
        return _capture()

    _install(monkeypatch, writer)

    with pytest.raises(De4dotError) as excinfo:
        run_de4dot(exe, source, destination, input_sha256=sha)

    assert excinfo.value.code == De4dotErrorCode.INPUT_MUTATED


def test_run_refuses_when_the_input_hash_changed_before_the_run(
    tmp_path: Path, monkeypatch: Any
) -> None:
    exe, source, destination, _sha = _prepare(tmp_path)

    def unreached(_dst: Path) -> _ProcessCapture:  # pragma: no cover
        raise AssertionError("capture must not run when the pre-hash mismatches")

    _install(monkeypatch, unreached)

    with pytest.raises(De4dotError) as excinfo:
        run_de4dot(exe, source, destination, input_sha256="0" * 64)

    assert excinfo.value.code == De4dotErrorCode.INPUT_MUTATED


def test_run_refuses_a_missing_executable(tmp_path: Path) -> None:
    _exe, source, destination, sha = _prepare(tmp_path)
    with pytest.raises(De4dotError) as excinfo:
        run_de4dot(tmp_path / "gone.exe", source, destination, input_sha256=sha)
    assert excinfo.value.code == De4dotErrorCode.EXECUTABLE_NOT_FOUND


def test_run_refuses_an_input_that_is_not_a_regular_file(tmp_path: Path) -> None:
    exe, _source, destination, _sha = _prepare(tmp_path)
    a_directory = tmp_path / "a_dir"
    a_directory.mkdir()
    with pytest.raises(De4dotError) as excinfo:
        run_de4dot(exe, a_directory, destination, input_sha256="0" * 64)
    assert excinfo.value.code == De4dotErrorCode.INPUT_NOT_FOUND


def test_run_refuses_an_input_over_the_size_cap(tmp_path: Path) -> None:
    exe, source, destination, sha = _prepare(tmp_path)
    with pytest.raises(De4dotError) as excinfo:
        run_de4dot(exe, source, destination, input_sha256=sha, max_file_size=1)
    assert excinfo.value.code == De4dotErrorCode.INPUT_TOO_LARGE


def test_run_refuses_a_destination_that_already_exists(tmp_path: Path) -> None:
    exe, source, destination, sha = _prepare(tmp_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(b"pre-existing")
    with pytest.raises(De4dotError) as excinfo:
        run_de4dot(exe, source, destination, input_sha256=sha)
    assert excinfo.value.code == De4dotErrorCode.INVALID_ARGUMENT
    assert destination.read_bytes() == b"pre-existing"


# --------------------------------------------------------------------------- #
# _capture_process: bounded subprocess I/O (real POSIX shell scripts)         #
# --------------------------------------------------------------------------- #
@posix_only
def test_capture_collects_streams_and_returncode(tmp_path: Path) -> None:
    script = _write_script(
        tmp_path / "ok.sh", "echo to-stdout\necho to-stderr >&2\nexit 0"
    )
    cap = de4dot_mod._capture_process(
        [str(script)], timeout=5.0, max_output_size=64 * 1024
    )
    assert cap.returncode == 0
    assert "to-stdout" in cap.stdout
    assert "to-stderr" in cap.stderr
    assert cap.stdout_exceeded is False
    assert cap.stderr_exceeded is False


@posix_only
def test_capture_propagates_a_nonzero_returncode(tmp_path: Path) -> None:
    script = _write_script(tmp_path / "fail.sh", "exit 4")
    cap = de4dot_mod._capture_process(
        [str(script)], timeout=5.0, max_output_size=64 * 1024
    )
    assert cap.returncode == 4


@posix_only
def test_capture_flags_output_over_the_ceiling(tmp_path: Path) -> None:
    script = _write_script(
        tmp_path / "big.sh", "head -c 5000 /dev/zero | tr '\\0' 'A'"
    )
    cap = de4dot_mod._capture_process([str(script)], timeout=5.0, max_output_size=10)
    assert cap.stdout_exceeded is True


@posix_only
def test_capture_times_out_and_kills_the_process(tmp_path: Path) -> None:
    script = _write_script(tmp_path / "slow.sh", "sleep 30")
    with pytest.raises(De4dotError) as excinfo:
        de4dot_mod._capture_process(
            [str(script)], timeout=0.3, max_output_size=64 * 1024
        )
    assert excinfo.value.code == De4dotErrorCode.TIMEOUT
    assert excinfo.value.retryable is True


@posix_only
def test_capture_honours_an_already_cancelled_scope(tmp_path: Path) -> None:
    script = _write_script(tmp_path / "slow.sh", "sleep 30")
    cancel = Event()
    cancel.set()
    with bound_cancel_scope(cancel), pytest.raises(BoundedCancelled):
        de4dot_mod._capture_process(
            [str(script)], timeout=5.0, max_output_size=64 * 1024
        )


def test_capture_maps_a_missing_executable(tmp_path: Path) -> None:
    with pytest.raises(De4dotError) as excinfo:
        de4dot_mod._capture_process(
            [str(tmp_path / "nope-binary")], timeout=5.0, max_output_size=1024
        )
    assert excinfo.value.code == De4dotErrorCode.EXECUTABLE_NOT_FOUND


# --------------------------------------------------------------------------- #
# probe_de4dot_version                                                         #
# --------------------------------------------------------------------------- #
def test_probe_reports_absent_for_a_missing_executable(tmp_path: Path) -> None:
    ok, text = de4dot_mod.probe_de4dot_version(tmp_path / "nope.exe")
    assert ok is False
    assert text == ""


@posix_only
def test_probe_recognizes_de4dot_banner(tmp_path: Path) -> None:
    script = _write_script(tmp_path / "probe.sh", "echo 'de4dot v3.1.41592'")
    ok, text = de4dot_mod.probe_de4dot_version(script)
    assert ok is True
    assert "de4dot" in text.casefold()
