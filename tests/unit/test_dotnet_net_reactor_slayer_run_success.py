"""Success path and post-run guards for ``run_net_reactor_slayer``.

The sibling ``test_dotnet_net_reactor_slayer`` file exercises the pre-run
validation and the two ``_capture_process`` failure exits (cancel and generic
remap). It never reaches the block that runs after a *successful* capture --
the input-mutated-after-run guard, the output-limit guard, the non-zero-exit
handling, the ``*_Slayed`` output selection (including its single-candidate
fallback and its fail-closed missing/ambiguous verdict), the publish copy, and
the error-path cleanup. Those are the honesty-critical parts of the adapter, so
they are pinned here.

Each stand-in receives the whitelisted argv (``[exe, work_copy, --no-pause,
True]``) and stands in for the real CLI by writing whatever output files the
scenario needs beside the work copy, then returning a ``_ProcessCapture``. No
real NETReactorSlayer binary is required, so the whole success surface runs on
any platform.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.core.session import file_sha256
from headless_re_mcp.dotnet import net_reactor_slayer as nrs_mod
from headless_re_mcp.dotnet.de4dot import _ProcessCapture
from headless_re_mcp.dotnet.net_reactor_slayer import (
    NetReactorSlayerError,
    NetReactorSlayerErrorCode,
    NetReactorSlayerResult,
    run_net_reactor_slayer,
)


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
    exe = tmp_path / "NETReactorSlayer.CLI.exe"
    exe.write_bytes(b"placeholder")
    source = tmp_path / "managed.exe"
    source.write_bytes(b"managed-assembly-bytes")
    destination = tmp_path / "out" / "slayed.exe"
    return exe, source, destination, file_sha256(source)


def _install(
    monkeypatch: Any,
    writer: Callable[[Path], _ProcessCapture],
) -> None:
    """Route ``_capture_process`` to ``writer(work_copy) -> _ProcessCapture``."""

    def fake(argv: list[str], **_: Any) -> _ProcessCapture:
        work_copy = Path(argv[1])
        return writer(work_copy)

    monkeypatch.setattr(nrs_mod, "_capture_process", fake)


def test_run_publishes_the_expected_slayed_output(
    tmp_path: Path, monkeypatch: Any
) -> None:
    exe, source, destination, sha = _prepare(tmp_path)

    def writer(work_copy: Path) -> _ProcessCapture:
        slayed = work_copy.with_name(f"{work_copy.stem}_Slayed{work_copy.suffix}")
        slayed.write_bytes(b"slayed-payload")
        return _capture(stdout="Saved to: managed_Slayed.exe")

    _install(monkeypatch, writer)
    result = run_net_reactor_slayer(exe, source, destination, input_sha256=sha)

    assert isinstance(result, NetReactorSlayerResult)
    assert destination.is_file()
    assert destination.read_bytes() == b"slayed-payload"
    assert result.returncode == 0
    assert result.input_sha256 == sha
    assert result.output_sha256 == file_sha256(destination)
    # The original session input must be untouched.
    assert file_sha256(source) == sha
    payload = result.to_dict()
    assert payload["source"] == "net_reactor_slayer"
    assert payload["claims_universal_unpack"] is False
    assert payload["target"] == "authorized_reactor_samples_only"


def test_run_accepts_a_single_slayed_candidate_when_the_exact_name_is_absent(
    tmp_path: Path, monkeypatch: Any
) -> None:
    exe, source, destination, sha = _prepare(tmp_path)

    def writer(work_copy: Path) -> _ProcessCapture:
        # A differently-named but unique ``*_Slayed*`` file: the fallback should
        # take it rather than fail, because there is no ambiguity.
        alt = work_copy.with_name(f"cleaned_Slayed_final{work_copy.suffix}")
        alt.write_bytes(b"alt-slayed-payload")
        return _capture()

    _install(monkeypatch, writer)
    result = run_net_reactor_slayer(exe, source, destination, input_sha256=sha)

    assert destination.read_bytes() == b"alt-slayed-payload"
    assert result.output_sha256 == file_sha256(destination)


def test_run_fails_closed_when_no_slayed_output_appears(
    tmp_path: Path, monkeypatch: Any
) -> None:
    exe, source, destination, sha = _prepare(tmp_path)

    _install(monkeypatch, lambda _work_copy: _capture())  # writes nothing

    with pytest.raises(NetReactorSlayerError) as excinfo:
        run_net_reactor_slayer(exe, source, destination, input_sha256=sha)

    assert excinfo.value.code == NetReactorSlayerErrorCode.OUTPUT_MISSING
    # Nothing was published, and the error path leaves no stray destination.
    assert not destination.exists()


def test_run_fails_closed_when_slayed_candidates_are_ambiguous(
    tmp_path: Path, monkeypatch: Any
) -> None:
    exe, source, destination, sha = _prepare(tmp_path)

    def writer(work_copy: Path) -> _ProcessCapture:
        # Two ``*_Slayed*`` files and none with the exact expected name: the
        # adapter cannot know which is the real output, so it must refuse.
        work_copy.with_name(f"a_Slayed{work_copy.suffix}").write_bytes(b"a")
        work_copy.with_name(f"b_Slayed{work_copy.suffix}").write_bytes(b"b")
        return _capture()

    _install(monkeypatch, writer)

    with pytest.raises(NetReactorSlayerError) as excinfo:
        run_net_reactor_slayer(exe, source, destination, input_sha256=sha)

    assert excinfo.value.code == NetReactorSlayerErrorCode.OUTPUT_MISSING
    assert not destination.exists()


def test_run_reports_a_nonzero_exit_as_a_retryable_process_failure(
    tmp_path: Path, monkeypatch: Any
) -> None:
    exe, source, destination, sha = _prepare(tmp_path)

    def writer(work_copy: Path) -> _ProcessCapture:
        # Even if a stray output exists, a non-zero exit is a failure.
        work_copy.with_name(f"{work_copy.stem}_Slayed{work_copy.suffix}").write_bytes(b"x")
        return _capture(returncode=3, stderr="reactor slayer blew up")

    _install(monkeypatch, writer)

    with pytest.raises(NetReactorSlayerError) as excinfo:
        run_net_reactor_slayer(exe, source, destination, input_sha256=sha)

    assert excinfo.value.code == NetReactorSlayerErrorCode.PROCESS_FAILED
    assert excinfo.value.returncode == 3
    assert excinfo.value.retryable is True
    assert not destination.exists()


def test_run_reports_exceeded_output_as_output_limit(
    tmp_path: Path, monkeypatch: Any
) -> None:
    exe, source, destination, sha = _prepare(tmp_path)

    def writer(work_copy: Path) -> _ProcessCapture:
        work_copy.with_name(f"{work_copy.stem}_Slayed{work_copy.suffix}").write_bytes(b"x")
        return _capture(stdout_exceeded=True)

    _install(monkeypatch, writer)

    with pytest.raises(NetReactorSlayerError) as excinfo:
        run_net_reactor_slayer(exe, source, destination, input_sha256=sha)

    assert excinfo.value.code == NetReactorSlayerErrorCode.OUTPUT_LIMIT
    assert not destination.exists()


def test_run_detects_the_tool_mutating_the_original_input(
    tmp_path: Path, monkeypatch: Any
) -> None:
    exe, source, destination, sha = _prepare(tmp_path)

    def writer(work_copy: Path) -> _ProcessCapture:
        # A misbehaving tool that writes back to the original session input,
        # not just the isolated work copy. The adapter reads the original's
        # hash again after the run and must catch the change.
        source.write_bytes(b"managed-assembly-bytes-MUTATED")
        return _capture()

    _install(monkeypatch, writer)

    with pytest.raises(NetReactorSlayerError) as excinfo:
        run_net_reactor_slayer(exe, source, destination, input_sha256=sha)

    assert excinfo.value.code == NetReactorSlayerErrorCode.INPUT_MUTATED
    assert not destination.exists()


def test_run_refuses_when_the_input_hash_changed_before_the_run(
    tmp_path: Path, monkeypatch: Any
) -> None:
    exe, source, destination, _sha = _prepare(tmp_path)

    def unreached(_work_copy: Path) -> _ProcessCapture:  # pragma: no cover
        raise AssertionError("capture must not run when the pre-hash mismatches")

    _install(monkeypatch, unreached)

    with pytest.raises(NetReactorSlayerError) as excinfo:
        run_net_reactor_slayer(exe, source, destination, input_sha256="0" * 64)

    assert excinfo.value.code == NetReactorSlayerErrorCode.INPUT_MUTATED


def test_run_refuses_a_missing_executable(tmp_path: Path) -> None:
    _exe, source, destination, sha = _prepare(tmp_path)
    missing = tmp_path / "not-here.exe"

    with pytest.raises(NetReactorSlayerError) as excinfo:
        run_net_reactor_slayer(missing, source, destination, input_sha256=sha)

    assert excinfo.value.code == NetReactorSlayerErrorCode.EXECUTABLE_NOT_FOUND


def test_run_refuses_an_input_that_is_not_a_regular_file(tmp_path: Path) -> None:
    exe, _source, destination, _sha = _prepare(tmp_path)
    a_directory = tmp_path / "a_dir"
    a_directory.mkdir()

    with pytest.raises(NetReactorSlayerError) as excinfo:
        run_net_reactor_slayer(exe, a_directory, destination, input_sha256="0" * 64)

    assert excinfo.value.code == NetReactorSlayerErrorCode.INPUT_NOT_FOUND


def test_run_refuses_an_input_over_the_size_cap(tmp_path: Path) -> None:
    exe, source, destination, sha = _prepare(tmp_path)

    with pytest.raises(NetReactorSlayerError) as excinfo:
        run_net_reactor_slayer(
            exe, source, destination, input_sha256=sha, max_file_size=1
        )

    assert excinfo.value.code == NetReactorSlayerErrorCode.INPUT_TOO_LARGE


def test_run_refuses_a_destination_that_already_exists(tmp_path: Path) -> None:
    exe, source, destination, sha = _prepare(tmp_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(b"pre-existing")

    with pytest.raises(NetReactorSlayerError) as excinfo:
        run_net_reactor_slayer(exe, source, destination, input_sha256=sha)

    assert excinfo.value.code == NetReactorSlayerErrorCode.INVALID_ARGUMENT
    # An existing destination must be left untouched, not clobbered or deleted.
    assert destination.read_bytes() == b"pre-existing"


def test_probe_reports_absent_for_a_missing_executable(tmp_path: Path) -> None:
    ok, text = nrs_mod.probe_net_reactor_slayer(tmp_path / "nope.exe")
    assert ok is False
    assert text == ""


@pytest.mark.skipif(os.name == "nt", reason="POSIX shell stand-in for the CLI")
def test_probe_recognizes_usage_output(tmp_path: Path) -> None:
    exe = tmp_path / "nrs-stub.sh"
    exe.write_text(
        "#!/bin/sh\necho 'NETReactorSlayer.CLI assemblyPath --no-pause True'\n"
    )
    exe.chmod(0o755)

    ok, text = nrs_mod.probe_net_reactor_slayer(exe)

    assert ok is True
    assert "netreactorslayer" in text.casefold()
