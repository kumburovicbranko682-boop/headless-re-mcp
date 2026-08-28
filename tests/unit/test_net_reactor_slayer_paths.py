"""Guard branches, the success path and the help probe of the NRS adapter.

test_dotnet_net_reactor_slayer.py drives the cancel/remap seams, the service
passthrough and the doctor-missing probe. This file exercises every argument
guard, the input-mutation and output-limit / process-failure envelopes, the
best-effort *_Slayed discovery, and the happy path -- all against a fake
``_capture_process`` so nothing external launches.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.common.bounded_run import Completed, TimedOut
from headless_re_mcp.core.session import file_sha256
from headless_re_mcp.dotnet import net_reactor_slayer as nrs_mod
from headless_re_mcp.dotnet.de4dot import _ProcessCapture
from headless_re_mcp.dotnet.net_reactor_slayer import (
    NetReactorSlayerError,
    NetReactorSlayerErrorCode,
    probe_net_reactor_slayer,
    run_net_reactor_slayer,
)


def _inputs(
    tmp_path: Path, *, contents: bytes = b"managed-assembly-bytes"
) -> tuple[Path, Path, Path, str]:
    exe = tmp_path / "NETReactorSlayer.CLI.exe"
    exe.write_bytes(b"placeholder")
    source = tmp_path / "managed.exe"
    source.write_bytes(contents)
    destination = tmp_path / "out" / "slayed.exe"
    return exe, source, destination, file_sha256(source)


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


def _fake_capture(
    monkeypatch: pytest.MonkeyPatch,
    capture: _ProcessCapture,
    *,
    slayed_name: str | None = "managed_Slayed.exe",
    mutate_source: Path | None = None,
) -> None:
    """Patch ``_capture_process`` to act like a successful tool run.

    It writes the requested ``*_Slayed`` file into the work dir (the copy's
    parent), optionally mutating the still-referenced original, then returns
    the supplied capture so the caller's guard branches can be reached.
    """

    def runner(argv: list[str], **kwargs: Any) -> _ProcessCapture:
        work_input = Path(argv[1])
        if slayed_name is not None:
            (work_input.parent / slayed_name).write_bytes(b"slayed-bytes")
        if mutate_source is not None:
            mutate_source.write_bytes(b"tampered")
        return capture

    monkeypatch.setattr(nrs_mod, "_capture_process", runner)


# --- argument guards ------------------------------------------------------------


def test_a_missing_executable_is_reported(tmp_path: Path) -> None:
    _, source, destination, sha = _inputs(tmp_path)

    with pytest.raises(NetReactorSlayerError) as caught:
        run_net_reactor_slayer(tmp_path / "gone.exe", source, destination, input_sha256=sha)

    assert caught.value.code == NetReactorSlayerErrorCode.EXECUTABLE_NOT_FOUND


def test_an_oversized_input_is_refused(tmp_path: Path) -> None:
    exe, source, destination, sha = _inputs(tmp_path)

    with pytest.raises(NetReactorSlayerError) as caught:
        run_net_reactor_slayer(exe, source, destination, input_sha256=sha, max_file_size=4)

    assert caught.value.code == NetReactorSlayerErrorCode.INPUT_TOO_LARGE


def test_an_existing_output_is_refused(tmp_path: Path) -> None:
    exe, source, destination, sha = _inputs(tmp_path)
    destination.parent.mkdir(parents=True)
    destination.write_bytes(b"already here")

    with pytest.raises(NetReactorSlayerError) as caught:
        run_net_reactor_slayer(exe, source, destination, input_sha256=sha)

    assert caught.value.code == NetReactorSlayerErrorCode.INVALID_ARGUMENT
    assert "already exist" in str(caught.value)


def test_an_input_that_is_not_a_file_is_refused(tmp_path: Path) -> None:
    exe = tmp_path / "NETReactorSlayer.CLI.exe"
    exe.write_bytes(b"placeholder")
    source_dir = tmp_path / "managed"  # resolves strict, but is a directory
    source_dir.mkdir()

    with pytest.raises(NetReactorSlayerError) as caught:
        run_net_reactor_slayer(exe, source_dir, tmp_path / "out.exe", input_sha256="0" * 64)

    assert caught.value.code == NetReactorSlayerErrorCode.INPUT_NOT_FOUND


def test_output_equal_to_input_is_refused(tmp_path: Path) -> None:
    exe, source, _, sha = _inputs(tmp_path)
    # A dot-dot spelling that resolves onto the source must be rejected. On
    # POSIX exists() fails on the missing "nope" component, so the alias slips
    # past the "must not exist" guard and the "must differ from input" guard
    # fires. Windows collapses the ".." lexically before the stat, so the same
    # spelling stats as the existing source and the "must not already exist"
    # guard fires first. Either rejection is correct; assert the shared
    # INVALID_ARGUMENT code and accept either guard's message.
    aliased = tmp_path / "nope" / ".." / "managed.exe"

    with pytest.raises(NetReactorSlayerError) as caught:
        run_net_reactor_slayer(exe, source, aliased, input_sha256=sha)

    assert caught.value.code == NetReactorSlayerErrorCode.INVALID_ARGUMENT
    message = str(caught.value)
    assert "differ from input" in message or "must not already exist" in message


def test_a_sha_that_changed_before_the_run_is_refused(tmp_path: Path) -> None:
    exe, source, destination, _ = _inputs(tmp_path)

    with pytest.raises(NetReactorSlayerError) as caught:
        run_net_reactor_slayer(exe, source, destination, input_sha256="0" * 64)

    assert caught.value.code == NetReactorSlayerErrorCode.INPUT_MUTATED
    assert caught.value.details["expected"] == "0" * 64


# --- post-run guards ------------------------------------------------------------


def test_a_mutated_original_after_the_run_is_reported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exe, source, destination, sha = _inputs(tmp_path)
    _fake_capture(monkeypatch, _capture(), mutate_source=source)

    with pytest.raises(NetReactorSlayerError) as caught:
        run_net_reactor_slayer(exe, source, destination, input_sha256=sha)

    assert caught.value.code == NetReactorSlayerErrorCode.INPUT_MUTATED
    assert not destination.exists()  # cleanup removed any partial output


def test_an_output_limit_overrun_is_reported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exe, source, destination, sha = _inputs(tmp_path)
    _fake_capture(monkeypatch, _capture(stdout_exceeded=True))

    with pytest.raises(NetReactorSlayerError) as caught:
        run_net_reactor_slayer(exe, source, destination, input_sha256=sha)

    assert caught.value.code == NetReactorSlayerErrorCode.OUTPUT_LIMIT


def test_a_nonzero_exit_is_a_retryable_process_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exe, source, destination, sha = _inputs(tmp_path)
    _fake_capture(monkeypatch, _capture(returncode=3, stderr="crashed"))

    with pytest.raises(NetReactorSlayerError) as caught:
        run_net_reactor_slayer(exe, source, destination, input_sha256=sha)

    assert caught.value.code == NetReactorSlayerErrorCode.PROCESS_FAILED
    assert caught.value.returncode == 3
    assert caught.value.retryable is True
    assert caught.value.details["argv"][0] == "NETReactorSlayer"


def test_success_without_the_slayed_output_is_reported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exe, source, destination, sha = _inputs(tmp_path)
    _fake_capture(monkeypatch, _capture(), slayed_name=None)

    with pytest.raises(NetReactorSlayerError) as caught:
        run_net_reactor_slayer(exe, source, destination, input_sha256=sha)

    assert caught.value.code == NetReactorSlayerErrorCode.OUTPUT_MISSING


# --- success paths --------------------------------------------------------------


def test_the_default_named_slayed_output_is_published(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exe, source, destination, sha = _inputs(tmp_path)
    _fake_capture(monkeypatch, _capture(stdout="Saved managed_Slayed.exe"))

    result = run_net_reactor_slayer(exe, source, destination, input_sha256=sha)

    assert destination.is_file()
    assert destination.read_bytes() == b"slayed-bytes"
    payload = result.to_dict()
    assert payload["source"] == nrs_mod.NRS_SOURCE
    assert payload["claims_universal_unpack"] is False
    assert payload["output_sha256"] == file_sha256(destination)
    assert result.input_sha256 == sha


def test_a_failure_after_publishing_removes_the_partial_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The finally-cleanup unlinks a published output when a late guard raises.

    file_sha256 runs three times (input before, input after, output). We let the
    two input reads succeed and make the output read raise the adapter error, so
    the copied destination exists when the except-arm reaches its unlink.
    """
    import headless_re_mcp.core.session as session_mod

    exe, source, destination, sha = _inputs(tmp_path)
    _fake_capture(monkeypatch, _capture())
    real_sha = session_mod.file_sha256
    seen: list[Path] = []

    def flaky_sha(path: Path) -> str:
        seen.append(Path(path))
        if len(seen) == 3:
            raise NetReactorSlayerError(
                NetReactorSlayerErrorCode.OUTPUT_MISSING, "output vanished mid-hash"
            )
        return real_sha(path)

    monkeypatch.setattr(session_mod, "file_sha256", flaky_sha)

    with pytest.raises(NetReactorSlayerError):
        run_net_reactor_slayer(exe, source, destination, input_sha256=sha)

    assert not destination.exists()  # the partial publish was cleaned up


def test_a_differently_named_lone_slayed_file_is_accepted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exe, source, destination, sha = _inputs(tmp_path)
    # The exact stem file is absent, but a single *_Slayed* candidate exists.
    _fake_capture(monkeypatch, _capture(), slayed_name="managed_Slayed_x64.dll")

    result = run_net_reactor_slayer(exe, source, destination, input_sha256=sha)

    assert result.output_path == str(destination.resolve())
    assert destination.is_file()


# --- help probe -----------------------------------------------------------------


def test_probe_returns_false_when_the_executable_is_absent(tmp_path: Path) -> None:
    assert probe_net_reactor_slayer(tmp_path / "gone.exe") == (False, "")


def test_probe_returns_false_when_the_tool_will_not_start(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exe = tmp_path / "nrs.exe"
    exe.write_bytes(b"x")

    def unlaunchable(cmd: list[str], **kwargs: Any) -> Any:
        raise OSError("exec format error")

    monkeypatch.setattr(nrs_mod, "run_bounded", unlaunchable)

    assert probe_net_reactor_slayer(exe) == (False, "")


def test_probe_recognizes_the_tool_banner(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    exe = tmp_path / "nrs.exe"
    exe.write_bytes(b"x")
    monkeypatch.setattr(
        nrs_mod,
        "run_bounded",
        lambda cmd, **kwargs: Completed(1, b"NETReactorSlayer 1.0", b""),
    )

    ok, text = probe_net_reactor_slayer(exe)

    assert ok is True
    assert "NETReactorSlayer" in text


def test_probe_accepts_a_usage_banner_from_a_nonzero_exit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exe = tmp_path / "nrs.exe"
    exe.write_bytes(b"x")
    monkeypatch.setattr(
        nrs_mod,
        "run_bounded",
        lambda cmd, **kwargs: Completed(1, b"", b"Usage: run <file>"),
    )

    ok, text = probe_net_reactor_slayer(exe)

    assert ok is True
    assert "Usage" in text


def test_probe_reports_unrecognized_output_as_present_but_unverified(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exe = tmp_path / "nrs.exe"
    exe.write_bytes(b"x")
    monkeypatch.setattr(
        nrs_mod,
        "run_bounded",
        lambda cmd, **kwargs: Completed(2, b"garbage output", b""),
    )

    ok, text = probe_net_reactor_slayer(exe)

    assert ok is True  # non-empty text, but no recognized banner
    assert text == "garbage output"


def test_probe_reports_empty_output_as_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exe = tmp_path / "nrs.exe"
    exe.write_bytes(b"x")
    monkeypatch.setattr(nrs_mod, "run_bounded", lambda cmd, **kwargs: Completed(0, b"", b""))

    assert probe_net_reactor_slayer(exe) == (False, "")


def test_probe_treats_a_timeout_as_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exe = tmp_path / "nrs.exe"
    exe.write_bytes(b"x")

    def timing_out(cmd: list[str], **kwargs: Any) -> Any:
        raise TimedOut(timeout=5.0, killed=[])

    monkeypatch.setattr(nrs_mod, "run_bounded", timing_out)

    assert probe_net_reactor_slayer(exe) == (False, "")
