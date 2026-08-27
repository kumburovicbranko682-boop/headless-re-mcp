"""Pre-flight guards, the publish path, and the help probe of the NETReactorSlayer adapter.

The sibling ``test_dotnet_net_reactor_slayer.py`` pins the cancel/remap seam and
the service wiring; this covers the argument-validation envelope each bad input
maps to, the full work-copy -> ``*_Slayed`` -> publish path driven by a fake
``_capture_process`` that writes the output the tool would, the honesty branches
after the process returns (a mutated original, a blown output bound, a non-zero
exit, a missing artifact), and the usage-sniffing ``probe`` -- all without a real
NETReactorSlayer binary, since the value here is the envelope, not the tool.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from headless_re_mcp.backends.common.bounded_run import TimedOut
from headless_re_mcp.core.session import file_sha256
from headless_re_mcp.dotnet import net_reactor_slayer as nrs_mod
from headless_re_mcp.dotnet.de4dot import _ProcessCapture
from headless_re_mcp.dotnet.net_reactor_slayer import (
    NetReactorSlayerError,
    NetReactorSlayerErrorCode,
    probe_net_reactor_slayer,
    run_net_reactor_slayer,
)


def _inputs(tmp_path: Path) -> tuple[Path, Path, Path, str]:
    exe = tmp_path / "NETReactorSlayer.CLI.exe"
    exe.write_bytes(b"placeholder")
    source = tmp_path / "managed.exe"
    source.write_bytes(b"managed-assembly-bytes")
    destination = tmp_path / "out" / "slayed.exe"
    return exe, source, destination, file_sha256(source)


def _clean_capture(returncode: int = 0) -> _ProcessCapture:
    return _ProcessCapture(
        stdout="done",
        stderr="",
        returncode=returncode,
        stdout_exceeded=False,
        stderr_exceeded=False,
    )


# ---------------------------------------------------------------------------
# pre-flight guards
# ---------------------------------------------------------------------------
def test_missing_executable_is_reported(tmp_path: Path) -> None:
    _, source, destination, sha = _inputs(tmp_path)
    with pytest.raises(NetReactorSlayerError) as caught:
        run_net_reactor_slayer(
            tmp_path / "absent.exe", source, destination, input_sha256=sha
        )
    assert caught.value.code == NetReactorSlayerErrorCode.EXECUTABLE_NOT_FOUND


def test_a_directory_input_is_not_a_file(tmp_path: Path) -> None:
    exe, _, destination, _ = _inputs(tmp_path)
    a_dir = tmp_path / "adir"
    a_dir.mkdir()
    with pytest.raises(NetReactorSlayerError) as caught:
        run_net_reactor_slayer(exe, a_dir, destination, input_sha256="0" * 64)
    assert caught.value.code == NetReactorSlayerErrorCode.INPUT_NOT_FOUND


def test_oversized_input_is_refused(tmp_path: Path) -> None:
    exe, source, destination, sha = _inputs(tmp_path)
    with pytest.raises(NetReactorSlayerError) as caught:
        run_net_reactor_slayer(
            exe, source, destination, input_sha256=sha, max_file_size=1
        )
    assert caught.value.code == NetReactorSlayerErrorCode.INPUT_TOO_LARGE


def test_an_existing_destination_is_refused(tmp_path: Path) -> None:
    exe, source, destination, sha = _inputs(tmp_path)
    destination.parent.mkdir(parents=True)
    destination.write_bytes(b"do not clobber")
    with pytest.raises(NetReactorSlayerError) as caught:
        run_net_reactor_slayer(exe, source, destination, input_sha256=sha)
    assert caught.value.code == NetReactorSlayerErrorCode.INVALID_ARGUMENT


def test_destination_equal_to_input_is_refused(tmp_path: Path) -> None:
    exe, source, _, sha = _inputs(tmp_path)
    with pytest.raises(NetReactorSlayerError) as caught:
        run_net_reactor_slayer(exe, source, source, input_sha256=sha)
    assert caught.value.code == NetReactorSlayerErrorCode.INVALID_ARGUMENT


def test_a_changed_input_sha_before_run_is_refused(tmp_path: Path) -> None:
    exe, source, destination, _ = _inputs(tmp_path)
    with pytest.raises(NetReactorSlayerError) as caught:
        run_net_reactor_slayer(exe, source, destination, input_sha256="dead" * 16)
    assert caught.value.code == NetReactorSlayerErrorCode.INPUT_MUTATED


# ---------------------------------------------------------------------------
# publish path and post-process honesty
# ---------------------------------------------------------------------------
def test_happy_path_publishes_the_slayed_artifact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exe, source, destination, sha = _inputs(tmp_path)

    def fake_capture(argv: list[str], **kwargs: Any) -> _ProcessCapture:
        work_input = Path(argv[1])
        slayed = work_input.with_name(f"{work_input.stem}_Slayed{work_input.suffix}")
        slayed.write_bytes(b"deobfuscated-bytes")
        return _clean_capture()

    monkeypatch.setattr(nrs_mod, "_capture_process", fake_capture)
    result = run_net_reactor_slayer(exe, source, destination, input_sha256=sha)
    assert destination.is_file()
    assert destination.read_bytes() == b"deobfuscated-bytes"
    assert result.output_sha256 == file_sha256(destination)
    assert result.input_sha256 == sha
    payload = result.to_dict()
    assert payload["claims_universal_unpack"] is False
    assert payload["source"] == nrs_mod.NRS_SOURCE


def test_slayed_output_is_found_by_glob_fallback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exe, source, destination, sha = _inputs(tmp_path)

    def fake_capture(argv: list[str], **kwargs: Any) -> _ProcessCapture:
        # A build that names the artifact differently but still tags it _Slayed;
        # the exact-name lookup misses and the single-candidate glob recovers it.
        work_input = Path(argv[1])
        (work_input.parent / "Renamed_Slayed_final.exe").write_bytes(b"x")
        return _clean_capture()

    monkeypatch.setattr(nrs_mod, "_capture_process", fake_capture)
    result = run_net_reactor_slayer(exe, source, destination, input_sha256=sha)
    assert destination.is_file()
    assert result.returncode == 0


def test_missing_slayed_output_is_reported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exe, source, destination, sha = _inputs(tmp_path)
    monkeypatch.setattr(nrs_mod, "_capture_process", lambda *a, **k: _clean_capture())
    with pytest.raises(NetReactorSlayerError) as caught:
        run_net_reactor_slayer(exe, source, destination, input_sha256=sha)
    assert caught.value.code == NetReactorSlayerErrorCode.OUTPUT_MISSING
    # A failed run must not leave a phantom destination behind.
    assert not destination.exists()


def test_a_mutated_original_after_run_is_reported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exe, source, destination, sha = _inputs(tmp_path)

    def mutate(argv: list[str], **kwargs: Any) -> _ProcessCapture:
        source.write_bytes(b"the tool rewrote the original")
        return _clean_capture()

    monkeypatch.setattr(nrs_mod, "_capture_process", mutate)
    with pytest.raises(NetReactorSlayerError) as caught:
        run_net_reactor_slayer(exe, source, destination, input_sha256=sha)
    assert caught.value.code == NetReactorSlayerErrorCode.INPUT_MUTATED


def test_a_blown_output_bound_is_reported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exe, source, destination, sha = _inputs(tmp_path)
    capped = _ProcessCapture(
        stdout="x", stderr="", returncode=0, stdout_exceeded=True, stderr_exceeded=False
    )
    monkeypatch.setattr(nrs_mod, "_capture_process", lambda *a, **k: capped)
    with pytest.raises(NetReactorSlayerError) as caught:
        run_net_reactor_slayer(exe, source, destination, input_sha256=sha)
    assert caught.value.code == NetReactorSlayerErrorCode.OUTPUT_LIMIT


def test_a_nonzero_exit_is_reported_and_retryable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exe, source, destination, sha = _inputs(tmp_path)
    monkeypatch.setattr(nrs_mod, "_capture_process", lambda *a, **k: _clean_capture(2))
    with pytest.raises(NetReactorSlayerError) as caught:
        run_net_reactor_slayer(exe, source, destination, input_sha256=sha)
    assert caught.value.code == NetReactorSlayerErrorCode.PROCESS_FAILED
    assert caught.value.returncode == 2
    assert caught.value.retryable is True


# ---------------------------------------------------------------------------
# help probe
# ---------------------------------------------------------------------------
def test_probe_returns_false_without_an_executable(tmp_path: Path) -> None:
    ok, text = probe_net_reactor_slayer(tmp_path / "nope.exe")
    assert ok is False
    assert text == ""


def test_probe_is_false_when_the_launch_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exe = tmp_path / "NETReactorSlayer.CLI.exe"
    exe.write_bytes(b"x")

    def boom(*args: Any, **kwargs: Any) -> Any:
        raise TimedOut(5.0, [])

    monkeypatch.setattr(nrs_mod, "run_bounded", boom)
    ok, text = probe_net_reactor_slayer(exe)
    assert ok is False
    assert text == ""


def test_probe_recognises_the_tool_banner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exe = tmp_path / "NETReactorSlayer.CLI.exe"
    exe.write_bytes(b"x")
    monkeypatch.setattr(
        nrs_mod,
        "run_bounded",
        lambda *a, **k: SimpleNamespace(
            stdout=b"NETReactorSlayer 1.0 assemblyPath --no-pause", stderr=b"", returncode=1
        ),
    )
    ok, text = probe_net_reactor_slayer(exe)
    assert ok is True
    assert "NETReactorSlayer" in text


def test_probe_accepts_a_bare_usage_banner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exe = tmp_path / "NETReactorSlayer.CLI.exe"
    exe.write_bytes(b"x")
    monkeypatch.setattr(
        nrs_mod,
        "run_bounded",
        lambda *a, **k: SimpleNamespace(stdout=b"Usage: <input>", stderr=b"", returncode=1),
    )
    ok, text = probe_net_reactor_slayer(exe)
    assert ok is True
    assert "Usage" in text


def test_probe_falls_back_to_any_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exe = tmp_path / "NETReactorSlayer.CLI.exe"
    exe.write_bytes(b"x")
    monkeypatch.setattr(
        nrs_mod,
        "run_bounded",
        lambda *a, **k: SimpleNamespace(stdout=b"something unrelated", stderr=b"", returncode=3),
    )
    ok, text = probe_net_reactor_slayer(exe)
    assert ok is True
    assert text == "something unrelated"

    monkeypatch.setattr(
        nrs_mod,
        "run_bounded",
        lambda *a, **k: SimpleNamespace(stdout=b"", stderr=b"", returncode=3),
    )
    empty_ok, empty_text = probe_net_reactor_slayer(exe)
    assert empty_ok is False
    assert empty_text == ""
