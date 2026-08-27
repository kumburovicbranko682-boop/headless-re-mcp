"""Path coverage for the NETReactorSlayer adapter (``dotnet/net_reactor_slayer``).

``test_dotnet_net_reactor_slayer.py`` pins the cancel/remap arcs around
``_capture_process`` and a service-level success that swaps the whole runner.
Left uncovered were ``run_net_reactor_slayer``'s own input validation, the
post-run integrity/limit/exit guards, the ``*_Slayed`` discovery fallbacks, the
happy path that publishes the output, the failure cleanup, and every branch of
``probe_net_reactor_slayer``. These drive those with a faked capture and a faked
bounded run so no real CLI is needed.

Not exercised: the ``output_path == input_path`` guard (line 139-140). An
existing input always makes the earlier ``destination.exists()`` check fire
first, so that arc is unreachable through the public function on this platform.
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


def _prepare(tmp_path: Path) -> tuple[Path, Path, Path, str]:
    exe = tmp_path / "NETReactorSlayer.CLI.exe"
    exe.write_bytes(b"placeholder")
    source = tmp_path / "managed.exe"
    source.write_bytes(b"managed-assembly-bytes")
    destination = tmp_path / "out" / "slayed.exe"
    return exe, source, destination, file_sha256(source)


def _capture(**overrides: Any) -> _ProcessCapture:
    fields: dict[str, Any] = {
        "stdout": "ok",
        "stderr": "",
        "returncode": 0,
        "stdout_exceeded": False,
        "stderr_exceeded": False,
    }
    fields.update(overrides)
    return _ProcessCapture(**fields)


def test_missing_executable_is_rejected(tmp_path: Path) -> None:
    _, source, destination, sha = _prepare(tmp_path)
    missing = tmp_path / "nope.exe"
    with pytest.raises(NetReactorSlayerError) as excinfo:
        run_net_reactor_slayer(missing, source, destination, input_sha256=sha)
    assert excinfo.value.code == NetReactorSlayerErrorCode.EXECUTABLE_NOT_FOUND


def test_non_file_input_is_rejected(tmp_path: Path) -> None:
    """A directory resolves but is not a file, so it is the input-not-found arc."""
    exe, _, destination, _ = _prepare(tmp_path)
    a_dir = tmp_path / "adir"
    a_dir.mkdir()
    with pytest.raises(NetReactorSlayerError) as excinfo:
        run_net_reactor_slayer(exe, a_dir, destination, input_sha256="")
    assert excinfo.value.code == NetReactorSlayerErrorCode.INPUT_NOT_FOUND


def test_oversize_input_is_rejected(tmp_path: Path) -> None:
    exe, source, destination, sha = _prepare(tmp_path)
    with pytest.raises(NetReactorSlayerError) as excinfo:
        run_net_reactor_slayer(
            exe, source, destination, input_sha256=sha, max_file_size=1
        )
    assert excinfo.value.code == NetReactorSlayerErrorCode.INPUT_TOO_LARGE


def test_preexisting_output_is_rejected(tmp_path: Path) -> None:
    exe, source, destination, sha = _prepare(tmp_path)
    destination.parent.mkdir(parents=True)
    destination.write_bytes(b"already here")
    with pytest.raises(NetReactorSlayerError) as excinfo:
        run_net_reactor_slayer(exe, source, destination, input_sha256=sha)
    assert excinfo.value.code == NetReactorSlayerErrorCode.INVALID_ARGUMENT


def test_input_sha_changed_before_run_is_rejected(tmp_path: Path) -> None:
    exe, source, destination, _ = _prepare(tmp_path)
    with pytest.raises(NetReactorSlayerError) as excinfo:
        run_net_reactor_slayer(exe, source, destination, input_sha256="0" * 64)
    assert excinfo.value.code == NetReactorSlayerErrorCode.INPUT_MUTATED


def test_input_mutated_during_run_is_rejected(
    tmp_path: Path, monkeypatch: Any
) -> None:
    exe, source, destination, sha = _prepare(tmp_path)

    def mutate(argv: list[str], *, timeout: float, max_output_size: int) -> _ProcessCapture:
        source.write_bytes(b"tampered-after-copy")
        return _capture()

    monkeypatch.setattr(nrs_mod, "_capture_process", mutate)
    with pytest.raises(NetReactorSlayerError) as excinfo:
        run_net_reactor_slayer(exe, source, destination, input_sha256=sha)
    assert excinfo.value.code == NetReactorSlayerErrorCode.INPUT_MUTATED


def test_output_limit_is_reported(tmp_path: Path, monkeypatch: Any) -> None:
    exe, source, destination, sha = _prepare(tmp_path)

    def capped(argv: list[str], *, timeout: float, max_output_size: int) -> _ProcessCapture:
        return _capture(stdout_exceeded=True)

    monkeypatch.setattr(nrs_mod, "_capture_process", capped)
    with pytest.raises(NetReactorSlayerError) as excinfo:
        run_net_reactor_slayer(exe, source, destination, input_sha256=sha)
    assert excinfo.value.code == NetReactorSlayerErrorCode.OUTPUT_LIMIT


def test_nonzero_exit_cleans_up_a_stray_output(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A failing run whose output path was already written must be swept away.

    Exit-code failure raises before the copy step, so the only way ``destination``
    is present is a residue; the failure handler unlinks it. The fake writes
    ``destination`` and fails to drive that cleanup arc.
    """
    exe, source, destination, sha = _prepare(tmp_path)

    def failing(argv: list[str], *, timeout: float, max_output_size: int) -> _ProcessCapture:
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(b"stray-residue")
        return _capture(returncode=3)

    monkeypatch.setattr(nrs_mod, "_capture_process", failing)
    with pytest.raises(NetReactorSlayerError) as excinfo:
        run_net_reactor_slayer(exe, source, destination, input_sha256=sha)
    assert excinfo.value.code == NetReactorSlayerErrorCode.PROCESS_FAILED
    assert excinfo.value.returncode == 3
    assert not destination.exists()


def test_missing_slayed_output_is_reported(
    tmp_path: Path, monkeypatch: Any
) -> None:
    exe, source, destination, sha = _prepare(tmp_path)

    def no_output(argv: list[str], *, timeout: float, max_output_size: int) -> _ProcessCapture:
        return _capture()

    monkeypatch.setattr(nrs_mod, "_capture_process", no_output)
    with pytest.raises(NetReactorSlayerError) as excinfo:
        run_net_reactor_slayer(exe, source, destination, input_sha256=sha)
    assert excinfo.value.code == NetReactorSlayerErrorCode.OUTPUT_MISSING


def test_slayed_output_recovered_from_single_candidate(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """The exact ``{stem}_Slayed`` name is absent but one ``*_Slayed*`` remains."""
    exe, source, destination, sha = _prepare(tmp_path)

    def odd_name(argv: list[str], *, timeout: float, max_output_size: int) -> _ProcessCapture:
        work_input = Path(argv[1])
        odd = work_input.with_name(f"unexpected{nrs_mod._SLAYED_SUFFIX}Name.bin")
        odd.write_bytes(b"recovered-output")
        return _capture()

    monkeypatch.setattr(nrs_mod, "_capture_process", odd_name)
    result = run_net_reactor_slayer(exe, source, destination, input_sha256=sha)
    assert destination.is_file()
    assert destination.read_bytes() == b"recovered-output"
    assert result.output_sha256 == file_sha256(destination)


def test_successful_run_publishes_the_slayed_output(
    tmp_path: Path, monkeypatch: Any
) -> None:
    exe, source, destination, sha = _prepare(tmp_path)

    def produce(argv: list[str], *, timeout: float, max_output_size: int) -> _ProcessCapture:
        work_input = Path(argv[1])
        slayed = work_input.with_name(
            f"{work_input.stem}{nrs_mod._SLAYED_SUFFIX}{work_input.suffix}"
        )
        slayed.write_bytes(b"deobfuscated")
        return _capture(stdout="Saved to managed_Slayed.exe")

    monkeypatch.setattr(nrs_mod, "_capture_process", produce)
    result = run_net_reactor_slayer(exe, source, destination, input_sha256=sha)
    assert result.returncode == 0
    assert result.input_sha256 == sha
    assert Path(result.output_path).read_bytes() == b"deobfuscated"
    payload = result.to_dict()
    assert payload["source"] == nrs_mod.NRS_SOURCE
    assert payload["claims_universal_unpack"] is False


def test_probe_missing_executable_returns_false(tmp_path: Path) -> None:
    ok, text = probe_net_reactor_slayer(tmp_path / "absent.exe")
    assert ok is False
    assert text == ""


def test_probe_swallows_a_bounded_failure(tmp_path: Path, monkeypatch: Any) -> None:
    exe = tmp_path / "NETReactorSlayer.CLI.exe"
    exe.write_bytes(b"placeholder")

    def boom(cmd: list[str], *, timeout: float, creationflags: int = 0) -> Completed:
        raise TimedOut(timeout, [])

    monkeypatch.setattr(nrs_mod, "run_bounded", boom)
    ok, text = probe_net_reactor_slayer(exe)
    assert ok is False
    assert text == ""


def test_probe_recognizes_the_tool_banner(tmp_path: Path, monkeypatch: Any) -> None:
    exe = tmp_path / "NETReactorSlayer.CLI.exe"
    exe.write_bytes(b"placeholder")

    def banner(cmd: list[str], *, timeout: float, creationflags: int = 0) -> Completed:
        return Completed(returncode=1, stdout=b"NETReactorSlayer 1.0", stderr=b"")

    monkeypatch.setattr(nrs_mod, "run_bounded", banner)
    ok, text = probe_net_reactor_slayer(exe)
    assert ok is True
    assert "NETReactorSlayer" in text


def test_probe_accepts_a_usage_dump_without_the_banner(
    tmp_path: Path, monkeypatch: Any
) -> None:
    exe = tmp_path / "NETReactorSlayer.CLI.exe"
    exe.write_bytes(b"placeholder")

    def usage(cmd: list[str], *, timeout: float, creationflags: int = 0) -> Completed:
        return Completed(returncode=1, stdout=b"", stderr=b"Usage: run <input>")

    monkeypatch.setattr(nrs_mod, "run_bounded", usage)
    ok, text = probe_net_reactor_slayer(exe)
    assert ok is True
    assert "Usage" in text


def test_probe_reports_unrecognized_output_by_its_text(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """Neither a banner nor a usage dump, but there is output, so it is text-truthy."""
    exe = tmp_path / "NETReactorSlayer.CLI.exe"
    exe.write_bytes(b"placeholder")

    def other(cmd: list[str], *, timeout: float, creationflags: int = 0) -> Completed:
        return Completed(returncode=2, stdout=b"unrelated diagnostic", stderr=b"")

    monkeypatch.setattr(nrs_mod, "run_bounded", other)
    ok, text = probe_net_reactor_slayer(exe)
    assert ok is True
    assert text == "unrelated diagnostic"
