"""Guard, execution and probe paths of the NETReactorSlayer adapter.

The existing suite covers the service happy path (whole runner faked) and the
cancel/remap arms. This drives ``run_net_reactor_slayer`` itself: the argv/size
guards, the post-run integrity checks (input mutated, output bound, nonzero
exit, missing ``*_Slayed`` output), the ``*_Slayed`` publish including the glob
fallback, and the capability probe. The process is faked by swapping
``_capture_process`` (which also fabricates the tool's output file), so no
NETReactorSlayer binary is needed.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.common.bounded_run import Completed
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


def _make_capture(**opts: Any) -> Any:
    """A fake _capture_process that fabricates the tool's *_Slayed output."""

    def _cap(argv: list[str], *, timeout: float, max_output_size: int) -> _ProcessCapture:
        work_input = Path(argv[1])
        work_dir = work_input.parent
        if opts.get("write_slayed", True):
            name = opts.get("slayed_name") or (
                f"{work_input.stem}{nrs_mod._SLAYED_SUFFIX}{work_input.suffix}"
            )
            (work_dir / name).write_bytes(b"deobfuscated-bytes")
        mutate = opts.get("mutate_source")
        if mutate is not None:
            Path(mutate).write_bytes(b"mutated-after-run")
        return _ProcessCapture(
            stdout=opts.get("stdout", "done"),
            stderr=opts.get("stderr", ""),
            returncode=opts.get("returncode", 0),
            stdout_exceeded=opts.get("stdout_exceeded", False),
            stderr_exceeded=opts.get("stderr_exceeded", False),
        )

    return _cap


# ---------------------------------------------------------------------------
# argv / input guards


def test_missing_executable_is_rejected(tmp_path: Path) -> None:
    _exe, source, destination, sha = _inputs(tmp_path)

    with pytest.raises(NetReactorSlayerError) as caught:
        run_net_reactor_slayer(tmp_path / "gone.exe", source, destination, input_sha256=sha)

    assert caught.value.code == NetReactorSlayerErrorCode.EXECUTABLE_NOT_FOUND


def test_a_directory_input_is_not_found(tmp_path: Path) -> None:
    exe, _source, destination, _sha = _inputs(tmp_path)
    a_dir = tmp_path / "adir"
    a_dir.mkdir()

    with pytest.raises(NetReactorSlayerError) as caught:
        run_net_reactor_slayer(exe, a_dir, destination, input_sha256="0" * 64)

    assert caught.value.code == NetReactorSlayerErrorCode.INPUT_NOT_FOUND


def test_oversize_input_is_rejected(tmp_path: Path) -> None:
    exe, source, destination, sha = _inputs(tmp_path)

    with pytest.raises(NetReactorSlayerError) as caught:
        run_net_reactor_slayer(
            exe, source, destination, input_sha256=sha, max_file_size=0
        )

    assert caught.value.code == NetReactorSlayerErrorCode.INPUT_TOO_LARGE


def test_a_preexisting_destination_is_rejected(tmp_path: Path) -> None:
    exe, source, destination, sha = _inputs(tmp_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(b"already here")

    with pytest.raises(NetReactorSlayerError) as caught:
        run_net_reactor_slayer(exe, source, destination, input_sha256=sha)

    assert caught.value.code == NetReactorSlayerErrorCode.INVALID_ARGUMENT


def test_a_changed_input_sha_is_rejected(tmp_path: Path) -> None:
    exe, source, destination, _sha = _inputs(tmp_path)

    with pytest.raises(NetReactorSlayerError) as caught:
        run_net_reactor_slayer(exe, source, destination, input_sha256="f" * 64)

    assert caught.value.code == NetReactorSlayerErrorCode.INPUT_MUTATED


# ---------------------------------------------------------------------------
# execution body


def test_run_publishes_the_slayed_output(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    exe, source, destination, sha = _inputs(tmp_path)
    monkeypatch.setattr(nrs_mod, "_capture_process", _make_capture())

    result = run_net_reactor_slayer(exe, source, destination, input_sha256=sha)

    assert result.returncode == 0
    assert Path(result.output_path).is_file()
    assert result.to_dict()["claims_universal_unpack"] is False
    assert result.to_dict()["target"] == "authorized_reactor_samples_only"


def test_run_accepts_a_glob_matched_slayed_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exe, source, destination, sha = _inputs(tmp_path)
    monkeypatch.setattr(
        nrs_mod, "_capture_process", _make_capture(slayed_name="managed_Slayed_final.exe")
    )

    result = run_net_reactor_slayer(exe, source, destination, input_sha256=sha)

    assert Path(result.output_path).is_file()


def test_run_flags_an_input_mutated_by_the_tool(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exe, source, destination, sha = _inputs(tmp_path)
    monkeypatch.setattr(nrs_mod, "_capture_process", _make_capture(mutate_source=source))

    with pytest.raises(NetReactorSlayerError) as caught:
        run_net_reactor_slayer(exe, source, destination, input_sha256=sha)

    assert caught.value.code == NetReactorSlayerErrorCode.INPUT_MUTATED


def test_run_flags_an_output_bound_breach(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exe, source, destination, sha = _inputs(tmp_path)
    monkeypatch.setattr(nrs_mod, "_capture_process", _make_capture(stdout_exceeded=True))

    with pytest.raises(NetReactorSlayerError) as caught:
        run_net_reactor_slayer(exe, source, destination, input_sha256=sha)

    assert caught.value.code == NetReactorSlayerErrorCode.OUTPUT_LIMIT


def test_run_flags_a_nonzero_exit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    exe, source, destination, sha = _inputs(tmp_path)
    monkeypatch.setattr(
        nrs_mod, "_capture_process", _make_capture(returncode=3, write_slayed=False)
    )

    with pytest.raises(NetReactorSlayerError) as caught:
        run_net_reactor_slayer(exe, source, destination, input_sha256=sha)

    assert caught.value.code == NetReactorSlayerErrorCode.PROCESS_FAILED
    assert caught.value.retryable is True


def test_run_flags_a_missing_output(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    exe, source, destination, sha = _inputs(tmp_path)
    monkeypatch.setattr(nrs_mod, "_capture_process", _make_capture(write_slayed=False))

    with pytest.raises(NetReactorSlayerError) as caught:
        run_net_reactor_slayer(exe, source, destination, input_sha256=sha)

    assert caught.value.code == NetReactorSlayerErrorCode.OUTPUT_MISSING


# ---------------------------------------------------------------------------
# probe_net_reactor_slayer


def test_probe_is_false_for_a_missing_binary(tmp_path: Path) -> None:
    assert probe_net_reactor_slayer(tmp_path / "gone.exe") == (False, "")


def test_probe_recognises_the_tool_banner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exe = tmp_path / "NETReactorSlayer.CLI.exe"
    exe.write_bytes(b"placeholder")
    monkeypatch.setattr(
        nrs_mod,
        "run_bounded",
        lambda *a, **k: Completed(
            returncode=0, stdout=b"NETReactorSlayer 1.0 <AssemblyPath>", stderr=b""
        ),
    )

    ok, text = probe_net_reactor_slayer(exe)

    assert ok is True
    assert "NETReactorSlayer" in text


def test_probe_accepts_a_usage_banner_on_nonzero_exit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exe = tmp_path / "tool.exe"
    exe.write_bytes(b"placeholder")
    monkeypatch.setattr(
        nrs_mod,
        "run_bounded",
        lambda *a, **k: Completed(returncode=1, stdout=b"Usage: tool <path>", stderr=b""),
    )

    ok, _text = probe_net_reactor_slayer(exe)

    assert ok is True


def test_probe_falls_back_to_any_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exe = tmp_path / "tool.exe"
    exe.write_bytes(b"placeholder")
    monkeypatch.setattr(
        nrs_mod,
        "run_bounded",
        lambda *a, **k: Completed(returncode=2, stdout=b"some unrelated output", stderr=b""),
    )

    ok, text = probe_net_reactor_slayer(exe)

    assert ok is True
    assert text == "some unrelated output"


def test_probe_is_false_for_silent_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exe = tmp_path / "tool.exe"
    exe.write_bytes(b"placeholder")
    monkeypatch.setattr(
        nrs_mod,
        "run_bounded",
        lambda *a, **k: Completed(returncode=2, stdout=b"", stderr=b""),
    )

    assert probe_net_reactor_slayer(exe) == (False, "")


def test_probe_is_false_when_the_process_cannot_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exe = tmp_path / "tool.exe"
    exe.write_bytes(b"placeholder")

    def boom(*a: Any, **k: Any) -> Completed:
        raise OSError("cannot start process")

    monkeypatch.setattr(nrs_mod, "run_bounded", boom)

    assert probe_net_reactor_slayer(exe) == (False, "")
