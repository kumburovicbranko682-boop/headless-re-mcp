"""M6.3 NETReactorSlayer adapter unit tests (mocked process)."""

from __future__ import annotations

import struct
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from headless_re_mcp.backends.common.bounded_run import BoundedCancelled, TimedOut
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.core.session import file_sha256
from headless_re_mcp.dotnet import net_reactor_slayer as nrs_mod
from headless_re_mcp.dotnet.de4dot import _ProcessCapture
from headless_re_mcp.dotnet.net_reactor_slayer import (
    NetReactorSlayerError,
    NetReactorSlayerErrorCode,
    NetReactorSlayerResult,
    run_net_reactor_slayer,
)

_SUFFIX = nrs_mod._SLAYED_SUFFIX


def _capture(
    *,
    returncode: int = 0,
    stdout: str = "out",
    stderr: str = "err",
    stdout_exceeded: bool = False,
    stderr_exceeded: bool = False,
) -> _ProcessCapture:
    return _ProcessCapture(stdout, stderr, returncode, stdout_exceeded, stderr_exceeded)


def _write_verified_clr_pe(path: Path) -> None:
    image = bytearray(0x800)
    pe_offset = 0x80
    image[:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, pe_offset)
    image[pe_offset : pe_offset + 4] = b"PE\0\0"
    file_header = pe_offset + 4
    struct.pack_into("<HHIIIHH", image, file_header, 0x8664, 1, 0, 0, 0, 0xF0, 0x2022)
    optional = file_header + 20
    struct.pack_into("<HBB", image, optional, 0x20B, 14, 0)
    struct.pack_into("<I", image, optional + 16, 0x1000)
    struct.pack_into("<Q", image, optional + 24, 0x140000000)
    struct.pack_into("<II", image, optional + 32, 0x1000, 0x200)
    struct.pack_into("<II", image, optional + 56, 0x2000, 0x200)
    struct.pack_into("<HH", image, optional + 68, 3, 0x8160)
    struct.pack_into("<I", image, optional + 108, 16)
    dir_base = optional + 112
    struct.pack_into("<II", image, dir_base + 14 * 8, 0x1100, 72)
    section = optional + 0xF0
    image[section : section + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", image, section + 8, 0x400, 0x1000, 0x400, 0x200)
    struct.pack_into("<I", image, section + 36, 0x60000020)
    cor_off = 0x300
    struct.pack_into("<I", image, cor_off, 72)
    struct.pack_into("<HH", image, cor_off + 4, 2, 5)
    struct.pack_into("<II", image, cor_off + 8, 0x1200, 0x40)
    struct.pack_into("<I", image, cor_off + 16, 0x1)
    struct.pack_into("<I", image, cor_off + 20, 0x06000001)
    meta_off = 0x400
    version = b"v4.0.30319\0"
    version_padded = version + b"\0" * ((4 - (len(version) % 4)) % 4)
    image[meta_off : meta_off + 4] = b"BSJB"
    struct.pack_into("<HH", image, meta_off + 4, 1, 1)
    struct.pack_into("<I", image, meta_off + 8, 0)
    struct.pack_into("<I", image, meta_off + 12, len(version))
    image[meta_off + 16 : meta_off + 16 + len(version_padded)] = version_padded
    cursor = meta_off + 16 + len(version_padded)
    struct.pack_into("<HH", image, cursor, 0, 0)
    path.write_bytes(image)


def test_dotnet_reactor_unpack_mocked(tmp_path: Path) -> None:
    binary = tmp_path / "managed.exe"
    _write_verified_clr_pe(binary)
    nrs = tmp_path / "NETReactorSlayer.CLI.exe"
    nrs.write_bytes(b"placeholder")
    artifact_root = tmp_path / "artifacts"

    def fake_runner(
        executable: Path,
        input_path: Path,
        output_path: Path,
        *,
        input_sha256: str,
        timeout: float = 120.0,
        max_file_size: int = 0,
        max_output_size: int = 0,
    ) -> NetReactorSlayerResult:
        del timeout, max_file_size, max_output_size
        assert executable == nrs
        assert file_sha256(input_path) == input_sha256
        output_path.write_bytes(input_path.read_bytes())
        return NetReactorSlayerResult(
            executable=str(executable),
            input_path=str(input_path),
            output_path=str(output_path.resolve()),
            input_sha256=input_sha256,
            output_sha256=file_sha256(output_path),
            returncode=0,
            stdout="Saved to: managed_Slayed.exe",
            stderr="",
            duration_ms=1,
        )

    service = AnalysisService(
        Settings(
            ida_home=None,
            x64dbg_source=None,
            x64dbg_headless_x64=None,
            x64dbg_headless_x86=None,
            artifact_root=artifact_root,
            net_reactor_slayer=nrs,
        ),
        net_reactor_slayer_runner=fake_runner,
    )
    session_id = service.create_session(str(binary)).data["session"]["id"]
    result = service.dotnet_reactor_unpack(session_id)
    assert result.ok
    assert result.data is not None
    assert result.data["claims_universal_unpack"] is False
    assert result.data["authorized_samples_only"] is True
    out = Path(result.data["net_reactor_slayer"]["output_path"])
    assert out.is_file()
    assert file_sha256(binary) == result.data["net_reactor_slayer"]["input_sha256"]


def _prepare_run_inputs(tmp_path: Path) -> tuple[Path, Path, Path, str]:
    exe = tmp_path / "NETReactorSlayer.CLI.exe"
    exe.write_bytes(b"placeholder")
    source = tmp_path / "managed.exe"
    source.write_bytes(b"managed-assembly-bytes")
    destination = tmp_path / "out" / "slayed.exe"
    return exe, source, destination, file_sha256(source)


def test_run_net_reactor_slayer_propagates_cancel(tmp_path: Path, monkeypatch: Any) -> None:
    """A caller cancel must surface as BoundedCancelled, not a tool failure.

    scylla/vmp_dumper/xvlkc re-raise BoundedCancelled before their generic
    remap; this adapter used to fold it into NetReactorSlayerError(process_failed)
    and diverge from every sibling.
    """
    exe, source, destination, sha = _prepare_run_inputs(tmp_path)

    def cancel_capture(*args: Any, **kwargs: Any) -> Any:
        raise BoundedCancelled()

    monkeypatch.setattr(nrs_mod, "_capture_process", cancel_capture)

    with pytest.raises(BoundedCancelled):
        run_net_reactor_slayer(exe, source, destination, input_sha256=sha)


def test_run_net_reactor_slayer_remaps_other_failures(tmp_path: Path, monkeypatch: Any) -> None:
    """A genuine tool error still becomes the adapter's error envelope."""
    exe, source, destination, sha = _prepare_run_inputs(tmp_path)

    def boom(*args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("de4dot capture failed")

    monkeypatch.setattr(nrs_mod, "_capture_process", boom)

    with pytest.raises(NetReactorSlayerError):
        run_net_reactor_slayer(exe, source, destination, input_sha256=sha)


def test_run_publishes_the_slayed_output_and_marks_it_authorized_only(
    tmp_path: Path, monkeypatch: Any
) -> None:
    exe, source, destination, sha = _prepare_run_inputs(tmp_path)

    def fake_capture(argv: list[str], *, timeout: float, max_output_size: int) -> _ProcessCapture:
        del timeout, max_output_size
        work_input = Path(argv[1])
        slayed = work_input.parent / f"{work_input.stem}{_SUFFIX}{work_input.suffix}"
        slayed.write_bytes(b"deobfuscated-bytes")
        return _capture()

    monkeypatch.setattr(nrs_mod, "_capture_process", fake_capture)
    result = run_net_reactor_slayer(exe, source, destination, input_sha256=sha)
    assert result.returncode == 0
    assert destination.is_file()
    assert result.output_sha256 == file_sha256(destination)
    serialized = result.to_dict()
    assert serialized["claims_universal_unpack"] is False
    assert serialized["target"] == "authorized_reactor_samples_only"


def test_run_accepts_a_single_slayed_variant_via_the_glob_fallback(
    tmp_path: Path, monkeypatch: Any
) -> None:
    # The tool does not always emit exactly ``{stem}_Slayed{suffix}``; a lone
    # ``*_Slayed*`` file in the work dir is still an honest single result.
    exe, source, destination, sha = _prepare_run_inputs(tmp_path)

    def fake_capture(argv: list[str], *, timeout: float, max_output_size: int) -> _ProcessCapture:
        del timeout, max_output_size
        work_dir = Path(argv[1]).parent
        (work_dir / f"variant{_SUFFIX}name.exe").write_bytes(b"deobfuscated")
        return _capture()

    monkeypatch.setattr(nrs_mod, "_capture_process", fake_capture)
    result = run_net_reactor_slayer(exe, source, destination, input_sha256=sha)
    assert destination.is_file()
    assert result.returncode == 0


def test_run_fails_closed_when_the_slayed_output_is_ambiguous(
    tmp_path: Path, monkeypatch: Any
) -> None:
    exe, source, destination, sha = _prepare_run_inputs(tmp_path)

    def fake_capture(argv: list[str], *, timeout: float, max_output_size: int) -> _ProcessCapture:
        del timeout, max_output_size
        work_dir = Path(argv[1]).parent
        (work_dir / f"a{_SUFFIX}.exe").write_bytes(b"1")
        (work_dir / f"b{_SUFFIX}.exe").write_bytes(b"2")
        return _capture()

    monkeypatch.setattr(nrs_mod, "_capture_process", fake_capture)
    with pytest.raises(NetReactorSlayerError) as caught:
        run_net_reactor_slayer(exe, source, destination, input_sha256=sha)
    assert caught.value.code == NetReactorSlayerErrorCode.OUTPUT_MISSING
    assert not destination.exists()


def test_run_reports_missing_output_when_nothing_slayed_is_written(
    tmp_path: Path, monkeypatch: Any
) -> None:
    exe, source, destination, sha = _prepare_run_inputs(tmp_path)
    monkeypatch.setattr(nrs_mod, "_capture_process", lambda *a, **k: _capture())
    with pytest.raises(NetReactorSlayerError) as caught:
        run_net_reactor_slayer(exe, source, destination, input_sha256=sha)
    assert caught.value.code == NetReactorSlayerErrorCode.OUTPUT_MISSING


def test_run_reports_a_nonzero_exit_as_retryable_process_failed(
    tmp_path: Path, monkeypatch: Any
) -> None:
    exe, source, destination, sha = _prepare_run_inputs(tmp_path)
    monkeypatch.setattr(nrs_mod, "_capture_process", lambda *a, **k: _capture(returncode=3))
    with pytest.raises(NetReactorSlayerError) as caught:
        run_net_reactor_slayer(exe, source, destination, input_sha256=sha)
    assert caught.value.code == NetReactorSlayerErrorCode.PROCESS_FAILED
    assert caught.value.retryable is True
    assert not destination.exists()


def test_run_reports_an_output_cap_overrun(tmp_path: Path, monkeypatch: Any) -> None:
    exe, source, destination, sha = _prepare_run_inputs(tmp_path)
    monkeypatch.setattr(nrs_mod, "_capture_process", lambda *a, **k: _capture(stdout_exceeded=True))
    with pytest.raises(NetReactorSlayerError) as caught:
        run_net_reactor_slayer(exe, source, destination, input_sha256=sha)
    assert caught.value.code == NetReactorSlayerErrorCode.OUTPUT_LIMIT


def test_run_detects_the_tool_mutating_the_original_input(tmp_path: Path, monkeypatch: Any) -> None:
    exe, source, destination, sha = _prepare_run_inputs(tmp_path)

    def fake_capture(argv: list[str], *, timeout: float, max_output_size: int) -> _ProcessCapture:
        del timeout, max_output_size
        # A well-behaved tool works on the copy; here it tampers the original.
        source.write_bytes(source.read_bytes() + b"MUTATED")
        work_input = Path(argv[1])
        (work_input.parent / f"{work_input.stem}{_SUFFIX}{work_input.suffix}").write_bytes(b"x")
        return _capture()

    monkeypatch.setattr(nrs_mod, "_capture_process", fake_capture)
    with pytest.raises(NetReactorSlayerError) as caught:
        run_net_reactor_slayer(exe, source, destination, input_sha256=sha)
    assert caught.value.code == NetReactorSlayerErrorCode.INPUT_MUTATED


def test_missing_input_is_a_structured_not_found_not_a_raw_oserror(
    tmp_path: Path, monkeypatch: Any
) -> None:
    # resolve(strict=True) raised FileNotFoundError before this guard, so a
    # missing input surfaced as a generic internal_error at the agent
    # transport instead of the INPUT_NOT_FOUND this taxonomy already raises
    # for a directory. Both shapes must now be the same structured error.
    exe, source, _destination, sha = _prepare_run_inputs(tmp_path)

    def no_spawn(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("must not spawn when the input is missing")

    monkeypatch.setattr(nrs_mod, "_capture_process", no_spawn)
    with pytest.raises(NetReactorSlayerError) as caught:
        run_net_reactor_slayer(exe, tmp_path / "nope.bin", tmp_path / "o.exe", input_sha256=sha)
    assert caught.value.code == NetReactorSlayerErrorCode.INPUT_NOT_FOUND
    assert caught.value.details["input_path"].endswith("nope.bin")

    directory = tmp_path / "adir"
    directory.mkdir()
    with pytest.raises(NetReactorSlayerError) as caught:
        run_net_reactor_slayer(exe, directory, tmp_path / "o2.exe", input_sha256=sha)
    assert caught.value.code == NetReactorSlayerErrorCode.INPUT_NOT_FOUND


def test_run_rejects_a_missing_executable_before_touching_the_input(
    tmp_path: Path, monkeypatch: Any
) -> None:
    # Both the tool and the input are missing; the executable check runs first.
    _exe, _source, _destination, sha = _prepare_run_inputs(tmp_path)

    def no_spawn(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("must not spawn")

    monkeypatch.setattr(nrs_mod, "_capture_process", no_spawn)
    with pytest.raises(NetReactorSlayerError) as caught:
        run_net_reactor_slayer(
            tmp_path / "nope.exe",
            tmp_path / "also-missing.bin",
            tmp_path / "o.exe",
            input_sha256=sha,
        )
    assert caught.value.code == NetReactorSlayerErrorCode.EXECUTABLE_NOT_FOUND


@pytest.mark.parametrize("timeout", [0, -1.0, float("nan"), float("inf"), "soon", True])
def test_run_refuses_a_non_positive_or_non_finite_timeout(
    tmp_path: Path, monkeypatch: Any, timeout: Any
) -> None:
    exe, source, destination, sha = _prepare_run_inputs(tmp_path)

    def no_spawn(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("must not spawn for an invalid timeout")

    monkeypatch.setattr(nrs_mod, "_capture_process", no_spawn)
    with pytest.raises(NetReactorSlayerError) as caught:
        run_net_reactor_slayer(exe, source, destination, input_sha256=sha, timeout=timeout)
    assert caught.value.code == NetReactorSlayerErrorCode.INVALID_ARGUMENT


def test_run_rejects_input_larger_than_the_budget(tmp_path: Path, monkeypatch: Any) -> None:
    exe, source, destination, sha = _prepare_run_inputs(tmp_path)
    monkeypatch.setattr(nrs_mod, "_capture_process", lambda *a, **k: pytest.fail("must not spawn"))
    with pytest.raises(NetReactorSlayerError) as caught:
        run_net_reactor_slayer(exe, source, destination, input_sha256=sha, max_file_size=2)
    assert caught.value.code == NetReactorSlayerErrorCode.INPUT_TOO_LARGE


def test_run_refuses_a_preexisting_or_aliased_output(tmp_path: Path, monkeypatch: Any) -> None:
    exe, source, _destination, sha = _prepare_run_inputs(tmp_path)
    monkeypatch.setattr(nrs_mod, "_capture_process", lambda *a, **k: pytest.fail("must not spawn"))

    existing = tmp_path / "already.exe"
    existing.write_bytes(b"x")
    with pytest.raises(NetReactorSlayerError) as caught:
        run_net_reactor_slayer(exe, source, existing, input_sha256=sha)
    assert caught.value.code == NetReactorSlayerErrorCode.INVALID_ARGUMENT

    with pytest.raises(NetReactorSlayerError) as caught:
        run_net_reactor_slayer(exe, source, source, input_sha256=sha)
    assert caught.value.code == NetReactorSlayerErrorCode.INVALID_ARGUMENT


def test_run_detects_a_pre_run_sha_mismatch(tmp_path: Path, monkeypatch: Any) -> None:
    exe, source, destination, _sha = _prepare_run_inputs(tmp_path)
    monkeypatch.setattr(nrs_mod, "_capture_process", lambda *a, **k: pytest.fail("must not spawn"))
    with pytest.raises(NetReactorSlayerError) as caught:
        run_net_reactor_slayer(exe, source, destination, input_sha256="deadbeef")
    assert caught.value.code == NetReactorSlayerErrorCode.INPUT_MUTATED


def test_probe_returns_false_for_a_missing_executable(tmp_path: Path) -> None:
    assert nrs_mod.probe_net_reactor_slayer(tmp_path / "nope.exe") == (False, "")


@pytest.mark.parametrize(
    ("stdout", "returncode"),
    [
        pytest.param(b"NETReactorSlayer v1.0", 0, id="tool-name"),
        pytest.param(b"Usage: <assemblyPath>", 1, id="assemblypath"),
        pytest.param(b"generic usage banner", 0, id="usage-with-benign-rc"),
    ],
)
def test_probe_recognises_a_usage_banner(
    tmp_path: Path, monkeypatch: Any, stdout: bytes, returncode: int
) -> None:
    executable = tmp_path / "nrs.exe"
    executable.write_bytes(b"placeholder")
    monkeypatch.setattr(
        nrs_mod,
        "run_bounded",
        lambda *a, **k: SimpleNamespace(stdout=stdout, stderr=b"", returncode=returncode),
    )
    ok, text = nrs_mod.probe_net_reactor_slayer(executable)
    assert ok is True
    assert text


def test_probe_reports_false_on_silent_failure(tmp_path: Path, monkeypatch: Any) -> None:
    executable = tmp_path / "nrs.exe"
    executable.write_bytes(b"placeholder")
    monkeypatch.setattr(
        nrs_mod,
        "run_bounded",
        lambda *a, **k: SimpleNamespace(stdout=b"", stderr=b"", returncode=2),
    )
    assert nrs_mod.probe_net_reactor_slayer(executable) == (False, "")


def test_probe_swallows_a_launch_timeout(tmp_path: Path, monkeypatch: Any) -> None:
    executable = tmp_path / "nrs.exe"
    executable.write_bytes(b"placeholder")

    def boom(*args: Any, **kwargs: Any) -> Any:
        raise TimedOut(5.0, [])

    monkeypatch.setattr(nrs_mod, "run_bounded", boom)
    assert nrs_mod.probe_net_reactor_slayer(executable) == (False, "")


def test_doctor_reports_net_reactor_slayer_missing(tmp_path: Path) -> None:
    from headless_re_mcp.doctor import run_doctor

    report = run_doctor(
        Settings(
            ida_home=None,
            x64dbg_source=None,
            x64dbg_headless_x64=None,
            x64dbg_headless_x86=None,
            artifact_root=tmp_path,
            net_reactor_slayer=None,
        )
    )
    probes = {item.name: item for item in report.probes}
    assert probes["net_reactor_slayer"].status.value == "missing"
