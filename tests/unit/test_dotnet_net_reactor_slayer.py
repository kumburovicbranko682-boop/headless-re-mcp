"""M6.3 NETReactorSlayer adapter unit tests (mocked process)."""

from __future__ import annotations

import struct
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.common.bounded_run import (
    BoundedCancelled,
    Completed,
)
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.core.session import file_sha256
from headless_re_mcp.dotnet import net_reactor_slayer as nrs_mod
from headless_re_mcp.dotnet.de4dot import _ProcessCapture
from headless_re_mcp.dotnet.net_reactor_slayer import (
    NetReactorSlayerError,
    NetReactorSlayerErrorCode,
    NetReactorSlayerResult,
    probe_net_reactor_slayer,
    run_net_reactor_slayer,
)


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


# --------------------------------------------------------------------------- #
# Fail-closed guards before anything is launched                              #
# --------------------------------------------------------------------------- #
def test_run_rejects_a_missing_executable(tmp_path: Path) -> None:
    _exe, source, destination, sha = _prepare_run_inputs(tmp_path)
    missing = tmp_path / "not-there.exe"
    with pytest.raises(NetReactorSlayerError) as excinfo:
        run_net_reactor_slayer(missing, source, destination, input_sha256=sha)
    assert excinfo.value.code == NetReactorSlayerErrorCode.EXECUTABLE_NOT_FOUND


def test_run_rejects_an_input_that_is_not_a_file(tmp_path: Path) -> None:
    exe, _source, destination, _sha = _prepare_run_inputs(tmp_path)
    a_directory = tmp_path / "adir"
    a_directory.mkdir()
    with pytest.raises(NetReactorSlayerError) as excinfo:
        run_net_reactor_slayer(exe, a_directory, destination, input_sha256="0" * 64)
    assert excinfo.value.code == NetReactorSlayerErrorCode.INPUT_NOT_FOUND


def test_run_rejects_an_input_over_the_size_bound(tmp_path: Path) -> None:
    exe, source, destination, sha = _prepare_run_inputs(tmp_path)
    with pytest.raises(NetReactorSlayerError) as excinfo:
        run_net_reactor_slayer(exe, source, destination, input_sha256=sha, max_file_size=1)
    assert excinfo.value.code == NetReactorSlayerErrorCode.INPUT_TOO_LARGE
    assert excinfo.value.details["max_file_size"] == 1


def test_run_refuses_to_overwrite_an_existing_output(tmp_path: Path) -> None:
    exe, source, destination, sha = _prepare_run_inputs(tmp_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(b"already here")
    with pytest.raises(NetReactorSlayerError) as excinfo:
        run_net_reactor_slayer(exe, source, destination, input_sha256=sha)
    assert excinfo.value.code == NetReactorSlayerErrorCode.INVALID_ARGUMENT


def test_run_rejects_a_stale_input_hash(tmp_path: Path) -> None:
    exe, source, destination, _sha = _prepare_run_inputs(tmp_path)
    with pytest.raises(NetReactorSlayerError) as excinfo:
        run_net_reactor_slayer(exe, source, destination, input_sha256="dead" * 16)
    assert excinfo.value.code == NetReactorSlayerErrorCode.INPUT_MUTATED


# --------------------------------------------------------------------------- #
# Post-capture handling of a (mocked) tool run                                #
# --------------------------------------------------------------------------- #
def _slayed_path(work_input: Path) -> Path:
    return work_input.with_name(f"{work_input.stem}_Slayed{work_input.suffix}")


def test_run_publishes_the_slayed_output_on_success(tmp_path: Path, monkeypatch: Any) -> None:
    """A clean run copies the tool's ``*_Slayed`` file to the output path."""
    exe, source, destination, sha = _prepare_run_inputs(tmp_path)

    def capture(argv: list[str], **_kwargs: Any) -> _ProcessCapture:
        _slayed_path(Path(argv[1])).write_bytes(b"deobfuscated-bytes")
        return _ProcessCapture("done", "", 0, False, False)

    monkeypatch.setattr(nrs_mod, "_capture_process", capture)

    result = run_net_reactor_slayer(exe, source, destination, input_sha256=sha)

    assert isinstance(result, NetReactorSlayerResult)
    assert result.returncode == 0
    assert Path(result.output_path).read_bytes() == b"deobfuscated-bytes"
    assert result.output_sha256 == file_sha256(destination)
    assert result.input_sha256 == sha
    # The original input is left untouched.
    assert file_sha256(source) == sha


def test_run_accepts_a_differently_named_slayed_file(tmp_path: Path, monkeypatch: Any) -> None:
    """When the expected name is absent, a lone ``*_Slayed*`` file is accepted."""
    exe, source, destination, sha = _prepare_run_inputs(tmp_path)

    def capture(argv: list[str], **_kwargs: Any) -> _ProcessCapture:
        work_input = Path(argv[1])
        (work_input.parent / "renamed_Slayed_v2.exe").write_bytes(b"fallback-bytes")
        return _ProcessCapture("done", "", 0, False, False)

    monkeypatch.setattr(nrs_mod, "_capture_process", capture)

    result = run_net_reactor_slayer(exe, source, destination, input_sha256=sha)
    assert Path(result.output_path).read_bytes() == b"fallback-bytes"


def test_run_flags_an_input_mutated_by_the_tool(tmp_path: Path, monkeypatch: Any) -> None:
    """If the tool touches the original input, the run fails input_mutated."""
    exe, source, destination, sha = _prepare_run_inputs(tmp_path)

    def capture(argv: list[str], **_kwargs: Any) -> _ProcessCapture:
        source.write_bytes(b"tool-rewrote-the-original")
        return _ProcessCapture("done", "", 0, False, False)

    monkeypatch.setattr(nrs_mod, "_capture_process", capture)

    with pytest.raises(NetReactorSlayerError) as excinfo:
        run_net_reactor_slayer(exe, source, destination, input_sha256=sha)
    assert excinfo.value.code == NetReactorSlayerErrorCode.INPUT_MUTATED
    assert not destination.exists()


def test_run_flags_output_that_exceeds_the_stream_bound(tmp_path: Path, monkeypatch: Any) -> None:
    exe, source, destination, sha = _prepare_run_inputs(tmp_path)

    def capture(argv: list[str], **_kwargs: Any) -> _ProcessCapture:
        return _ProcessCapture("noisy", "", 0, True, False)

    monkeypatch.setattr(nrs_mod, "_capture_process", capture)

    with pytest.raises(NetReactorSlayerError) as excinfo:
        run_net_reactor_slayer(exe, source, destination, input_sha256=sha)
    assert excinfo.value.code == NetReactorSlayerErrorCode.OUTPUT_LIMIT


def test_run_flags_a_nonzero_exit_as_retryable(tmp_path: Path, monkeypatch: Any) -> None:
    exe, source, destination, sha = _prepare_run_inputs(tmp_path)

    def capture(argv: list[str], **_kwargs: Any) -> _ProcessCapture:
        return _ProcessCapture("", "crashed", 3, False, False)

    monkeypatch.setattr(nrs_mod, "_capture_process", capture)

    with pytest.raises(NetReactorSlayerError) as excinfo:
        run_net_reactor_slayer(exe, source, destination, input_sha256=sha)
    assert excinfo.value.code == NetReactorSlayerErrorCode.PROCESS_FAILED
    assert excinfo.value.returncode == 3
    assert excinfo.value.retryable is True


def test_run_flags_a_clean_exit_with_no_output(tmp_path: Path, monkeypatch: Any) -> None:
    exe, source, destination, sha = _prepare_run_inputs(tmp_path)

    def capture(argv: list[str], **_kwargs: Any) -> _ProcessCapture:
        return _ProcessCapture("said ok", "", 0, False, False)

    monkeypatch.setattr(nrs_mod, "_capture_process", capture)

    with pytest.raises(NetReactorSlayerError) as excinfo:
        run_net_reactor_slayer(exe, source, destination, input_sha256=sha)
    assert excinfo.value.code == NetReactorSlayerErrorCode.OUTPUT_MISSING


# --------------------------------------------------------------------------- #
# probe_net_reactor_slayer                                                    #
# --------------------------------------------------------------------------- #
def test_probe_reports_missing_when_the_executable_is_absent(tmp_path: Path) -> None:
    ok, text = probe_net_reactor_slayer(tmp_path / "nope.exe")
    assert ok is False
    assert text == ""


def test_probe_swallows_launch_failures(tmp_path: Path, monkeypatch: Any) -> None:
    exe = tmp_path / "NETReactorSlayer.CLI.exe"
    exe.write_bytes(b"x")

    def boom(*_args: Any, **_kwargs: Any) -> Completed:
        raise OSError("cannot launch")

    monkeypatch.setattr(nrs_mod, "run_bounded", boom)
    ok, text = probe_net_reactor_slayer(exe)
    assert ok is False
    assert text == ""


def test_probe_recognizes_the_tool_banner(tmp_path: Path, monkeypatch: Any) -> None:
    exe = tmp_path / "NETReactorSlayer.CLI.exe"
    exe.write_bytes(b"x")

    def banner(*_args: Any, **_kwargs: Any) -> Completed:
        return Completed(returncode=1, stdout=b"NETReactorSlayer 1.0\n", stderr=b"")

    monkeypatch.setattr(nrs_mod, "run_bounded", banner)
    ok, text = probe_net_reactor_slayer(exe)
    assert ok is True
    assert "NETReactorSlayer" in text


def test_probe_recognizes_usage_text_on_a_benign_exit(tmp_path: Path, monkeypatch: Any) -> None:
    exe = tmp_path / "NETReactorSlayer.CLI.exe"
    exe.write_bytes(b"x")

    def usage(*_args: Any, **_kwargs: Any) -> Completed:
        return Completed(returncode=1, stdout=b"Usage: run it like so\n", stderr=b"")

    monkeypatch.setattr(nrs_mod, "run_bounded", usage)
    ok, text = probe_net_reactor_slayer(exe)
    assert ok is True
    assert "usage" in text.lower()


def test_probe_falls_back_to_whether_there_was_any_output(tmp_path: Path, monkeypatch: Any) -> None:
    exe = tmp_path / "NETReactorSlayer.CLI.exe"
    exe.write_bytes(b"x")

    def unknown(*_args: Any, **_kwargs: Any) -> Completed:
        return Completed(returncode=42, stdout=b"some unrelated chatter", stderr=b"")

    monkeypatch.setattr(nrs_mod, "run_bounded", unknown)
    ok, text = probe_net_reactor_slayer(exe)
    assert ok is True
    assert text == "some unrelated chatter"

    def empty(*_args: Any, **_kwargs: Any) -> Completed:
        return Completed(returncode=42, stdout=b"", stderr=b"")

    monkeypatch.setattr(nrs_mod, "run_bounded", empty)
    ok, text = probe_net_reactor_slayer(exe)
    assert ok is False
    assert text == ""


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
