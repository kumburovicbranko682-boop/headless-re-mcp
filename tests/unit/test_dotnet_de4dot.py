"""M6.2 de4dot adapter unit tests (mocked process)."""

from __future__ import annotations

import struct
from pathlib import Path
from threading import Event
from types import SimpleNamespace
from typing import Any, cast

import pytest

from headless_re_mcp.backends.common.bounded_run import TimedOut
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.core.session import file_sha256
from headless_re_mcp.dotnet import de4dot as d
from headless_re_mcp.dotnet.de4dot import (
    De4dotError,
    De4dotErrorCode,
    De4dotResult,
    _CapturedStream,
    _ProcessCapture,
    run_de4dot,
)


def _capture(
    *,
    returncode: int = 0,
    stdout: str = "out",
    stderr: str = "err",
    stdout_exceeded: bool = False,
    stderr_exceeded: bool = False,
) -> _ProcessCapture:
    return _ProcessCapture(stdout, stderr, returncode, stdout_exceeded, stderr_exceeded)


def _prepare_run_inputs(tmp_path: Path) -> tuple[Path, Path, Path, str]:
    exe = tmp_path / "de4dot.exe"
    exe.write_bytes(b"placeholder")
    source = tmp_path / "managed.exe"
    source.write_bytes(b"managed-assembly-bytes")
    destination = tmp_path / "out" / "clean.exe"
    return exe, source, destination, file_sha256(source)


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


def test_dotnet_deobfuscate_mocked(tmp_path: Path) -> None:
    binary = tmp_path / "managed.exe"
    _write_verified_clr_pe(binary)
    de4dot = tmp_path / "de4dot.exe"
    de4dot.write_bytes(b"placeholder")
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
    ) -> De4dotResult:
        del timeout, max_file_size, max_output_size
        assert executable == de4dot
        assert file_sha256(input_path) == input_sha256
        output_path.write_bytes(input_path.read_bytes())
        return De4dotResult(
            executable=str(executable),
            input_path=str(input_path),
            output_path=str(output_path.resolve()),
            input_sha256=input_sha256,
            output_sha256=file_sha256(output_path),
            returncode=0,
            stdout="ok",
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
            de4dot=de4dot,
        ),
        de4dot_runner=fake_runner,
    )
    session_id = service.create_session(str(binary)).data["session"]["id"]
    result = service.dotnet_deobfuscate(session_id)
    assert result.ok and result.data is not None
    assert result.data["claims_universal_unpack"] is False
    assert result.data["input_unchanged"] is True
    out = Path(result.data["de4dot"]["output_path"])
    assert out.is_file()
    assert str(artifact_root.resolve()) in str(out.resolve())

    verified = service.dotnet_verify(session_id, str(out))
    assert verified.ok and verified.data is not None
    assert verified.data["ok"] is True


def test_dotnet_deobfuscate_timeout_stays_retryable(tmp_path: Path) -> None:
    """A de4dot timeout must reach the caller with retryable=True.

    De4dotError marks a timeout retryable exactly as the upx/die/exeinfope
    adapters do, but the dotnet handler translated it to an RpcError without
    forwarding the flag, so an unattended caller that retries on retryable saw
    a permanent failure for what a second run often clears.
    """
    from headless_re_mcp.dotnet.de4dot import De4dotError, De4dotErrorCode

    binary = tmp_path / "managed.exe"
    _write_verified_clr_pe(binary)
    de4dot = tmp_path / "de4dot.exe"
    de4dot.write_bytes(b"placeholder")

    def timing_out_runner(*args: object, **kwargs: object) -> object:
        raise De4dotError(De4dotErrorCode.TIMEOUT, "de4dot timed out", retryable=True)

    service = AnalysisService(
        Settings(
            ida_home=None,
            x64dbg_source=None,
            x64dbg_headless_x64=None,
            x64dbg_headless_x86=None,
            artifact_root=tmp_path / "artifacts",
            de4dot=de4dot,
        ),
        de4dot_runner=timing_out_runner,
    )
    try:
        session_id = service.create_session(str(binary)).data["session"]["id"]
        result = service.dotnet_deobfuscate(session_id)
        assert not result.ok
        assert result.error is not None
        assert result.error.code == "timeout"
        assert result.error.retryable is True
    finally:
        service.close_all()


def test_dotnet_verify_rejects_other_session_artifact(tmp_path: Path) -> None:
    binary_a = tmp_path / "managed-a.exe"
    binary_b = tmp_path / "managed-b.exe"
    _write_verified_clr_pe(binary_a)
    _write_verified_clr_pe(binary_b)
    artifact_root = tmp_path / "artifacts"

    service = AnalysisService(
        Settings(
            ida_home=None,
            x64dbg_source=None,
            x64dbg_headless_x64=None,
            x64dbg_headless_x86=None,
            artifact_root=artifact_root,
            de4dot=None,
        )
    )
    session_a = service.create_session(str(binary_a)).data["session"]["id"]
    session_b = service.create_session(str(binary_b)).data["session"]["id"]

    foreign_dir = artifact_root / "dotnet" / session_b
    foreign_dir.mkdir(parents=True, exist_ok=True)
    foreign = foreign_dir / "de4dot-foreign.exe"
    foreign.write_bytes(binary_b.read_bytes())

    rejected = service.dotnet_verify(session_a, str(foreign))
    assert not rejected.ok
    assert rejected.error is not None
    assert rejected.error.code == "invalid_params"
    assert "session" in rejected.error.message.lower()

    owned_dir = artifact_root / "dotnet" / session_a
    owned_dir.mkdir(parents=True, exist_ok=True)
    owned = owned_dir / "de4dot-owned.exe"
    owned.write_bytes(binary_a.read_bytes())
    accepted = service.dotnet_verify(session_a, str(owned))
    assert accepted.ok and accepted.data is not None
    assert accepted.data["ok"] is True


def test_run_writes_the_output_and_never_claims_universal_unpack(
    tmp_path: Path, monkeypatch: Any
) -> None:
    exe, source, destination, sha = _prepare_run_inputs(tmp_path)

    def fake_capture(argv: list[str], *, timeout: float, max_output_size: int) -> _ProcessCapture:
        del timeout, max_output_size
        # de4dot writes straight to its ``-o`` target (argv[4]).
        out = Path(argv[4])
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(b"deobfuscated-bytes")
        return _capture()

    monkeypatch.setattr(d, "_capture_process", fake_capture)
    result = run_de4dot(exe, source, destination, input_sha256=sha)
    assert result.returncode == 0
    assert destination.is_file()
    assert result.output_sha256 == file_sha256(destination)
    assert result.to_dict()["claims_universal_unpack"] is False


def test_run_reports_missing_output_when_de4dot_writes_nothing(
    tmp_path: Path, monkeypatch: Any
) -> None:
    exe, source, destination, sha = _prepare_run_inputs(tmp_path)
    monkeypatch.setattr(d, "_capture_process", lambda *a, **k: _capture())
    with pytest.raises(De4dotError) as caught:
        run_de4dot(exe, source, destination, input_sha256=sha)
    assert caught.value.code == De4dotErrorCode.OUTPUT_MISSING


def test_run_removes_a_partial_output_on_a_nonzero_exit(tmp_path: Path, monkeypatch: Any) -> None:
    exe, source, destination, sha = _prepare_run_inputs(tmp_path)

    def fake_capture(argv: list[str], *, timeout: float, max_output_size: int) -> _ProcessCapture:
        del timeout, max_output_size
        out = Path(argv[4])
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(b"half-written")
        return _capture(returncode=3)

    monkeypatch.setattr(d, "_capture_process", fake_capture)
    with pytest.raises(De4dotError) as caught:
        run_de4dot(exe, source, destination, input_sha256=sha)
    assert caught.value.code == De4dotErrorCode.PROCESS_FAILED
    assert caught.value.retryable is True
    # A failed run must not leave a half-deobfuscated artifact behind.
    assert not destination.exists()


def test_run_removes_a_partial_output_on_an_output_cap_overrun(
    tmp_path: Path, monkeypatch: Any
) -> None:
    exe, source, destination, sha = _prepare_run_inputs(tmp_path)

    def fake_capture(argv: list[str], *, timeout: float, max_output_size: int) -> _ProcessCapture:
        del timeout, max_output_size
        out = Path(argv[4])
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(b"partial")
        return _capture(stderr_exceeded=True)

    monkeypatch.setattr(d, "_capture_process", fake_capture)
    with pytest.raises(De4dotError) as caught:
        run_de4dot(exe, source, destination, input_sha256=sha)
    assert caught.value.code == De4dotErrorCode.OUTPUT_LIMIT
    assert not destination.exists()


def test_run_detects_the_tool_mutating_the_original_input(tmp_path: Path, monkeypatch: Any) -> None:
    exe, source, destination, sha = _prepare_run_inputs(tmp_path)

    def fake_capture(argv: list[str], *, timeout: float, max_output_size: int) -> _ProcessCapture:
        del timeout, max_output_size
        # de4dot must only touch its output; here it tampers the input.
        source.write_bytes(source.read_bytes() + b"MUTATED")
        return _capture()

    monkeypatch.setattr(d, "_capture_process", fake_capture)
    with pytest.raises(De4dotError) as caught:
        run_de4dot(exe, source, destination, input_sha256=sha)
    assert caught.value.code == De4dotErrorCode.INPUT_MUTATED


def test_missing_input_is_a_structured_not_found_not_a_raw_oserror(
    tmp_path: Path, monkeypatch: Any
) -> None:
    # resolve(strict=True) raised FileNotFoundError before this guard, so a
    # missing input surfaced as a generic internal_error at the agent
    # transport instead of the INPUT_NOT_FOUND this taxonomy already raises
    # for a directory. Both shapes must now be the same structured error.
    exe, _source, _destination, sha = _prepare_run_inputs(tmp_path)

    def no_spawn(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("must not spawn when the input is missing")

    monkeypatch.setattr(d, "_capture_process", no_spawn)
    with pytest.raises(De4dotError) as caught:
        run_de4dot(exe, tmp_path / "nope.bin", tmp_path / "o.exe", input_sha256=sha)
    assert caught.value.code == De4dotErrorCode.INPUT_NOT_FOUND
    assert caught.value.details["input_path"].endswith("nope.bin")

    directory = tmp_path / "adir"
    directory.mkdir()
    with pytest.raises(De4dotError) as caught:
        run_de4dot(exe, directory, tmp_path / "o2.exe", input_sha256=sha)
    assert caught.value.code == De4dotErrorCode.INPUT_NOT_FOUND


def test_run_rejects_a_missing_executable_first(tmp_path: Path, monkeypatch: Any) -> None:
    _exe, _source, _destination, sha = _prepare_run_inputs(tmp_path)
    monkeypatch.setattr(d, "_capture_process", lambda *a, **k: pytest.fail("must not spawn"))
    with pytest.raises(De4dotError) as caught:
        run_de4dot(
            tmp_path / "nope.exe",
            tmp_path / "also-missing.bin",
            tmp_path / "o.exe",
            input_sha256=sha,
        )
    assert caught.value.code == De4dotErrorCode.EXECUTABLE_NOT_FOUND


@pytest.mark.parametrize("timeout", [0, -1.0, float("nan"), float("inf"), "soon", True])
def test_run_refuses_a_non_positive_or_non_finite_timeout(
    tmp_path: Path, monkeypatch: Any, timeout: Any
) -> None:
    exe, source, destination, sha = _prepare_run_inputs(tmp_path)
    monkeypatch.setattr(d, "_capture_process", lambda *a, **k: pytest.fail("must not spawn"))
    with pytest.raises(De4dotError) as caught:
        run_de4dot(exe, source, destination, input_sha256=sha, timeout=timeout)
    assert caught.value.code == De4dotErrorCode.INVALID_ARGUMENT


def test_run_rejects_input_larger_than_the_budget(tmp_path: Path, monkeypatch: Any) -> None:
    exe, source, destination, sha = _prepare_run_inputs(tmp_path)
    monkeypatch.setattr(d, "_capture_process", lambda *a, **k: pytest.fail("must not spawn"))
    with pytest.raises(De4dotError) as caught:
        run_de4dot(exe, source, destination, input_sha256=sha, max_file_size=2)
    assert caught.value.code == De4dotErrorCode.INPUT_TOO_LARGE


def test_run_refuses_a_preexisting_or_aliased_output(tmp_path: Path, monkeypatch: Any) -> None:
    exe, source, _destination, sha = _prepare_run_inputs(tmp_path)
    monkeypatch.setattr(d, "_capture_process", lambda *a, **k: pytest.fail("must not spawn"))

    existing = tmp_path / "already.exe"
    existing.write_bytes(b"x")
    with pytest.raises(De4dotError) as caught:
        run_de4dot(exe, source, existing, input_sha256=sha)
    assert caught.value.code == De4dotErrorCode.INVALID_ARGUMENT

    with pytest.raises(De4dotError) as caught:
        run_de4dot(exe, source, source, input_sha256=sha)
    assert caught.value.code == De4dotErrorCode.INVALID_ARGUMENT


def test_run_detects_a_pre_run_sha_mismatch(tmp_path: Path, monkeypatch: Any) -> None:
    exe, source, destination, _sha = _prepare_run_inputs(tmp_path)
    monkeypatch.setattr(d, "_capture_process", lambda *a, **k: pytest.fail("must not spawn"))
    with pytest.raises(De4dotError) as caught:
        run_de4dot(exe, source, destination, input_sha256="deadbeef")
    assert caught.value.code == De4dotErrorCode.INPUT_MUTATED


def test_captured_stream_survives_a_broken_pipe_and_decodes_leniently() -> None:
    class _BrokenPipe:
        closed = False

        def read(self, size: int) -> bytes:
            raise OSError("io fail")

        def close(self) -> None:
            self.closed = True

    broken = _CapturedStream(1024)
    pipe = _BrokenPipe()
    broken.read_from(cast(Any, pipe), Event())
    assert pipe.closed
    assert broken.text() == ""

    class _BytesPipe:
        def __init__(self, payload: bytes) -> None:
            self._payload = payload
            self._sent = False

        def read(self, size: int) -> bytes:
            if self._sent:
                return b""
            self._sent = True
            return self._payload

        def close(self) -> None:
            return None

    stream = _CapturedStream(1024)
    stream.read_from(cast(Any, _BytesPipe(b"caf\xc3\xa9\xff")), Event())
    # Invalid trailing byte is replaced, not raised.
    assert stream.text() == "caf\u00e9\ufffd"


def test_capture_maps_a_launch_oserror_to_process_failed(monkeypatch: Any) -> None:
    # A non-FileNotFoundError launch failure (e.g. Exec format error) must be
    # the structured process_failed, not a raw OSError.
    def raise_oserror(*args: Any, **kwargs: Any) -> Any:
        raise OSError("exec format error")

    monkeypatch.setattr(d.subprocess, "Popen", raise_oserror)
    with pytest.raises(De4dotError) as caught:
        d._capture_process(["de4dot"], timeout=1.0, max_output_size=8)
    assert caught.value.code == De4dotErrorCode.PROCESS_FAILED


def test_capture_terminates_a_process_that_exposes_no_pipes(monkeypatch: Any) -> None:
    class _NoPipeProcess:
        def __init__(self) -> None:
            self.stdout = None
            self.stderr = None
            self.pid = 4242
            self.terminated = False

        def poll(self) -> int:
            return 0

    process = _NoPipeProcess()
    monkeypatch.setattr(d.subprocess, "Popen", lambda *a, **k: process)
    monkeypatch.setattr(d, "_terminate_process", lambda proc: setattr(proc, "terminated", True))
    with pytest.raises(De4dotError) as caught:
        d._capture_process(["de4dot"], timeout=1.0, max_output_size=8)
    assert caught.value.code == De4dotErrorCode.PROCESS_FAILED
    assert process.terminated is True


def test_probe_returns_false_for_a_missing_executable(tmp_path: Path) -> None:
    assert d.probe_de4dot_version(tmp_path / "nope.exe") == (False, "")


def test_probe_recognises_a_de4dot_banner(tmp_path: Path, monkeypatch: Any) -> None:
    exe = tmp_path / "de4dot.exe"
    exe.write_bytes(b"placeholder")
    monkeypatch.setattr(
        d,
        "run_bounded",
        lambda args, **kwargs: SimpleNamespace(stdout=b"de4dot v3.1", stderr=b"", returncode=0),
    )
    ok, text = d.probe_de4dot_version(exe)
    assert ok is True
    assert "de4dot" in text


def test_probe_skips_a_failing_argv_and_accepts_a_benign_returncode(
    tmp_path: Path, monkeypatch: Any
) -> None:
    exe = tmp_path / "de4dot.exe"
    exe.write_bytes(b"placeholder")
    calls = {"n": 0}

    def flaky(args: list[str], **kwargs: Any) -> Any:
        calls["n"] += 1
        if calls["n"] == 1:
            raise OSError("first argv unsupported")
        return SimpleNamespace(stdout=b"generic help text", stderr=b"", returncode=1)

    monkeypatch.setattr(d, "run_bounded", flaky)
    ok, text = d.probe_de4dot_version(exe)
    assert ok is True
    assert calls["n"] == 2
    assert text == "generic help text"


def test_probe_reports_false_when_no_argv_looks_like_de4dot(
    tmp_path: Path, monkeypatch: Any
) -> None:
    exe = tmp_path / "de4dot.exe"
    exe.write_bytes(b"placeholder")
    monkeypatch.setattr(
        d,
        "run_bounded",
        lambda args, **kwargs: SimpleNamespace(stdout=b"unrelated", stderr=b"", returncode=2),
    )
    assert d.probe_de4dot_version(exe) == (False, "")


def test_probe_swallows_a_launch_timeout_without_retrying(tmp_path: Path, monkeypatch: Any) -> None:
    exe = tmp_path / "de4dot.exe"
    exe.write_bytes(b"placeholder")
    calls = {"n": 0}

    def boom(args: list[str], **kwargs: Any) -> Any:
        calls["n"] += 1
        raise TimedOut(5.0, [])

    monkeypatch.setattr(d, "run_bounded", boom)
    assert d.probe_de4dot_version(exe) == (False, "")
    # A hung binary must not be retried across every help argv.
    assert calls["n"] == 1


def test_doctor_reports_de4dot_missing(tmp_path: Path) -> None:
    service = AnalysisService(
        Settings(
            ida_home=None,
            x64dbg_source=None,
            x64dbg_headless_x64=None,
            x64dbg_headless_x86=None,
            artifact_root=tmp_path / "artifacts",
            de4dot=None,
        )
    )
    report = service.doctor().data
    assert report is not None
    probes = {item["name"]: item for item in report["probes"]}
    assert probes["de4dot"]["status"] == "missing"
