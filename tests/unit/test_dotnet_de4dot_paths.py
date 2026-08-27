"""Guard, execution, capture and probe paths of the de4dot adapter.

The service suite fakes the whole runner; this drives ``run_de4dot`` directly
(argv/size guards, the post-run integrity checks, output publication and the
missing-output arm), plus the shared ``_capture_process`` launch-failure and
pipe arms, the bounded stream reader, and the version probe. The subprocess is
faked, so no de4dot binary runs.
"""

from __future__ import annotations

from pathlib import Path
from threading import Event
from typing import Any

import pytest

from headless_re_mcp.backends.common.bounded_run import Completed, TimedOut
from headless_re_mcp.core.session import file_sha256
from headless_re_mcp.dotnet import de4dot as de4dot_mod
from headless_re_mcp.dotnet.de4dot import (
    De4dotError,
    De4dotErrorCode,
    _capture_process,
    _CapturedStream,
    _ProcessCapture,
    probe_de4dot_version,
    run_de4dot,
)


def _inputs(tmp_path: Path) -> tuple[Path, Path, Path, str]:
    exe = tmp_path / "de4dot.exe"
    exe.write_bytes(b"placeholder")
    source = tmp_path / "managed.exe"
    source.write_bytes(b"managed-assembly-bytes")
    destination = tmp_path / "out" / "clean.exe"
    return exe, source, destination, file_sha256(source)


def _make_capture(**opts: Any) -> Any:
    def _cap(argv: list[str], *, timeout: float, max_output_size: int) -> _ProcessCapture:
        destination = Path(argv[4])  # de4dot argv: exe -f <input> -o <output>
        if opts.get("write_output", True):
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(b"cleaned-assembly")
        mutate = opts.get("mutate_source")
        if mutate is not None:
            Path(mutate).write_bytes(b"changed-after-run")
        return _ProcessCapture(
            stdout=opts.get("stdout", "done"),
            stderr=opts.get("stderr", ""),
            returncode=opts.get("returncode", 0),
            stdout_exceeded=opts.get("stdout_exceeded", False),
            stderr_exceeded=opts.get("stderr_exceeded", False),
        )

    return _cap


# ---------------------------------------------------------------------------
# run_de4dot guards


def test_missing_executable_is_rejected(tmp_path: Path) -> None:
    _exe, source, destination, sha = _inputs(tmp_path)

    with pytest.raises(De4dotError) as caught:
        run_de4dot(tmp_path / "gone.exe", source, destination, input_sha256=sha)

    assert caught.value.code == De4dotErrorCode.EXECUTABLE_NOT_FOUND


def test_a_directory_input_is_not_found(tmp_path: Path) -> None:
    exe, _source, destination, _sha = _inputs(tmp_path)
    a_dir = tmp_path / "adir"
    a_dir.mkdir()

    with pytest.raises(De4dotError) as caught:
        run_de4dot(exe, a_dir, destination, input_sha256="0" * 64)

    assert caught.value.code == De4dotErrorCode.INPUT_NOT_FOUND


def test_oversize_input_is_rejected(tmp_path: Path) -> None:
    exe, source, destination, sha = _inputs(tmp_path)

    with pytest.raises(De4dotError) as caught:
        run_de4dot(exe, source, destination, input_sha256=sha, max_file_size=0)

    assert caught.value.code == De4dotErrorCode.INPUT_TOO_LARGE


def test_a_preexisting_destination_is_rejected(tmp_path: Path) -> None:
    exe, source, destination, sha = _inputs(tmp_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(b"already here")

    with pytest.raises(De4dotError) as caught:
        run_de4dot(exe, source, destination, input_sha256=sha)

    assert caught.value.code == De4dotErrorCode.INVALID_ARGUMENT


def test_a_changed_input_sha_is_rejected(tmp_path: Path) -> None:
    exe, source, destination, _sha = _inputs(tmp_path)

    with pytest.raises(De4dotError) as caught:
        run_de4dot(exe, source, destination, input_sha256="f" * 64)

    assert caught.value.code == De4dotErrorCode.INPUT_MUTATED


# ---------------------------------------------------------------------------
# run_de4dot execution body


def test_run_publishes_the_cleaned_output(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    exe, source, destination, sha = _inputs(tmp_path)
    monkeypatch.setattr(de4dot_mod, "_capture_process", _make_capture())

    result = run_de4dot(exe, source, destination, input_sha256=sha)

    assert result.returncode == 0
    assert Path(result.output_path).is_file()
    assert result.to_dict()["source"] == "de4dot"
    assert result.to_dict()["claims_universal_unpack"] is False


def test_run_flags_an_input_mutated_by_the_tool(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exe, source, destination, sha = _inputs(tmp_path)
    monkeypatch.setattr(de4dot_mod, "_capture_process", _make_capture(mutate_source=source))

    with pytest.raises(De4dotError) as caught:
        run_de4dot(exe, source, destination, input_sha256=sha)

    assert caught.value.code == De4dotErrorCode.INPUT_MUTATED


def test_run_flags_an_output_bound_breach_and_cleans_up(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exe, source, destination, sha = _inputs(tmp_path)
    monkeypatch.setattr(de4dot_mod, "_capture_process", _make_capture(stdout_exceeded=True))

    with pytest.raises(De4dotError) as caught:
        run_de4dot(exe, source, destination, input_sha256=sha)

    assert caught.value.code == De4dotErrorCode.OUTPUT_LIMIT
    # the half-written output must not be left behind
    assert not destination.is_file()


def test_run_flags_a_nonzero_exit_and_cleans_up(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exe, source, destination, sha = _inputs(tmp_path)
    monkeypatch.setattr(de4dot_mod, "_capture_process", _make_capture(returncode=2))

    with pytest.raises(De4dotError) as caught:
        run_de4dot(exe, source, destination, input_sha256=sha)

    assert caught.value.code == De4dotErrorCode.PROCESS_FAILED
    assert caught.value.retryable is True
    assert not destination.is_file()


def test_run_flags_a_missing_output(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    exe, source, destination, sha = _inputs(tmp_path)
    monkeypatch.setattr(de4dot_mod, "_capture_process", _make_capture(write_output=False))

    with pytest.raises(De4dotError) as caught:
        run_de4dot(exe, source, destination, input_sha256=sha)

    assert caught.value.code == De4dotErrorCode.OUTPUT_MISSING


# ---------------------------------------------------------------------------
# _capture_process launch failures / pipe wiring


def test_capture_maps_a_missing_executable(monkeypatch: pytest.MonkeyPatch) -> None:
    def _popen(*a: Any, **k: Any) -> Any:
        raise FileNotFoundError("no such file")

    monkeypatch.setattr(de4dot_mod.subprocess, "Popen", _popen)

    with pytest.raises(De4dotError) as caught:
        _capture_process(["/nope/de4dot", "-f", "x", "-o", "y"], timeout=1.0, max_output_size=1024)

    assert caught.value.code == De4dotErrorCode.EXECUTABLE_NOT_FOUND


def test_capture_maps_a_launch_oserror(monkeypatch: pytest.MonkeyPatch) -> None:
    def _popen(*a: Any, **k: Any) -> Any:
        raise OSError("exec format error")

    monkeypatch.setattr(de4dot_mod.subprocess, "Popen", _popen)

    with pytest.raises(De4dotError) as caught:
        _capture_process(["/bin/de4dot", "-f", "x", "-o", "y"], timeout=1.0, max_output_size=1024)

    assert caught.value.code == De4dotErrorCode.PROCESS_FAILED


def test_capture_rejects_a_process_without_pipes(monkeypatch: pytest.MonkeyPatch) -> None:
    class _NoPipes:
        pid = 0
        stdout = None
        stderr = None

    monkeypatch.setattr(de4dot_mod.subprocess, "Popen", lambda *a, **k: _NoPipes())
    monkeypatch.setattr(de4dot_mod, "_terminate_process", lambda process: None)

    with pytest.raises(De4dotError) as caught:
        _capture_process(["de4dot", "-f", "x", "-o", "y"], timeout=1.0, max_output_size=1024)

    assert caught.value.code == De4dotErrorCode.PROCESS_FAILED


# ---------------------------------------------------------------------------
# _CapturedStream


class _Pipe:
    def __init__(self, data: bytes) -> None:
        self._chunks = [data] if data else []

    def read(self, n: int) -> bytes:
        return self._chunks.pop(0) if self._chunks else b""

    def close(self) -> None:
        pass


def test_captured_stream_collects_bounded_output() -> None:
    stream = _CapturedStream(max_size=64)
    stream.read_from(_Pipe(b"hello world"), Event())
    assert stream.text() == "hello world"
    assert stream.exceeded is False


def test_captured_stream_marks_an_overrun() -> None:
    event = Event()
    stream = _CapturedStream(max_size=3)
    stream.read_from(_Pipe(b"way too much"), event)
    assert stream.exceeded is True
    assert event.is_set()


def test_captured_stream_swallows_a_read_error() -> None:
    class _BadPipe:
        def read(self, n: int) -> bytes:
            raise OSError("pipe broke")

        def close(self) -> None:
            pass

    stream = _CapturedStream(max_size=64)
    stream.read_from(_BadPipe(), Event())
    assert stream.text() == ""


# ---------------------------------------------------------------------------
# probe_de4dot_version


def test_probe_is_false_for_a_missing_binary(tmp_path: Path) -> None:
    assert probe_de4dot_version(tmp_path / "gone.exe") == (False, "")


def test_probe_recognises_the_de4dot_banner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exe = tmp_path / "de4dot.exe"
    exe.write_bytes(b"placeholder")
    monkeypatch.setattr(
        de4dot_mod,
        "run_bounded",
        lambda *a, **k: Completed(returncode=3, stdout=b"de4dot v3.1.41592", stderr=b""),
    )

    ok, text = probe_de4dot_version(exe)

    assert ok is True
    assert "de4dot" in text


def test_probe_retries_the_next_arg_after_an_oserror(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exe = tmp_path / "de4dot.exe"
    exe.write_bytes(b"placeholder")
    calls = {"n": 0}

    def flaky(args: list[str], **kwargs: Any) -> Completed:
        calls["n"] += 1
        if calls["n"] == 1:
            raise OSError("bad argv")
        return Completed(returncode=0, stdout=b"", stderr=b"")

    monkeypatch.setattr(de4dot_mod, "run_bounded", flaky)

    ok, _text = probe_de4dot_version(exe)

    assert ok is True
    assert calls["n"] == 2


def test_probe_gives_up_on_a_timeout(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    exe = tmp_path / "de4dot.exe"
    exe.write_bytes(b"placeholder")

    def hang(*a: Any, **k: Any) -> Completed:
        raise TimedOut(5.0, [])

    monkeypatch.setattr(de4dot_mod, "run_bounded", hang)

    assert probe_de4dot_version(exe) == (False, "")


def test_probe_is_false_when_no_arg_looks_like_de4dot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exe = tmp_path / "de4dot.exe"
    exe.write_bytes(b"placeholder")
    monkeypatch.setattr(
        de4dot_mod,
        "run_bounded",
        lambda *a, **k: Completed(returncode=2, stdout=b"unrelated tool", stderr=b""),
    )

    assert probe_de4dot_version(exe) == (False, "")
