"""Coverage for the de4dot and NETReactorSlayer adapter arms.

Real fake executables (POSIX shell scripts) drive the full ``run_de4dot`` and
``run_net_reactor_slayer`` flows: validation guards, success, input-mutation
detection, output limits, process failures, missing outputs, leftover process
sweeps, and the version/help probes.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from threading import Event
from typing import Any

import pytest

import headless_re_mcp.dotnet.de4dot as d4
import headless_re_mcp.dotnet.net_reactor_slayer as nrs
from headless_re_mcp.core.session import file_sha256
from headless_re_mcp.dotnet.de4dot import (
    De4dotError,
    probe_de4dot_version,
    run_de4dot,
)
from headless_re_mcp.dotnet.net_reactor_slayer import (
    NetReactorSlayerError,
    probe_net_reactor_slayer,
    run_net_reactor_slayer,
)

pytestmark = pytest.mark.skipif(os.name == "nt", reason="fake tools are POSIX shell scripts")


def _script(tmp_path: Path, body: str, *, name: str = "tool.sh") -> Path:
    path = tmp_path / name
    path.write_text(f"#!/bin/sh\n{body}\n")
    path.chmod(0o755)
    return path


def _assembly(tmp_path: Path, name: str = "input.exe") -> tuple[Path, str]:
    path = tmp_path / name
    path.write_bytes(b"MZ\x90\x00fake-assembly")
    return path, file_sha256(path)


# ---------------------------------------------------------------------------
# run_de4dot validation guards
# ---------------------------------------------------------------------------


def test_run_de4dot_validates_paths_sizes_and_hashes(tmp_path: Path) -> None:
    source, sha = _assembly(tmp_path)
    exe = _script(tmp_path, "exit 0")
    out = tmp_path / "out.exe"

    with pytest.raises(De4dotError) as missing_exe:
        run_de4dot(tmp_path / "nope", source, out, input_sha256=sha)
    assert missing_exe.value.code == "executable_not_found"

    directory = tmp_path / "dir"
    directory.mkdir()
    with pytest.raises(De4dotError) as not_file:
        run_de4dot(exe, directory, out, input_sha256=sha)
    assert not_file.value.code == "input_not_found"

    with pytest.raises(De4dotError) as too_large:
        run_de4dot(exe, source, out, input_sha256=sha, max_file_size=1)
    assert too_large.value.code == "input_too_large"

    existing = tmp_path / "exists.exe"
    existing.write_bytes(b"x")
    with pytest.raises(De4dotError) as dest_exists:
        run_de4dot(exe, source, existing, input_sha256=sha)
    assert dest_exists.value.code == "invalid_argument"

    with pytest.raises(De4dotError) as mismatch:
        run_de4dot(exe, source, out, input_sha256="0" * 64)
    assert mismatch.value.code == "input_mutated"


# ---------------------------------------------------------------------------
# run_de4dot outcome arms (argv is: exe -f <input> -o <output>)
# ---------------------------------------------------------------------------


def test_run_de4dot_success_copies_and_reports_hashes(tmp_path: Path) -> None:
    source, sha = _assembly(tmp_path)
    exe = _script(tmp_path, 'cp "$2" "$4"')
    out = tmp_path / "deob" / "out.exe"
    result = run_de4dot(exe, source, out, input_sha256=sha)
    assert result.returncode == 0
    assert result.input_sha256 == sha
    assert result.output_sha256 == sha
    payload = result.to_dict()
    assert payload["source"] == "de4dot"
    assert payload["claims_universal_unpack"] is False


def test_run_de4dot_detects_a_mutated_input(tmp_path: Path) -> None:
    source, sha = _assembly(tmp_path)
    exe = _script(tmp_path, 'echo tampered >> "$2"')
    with pytest.raises(De4dotError) as excinfo:
        run_de4dot(exe, source, tmp_path / "out.exe", input_sha256=sha)
    assert excinfo.value.code == "input_mutated"


def test_run_de4dot_enforces_the_output_bound_and_cleans_up(tmp_path: Path) -> None:
    source, sha = _assembly(tmp_path)
    exe = _script(tmp_path, 'cp "$2" "$4"; head -c 200000 /dev/zero')
    out = tmp_path / "out.exe"
    with pytest.raises(De4dotError) as excinfo:
        run_de4dot(exe, source, out, input_sha256=sha, max_output_size=1024)
    assert excinfo.value.code == "output_limit"
    assert not out.exists()


def test_run_de4dot_maps_a_nonzero_exit_and_cleans_up(tmp_path: Path) -> None:
    source, sha = _assembly(tmp_path)
    exe = _script(tmp_path, 'cp "$2" "$4"; exit 3')
    out = tmp_path / "out.exe"
    with pytest.raises(De4dotError) as excinfo:
        run_de4dot(exe, source, out, input_sha256=sha)
    assert excinfo.value.code == "process_failed"
    assert excinfo.value.retryable is True
    assert not out.exists()


def test_run_de4dot_requires_the_output_file_to_appear(tmp_path: Path) -> None:
    source, sha = _assembly(tmp_path)
    exe = _script(tmp_path, "exit 0")
    with pytest.raises(De4dotError) as excinfo:
        run_de4dot(exe, source, tmp_path / "out.exe", input_sha256=sha)
    assert excinfo.value.code == "output_missing"


# ---------------------------------------------------------------------------
# capture internals
# ---------------------------------------------------------------------------


class _ChunkPipe:
    def __init__(self, chunks: list[bytes]) -> None:
        self._chunks = list(chunks)
        self.closed = False

    def read(self, size: int) -> bytes:
        return self._chunks.pop(0) if self._chunks else b""

    def close(self) -> None:
        self.closed = True


class _ExplodingPipe:
    def read(self, size: int) -> bytes:
        raise OSError("pipe torn down")

    def close(self) -> None:
        raise OSError("already closed")


def test_captured_stream_stops_past_the_limit_and_survives_errors() -> None:
    stream = d4._CapturedStream(4)
    limit = Event()
    pipe = _ChunkPipe([b"abcdef"])
    stream.read_from(pipe, limit)
    assert stream.exceeded and limit.is_set()
    assert stream.text() == ""
    assert pipe.closed

    other = d4._CapturedStream(4)
    other.read_from(_ExplodingPipe(), Event())
    assert not other.exceeded


def test_creation_options_hides_the_console_on_windows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _StartupInfo:
        def __init__(self) -> None:
            self.dwFlags = 0
            self.wShowWindow = -1

    monkeypatch.setattr(os, "name", "nt")
    monkeypatch.setattr(subprocess, "STARTUPINFO", _StartupInfo, raising=False)
    options = d4._creation_options()
    assert options["startupinfo"].wShowWindow == 0
    assert "start_new_session" not in options


def test_capture_process_rejects_a_process_without_pipes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _NoPipes:
        stdout = None
        stderr = None
        pid = None

        def __init__(self, argv: object, **options: object) -> None:
            pass

        def poll(self) -> int:
            return 0

        def wait(self, timeout: float | None = None) -> int:
            return 0

    monkeypatch.setattr(subprocess, "Popen", _NoPipes)
    with pytest.raises(De4dotError, match="did not expose stdout/stderr"):
        d4._capture_process(["de4dot"], timeout=1.0, max_output_size=1024)


def test_capture_process_sweeps_a_leftover_group_member(tmp_path: Path) -> None:
    # The runner exits immediately but leaves a detached child holding the
    # pipes; the POSIX leftover sweep must kill the session group it led.
    exe = _script(tmp_path, "sleep 3 &\nexit 0")
    capture = d4._capture_process([str(exe)], timeout=10.0, max_output_size=1024)
    assert capture.returncode == 0
    assert not capture.stdout_exceeded


# ---------------------------------------------------------------------------
# probe_de4dot_version
# ---------------------------------------------------------------------------


def test_probe_de4dot_version_arms(tmp_path: Path) -> None:
    assert probe_de4dot_version(tmp_path / "nope") == (False, "")

    hung = _script(tmp_path, "sleep 2", name="hung.sh")
    assert probe_de4dot_version(hung, timeout=0.2) == (False, "")

    not_executable = tmp_path / "flat"
    not_executable.write_text("#!/bin/sh\n")
    assert probe_de4dot_version(not_executable, timeout=1.0) == (False, "")

    named = _script(tmp_path, "echo de4dot v3.1; exit 5", name="named.sh")
    ok, text = probe_de4dot_version(named, timeout=5.0)
    assert ok is True and "de4dot" in text

    silent_ok = _script(tmp_path, "echo helper; exit 0", name="ok.sh")
    ok, text = probe_de4dot_version(silent_ok, timeout=5.0)
    assert ok is True and "helper" in text

    unrelated = _script(tmp_path, "echo nope; exit 5", name="bad.sh")
    assert probe_de4dot_version(unrelated, timeout=5.0) == (False, "")


# ---------------------------------------------------------------------------
# run_net_reactor_slayer (argv is: exe <work-input> --no-pause True)
# ---------------------------------------------------------------------------


def test_run_nrs_validates_paths_sizes_and_hashes(tmp_path: Path) -> None:
    source, sha = _assembly(tmp_path)
    exe = _script(tmp_path, "exit 0")
    out = tmp_path / "out.exe"

    with pytest.raises(NetReactorSlayerError) as missing_exe:
        run_net_reactor_slayer(tmp_path / "nope", source, out, input_sha256=sha)
    assert missing_exe.value.code == "executable_not_found"

    directory = tmp_path / "dir"
    directory.mkdir()
    with pytest.raises(NetReactorSlayerError) as not_file:
        run_net_reactor_slayer(exe, directory, out, input_sha256=sha)
    assert not_file.value.code == "input_not_found"

    with pytest.raises(NetReactorSlayerError) as too_large:
        run_net_reactor_slayer(exe, source, out, input_sha256=sha, max_file_size=1)
    assert too_large.value.code == "input_too_large"

    existing = tmp_path / "exists.exe"
    existing.write_bytes(b"x")
    with pytest.raises(NetReactorSlayerError) as dest_exists:
        run_net_reactor_slayer(exe, source, existing, input_sha256=sha)
    assert dest_exists.value.code == "invalid_argument"

    with pytest.raises(NetReactorSlayerError) as mismatch:
        run_net_reactor_slayer(exe, source, out, input_sha256="0" * 64)
    assert mismatch.value.code == "input_mutated"


def test_run_nrs_publishes_the_slayed_output(tmp_path: Path) -> None:
    source, sha = _assembly(tmp_path)
    exe = _script(tmp_path, 'cp "$1" "${1%.exe}_Slayed.exe"')
    out = tmp_path / "deob" / "out.exe"
    result = run_net_reactor_slayer(exe, source, out, input_sha256=sha)
    assert result.returncode == 0
    assert result.output_sha256 == sha
    assert out.is_file()
    payload = result.to_dict()
    assert payload["source"] == "net_reactor_slayer"
    assert payload["target"] == "authorized_reactor_samples_only"


def test_run_nrs_accepts_a_renamed_slayed_candidate(tmp_path: Path) -> None:
    source, sha = _assembly(tmp_path)
    exe = _script(tmp_path, 'cp "$1" "$(dirname "$1")/renamed_Slayed.bin"')
    out = tmp_path / "out.exe"
    result = run_net_reactor_slayer(exe, source, out, input_sha256=sha)
    assert result.output_sha256 == sha


def test_run_nrs_detects_a_mutated_original_input(tmp_path: Path) -> None:
    source, sha = _assembly(tmp_path)
    # The tool only sees the work copy, so the fake reaches back to the
    # original to simulate a tool that follows the path home.
    exe = _script(tmp_path, f'echo tampered >> "{source}"')
    with pytest.raises(NetReactorSlayerError) as excinfo:
        run_net_reactor_slayer(exe, source, tmp_path / "out.exe", input_sha256=sha)
    assert excinfo.value.code == "input_mutated"


def test_run_nrs_enforces_the_output_bound(tmp_path: Path) -> None:
    source, sha = _assembly(tmp_path)
    exe = _script(tmp_path, "head -c 200000 /dev/zero")
    with pytest.raises(NetReactorSlayerError) as excinfo:
        run_net_reactor_slayer(
            exe, source, tmp_path / "out.exe", input_sha256=sha, max_output_size=1024
        )
    assert excinfo.value.code == "output_limit"


def test_run_nrs_maps_a_nonzero_exit(tmp_path: Path) -> None:
    source, sha = _assembly(tmp_path)
    exe = _script(tmp_path, "exit 3")
    with pytest.raises(NetReactorSlayerError) as excinfo:
        run_net_reactor_slayer(exe, source, tmp_path / "out.exe", input_sha256=sha)
    assert excinfo.value.code == "process_failed"
    assert excinfo.value.retryable is True


def test_run_nrs_requires_a_slayed_output(tmp_path: Path) -> None:
    source, sha = _assembly(tmp_path)
    exe = _script(tmp_path, "exit 0")
    with pytest.raises(NetReactorSlayerError) as excinfo:
        run_net_reactor_slayer(exe, source, tmp_path / "out.exe", input_sha256=sha)
    assert excinfo.value.code == "output_missing"


def test_run_nrs_removes_the_destination_on_a_late_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source, sha = _assembly(tmp_path)
    exe = _script(tmp_path, 'cp "$1" "${1%.exe}_Slayed.exe"')
    out = tmp_path / "out.exe"

    def explode(**kwargs: Any) -> nrs.NetReactorSlayerResult:
        raise NetReactorSlayerError("process_failed", "post-copy failure")

    monkeypatch.setattr(nrs, "NetReactorSlayerResult", explode)
    with pytest.raises(NetReactorSlayerError, match="post-copy failure"):
        run_net_reactor_slayer(exe, source, out, input_sha256=sha)
    assert not out.exists()


# ---------------------------------------------------------------------------
# probe_net_reactor_slayer
# ---------------------------------------------------------------------------


def test_probe_nrs_arms(tmp_path: Path) -> None:
    assert probe_net_reactor_slayer(tmp_path / "nope") == (False, "")

    hung = _script(tmp_path, "sleep 2", name="hung.sh")
    assert probe_net_reactor_slayer(hung, timeout=0.2) == (False, "")

    named = _script(tmp_path, "echo NETReactorSlayer 6.0; exit 1", name="named.sh")
    ok, text = probe_net_reactor_slayer(named, timeout=5.0)
    assert ok is True and "NETReactorSlayer" in text

    usage = _script(tmp_path, "echo Usage: slayer FILE; exit 1", name="usage.sh")
    ok, text = probe_net_reactor_slayer(usage, timeout=5.0)
    assert ok is True and "Usage" in text

    chatty = _script(tmp_path, "echo hello there; exit 5", name="chatty.sh")
    ok, text = probe_net_reactor_slayer(chatty, timeout=5.0)
    assert ok is True and text == "hello there"

    silent = _script(tmp_path, "exit 5", name="silent.sh")
    assert probe_net_reactor_slayer(silent, timeout=5.0) == (False, "")
