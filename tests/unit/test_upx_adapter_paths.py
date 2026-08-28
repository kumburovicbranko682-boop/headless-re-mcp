"""Coverage for the UPX adapter's guard, mutation, cleanup, and capture arms.

Real fake ``upx`` shell scripts (answering ``--version`` and then the
whitelisted ``-t`` / ``-d -o`` argv) drive the outcome arms; the capture
internals are exercised directly.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from threading import Event
from typing import Any, BinaryIO, cast

import pytest

import headless_re_mcp.unpack.upx as upx
from headless_re_mcp.backends.common.bounded_run import BoundedCancelled, bound_cancel_scope
from headless_re_mcp.core.session import file_sha256
from headless_re_mcp.unpack.upx import (
    UpxExecutableNotFoundError,
    UpxInputNotFoundError,
    UpxInputTooLargeError,
    UpxProcessError,
    UpxScanError,
    UpxTimeoutError,
    copy_input_for_safe_pack,
    probe_upx_version,
    unpack_upx,
)
from headless_re_mcp.unpack.upx import test_upx as run_upx_test

pytestmark = pytest.mark.skipif(os.name == "nt", reason="fake upx is a POSIX shell script")

_VERSION_GUARD = 'if [ "$1" = "--version" ]; then echo "upx 4.2.4"; exit 0; fi'


def _fake_upx(tmp_path: Path, *, body: str, name: str = "upx.sh") -> Path:
    script = tmp_path / name
    script.write_text(f"#!/bin/sh\n{_VERSION_GUARD}\n{body}\n")
    script.chmod(0o755)
    return script


def _packed(tmp_path: Path) -> tuple[Path, str]:
    path = tmp_path / "packed.exe"
    path.write_bytes(b"MZ\x90\x00UPX!")
    return path, file_sha256(path)


# ---------------------------------------------------------------------------
# guards and small helpers
# ---------------------------------------------------------------------------


def test_input_not_found_error_uses_the_default_message() -> None:
    assert "does not exist" in str(UpxInputNotFoundError(Path("/x")))
    assert str(UpxInputNotFoundError(Path("/x"), "custom")) == "custom"


def test_validate_paths_guards(tmp_path: Path) -> None:
    exe = _fake_upx(tmp_path, body="exit 0")
    packed, _sha = _packed(tmp_path)
    with pytest.raises(UpxExecutableNotFoundError):
        upx._validate_paths(tmp_path / "nope", packed, max_file_size=1024)
    with pytest.raises(UpxInputNotFoundError):
        upx._validate_paths(exe, tmp_path / "nope", max_file_size=1024)
    with pytest.raises(UpxInputTooLargeError):
        upx._validate_paths(exe, packed, max_file_size=1)


def test_probe_upx_version_requires_the_executable(tmp_path: Path) -> None:
    with pytest.raises(UpxExecutableNotFoundError):
        probe_upx_version(tmp_path / "nope")


def test_copy_input_for_safe_pack_creates_parents(tmp_path: Path) -> None:
    source, _sha = _packed(tmp_path)
    copied = copy_input_for_safe_pack(source, tmp_path / "work" / "copy.exe")
    assert copied.read_bytes() == source.read_bytes()


# ---------------------------------------------------------------------------
# capture internals
# ---------------------------------------------------------------------------


class _ChunkPipe:
    def __init__(self, chunks: list[bytes]) -> None:
        self._chunks = list(chunks)

    def read(self, size: int) -> bytes:
        return self._chunks.pop(0) if self._chunks else b""

    def close(self) -> None:
        return None


class _ExplodingPipe:
    def read(self, size: int) -> bytes:
        raise OSError("torn down")

    def close(self) -> None:
        return None


def test_captured_stream_limit_and_error_arms() -> None:
    stream = upx._CapturedStream(4)
    exceeded = Event()
    stream.read_from(cast(BinaryIO, _ChunkPipe([b"abcdef", b"gh", b""])), exceeded)
    assert bytes(stream.data) == b"abcd"
    assert stream.exceeded and exceeded.is_set()

    other = upx._CapturedStream(4)
    other.read_from(cast(BinaryIO, _ExplodingPipe()), Event())
    assert other.finished.is_set()


def test_creation_options_hides_the_console_on_windows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _StartupInfo:
        def __init__(self) -> None:
            self.dwFlags = 0
            self.wShowWindow = -1

    monkeypatch.setattr(os, "name", "nt")
    monkeypatch.setattr(subprocess, "STARTUPINFO", _StartupInfo, raising=False)
    options = upx._creation_options()
    assert options["startupinfo"].wShowWindow == 0
    assert "start_new_session" not in options

    monkeypatch.delattr(subprocess, "STARTUPINFO", raising=False)
    assert "startupinfo" not in upx._creation_options()


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
    with pytest.raises(UpxProcessError, match="did not expose stdout/stderr"):
        upx._capture_process(["upx"], timeout=1.0, max_output_size=1024)


def test_capture_process_defaults_an_unknown_exit_code(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A handle whose poll() never reports an exit exercises the timeout kill
    # and the returncode fallback to -1.
    class _Undead:
        pid = None

        def __init__(self, argv: object, **options: object) -> None:
            self.stdout = _ChunkPipe([b""])
            self.stderr = _ChunkPipe([b""])

        def poll(self) -> None:
            return None

        def wait(self, timeout: float | None = None) -> int:
            raise subprocess.TimeoutExpired(cmd="upx", timeout=timeout or 0.0)

        def kill(self) -> None:
            return None

    monkeypatch.setattr(subprocess, "Popen", _Undead)
    with pytest.raises(UpxTimeoutError) as excinfo:
        upx._capture_process(["upx"], timeout=0.2, max_output_size=1024)
    assert excinfo.value.returncode == -1


def test_capture_process_wraps_a_process_start_error(tmp_path: Path) -> None:
    not_executable = tmp_path / "upx.txt"
    not_executable.write_text("not a program\n")
    with pytest.raises(UpxProcessError, match="could not start upx"):
        upx._capture_process([str(not_executable)], timeout=1.0, max_output_size=1024)
    with pytest.raises(UpxExecutableNotFoundError):
        upx._capture_process([str(tmp_path / "gone")], timeout=1.0, max_output_size=1024)


def test_capture_process_honors_a_pre_set_cancel(tmp_path: Path) -> None:
    slow = _fake_upx(tmp_path, body="sleep 5", name="slow.sh")
    cancel = Event()
    cancel.set()
    with bound_cancel_scope(cancel), pytest.raises(BoundedCancelled):
        upx._capture_process([str(slow)], timeout=10.0, max_output_size=1024)


def test_capture_process_kills_a_stderr_flooder(tmp_path: Path) -> None:
    flooder = _fake_upx(
        tmp_path, body="head -c 200000 /dev/zero 1>&2; sleep 2", name="flood.sh"
    )
    with pytest.raises(upx.UpxOutputLimitError) as excinfo:
        upx._capture_process([str(flooder)], timeout=5.0, max_output_size=1024)
    assert excinfo.value.details["stream"] == "stderr"


# ---------------------------------------------------------------------------
# test_upx / unpack_upx outcome arms
# argv: [exe, -t, input] and [exe, -d, -o, output, input]
# ---------------------------------------------------------------------------


def test_test_upx_detects_a_mutated_input(tmp_path: Path) -> None:
    exe = _fake_upx(tmp_path, body='echo tampered >> "$2"; exit 0')
    packed, sha = _packed(tmp_path)
    with pytest.raises(UpxScanError) as excinfo:
        run_upx_test(exe, packed, input_sha256=sha)
    assert excinfo.value.code == "input_mutated"


def test_unpack_upx_rejects_a_stale_input_hash(tmp_path: Path) -> None:
    exe = _fake_upx(tmp_path, body="exit 0")
    packed, _sha = _packed(tmp_path)
    with pytest.raises(UpxScanError) as excinfo:
        unpack_upx(exe, packed, tmp_path / "out.exe", input_sha256="0" * 64)
    assert excinfo.value.code == "input_mutated"


def test_unpack_upx_cleans_up_when_the_input_is_mutated(tmp_path: Path) -> None:
    exe = _fake_upx(tmp_path, body='cp "$4" "$3"; echo tampered >> "$4"; exit 0')
    packed, sha = _packed(tmp_path)
    out = tmp_path / "out.exe"
    with pytest.raises(UpxScanError) as excinfo:
        unpack_upx(exe, packed, out, input_sha256=sha)
    assert excinfo.value.code == "input_mutated"
    assert not out.exists()


def test_unpack_upx_cleans_up_a_failed_decompression(tmp_path: Path) -> None:
    exe = _fake_upx(tmp_path, body='cp "$4" "$3"; exit 2')
    packed, sha = _packed(tmp_path)
    out = tmp_path / "out.exe"
    with pytest.raises(UpxProcessError, match="exit status 2"):
        unpack_upx(exe, packed, out, input_sha256=sha)
    assert not out.exists()


def test_unpack_upx_mutation_arm_tolerates_a_missing_output(tmp_path: Path) -> None:
    exe = _fake_upx(tmp_path, body='echo tampered >> "$4"; exit 0')
    packed, sha = _packed(tmp_path)
    with pytest.raises(UpxScanError) as excinfo:
        unpack_upx(exe, packed, tmp_path / "out.exe", input_sha256=sha)
    assert excinfo.value.code == "input_mutated"


def test_unpack_upx_failure_arm_tolerates_a_missing_output(tmp_path: Path) -> None:
    exe = _fake_upx(tmp_path, body="exit 3")
    packed, sha = _packed(tmp_path)
    with pytest.raises(UpxProcessError, match="exit status 3"):
        unpack_upx(exe, packed, tmp_path / "out.exe", input_sha256=sha)


def test_unpack_upx_requires_the_output_to_appear(tmp_path: Path) -> None:
    exe = _fake_upx(tmp_path, body="exit 0")
    packed, sha = _packed(tmp_path)
    with pytest.raises(UpxScanError) as excinfo:
        unpack_upx(exe, packed, tmp_path / "out.exe", input_sha256=sha)
    assert excinfo.value.code == "output_missing"


def test_unpack_upx_rejects_an_oversized_output(tmp_path: Path) -> None:
    exe = _fake_upx(tmp_path, body='head -c 400 /dev/zero > "$3"; exit 0')
    packed, sha = _packed(tmp_path)
    out = tmp_path / "out.exe"
    with pytest.raises(UpxInputTooLargeError):
        unpack_upx(exe, packed, out, input_sha256=sha, max_file_size=100)
    assert not out.exists()


def test_unpack_upx_success_reports_both_hashes(tmp_path: Path) -> None:
    exe = _fake_upx(tmp_path, body='cp "$4" "$3"; exit 0')
    packed, sha = _packed(tmp_path)
    result = unpack_upx(exe, packed, tmp_path / "deob" / "out.exe", input_sha256=sha)
    assert result.ok is True
    assert result.version == "4.2.4"
    assert result.output_sha256 == sha
    payload: dict[str, Any] = result.to_dict()
    assert payload["operation"] == "unpack"
