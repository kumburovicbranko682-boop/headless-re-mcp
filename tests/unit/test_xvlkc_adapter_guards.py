"""Input-validation and mid-run guard branches for the XVLKC adapter.

Complements ``test_xvlkc_adapter.py`` (which drives the fail-closed contract
with a fake CLI). These pin the caller-bound validation, the fix that turns a
missing input into a structured ``input_not_found`` instead of a raw
``FileNotFoundError``, and the cancel / mid-run integrity / output-limit
branches, which are easier to reach by stubbing the captured subprocess.
"""

from __future__ import annotations

import os
import struct
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from headless_re_mcp.backends.common.bounded_run import BoundedCancelled
from headless_re_mcp.core.session import file_sha256
from headless_re_mcp.unpack import xvlkc as xvlkc_mod
from headless_re_mcp.unpack.xvlkc import (
    XvlkcError,
    XvlkcErrorCode,
    _collect_newest_pe,
    probe_xvlkc,
    run_xvlkc,
)

posix_only = pytest.mark.skipif(os.name == "nt", reason="relies on POSIX exec semantics")


def _write_pe(path: Path, tag: bytes = b"\x00") -> Path:
    image = bytearray(0x80)
    image[:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, 0x40)
    image[0x40:0x44] = b"PE\0\0"
    image[0x44:0x45] = tag
    path.write_bytes(bytes(image))
    return path


def _capture(**overrides: Any) -> SimpleNamespace:
    base: dict[str, Any] = {
        "stdout": "",
        "stderr": "",
        "returncode": 0,
        "stdout_exceeded": False,
        "stderr_exceeded": False,
    }
    base.update(overrides)
    return SimpleNamespace(**base)


# --- the missing-input bug fix ------------------------------------------------


def test_run_reports_a_missing_input_as_structured_not_found(tmp_path: Path) -> None:
    exe = tmp_path / "xvlkc"
    exe.write_bytes(b"fake")
    # A path that does not exist at all: resolve() must not leak FileNotFoundError.
    with pytest.raises(XvlkcError) as caught:
        run_xvlkc(
            exe,
            tmp_path / "does-not-exist.exe",
            tmp_path / "out.exe",
            input_sha256="0" * 64,
        )
    assert caught.value.code == XvlkcErrorCode.INPUT_NOT_FOUND


# --- caller-supplied bound validation ----------------------------------------


@pytest.mark.parametrize(
    ("kwargs", "needle"),
    [
        ({"timeout": 0}, "timeout"),
        ({"timeout": -1.0}, "timeout"),
        ({"max_file_size": 0}, "max_file_size"),
        ({"max_file_size": -5}, "max_file_size"),
        ({"max_output_size": 0}, "max_output_size"),
        ({"max_output_size": -1}, "max_output_size"),
    ],
)
def test_run_rejects_non_positive_bounds(
    tmp_path: Path, kwargs: dict[str, Any], needle: str
) -> None:
    with pytest.raises(XvlkcError) as caught:
        run_xvlkc(
            tmp_path / "xvlkc",
            tmp_path / "in.exe",
            tmp_path / "out.exe",
            input_sha256="0" * 64,
            **kwargs,
        )
    assert caught.value.code == XvlkcErrorCode.INVALID_ARGUMENT
    assert needle in str(caught.value)


# --- _collect_newest_pe skips non-file entries --------------------------------


def test_collect_newest_pe_ignores_subdirectories(tmp_path: Path) -> None:
    work = tmp_path / "work"
    work.mkdir()
    work_input = _write_pe(work / "input.exe")
    (work / "nested").mkdir()  # a directory rglob yields but must skip
    produced = _write_pe(work / "unpacked.exe")
    assert _collect_newest_pe(work, work_input) == produced


# --- mid-run guards via a stubbed capture ------------------------------------


def _prepare(tmp_path: Path) -> tuple[Path, Path, Path, str]:
    exe = tmp_path / "xvlkc"
    exe.write_bytes(b"fake")
    src = _write_pe(tmp_path / "in.exe", tag=b"\x01")
    dest = tmp_path / "out" / "result.exe"
    return exe, src, dest, file_sha256(src)


def test_run_propagates_a_bounded_cancel(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exe, src, dest, digest = _prepare(tmp_path)

    def cancel(*_a: Any, **_k: Any) -> Any:
        raise BoundedCancelled()

    monkeypatch.setattr(xvlkc_mod, "_capture_process", cancel)
    with pytest.raises(BoundedCancelled):
        run_xvlkc(exe, src, dest, input_sha256=digest)
    assert not dest.exists()


def test_run_detects_input_mutated_during_the_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exe, src, dest, digest = _prepare(tmp_path)

    def mutate(_argv: list[str], **_k: Any) -> SimpleNamespace:
        src.write_bytes(b"tampered-by-tool")
        return _capture()

    monkeypatch.setattr(xvlkc_mod, "_capture_process", mutate)
    with pytest.raises(XvlkcError) as caught:
        run_xvlkc(exe, src, dest, input_sha256=digest)
    assert caught.value.code == XvlkcErrorCode.INPUT_MUTATED
    assert not dest.exists()


def test_run_flags_output_limit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    exe, src, dest, digest = _prepare(tmp_path)
    monkeypatch.setattr(
        xvlkc_mod, "_capture_process", lambda *_a, **_k: _capture(stdout_exceeded=True)
    )
    with pytest.raises(XvlkcError) as caught:
        run_xvlkc(exe, src, dest, input_sha256=digest)
    assert caught.value.code == XvlkcErrorCode.OUTPUT_LIMIT
    assert not dest.exists()


def test_run_maps_a_process_error_to_structured_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exe, src, dest, digest = _prepare(tmp_path)

    def fail(*_a: Any, **_k: Any) -> Any:
        raise XvlkcError(
            XvlkcErrorCode.TIMEOUT,
            "xvlkc did not finish",
            stdout="partial",
            stderr="slow",
            returncode=None,
            retryable=True,
        )

    monkeypatch.setattr(xvlkc_mod, "_capture_process", fail)
    with pytest.raises(XvlkcError) as caught:
        run_xvlkc(exe, src, dest, input_sha256=digest)
    # The adapter re-wraps the captured error, preserving its code and streams.
    assert caught.value.code == XvlkcErrorCode.TIMEOUT
    assert caught.value.stdout == "partial"
    assert caught.value.retryable is True


@posix_only
def test_probe_tolerates_a_present_but_unrunnable_executable(tmp_path: Path) -> None:
    # Present on disk but not executable: run_bounded raises OSError, which the
    # best-effort probe swallows into a not-present result rather than raising.
    exe = tmp_path / "xvlkc"
    exe.write_bytes(b"not runnable")
    exe.chmod(0o644)
    ok, text = probe_xvlkc(exe, timeout=5)
    assert ok is False
    assert text == ""
