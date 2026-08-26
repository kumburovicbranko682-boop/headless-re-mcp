"""A run_bounded adapter must map a launch failure to its own backend error.

subprocess.Popen raises OSError when a configured executable is present but
cannot be launched -- a file that is not marked +x raises PermissionError, and
a path that vanished between the is_file() check and the spawn raises
FileNotFoundError. jadx, apktool, jsre and windbg all catch that and re-raise
their own ``backend_error``; r2 and ghidra used to let it propagate, so a
backend misconfiguration reached the service envelope as an ``internal_error``
with a logged incident -- a config problem dressed up as a server defect.

These pin the two adapters that diverged. run_bounded is monkeypatched to raise
the OSError a real non-executable would, which is deterministic and needs no
real tool on the box.

Cross-platform: the except OSError mapping is identical on POSIX and Windows.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

import headless_re_mcp.backends.ghidra.client as ghidra_client
import headless_re_mcp.backends.r2.client as r2_client
import headless_re_mcp.core.ui_ocr as ui_ocr
from headless_re_mcp.backends.ghidra.client import GhidraClient, GhidraError
from headless_re_mcp.backends.r2.client import R2Client, R2Error
from headless_re_mcp.core.ui_ocr import UiPidBoundaryError, ocr_bmp_tesseract


def _nonexecutable_file(path: Path) -> Path:
    # A regular file that exists (passes is_file()) but that Popen cannot exec.
    path.write_bytes(b"not an executable")
    return path


def test_r2_launch_oserror_becomes_backend_error_not_internal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exe = _nonexecutable_file(tmp_path / "r2")
    binary = tmp_path / "sample.bin"
    binary.write_bytes(b"MZ\x00\x00")

    def boom(*_args: Any, **_kwargs: Any) -> Any:
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(r2_client, "run_bounded", boom)

    client = R2Client(executable=exe)
    with pytest.raises(R2Error) as caught:
        client.run(binary, ["i"], timeout=5.0)
    # The whole point: a launch failure is a backend problem, never an
    # unexpected internal error that mints an incident.
    assert caught.value.code == "backend_error"
    assert caught.value.code != "internal_error"


def test_ghidra_launch_oserror_becomes_backend_error_not_internal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "ghidra"
    (home / "support").mkdir(parents=True)
    (home / "support" / "analyzeHeadless.bat").write_text("@echo off\n", encoding="utf-8")
    client = GhidraClient(home=home)
    client.java = _nonexecutable_file(tmp_path / "java")
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")

    def boom(*_args: Any, **_kwargs: Any) -> Any:
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(ghidra_client, "run_bounded", boom)

    with pytest.raises(GhidraError) as caught:
        client.analyze_binary(binary, tmp_path / "project")
    assert caught.value.code == "backend_error"
    assert caught.value.code != "internal_error"


def test_tesseract_launch_oserror_becomes_backend_error_not_internal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """backend="tesseract" must not turn a bad binary into an internal fault.

    In backend="auto" the fallback chain's except Exception swallowed the
    OSError, which is why only the explicit-backend path ever showed it.
    """
    exe = _nonexecutable_file(tmp_path / "tesseract")
    bmp = tmp_path / "shot.bmp"
    bmp.write_bytes(b"BM" + b"\x00" * 64)

    def boom(*_args: Any, **_kwargs: Any) -> Any:
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(ui_ocr, "run_bounded", boom)

    with pytest.raises(UiPidBoundaryError) as caught:
        ocr_bmp_tesseract(bmp, tesseract=exe)
    assert caught.value.code == "backend_error"
    assert caught.value.code != "internal_error"
