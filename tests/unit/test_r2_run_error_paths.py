"""r2 run(): the two failure paths a corrupt binary or a broken install take.

The r2 client's success and truncation paths are pinned, but the two error
exits of ``run`` are not: a non-zero r2 exit (a corrupt or unsupported binary)
and an ``OSError`` at launch (an executable present but not runnable -- not +x,
or swapped out between the ``is_file`` check and the spawn). Both must surface
as ``backend_error`` -- the non-zero exit carrying its ``exit_code`` and a
decoded, bounded ``stderr``, the launch failure naming the executable -- so a
backend misconfiguration or a bad input never reaches the envelope as an
``internal_error`` incident. No test drives either path today.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.r2 import client as r2_client
from headless_re_mcp.backends.r2.client import R2Client, R2Error


class _Completed:
    def __init__(self, returncode: int, stdout: bytes, stderr: bytes) -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def _client(tmp_path: Path) -> tuple[R2Client, Path]:
    binary = tmp_path / "target.elf"
    binary.write_bytes(b"\x7fELF" + b"\x00" * 60)
    exe = tmp_path / "r2"
    exe.write_text("#!/bin/sh\n")
    exe.chmod(0o755)
    return R2Client(exe), binary


def test_a_non_zero_exit_is_a_backend_error_that_carries_the_exit_code(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """r2 exiting non-zero (corrupt/unsupported binary) must raise, not return.

    The success path builds a payload with ``raw``; if the returncode guard were
    dropped, a failed run would hand back that payload and a caller would read
    partial stdout as a complete analysis. Pin the raise and the exit_code.
    """
    client, binary = _client(tmp_path)
    monkeypatch.setattr(
        r2_client,
        "run_bounded",
        lambda *a, **k: _Completed(returncode=3, stdout=b"partial output", stderr=b"boom"),
    )

    with pytest.raises(R2Error) as caught:
        client.run(binary, ["i"], timeout=5.0)

    assert caught.value.code == "backend_error"
    assert caught.value.details["exit_code"] == 3


def test_the_non_zero_exit_stderr_is_decoded_and_bounded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """stderr rides along as text, capped at 2000 chars and decoded leniently.

    A verbose r2 failure can print megabytes; the error detail must not carry it
    all, and invalid UTF-8 in the diagnostic must not turn a clean backend_error
    into an uncaught UnicodeDecodeError. Feed 5000 bytes with a non-UTF-8 lead.
    """
    client, binary = _client(tmp_path)
    noisy = b"\xff\xfe" + b"E" * 4998
    monkeypatch.setattr(
        r2_client,
        "run_bounded",
        lambda *a, **k: _Completed(returncode=1, stdout=b"", stderr=noisy),
    )

    with pytest.raises(R2Error) as caught:
        client.run(binary, ["i"], timeout=5.0)

    stderr = caught.value.details["stderr"]
    assert isinstance(stderr, str)
    assert len(stderr) == 2000
    # Lenient decode turned the bad lead bytes into replacement chars, no crash.
    assert "\ufffd" in stderr


def test_a_launch_oserror_is_a_backend_error_not_an_internal_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An executable that passes is_file() but cannot be spawned (not +x, or
    replaced under us) makes Popen raise OSError. r2 must map that to
    backend_error naming the executable, like its sibling adapters -- letting it
    escape would log a server incident for a backend misconfiguration.
    """
    client, binary = _client(tmp_path)

    def boom(*args: Any, **kwargs: Any) -> Any:
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(r2_client, "run_bounded", boom)

    with pytest.raises(R2Error) as caught:
        client.run(binary, ["i"], timeout=5.0)

    assert caught.value.code == "backend_error"
    assert "failed to launch" in caught.value.message


def test_a_real_unspawnable_executable_maps_to_backend_error_not_a_raw_oserror() -> None:
    """Guard the mapping end to end without a stub: a plain file that passes
    is_file() but carries no execute bit spawns with a genuine PermissionError
    from Popen. The caller must see only R2Error(backend_error), never the raw
    OSError -- which would reach the envelope as an internal_error incident.
    """
    if os.name == "nt":
        pytest.skip("no execute-bit permission model on Windows (skip != pass)")
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        binary = root / "target.elf"
        binary.write_bytes(b"\x7fELF" + b"\x00" * 60)
        # is_file() is True (availability passes), but 0o644 has no +x, so the
        # spawn raises PermissionError -- an OSError subclass.
        not_exec = root / "r2noexec"
        not_exec.write_text("not a program\n")
        not_exec.chmod(0o644)
        client = R2Client(not_exec)
        assert client.available is True
        with pytest.raises(R2Error) as caught:
            client.run(binary, ["i"], timeout=5.0)
        assert caught.value.code == "backend_error"
        assert "failed to launch" in caught.value.message
