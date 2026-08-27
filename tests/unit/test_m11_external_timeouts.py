"""External optional-backend timeout / abnormal-exit unit coverage."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from headless_re_mcp.backends.apktool import ApktoolClient, ApktoolError
from headless_re_mcp.backends.common.bounded_run import Completed, TimedOut
from headless_re_mcp.backends.jadx import JadxClient, JadxError
from headless_re_mcp.backends.r2.client import R2Client, R2Error
from headless_re_mcp.backends.windbg.client import WindbgClient, WindbgError


def test_r2_timeout_maps_to_timeout(tmp_path: Path) -> None:
    binary = tmp_path / "x.exe"
    binary.write_bytes(b"MZ")
    stub = tmp_path / "r2.exe"
    stub.write_bytes(b"")
    client = R2Client(executable=stub)
    with patch(
        "headless_re_mcp.backends.r2.client.run_bounded",
        side_effect=TimedOut(1.0, [4321]),
    ):
        with pytest.raises(R2Error) as exc:
            client.run(binary, ["i"], timeout=1.0)
    assert exc.value.code == "timeout"
    assert exc.value.details["killed_pids"] == [4321]


def test_r2_nonzero_exit_maps_to_backend_error(tmp_path: Path) -> None:
    binary = tmp_path / "x.exe"
    binary.write_bytes(b"MZ")
    stub = tmp_path / "r2.exe"
    stub.write_bytes(b"")
    client = R2Client(executable=stub)
    fake = Completed(returncode=2, stdout=b"", stderr=b"boom")
    with patch("headless_re_mcp.backends.r2.client.run_bounded", return_value=fake):
        with pytest.raises(R2Error) as exc:
            client.run(binary, ["i"], timeout=1.0)
    assert exc.value.code == "backend_error"


def test_windbg_dump_timeout_maps_to_timeout(tmp_path: Path) -> None:
    dump = tmp_path / "a.dmp"
    dump.write_bytes(b"dump")
    stub = tmp_path / "cdb.exe"
    stub.write_bytes(b"")
    client = WindbgClient(cdb=stub, allow_kernel=False)
    # The bounded runner is the seam now: it kills the tree before it raises, so
    # the timeout a caller sees is the one it reports here.
    with patch(
        "headless_re_mcp.backends.windbg.client.run_bounded",
        side_effect=TimedOut(1.0, [4321]),
    ):
        with pytest.raises(WindbgError) as exc:
            client.open_dump(dump, ["lm"], timeout=1.0)
    assert exc.value.code == "timeout"
    assert exc.value.details["killed_pids"] == [4321]


def test_windbg_live_timeout_maps_to_timeout(tmp_path: Path) -> None:
    stub = tmp_path / "cdb.exe"
    stub.write_bytes(b"")
    client = WindbgClient(cdb=stub, allow_kernel=False)
    with patch(
        "headless_re_mcp.backends.windbg.client.run_bounded",
        side_effect=TimedOut(1.0, [4321]),
    ):
        with pytest.raises(WindbgError) as exc:
            client.attach(1234, allowed_pid=1234, timeout=1.0)
    assert exc.value.code == "timeout"


def test_apktool_timeout_maps_to_timeout(tmp_path: Path) -> None:
    # apktool launches a JVM, so the bounded runner is what kills the tree on a
    # deadline; the client only has to translate that into a timeout the caller
    # can read, carrying the pids the runner had to stop.
    stub = tmp_path / "apktool.bat"
    stub.write_text("@echo off\n", encoding="utf-8")
    apk = tmp_path / "a.apk"
    apk.write_bytes(b"PK\x03\x04")
    client = ApktoolClient(stub, None)
    with patch(
        "headless_re_mcp.backends.apktool.client.run_bounded",
        side_effect=TimedOut(1.0, [4321]),
    ):
        with pytest.raises(ApktoolError) as exc:
            client.decode(apk, tmp_path / "out", timeout=1.0)
    assert exc.value.code == "timeout"
    assert exc.value.details["killed_pids"] == [4321]


def test_jadx_timeout_maps_to_timeout(tmp_path: Path) -> None:
    stub = tmp_path / "jadx"
    stub.write_text("#!/bin/sh\n", encoding="utf-8")
    apk = tmp_path / "a.apk"
    apk.write_bytes(b"PK\x03\x04")
    client = JadxClient(stub)
    with patch(
        "headless_re_mcp.backends.jadx.client.run_bounded",
        side_effect=TimedOut(1.0, [4321]),
    ):
        with pytest.raises(JadxError) as exc:
            client.export_sources(apk, tmp_path / "out", timeout=1.0)
    assert exc.value.code == "timeout"
    assert exc.value.details["killed_pids"] == [4321]
