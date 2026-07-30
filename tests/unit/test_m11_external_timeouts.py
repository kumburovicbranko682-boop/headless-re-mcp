"""External optional-backend timeout / abnormal-exit unit coverage."""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from headless_re_mcp.backends.r2.client import R2Client, R2Error
from headless_re_mcp.backends.windbg.client import WindbgClient, WindbgError


def test_r2_timeout_maps_to_timeout(tmp_path: Path) -> None:
    binary = tmp_path / "x.exe"
    binary.write_bytes(b"MZ")
    stub = tmp_path / "r2.exe"
    stub.write_bytes(b"")
    client = R2Client(executable=stub)
    with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="r2", timeout=1)):
        with pytest.raises(R2Error) as exc:
            client.run(binary, ["i"], timeout=1.0)
    assert exc.value.code == "timeout"


def test_r2_nonzero_exit_maps_to_backend_error(tmp_path: Path) -> None:
    binary = tmp_path / "x.exe"
    binary.write_bytes(b"MZ")
    stub = tmp_path / "r2.exe"
    stub.write_bytes(b"")
    client = R2Client(executable=stub)
    fake = subprocess.CompletedProcess(args=["r2"], returncode=2, stdout=b"", stderr=b"boom")
    with patch("subprocess.run", return_value=fake), pytest.raises(R2Error) as exc:
        client.run(binary, ["i"], timeout=1.0)
    assert exc.value.code == "backend_error"


def test_windbg_dump_timeout_maps_to_timeout(tmp_path: Path) -> None:
    dump = tmp_path / "a.dmp"
    dump.write_bytes(b"dump")
    stub = tmp_path / "cdb.exe"
    stub.write_bytes(b"")
    client = WindbgClient(cdb=stub, allow_kernel=False)
    with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="cdb", timeout=1)):
        with pytest.raises(WindbgError) as exc:
            client.open_dump(dump, ["lm"], timeout=1.0)
    assert exc.value.code == "timeout"


def test_windbg_live_timeout_maps_to_timeout(tmp_path: Path) -> None:
    stub = tmp_path / "cdb.exe"
    stub.write_bytes(b"")
    client = WindbgClient(cdb=stub, allow_kernel=False)
    with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="cdb", timeout=1)):
        with pytest.raises(WindbgError) as exc:
            client.attach(1234, allowed_pid=1234, timeout=1.0)
    assert exc.value.code == "timeout"
