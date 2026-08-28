"""External optional-backend timeout / abnormal-exit unit coverage."""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from headless_re_mcp.backends.common.bounded_run import Completed, TimedOut
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


def _capture_timeout(captured: dict[str, float]) -> Any:
    """A run_bounded stub that records the timeout it was granted."""

    def fake_run(argv: list[str], *, timeout: float, **kwargs: Any) -> Completed:
        del argv, kwargs
        captured["timeout"] = timeout
        return Completed(returncode=0, stdout=b"", stderr=b"")

    return fake_run


# The windbg.* schemas declare a bounded timeout (300 for dumps, 120 for the
# live probe), but the agent transport calls handlers straight from model
# arguments with no schema enforcement, so the client clamps for itself.
@pytest.mark.parametrize("bad", [0.0, -1.0, float("nan")])
def test_windbg_dump_rejects_a_non_positive_or_nan_timeout(tmp_path: Path, bad: float) -> None:
    dump = tmp_path / "a.dmp"
    dump.write_bytes(b"dump")
    stub = tmp_path / "cdb.exe"
    stub.write_bytes(b"")
    client = WindbgClient(cdb=stub, allow_kernel=False)
    with patch(
        "headless_re_mcp.backends.windbg.client.run_bounded",
        side_effect=AssertionError("cdb must not launch for a bad timeout"),
    ):
        with pytest.raises(WindbgError) as exc:
            client.open_dump(dump, ["lm"], timeout=bad)
    assert exc.value.code == "invalid_params"


@pytest.mark.parametrize("bad", [0.0, -1.0, float("nan")])
def test_windbg_live_rejects_a_non_positive_or_nan_timeout(tmp_path: Path, bad: float) -> None:
    stub = tmp_path / "cdb.exe"
    stub.write_bytes(b"")
    client = WindbgClient(cdb=stub, allow_kernel=False)
    with patch(
        "headless_re_mcp.backends.windbg.client.run_bounded",
        side_effect=AssertionError("cdb must not launch for a bad timeout"),
    ):
        with pytest.raises(WindbgError) as exc:
            client.attach(1234, allowed_pid=1234, timeout=bad)
    assert exc.value.code == "invalid_params"


def test_windbg_dump_caps_an_oversized_timeout(tmp_path: Path) -> None:
    dump = tmp_path / "a.dmp"
    dump.write_bytes(b"dump")
    stub = tmp_path / "cdb.exe"
    stub.write_bytes(b"")
    client = WindbgClient(cdb=stub, allow_kernel=False)
    captured: dict[str, float] = {}
    with patch("headless_re_mcp.backends.windbg.client.run_bounded", _capture_timeout(captured)):
        client.open_dump(dump, ["lm"], timeout=10_000.0)
    assert captured["timeout"] == 300.0


def test_windbg_live_caps_an_oversized_timeout(tmp_path: Path) -> None:
    stub = tmp_path / "cdb.exe"
    stub.write_bytes(b"")
    client = WindbgClient(cdb=stub, allow_kernel=False)
    captured: dict[str, float] = {}
    with patch("headless_re_mcp.backends.windbg.client.run_bounded", _capture_timeout(captured)):
        client.attach(1234, allowed_pid=1234, timeout=10_000.0)
    assert captured["timeout"] == 120.0
