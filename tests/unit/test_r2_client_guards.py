"""R2Client input validation and error-mapping guards.

The command whitelist (test_r2_command_whitelist) and the address enrichment
(test_r2_disasm_fields) are covered elsewhere; this pins the client-level
robustness guards that turn a bad request or a launch failure into a structured
R2Error instead of letting it reach the service envelope as an internal_error:

* disasm/xrefs reject a non-int or negative address, and disasm bounds count,
  before any command is built or process spawned;
* run maps a missing capability, a missing binary, an un-launchable executable
  (OSError), and a non-zero exit onto the R2Error codes the service maps to
  capability_unavailable / not_found / backend_error.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

import headless_re_mcp.backends.r2.client as r2_module
from headless_re_mcp.backends.common.bounded_run import Completed
from headless_re_mcp.backends.r2.client import R2Client, R2Error


def _client_and_binary(tmp_path: Path) -> tuple[R2Client, Path]:
    executable = tmp_path / "r2.exe"
    executable.write_bytes(b"")
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    return R2Client(executable), binary


@pytest.mark.parametrize("bad_address", [-1, True, 1.5, "0x1000", None])
def test_disasm_rejects_a_bad_address_before_spawning(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, bad_address: object
) -> None:
    client, binary = _client_and_binary(tmp_path)

    def fail(*args: Any, **kwargs: Any) -> Completed:  # pragma: no cover - must not run
        raise AssertionError("run_bounded must not be reached on a bad address")

    monkeypatch.setattr(r2_module, "run_bounded", fail)
    with pytest.raises(R2Error) as caught:
        client.disasm(binary, bad_address)  # type: ignore[arg-type]
    assert caught.value.code == "invalid_params"


@pytest.mark.parametrize("bad_count", [0, -5, 513, 1000, True, 2.0])
def test_disasm_bounds_the_instruction_count(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, bad_count: object
) -> None:
    client, binary = _client_and_binary(tmp_path)

    def fail(*args: Any, **kwargs: Any) -> Completed:  # pragma: no cover - must not run
        raise AssertionError("run_bounded must not be reached on a bad count")

    monkeypatch.setattr(r2_module, "run_bounded", fail)
    with pytest.raises(R2Error) as caught:
        client.disasm(binary, 0x1000, count=bad_count)  # type: ignore[arg-type]
    assert caught.value.code == "invalid_params"


@pytest.mark.parametrize("bad_address", [-1, True, 1.5, "0x1000", None])
def test_xrefs_rejects_a_bad_address_before_spawning(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, bad_address: object
) -> None:
    client, binary = _client_and_binary(tmp_path)

    def fail(*args: Any, **kwargs: Any) -> Completed:  # pragma: no cover - must not run
        raise AssertionError("run_bounded must not be reached on a bad address")

    monkeypatch.setattr(r2_module, "run_bounded", fail)
    with pytest.raises(R2Error) as caught:
        client.xrefs(binary, bad_address)  # type: ignore[arg-type]
    assert caught.value.code == "invalid_params"


def test_run_reports_capability_unavailable_without_an_executable(tmp_path: Path) -> None:
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    # A configured path that is not a file: available is False, so the client
    # never tries to spawn a missing tool.
    client = R2Client(tmp_path / "does-not-exist-r2")
    with pytest.raises(R2Error) as caught:
        client.run(binary, ["i"])
    assert caught.value.code == "capability_unavailable"


def test_run_reports_not_found_for_a_missing_binary(tmp_path: Path) -> None:
    executable = tmp_path / "r2.exe"
    executable.write_bytes(b"")
    client = R2Client(executable)
    with pytest.raises(R2Error) as caught:
        client.run(tmp_path / "absent.exe", ["i"])
    assert caught.value.code == "not_found"


def test_run_maps_a_launch_oserror_to_backend_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client, binary = _client_and_binary(tmp_path)

    def raise_oserror(*args: Any, **kwargs: Any) -> Completed:
        raise PermissionError("exec format error")

    monkeypatch.setattr(r2_module, "run_bounded", raise_oserror)
    with pytest.raises(R2Error) as caught:
        client.run(binary, ["i"])
    assert caught.value.code == "backend_error"


def test_run_maps_a_nonzero_exit_to_backend_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client, binary = _client_and_binary(tmp_path)

    def nonzero(*args: Any, **kwargs: Any) -> Completed:
        return Completed(3, b"", b"r2: fatal")

    monkeypatch.setattr(r2_module, "run_bounded", nonzero)
    with pytest.raises(R2Error) as caught:
        client.run(binary, ["i"])
    assert caught.value.code == "backend_error"
    assert caught.value.details.get("exit_code") == 3


def test_open_reports_not_found_for_a_missing_binary(tmp_path: Path) -> None:
    executable = tmp_path / "r2.exe"
    executable.write_bytes(b"")
    client = R2Client(executable)
    with pytest.raises(R2Error) as caught:
        client.open(tmp_path / "absent.exe")
    assert caught.value.code == "not_found"
