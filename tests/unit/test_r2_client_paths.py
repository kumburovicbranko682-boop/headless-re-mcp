"""Branch coverage for the radare2/rizin one-shot backend.

r2 is usually absent on CI, so the query methods are exercised by pointing the
client at a real (empty) executable file and replacing run_bounded with a fake
completed process. That drives the validate -> run -> enrich_r2_payload path
without a real radare2, plus the not-found / unavailable / discovery arms.
"""

from __future__ import annotations

import shutil
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from headless_re_mcp.backends.common.bounded_run import TimedOut
from headless_re_mcp.backends.r2 import client as r2_mod
from headless_re_mcp.backends.r2.client import (
    R2Client,
    R2Error,
    _discover,
    _require_allowed_command,
)


def _exe(tmp_path: Path) -> Path:
    path = tmp_path / "r2"
    path.write_bytes(b"#!/bin/sh\n")
    return path


def _binary(tmp_path: Path) -> Path:
    # A tiny non-PE file: enrich_r2_payload reads the header and shrugs.
    path = tmp_path / "sample.bin"
    path.write_bytes(b"PK\x03\x04")
    return path


def _fake_run(stdout: bytes = b"[]", *, returncode: int = 0, stderr: bytes = b"") -> Any:
    def run(cmd: list[str], *, timeout: float, creationflags: int) -> Any:
        return SimpleNamespace(stdout=stdout, stderr=stderr, returncode=returncode)

    return run


# ---------------------------------------------------------------------------
# open
# ---------------------------------------------------------------------------


def test_open_reports_a_missing_binary(tmp_path: Path) -> None:
    client = R2Client(executable=_exe(tmp_path))
    with pytest.raises(R2Error) as caught:
        client.open(tmp_path / "absent.bin")
    assert caught.value.code == "not_found"


def test_open_validates_and_summarises(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(r2_mod, "run_bounded", _fake_run(stdout=b"arch x86\n"))
    client = R2Client(executable=_exe(tmp_path))
    payload = client.open(_binary(tmp_path))
    assert payload["opened"] is True
    assert "arch x86" in payload["info"]


# ---------------------------------------------------------------------------
# disasm
# ---------------------------------------------------------------------------


def test_disasm_rejects_bad_address_and_count(tmp_path: Path) -> None:
    client = R2Client(executable=_exe(tmp_path))
    binary = _binary(tmp_path)
    with pytest.raises(R2Error) as neg:
        client.disasm(binary, -1)
    assert neg.value.code == "invalid_params"
    with pytest.raises(R2Error) as zero:
        client.disasm(binary, 0, count=0)
    assert zero.value.code == "invalid_params"
    with pytest.raises(R2Error) as big:
        client.disasm(binary, 0, count=513)
    assert big.value.code == "invalid_params"


def test_disasm_runs_and_enriches(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(r2_mod, "run_bounded", _fake_run(stdout=b"[]"))
    client = R2Client(executable=_exe(tmp_path))
    payload = client.disasm(_binary(tmp_path), 0x401000, count=4)
    # enrich_r2_payload recomputes count from the parsed listing, so the empty
    # instruction list reports zero rather than the requested window.
    assert payload["address_va"] == 0x401000
    assert payload["parsed"] is True
    assert payload["items"] == []
    assert payload["count"] == 0


# ---------------------------------------------------------------------------
# xrefs
# ---------------------------------------------------------------------------


def test_xrefs_rejects_a_negative_address(tmp_path: Path) -> None:
    client = R2Client(executable=_exe(tmp_path))
    with pytest.raises(R2Error) as caught:
        client.xrefs(_binary(tmp_path), -5)
    assert caught.value.code == "invalid_params"


def test_xrefs_runs_and_enriches(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        r2_mod,
        "run_bounded",
        _fake_run(stdout=b'[{"from":4198400,"to":4198656}]'),
    )
    client = R2Client(executable=_exe(tmp_path))
    payload = client.xrefs(_binary(tmp_path), 0x401000)
    assert payload["address_va"] == 0x401000
    assert payload["parsed"] is True
    assert payload["count"] == 1
    assert "from_address" in payload["items"][0]


# ---------------------------------------------------------------------------
# run guards
# ---------------------------------------------------------------------------


def test_run_without_an_executable_is_capability_unavailable(tmp_path: Path) -> None:
    client = R2Client(executable=None)
    assert client.available is False
    with pytest.raises(R2Error) as caught:
        client.run(_binary(tmp_path), ["i"])
    assert caught.value.code == "capability_unavailable"


def test_run_reports_a_missing_binary(tmp_path: Path) -> None:
    client = R2Client(executable=_exe(tmp_path))
    assert client.available is True
    with pytest.raises(R2Error) as caught:
        client.run(tmp_path / "absent.bin", ["i"])
    assert caught.value.code == "not_found"


def test_run_rejects_an_invalid_timeout(tmp_path: Path) -> None:
    client = R2Client(executable=_exe(tmp_path))
    with pytest.raises(R2Error) as caught:
        client.run(_binary(tmp_path), ["i"], timeout=0)
    assert caught.value.code == "invalid_params"


def test_run_maps_a_timeout_to_its_killed_pids(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def raise_timeout(cmd: list[str], *, timeout: float, creationflags: int) -> Any:
        raise TimedOut(timeout=timeout, killed=[321])

    monkeypatch.setattr(r2_mod, "run_bounded", raise_timeout)
    client = R2Client(executable=_exe(tmp_path))
    with pytest.raises(R2Error) as caught:
        client.run(_binary(tmp_path), ["i"])
    assert caught.value.code == "timeout"
    assert caught.value.details["killed_pids"] == [321]


def test_run_maps_a_launch_oserror_to_backend_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def raise_oserror(cmd: list[str], *, timeout: float, creationflags: int) -> Any:
        raise PermissionError("not executable")

    monkeypatch.setattr(r2_mod, "run_bounded", raise_oserror)
    client = R2Client(executable=_exe(tmp_path))
    with pytest.raises(R2Error) as caught:
        client.run(_binary(tmp_path), ["i"])
    assert caught.value.code == "backend_error"
    assert "failed to launch" in caught.value.message


def test_run_reports_a_nonzero_exit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(r2_mod, "run_bounded", _fake_run(stdout=b"", returncode=2, stderr=b"boom"))
    client = R2Client(executable=_exe(tmp_path))
    with pytest.raises(R2Error) as caught:
        client.run(_binary(tmp_path), ["i"])
    assert caught.value.code == "backend_error"
    assert caught.value.details["exit_code"] == 2
    assert "boom" in str(caught.value.details["stderr"])


def test_run_flags_truncated_output(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(r2_mod, "_MAX_OUTPUT", 4)
    monkeypatch.setattr(r2_mod, "run_bounded", _fake_run(stdout=b"abcdefgh"))
    client = R2Client(executable=_exe(tmp_path))
    payload = client.run(_binary(tmp_path), ["i"])
    assert payload["truncated"] is True
    assert payload["output_bytes"] == 8
    assert payload["returned_bytes"] == 4


# ---------------------------------------------------------------------------
# command whitelist
# ---------------------------------------------------------------------------


def test_require_allowed_command_gates_the_whitelist() -> None:
    _require_allowed_command("aflj")  # plain allowed
    _require_allowed_command("pdj 512 @ 0x1000")  # bounded pdj
    _require_allowed_command("axj @ 0x1000")  # xref query
    with pytest.raises(R2Error) as too_many:
        _require_allowed_command("pdj 513 @ 0x1000")
    assert too_many.value.code == "invalid_params"
    with pytest.raises(R2Error):
        _require_allowed_command("!rm -rf /")


# ---------------------------------------------------------------------------
# discovery
# ---------------------------------------------------------------------------


def test_discover_prefers_the_first_available_name(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: list[str] = []

    def fake_which(name: str) -> str | None:
        seen.append(name)
        return "/opt/bin/rizin" if name == "rizin" else None

    monkeypatch.setattr(shutil, "which", fake_which)
    found = _discover()
    assert found == Path("/opt/bin/rizin")
    # r2 is tried before rizin, so a miss there still reaches rizin.
    assert seen[:2] == ["r2", "rizin"]


def test_discover_returns_none_when_nothing_is_installed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(shutil, "which", lambda name: None)
    assert _discover() is None
