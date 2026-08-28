"""Cover r2 client validation guards, success bodies, and discovery."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

import headless_re_mcp.backends.r2.client as r2_module
from headless_re_mcp.backends.common.bounded_run import Completed
from headless_re_mcp.backends.r2.client import R2Client, R2Error, _discover


def _client_and_binary(tmp_path: Path) -> tuple[R2Client, Path]:
    executable = tmp_path / "r2.exe"
    executable.write_bytes(b"")
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    return R2Client(executable), binary


def _fake_run(payload: bytes) -> Any:
    def run(cmd: list[str], **kwargs: Any) -> Completed:
        del cmd, kwargs
        return Completed(0, payload, b"")

    return run


def test_open_refuses_a_missing_binary(tmp_path: Path) -> None:
    client, _binary = _client_and_binary(tmp_path)
    with pytest.raises(R2Error, match="binary not found"):
        client.open(tmp_path / "absent.exe")


def test_open_reports_validation_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client, binary = _client_and_binary(tmp_path)
    monkeypatch.setattr(r2_module, "run_bounded", _fake_run(b"arch x86"))
    data = client.open(binary)
    assert data["opened"] is True
    assert data["binary"] == str(binary)
    assert "arch x86" in data["info"]


def test_disasm_rejects_bad_address_and_count(tmp_path: Path) -> None:
    client, binary = _client_and_binary(tmp_path)
    with pytest.raises(R2Error, match="non-negative int"):
        client.disasm(binary, -1)
    with pytest.raises(R2Error, match="count must be"):
        client.disasm(binary, 0x1000, count=0)


def test_disasm_returns_an_enriched_payload(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client, binary = _client_and_binary(tmp_path)
    monkeypatch.setattr(r2_module, "run_bounded", _fake_run(b"[]"))
    data = client.disasm(binary, 0x401000, count=8)
    assert data["address"] == {"va": 0x401000}
    assert data["commands"] == ["aa", "pdj 8 @ 4198400"]


def test_xrefs_rejects_a_bad_address(tmp_path: Path) -> None:
    client, binary = _client_and_binary(tmp_path)
    with pytest.raises(R2Error, match="non-negative int"):
        client.xrefs(binary, -5)


def test_xrefs_returns_an_enriched_payload(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client, binary = _client_and_binary(tmp_path)
    monkeypatch.setattr(r2_module, "run_bounded", _fake_run(b"[]"))
    data = client.xrefs(binary, 0x401000)
    assert data["address"] == {"va": 0x401000}


def test_run_reports_capability_unavailable_without_an_executable(
    tmp_path: Path,
) -> None:
    client = R2Client(tmp_path / "missing-r2")
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    with pytest.raises(R2Error, match="not installed"):
        client.run(binary, ["i"])


def test_run_refuses_a_missing_binary(tmp_path: Path) -> None:
    client, _binary = _client_and_binary(tmp_path)
    with pytest.raises(R2Error, match="binary not found"):
        client.run(tmp_path / "absent.exe", ["i"])


def test_run_rejects_an_out_of_range_timeout(tmp_path: Path) -> None:
    client, binary = _client_and_binary(tmp_path)
    with pytest.raises(R2Error) as excinfo:
        client.run(binary, ["i"], timeout=-1.0)
    assert excinfo.value.code == "invalid_params"


def test_discover_returns_the_first_tool_on_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_which(name: str) -> str | None:
        return "/usr/bin/rizin" if name == "rizin" else None

    monkeypatch.setattr(
        "headless_re_mcp.backends.r2.client.shutil.which", fake_which
    )
    found = _discover()
    assert found == Path("/usr/bin/rizin")


def test_discover_returns_none_when_no_tool_is_present(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "headless_re_mcp.backends.r2.client.shutil.which", lambda _name: None
    )
    assert _discover() is None
