"""Guard, validation and discovery branches of the radare2 backend client.

The r2 field tests drive :func:`enrich_r2_payload` directly, so the client's
own ``open``/``disasm``/``xrefs`` wrappers and ``run``'s capability and
not-found guards were never exercised. These fake ``run_bounded`` (like
test_r2_command_whitelist) so the real methods run end to end without a
radare2 install: the address/count validators reject bad input before any
launch, a request address is mapped to an Address object, and ``run`` refuses
a missing executable and a missing binary. ``_discover`` is checked both ways.
"""

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


def _fake_stdout(monkeypatch: pytest.MonkeyPatch, stdout: bytes) -> list[list[str]]:
    launched: list[list[str]] = []

    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        del kwargs
        launched.append(cmd)
        return Completed(0, stdout, b"")

    monkeypatch.setattr(r2_module, "run_bounded", fake_run)
    return launched


# ----------------------------------------------------------------------------
# available property.
# ----------------------------------------------------------------------------
def test_available_reflects_a_present_executable(tmp_path: Path) -> None:
    client, _ = _client_and_binary(tmp_path)
    assert client.available is True
    assert R2Client(tmp_path / "missing").available is False


# ----------------------------------------------------------------------------
# open(): missing binary is not_found; a present one is validated one-shot.
# ----------------------------------------------------------------------------
def test_open_rejects_a_missing_binary(tmp_path: Path) -> None:
    client, _ = _client_and_binary(tmp_path)
    with pytest.raises(R2Error) as info:
        client.open(tmp_path / "no-such.exe")
    assert info.value.code == "not_found"


def test_open_validates_and_summarizes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client, binary = _client_and_binary(tmp_path)
    launched = _fake_stdout(monkeypatch, b"arch x86\nbits 64\n")
    payload = client.open(binary)
    assert payload["opened"] is True
    assert payload["binary"] == str(binary)
    assert "arch x86" in payload["info"]
    assert "one-shot" in payload["note"]
    # open runs the single info command "i".
    assert launched == [[str(client.executable), "-q0", "-c", "i\nq", str(binary)]]


# ----------------------------------------------------------------------------
# disasm(): address and count validators, then a mapped request address.
# ----------------------------------------------------------------------------
@pytest.mark.parametrize("address", [-1, 1.0, True])
def test_disasm_rejects_a_bad_address(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, address: Any
) -> None:
    client, binary = _client_and_binary(tmp_path)
    _fake_stdout(monkeypatch, b"[]")
    with pytest.raises(R2Error) as info:
        client.disasm(binary, address, count=4)
    assert info.value.code == "invalid_params"


@pytest.mark.parametrize("count", [0, 513, 2.0])
def test_disasm_rejects_a_bad_count(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, count: Any
) -> None:
    client, binary = _client_and_binary(tmp_path)
    _fake_stdout(monkeypatch, b"[]")
    with pytest.raises(R2Error) as info:
        client.disasm(binary, 0x1000, count=count)
    assert info.value.code == "invalid_params"


def test_disasm_maps_the_request_address(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client, binary = _client_and_binary(tmp_path)
    _fake_stdout(monkeypatch, b'[{"offset": 4096, "opcode": "nop"}]')
    payload = client.disasm(binary, 0x1000, count=4)
    assert payload["address_va"] == 0x1000
    assert type(payload["address"]) is dict
    assert payload["parsed"] is True
    # enrich_r2_payload reports count as the number of decoded items.
    assert len(payload["items"]) == 1
    assert payload["count"] == 1


# ----------------------------------------------------------------------------
# xrefs(): address validator, then a mapped request address.
# ----------------------------------------------------------------------------
@pytest.mark.parametrize("address", [-5, "0x1000"])
def test_xrefs_rejects_a_bad_address(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, address: Any
) -> None:
    client, binary = _client_and_binary(tmp_path)
    _fake_stdout(monkeypatch, b"[]")
    with pytest.raises(R2Error) as info:
        client.xrefs(binary, address)
    assert info.value.code == "invalid_params"


def test_xrefs_maps_the_request_address(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client, binary = _client_and_binary(tmp_path)
    _fake_stdout(monkeypatch, b'[{"from": 4096, "to": 8192}]')
    payload = client.xrefs(binary, 0x1000)
    assert payload["address_va"] == 0x1000
    assert type(payload["address"]) is dict
    assert payload["parsed"] is True
    assert len(payload["items"]) == 1


# ----------------------------------------------------------------------------
# run(): capability and not-found guards fire before any launch.
# ----------------------------------------------------------------------------
def test_run_reports_capability_unavailable(tmp_path: Path) -> None:
    # A configured-but-absent executable is not available.
    client = R2Client(tmp_path / "missing-r2")
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    with pytest.raises(R2Error) as info:
        client.run(binary, ["i"])
    assert info.value.code == "capability_unavailable"


def test_run_reports_a_missing_binary(tmp_path: Path) -> None:
    client, _ = _client_and_binary(tmp_path)
    with pytest.raises(R2Error) as info:
        client.run(tmp_path / "gone.exe", ["i"])
    assert info.value.code == "not_found"


# ----------------------------------------------------------------------------
# _discover(): finds the first tool on PATH, else None.
# ----------------------------------------------------------------------------
def test_discover_returns_the_first_tool_on_path(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        r2_module.shutil,
        "which",
        lambda name: "/usr/bin/r2" if name == "r2" else None,
    )
    assert _discover() == Path("/usr/bin/r2")


def test_discover_returns_none_when_no_tool_is_present(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(r2_module.shutil, "which", lambda name: None)
    assert _discover() is None
