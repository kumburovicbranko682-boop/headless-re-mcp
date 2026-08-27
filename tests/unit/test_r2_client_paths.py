"""Guard and happy-path arms of the radare2/rizin CLI client.

The field-name contracts and the command whitelist already live in the other
``test_r2_*`` files, and those drive ``enrich_r2_payload`` directly. This file
covers what they skip on ``R2Client`` itself: the ``open`` not-found guard, the
``disasm``/``xrefs`` argument guards and their run wiring, ``run``'s
capability-unavailable and missing-binary refusals, and executable discovery.
A fake ``run_bounded`` stands in for the subprocess so no real r2 is needed.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

import headless_re_mcp.backends.r2.client as r2_module
from headless_re_mcp.backends.common.bounded_run import Completed
from headless_re_mcp.backends.r2.client import R2Client, R2Error, _discover


def _write_minimal_pe(path: Path) -> None:
    """A minimal x64 PE so enrich_r2_payload can map addresses off ImageBase."""
    image = bytearray(0x200)
    image[0:2] = b"MZ"
    image[0x3C:0x40] = (0x80).to_bytes(4, "little")
    image[0x80:0x84] = b"PE\0\0"
    image[0x94:0x96] = (0xF0).to_bytes(2, "little")
    image[0x98:0x9A] = (0x20B).to_bytes(2, "little")
    image[0xB0:0xB8] = (0x140000000).to_bytes(8, "little")
    path.write_bytes(bytes(image))


def _client_and_binary(tmp_path: Path) -> tuple[R2Client, Path]:
    executable = tmp_path / "r2.exe"
    executable.write_bytes(b"")
    binary = tmp_path / "sample.exe"
    _write_minimal_pe(binary)
    return R2Client(executable), binary


# ---------------------------------------------------------------------------
# open
# ---------------------------------------------------------------------------


def test_open_reports_a_missing_binary(tmp_path: Path) -> None:
    client, _binary = _client_and_binary(tmp_path)
    with pytest.raises(R2Error) as raised:
        client.open(tmp_path / "does-not-exist.exe")
    assert raised.value.code == "not_found"
    assert raised.value.details["path"].endswith("does-not-exist.exe")


# ---------------------------------------------------------------------------
# disasm
# ---------------------------------------------------------------------------


def test_disasm_refuses_a_negative_address(tmp_path: Path) -> None:
    client, binary = _client_and_binary(tmp_path)
    with pytest.raises(R2Error, match="non-negative"):
        client.disasm(binary, -1)


def test_disasm_refuses_a_non_integer_address(tmp_path: Path) -> None:
    client, binary = _client_and_binary(tmp_path)
    with pytest.raises(R2Error, match="non-negative"):
        client.disasm(binary, "0x1000")  # type: ignore[arg-type]


@pytest.mark.parametrize("count", [0, 513])
def test_disasm_refuses_an_out_of_range_count(tmp_path: Path, count: int) -> None:
    client, binary = _client_and_binary(tmp_path)
    with pytest.raises(R2Error, match="count must be"):
        client.disasm(binary, 0x140001000, count=count)


def test_disasm_runs_a_bounded_pdj_and_maps_the_request_address(
    tmp_path: Path, monkeypatch: Any
) -> None:
    client, binary = _client_and_binary(tmp_path)
    launched: list[list[str]] = []

    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        del kwargs
        launched.append(cmd)
        return Completed(0, b'[{"offset": 5368713216, "opcode": "nop"}]', b"")

    monkeypatch.setattr(r2_module, "run_bounded", fake_run)
    payload = client.disasm(binary, 0x140001000, count=4)

    assert payload["address_va"] == 0x140001000
    assert payload["parsed"] is True
    assert len(launched) == 1
    script = launched[0][launched[0].index("-c") + 1]
    assert "pdj 4 @ 5368713216" in script
    assert script.startswith("aa\n")


# ---------------------------------------------------------------------------
# xrefs
# ---------------------------------------------------------------------------


def test_xrefs_refuses_a_negative_address(tmp_path: Path) -> None:
    client, binary = _client_and_binary(tmp_path)
    with pytest.raises(R2Error, match="non-negative"):
        client.xrefs(binary, -5)


def test_xrefs_runs_a_bounded_axj_and_maps_the_request_address(
    tmp_path: Path, monkeypatch: Any
) -> None:
    client, binary = _client_and_binary(tmp_path)
    launched: list[list[str]] = []

    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        del kwargs
        launched.append(cmd)
        return Completed(0, b"[]", b"")

    monkeypatch.setattr(r2_module, "run_bounded", fake_run)
    payload = client.xrefs(binary, 0x140001000)

    assert payload["address_va"] == 0x140001000
    assert payload["parsed"] is True
    script = launched[0][launched[0].index("-c") + 1]
    assert "axj @ 5368713216" in script


# ---------------------------------------------------------------------------
# run guards
# ---------------------------------------------------------------------------


def test_run_reports_capability_unavailable_without_an_executable(tmp_path: Path) -> None:
    """A configured path that is not a file leaves the client unavailable."""
    client = R2Client(tmp_path / "no-such-r2")
    assert client.available is False
    binary = tmp_path / "sample.exe"
    _write_minimal_pe(binary)
    with pytest.raises(R2Error) as raised:
        client.run(binary, ["i"])
    assert raised.value.code == "capability_unavailable"


def test_run_reports_a_missing_binary(tmp_path: Path) -> None:
    client, _binary = _client_and_binary(tmp_path)
    with pytest.raises(R2Error) as raised:
        client.run(tmp_path / "missing.exe", ["i"])
    assert raised.value.code == "not_found"
    assert raised.value.details["path"].endswith("missing.exe")


# ---------------------------------------------------------------------------
# _discover
# ---------------------------------------------------------------------------


def test_discover_returns_the_first_tool_on_path(monkeypatch: Any) -> None:
    monkeypatch.setattr(
        r2_module.shutil,
        "which",
        lambda name: "/usr/bin/r2" if name == "r2" else None,
    )
    assert _discover() == Path("/usr/bin/r2")


def test_discover_prefers_rizin_when_r2_is_absent(monkeypatch: Any) -> None:
    found = {"r2": None, "rizin": "/opt/bin/rizin", "radare2": None}
    monkeypatch.setattr(r2_module.shutil, "which", lambda name: found.get(name))
    assert _discover() == Path("/opt/bin/rizin")


def test_discover_is_none_when_no_tool_is_installed(monkeypatch: Any) -> None:
    monkeypatch.setattr(r2_module.shutil, "which", lambda name: None)
    assert _discover() is None


# ---------------------------------------------------------------------------
# R2Error
# ---------------------------------------------------------------------------


def test_r2_error_is_a_runtime_error_carrying_code_and_details() -> None:
    err = R2Error("invalid_params", "bad", command="ii ii")
    assert isinstance(err, RuntimeError)
    assert err.code == "invalid_params"
    assert err.details["command"] == "ii ii"
