"""Guard- and delegation-path tests for the radare2/rizin client.

The success, timeout, and launch-OSError arcs of ``R2Client.run`` are pinned by
other r2 tests; this file covers the input guards (``open`` on a missing file,
``disasm``/``xrefs`` argument validation, ``run`` availability and file checks),
the ``disasm``/``xrefs`` delegation into ``enrich_r2_payload``, and executable
discovery.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import headless_re_mcp.backends.r2.client as r2_client
from headless_re_mcp.backends.r2.client import R2Client, R2Error, _discover


def _binary(tmp_path: Path) -> Path:
    path = tmp_path / "sample.bin"
    path.write_bytes(b"MZ\x00\x00")
    return path


# --- open -------------------------------------------------------------------


def test_open_rejects_missing_binary(tmp_path: Path) -> None:
    client = R2Client(executable=None)
    with pytest.raises(R2Error) as exc:
        client.open(tmp_path / "nope.bin")
    assert exc.value.code == "not_found"


# --- disasm argument guards + delegation ------------------------------------


def test_disasm_rejects_negative_address(tmp_path: Path) -> None:
    client = R2Client(executable=None)
    with pytest.raises(R2Error) as exc:
        client.disasm(_binary(tmp_path), -1)
    assert exc.value.code == "invalid_params"


def test_disasm_rejects_out_of_range_count(tmp_path: Path) -> None:
    client = R2Client(executable=None)
    with pytest.raises(R2Error) as exc:
        client.disasm(_binary(tmp_path), 0x1000, count=0)
    assert exc.value.code == "invalid_params"


def test_disasm_enriches_delegated_payload(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    binary = _binary(tmp_path)
    client = R2Client(executable=None)

    def fake_run(target: Path, commands: list[str], *, timeout: float = 30.0) -> dict[str, object]:
        assert commands == ["aa", "pdj 4 @ 4096"]
        return {"raw": "{}", "commands": commands}

    monkeypatch.setattr(client, "run", fake_run)
    result = client.disasm(binary, 0x1000, count=4)
    assert result["address_va"] == 0x1000
    assert result["count"] == 4
    assert result["parsed"] is True


# --- xrefs argument guards + delegation -------------------------------------


def test_xrefs_rejects_negative_address(tmp_path: Path) -> None:
    client = R2Client(executable=None)
    with pytest.raises(R2Error) as exc:
        client.xrefs(_binary(tmp_path), -5)
    assert exc.value.code == "invalid_params"


def test_xrefs_enriches_delegated_payload(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    binary = _binary(tmp_path)
    client = R2Client(executable=None)

    def fake_run(target: Path, commands: list[str], *, timeout: float = 30.0) -> dict[str, object]:
        assert commands == ["aa", "axj @ 8192"]
        return {"raw": "{}", "commands": commands}

    monkeypatch.setattr(client, "run", fake_run)
    result = client.xrefs(binary, 0x2000)
    assert result["address_va"] == 0x2000
    assert result["parsed"] is True


# --- run availability / file guards -----------------------------------------


def test_run_reports_capability_unavailable_without_executable(tmp_path: Path) -> None:
    client = R2Client(executable=None)
    with pytest.raises(R2Error) as exc:
        client.run(_binary(tmp_path), ["i"])
    assert exc.value.code == "capability_unavailable"


def test_run_rejects_missing_binary(tmp_path: Path) -> None:
    executable = tmp_path / "r2"
    executable.write_bytes(b"#!/bin/sh\n")
    client = R2Client(executable=executable)
    with pytest.raises(R2Error) as exc:
        client.run(tmp_path / "absent.bin", ["i"])
    assert exc.value.code == "not_found"


# --- discovery --------------------------------------------------------------


def test_discover_returns_first_tool_on_path(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        r2_client.shutil, "which", lambda name: "/usr/bin/r2" if name == "r2" else None
    )
    assert _discover() == Path("/usr/bin/r2")


def test_discover_returns_none_when_absent(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(r2_client.shutil, "which", lambda _name: None)
    assert _discover() is None
