"""R2Client whitelist, guard, and subprocess error contracts without radare2.

radare2 is not installed in CI, so ``run_bounded`` is monkeypatched to return a
chosen ``Completed`` (or raise). The binary handed to ``run`` is a real file so
payload enrichment runs exactly as it would in production.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.common.bounded_run import Completed, TimedOut
from headless_re_mcp.backends.r2 import client as r2_client
from headless_re_mcp.backends.r2.client import R2Client, R2Error, _require_allowed_command


def _exe(tmp_path: Path) -> Path:
    path = tmp_path / "r2"
    path.write_text("#!/bin/sh\n", encoding="utf-8")
    return path


def _binary(tmp_path: Path) -> Path:
    path = tmp_path / "sample.bin"
    path.write_bytes(b"\x7fELF not really but readable")
    return path


def _returns(monkeypatch: pytest.MonkeyPatch, completed: Completed) -> None:
    monkeypatch.setattr(r2_client, "run_bounded", lambda *a, **k: completed)


# --- command whitelist ------------------------------------------------------


def test_require_allowed_command_accepts_the_whitelist_and_bounded_forms() -> None:
    _require_allowed_command("i")
    _require_allowed_command("pdj 10 @ 0x1000")
    _require_allowed_command("axj @ 4096")


def test_require_allowed_command_rejects_oversized_pdj_and_unknowns() -> None:
    with pytest.raises(R2Error) as info:
        _require_allowed_command("pdj 513 @ 0x1000")
    assert info.value.code == "invalid_params"
    with pytest.raises(R2Error):
        _require_allowed_command("rm -rf /")


# --- open -------------------------------------------------------------------


def test_open_reports_a_missing_binary(tmp_path: Path) -> None:
    client = R2Client(executable=_exe(tmp_path))
    with pytest.raises(R2Error) as info:
        client.open(tmp_path / "missing.bin")
    assert info.value.code == "not_found"


def test_open_validates_and_summarizes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    client = R2Client(executable=_exe(tmp_path))
    _returns(monkeypatch, Completed(0, b'{"bin":"info"}', b""))
    data = client.open(_binary(tmp_path))
    assert data["opened"] is True
    assert "one-shot" in data["note"]


# --- disasm / xrefs guards --------------------------------------------------


def test_disasm_rejects_bad_address_and_count(tmp_path: Path) -> None:
    client = R2Client(executable=_exe(tmp_path))
    binary = _binary(tmp_path)
    with pytest.raises(R2Error) as bad_addr:
        client.disasm(binary, -1)
    assert bad_addr.value.code == "invalid_params"
    with pytest.raises(R2Error) as bad_count:
        client.disasm(binary, 0x1000, count=0)
    assert bad_count.value.code == "invalid_params"


def test_disasm_success_annotates_address_and_count(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = R2Client(executable=_exe(tmp_path))
    _returns(monkeypatch, Completed(0, b'[{"offset":4096,"opcode":"nop"}]', b""))
    data = client.disasm(_binary(tmp_path), 0x1000, count=4)
    assert data["address_va"] == 0x1000
    assert data["parsed"] is True
    assert len(data["items"]) == 1


def test_xrefs_rejects_bad_address_and_succeeds(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = R2Client(executable=_exe(tmp_path))
    binary = _binary(tmp_path)
    with pytest.raises(R2Error):
        client.xrefs(binary, -5)
    _returns(monkeypatch, Completed(0, b'[{"from":4096,"to":8192}]', b""))
    data = client.xrefs(binary, 0x1000)
    assert data["address_va"] == 0x1000
    assert data["parsed"] is True


# --- run --------------------------------------------------------------------


def test_run_rejects_a_non_positive_timeout(tmp_path: Path) -> None:
    client = R2Client(executable=_exe(tmp_path))
    with pytest.raises(R2Error) as info:
        client.run(_binary(tmp_path), ["i"], timeout=0.0)
    assert info.value.code == "invalid_params"


def test_run_reports_when_r2_is_not_installed(tmp_path: Path) -> None:
    client = R2Client(executable=tmp_path / "does-not-exist")
    with pytest.raises(R2Error) as info:
        client.run(_binary(tmp_path), ["i"])
    assert info.value.code == "capability_unavailable"


def test_run_reports_a_missing_binary(tmp_path: Path) -> None:
    client = R2Client(executable=_exe(tmp_path))
    with pytest.raises(R2Error) as info:
        client.run(tmp_path / "gone.bin", ["i"])
    assert info.value.code == "not_found"


def test_run_maps_a_timeout(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    client = R2Client(executable=_exe(tmp_path))

    def _timeout(*_a: Any, **_k: Any) -> Any:
        raise TimedOut(2.0, [999])

    monkeypatch.setattr(r2_client, "run_bounded", _timeout)
    with pytest.raises(R2Error) as info:
        client.run(_binary(tmp_path), ["i"])
    assert info.value.code == "timeout"
    assert info.value.details.get("killed_pids") == [999]


def test_run_maps_a_launch_failure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    client = R2Client(executable=_exe(tmp_path))

    def _oserror(*_a: Any, **_k: Any) -> Any:
        raise PermissionError("not executable")

    monkeypatch.setattr(r2_client, "run_bounded", _oserror)
    with pytest.raises(R2Error) as info:
        client.run(_binary(tmp_path), ["i"])
    assert info.value.code == "backend_error"


def test_run_maps_a_non_zero_exit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    client = R2Client(executable=_exe(tmp_path))
    _returns(monkeypatch, Completed(3, b"", b"r2 fell over"))
    with pytest.raises(R2Error) as info:
        client.run(_binary(tmp_path), ["i"])
    assert info.value.code == "backend_error"
    assert info.value.details.get("exit_code") == 3


def test_run_success_parses_json(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    client = R2Client(executable=_exe(tmp_path))
    _returns(monkeypatch, Completed(0, b'{"core":"info"}', b""))
    data = client.run(_binary(tmp_path), ["i"])
    assert data["parsed"] is True
    assert data["commands"] == ["i"]


def test_run_flags_truncated_output(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    client = R2Client(executable=_exe(tmp_path))
    big = b"a" * (1_000_001)
    _returns(monkeypatch, Completed(0, big, b""))
    data = client.run(_binary(tmp_path), ["i"])
    assert data["truncated"] is True
    assert data["output_bytes"] == 1_000_001


# --- discovery --------------------------------------------------------------


def test_discover_returns_the_first_tool_on_path(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        r2_client.shutil, "which", lambda name: "/usr/bin/r2" if name == "r2" else None
    )
    assert r2_client._discover() == Path("/usr/bin/r2")


def test_discover_returns_none_when_no_tool_is_present(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(r2_client.shutil, "which", lambda name: None)
    assert r2_client._discover() is None
