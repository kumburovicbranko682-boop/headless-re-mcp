from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

import headless_re_mcp.backends.windbg.client as windbg_module
from headless_re_mcp.backends.windbg.client import WindbgClient, WindbgError


def _store_cdb(tmp_path: Path) -> Path:
    path = tmp_path / "WindowsApps" / "Microsoft.WinDbg_1.0_x64__abc" / "amd64" / "cdb.exe"
    path.parent.mkdir(parents=True)
    path.write_bytes(b"MZ")
    return path


def test_store_package_cdb_is_reported_unavailable(tmp_path: Path) -> None:
    """Store package paths stat fine but CreateProcess denies them."""
    client = WindbgClient(_store_cdb(tmp_path))

    assert client.available is False


def test_store_package_cdb_raises_actionable_error(tmp_path: Path) -> None:
    dump = tmp_path / "crash.dmp"
    dump.write_bytes(b"dump")
    client = WindbgClient(_store_cdb(tmp_path))

    with pytest.raises(WindbgError) as exc:
        client.modules(dump)

    assert exc.value.code == "capability_unavailable"
    assert "HEADLESS_RE_CDB" in exc.value.message


def test_discovery_never_returns_a_store_package(monkeypatch: pytest.MonkeyPatch) -> None:
    store = r"C:\Program Files\WindowsApps\Microsoft.WinDbg_1.0_x64__abc\amd64\cdb.exe"
    monkeypatch.delenv("HEADLESS_RE_CDB", raising=False)
    monkeypatch.setattr(windbg_module.shutil, "which", lambda _name: store)

    discovered = windbg_module._discover_cdb()

    assert discovered is None or "windowsapps" not in str(discovered).casefold()


def test_launch_failure_becomes_a_structured_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cdb = tmp_path / "cdb.exe"
    cdb.write_bytes(b"MZ")
    dump = tmp_path / "crash.dmp"
    dump.write_bytes(b"dump")
    client = WindbgClient(cdb)

    def denied(*_args: Any, **_kwargs: Any) -> Any:
        raise PermissionError(5, "Access is denied")

    monkeypatch.setattr(windbg_module.subprocess, "run", denied)

    with pytest.raises(WindbgError) as exc:
        client.modules(dump)

    assert exc.value.code == "backend_error"
    assert "could not be launched" in exc.value.message
    assert exc.value.details["cdb"] == str(cdb)
