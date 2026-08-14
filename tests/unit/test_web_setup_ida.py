"""configure_ida must not report a failed idalib activation as success."""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.web import setup as setup_mod
from headless_re_mcp.web.setup import configure_ida


def test_failed_idalib_activation_is_not_reported_as_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The installer treats ok as whether IDA is usable.

    Measured: activate_idalib returned ok=False and configure_ida still answered
    ok=True, saved=True. setup.py then skips InstallError and the supervised
    service starts; every later static.open fails for the rest of the night.
    """
    fake_ida = tmp_path / "IDA Professional 9.9"
    fake_ida.mkdir()
    (fake_ida / "idalib.dll").write_bytes(b"MZ")
    config_path = tmp_path / "user-config.json"

    monkeypatch.setattr(
        setup_mod,
        "activate_idalib",
        lambda home: {
            "ok": False,
            "code": "activation_failed",
            "message": "idalib did not activate",
        },
    )

    result = configure_ida(ida_home=fake_ida, activate=True, config_path=config_path)

    assert result["saved"] is True
    assert result["activation"]["ok"] is False
    assert result["ok"] is False, (
        f"activation failed but configure_ida answered ok={result.get('ok')!r}"
    )


def test_skipping_activation_still_reports_the_saved_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Saving the path without activating is a real success."""
    fake_ida = tmp_path / "IDA Professional 9.9"
    fake_ida.mkdir()
    (fake_ida / "idalib.dll").write_bytes(b"MZ")
    config_path = tmp_path / "user-config.json"
    monkeypatch.setattr(
        setup_mod,
        "activate_idalib",
        lambda home: (_ for _ in ()).throw(AssertionError("must not activate")),
    )
    result = configure_ida(ida_home=fake_ida, activate=False, config_path=config_path)
    assert result["ok"] is True
    assert result["saved"] is True
    assert result["activation"] is None

