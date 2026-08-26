"""Service shutdown must disclose ADB forwards it could not remove."""

from __future__ import annotations

import zipfile
from dataclasses import replace
from pathlib import Path

from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService


def test_close_all_fails_honestly_when_adb_forwards_remain(tmp_path: Path) -> None:
    """ADB keeps forwards after this process exits, so failed removal is live state.

    Measured with one retained forward: ``release_forwards`` returned one failure
    while ``close_all`` returned ``ok=True`` and no error details.
    """

    class _AdbWithStaleForward:
        def release_forwards(self) -> dict[str, object]:
            return {
                "removed": [],
                "failed": [
                    {
                        "serial": "emulator-5554",
                        "local": "tcp:27042",
                        "error": "device offline",
                    }
                ],
                "count": 0,
            }

    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    service._adb_backend = _AdbWithStaleForward()  # type: ignore[assignment]

    result = service.close_all()

    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "close_all_failed"
    assert result.error.details["errors"] == [
        {
            "backend": "adb",
            "error": {
                "code": "adb_cleanup_failed",
                "message": "one or more ADB forwards remain active",
                "details": {
                    "backend": "adb",
                    "failed_count": 1,
                    "failed": [
                        {
                            "serial": "emulator-5554",
                            "local": "tcp:27042",
                            "error": "device offline",
                        }
                    ],
                },
                "retryable": True,
            },
        }
    ]


def test_last_android_session_close_reports_a_forward_that_remains(
    tmp_path: Path,
) -> None:
    """A normal session close is also an ADB cleanup checkpoint.

    Measured: the final APK session returned ``ok=True`` while one failed
    forward removal was silently retained for a later retry.
    """

    class _AdbWithStaleForward:
        def release_forwards(self) -> dict[str, object]:
            return {
                "removed": [],
                "failed": [
                    {
                        "serial": "emulator-5554",
                        "local": "tcp:27042",
                        "error": "device offline",
                    }
                ],
                "count": 0,
            }

    apk = tmp_path / "app.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00m")
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    service._adb_backend = _AdbWithStaleForward()  # type: ignore[assignment]
    created = service.create_session(str(apk), target="apk")
    assert created.ok and created.data is not None
    session_id = str(created.data["session"]["id"])

    result = service.close_session(session_id)

    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "adb_cleanup_failed"
    assert result.error.details["backend"] == "adb"
    assert result.error.details["state"] == "closed"
    assert result.error.details["close_error_count"] == 1
    assert result.error.details["failed_count"] == 1
    assert service.registry.get(session_id).state.value == "closed"
