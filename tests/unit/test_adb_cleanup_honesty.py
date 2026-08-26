"""Service shutdown must disclose ADB forwards it could not remove."""

from __future__ import annotations

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
