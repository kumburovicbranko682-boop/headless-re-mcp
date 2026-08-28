"""apk paging reads must refuse a closed session and wrap success under apk.

open / decode / decompile / repack / sign / export_sources each pin that a
retained CLOSED session cannot reach the backend. The four paging reads --
classes / methods / strings / xrefs -- share the same ``_apk_binary`` guard but
had no closed-session test, and their service envelopes were exercised only at
the client level. A regression that let one of them resolve a dead session
would page an APK whose artifacts may already be gone; one that mislabelled the
envelope would break the backend attribution every caller reads. Both are
pinned here for all four, without androguard, via an injected fake client.
"""

from __future__ import annotations

import zipfile
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService


def _write_minimal_apk(path: Path) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00manifest")
        archive.writestr("classes.dex", b"dex\n035\x00")
    return path


class _TrackingApk:
    """Each paging read is counted so a test can prove the backend was reached
    exactly once on success and never once the session is closed."""

    def __init__(self) -> None:
        self.calls = 0

    def classes(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        self.calls += 1
        return {"classes": [], "count": 0, "has_more": False}

    def methods(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        self.calls += 1
        return {"class_name": "Lcom/example/A;", "found": True, "methods": [], "count": 0}

    def strings(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        self.calls += 1
        return {"strings": [], "count": 0, "has_more": False}

    def xrefs(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        self.calls += 1
        return {"method_name": "decrypt", "callers": [], "count": 0, "has_more": False}


def _invoke(service: AnalysisService, tool: str, session_id: str) -> Any:
    if tool == "apk_classes":
        return service.apk_classes(session_id)
    if tool == "apk_methods":
        return service.apk_methods(session_id, "Lcom/example/A;")
    if tool == "apk_strings":
        return service.apk_strings(session_id)
    if tool == "apk_xrefs":
        return service.apk_xrefs(session_id, "decrypt")
    raise AssertionError(f"unknown tool {tool}")


_TOOLS = ["apk_classes", "apk_methods", "apk_strings", "apk_xrefs"]


@pytest.mark.parametrize("tool", _TOOLS)
def test_apk_paging_read_on_a_closed_session_does_not_reach_the_backend(
    tmp_path: Path, monkeypatch: Any, tool: str
) -> None:
    tracker = _TrackingApk()
    monkeypatch.setattr("headless_re_mcp.core.service_apk.ApkClient", lambda: tracker)
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    apk = _write_minimal_apk(tmp_path / "app.apk")
    try:
        created = service.create_session(str(apk), target="apk")
        assert created.ok and created.data is not None, created.error
        session_id = created.data["session"]["id"]
        assert service.close_session(session_id).ok

        result = _invoke(service, tool, session_id)

        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "invalid_request"
        assert "closed" in result.error.message
        # The guard fires before ApkClient is constructed, so nothing paged a
        # session whose APK may already be gone.
        assert tracker.calls == 0
    finally:
        service.close_all()


@pytest.mark.parametrize("tool", _TOOLS)
def test_apk_paging_read_wraps_the_backend_payload_under_apk(
    tmp_path: Path, monkeypatch: Any, tool: str
) -> None:
    tracker = _TrackingApk()
    monkeypatch.setattr("headless_re_mcp.core.service_apk.ApkClient", lambda: tracker)
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    apk = _write_minimal_apk(tmp_path / "app.apk")
    try:
        created = service.create_session(str(apk), target="apk")
        assert created.ok and created.data is not None, created.error
        session_id = created.data["session"]["id"]

        result = _invoke(service, tool, session_id)

        assert result.ok, result.error
        assert result.meta.get("backend") == "apk"
        assert tracker.calls == 1
    finally:
        service.close_all()
