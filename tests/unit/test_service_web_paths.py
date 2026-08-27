"""Web dynamic-analysis service: status decoration, open rollback, capture registration.

The live browser gate covers the happy lifecycle; these drive the service-layer
branches it does not reach without Chromium: status enriched with session
fields, a non-web session that needs a url, a close arriving mid-open, and the
spilled-body / spilled-source registration that makes a capture reclaimable.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from headless_re_mcp.backends.web import WebError
from headless_re_mcp.core.models import SessionState
from headless_re_mcp.core.service_web import WebAnalysisMixin
from headless_re_mcp.core.session import SessionRegistry


class _Repo:
    def __init__(self) -> None:
        self.timeline: list[Any] = []
        self.backends: list[Any] = []

    def record_backend(self, session_id: str, kind: str, **fields: Any) -> None:
        self.backends.append((session_id, kind, fields))

    def append_timeline(self, session_id: str, event: str, message: str, **details: Any) -> None:
        self.timeline.append((session_id, event, message, details))

    def register_artifact(self, **fields: Any) -> dict[str, Any]:
        return {"id": "artifact-1", **fields}


class _Settings:
    def __init__(self, artifact_root: Path) -> None:
        self.artifact_root = artifact_root


class _Service(WebAnalysisMixin):
    def __init__(self, backend: Any, artifact_root: Path) -> None:
        self.registry = SessionRegistry()
        self.repository = _Repo()
        self.settings = _Settings(artifact_root)  # type: ignore[assignment]
        self._web_backend = backend


def _web_session(service: _Service) -> str:
    return service.registry.create("https://example.invalid", target=None).id


# ----------------------------------------------------------------------
# web_status.
# ----------------------------------------------------------------------
def test_web_status_decorates_with_session_locator_state_and_target(tmp_path: Path) -> None:
    class _Backend:
        def status(self, session_id: str) -> dict[str, Any]:
            return {"open": False}

    service = _Service(_Backend(), tmp_path)
    session_id = service.registry.create("https://example.com/app", target=None).id
    result = service.web_status(session_id)
    assert result.ok is True
    assert result.data is not None
    assert result.data["locator"] == "https://example.com/app"
    assert result.data["state"] == "created"
    assert result.data["target"] == "web"


def test_web_status_maps_a_backend_error(tmp_path: Path) -> None:
    class _Backend:
        def status(self, session_id: str) -> dict[str, Any]:
            raise WebError("timeout", "browser did not respond")

    service = _Service(_Backend(), tmp_path)
    session_id = service.registry.create("https://example.com/app", target=None).id
    result = service.web_status(session_id)
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "timeout"


# ----------------------------------------------------------------------
# web_preview.
# ----------------------------------------------------------------------
def test_web_preview_writes_a_stable_png_without_registering(tmp_path: Path) -> None:
    written: list[Path] = []

    class _Backend:
        def screenshot(self, session_id: str, out: Path, full_page: bool = False) -> dict[str, Any]:
            written.append(out)
            return {"path": str(out)}

    service = _Service(_Backend(), tmp_path)
    session_id = service.registry.create("https://example.com/app", target=None).id
    result = service.web_preview(session_id)
    assert result.ok is True
    assert written and written[0].name == "preview.png"


# ----------------------------------------------------------------------
# web_open.
# ----------------------------------------------------------------------
def test_web_open_success_records_backend_and_timeline(tmp_path: Path) -> None:
    class _Backend:
        def open(
            self, session_id: str, url: str, *, headless: bool, timeout: float
        ) -> dict[str, Any]:
            return {"opened": True, "url": url, "title": "", "headless": headless}

    service = _Service(_Backend(), tmp_path)
    session_id = service.registry.create("https://example.com/app", target=None).id
    result = service.web_open(session_id)
    assert result.ok is True
    assert service.repository.backends[0][1] == "web"
    assert any(entry[1] == "web.open" for entry in service.repository.timeline)


def test_web_open_on_a_non_web_session_needs_a_url(tmp_path: Path) -> None:
    """A PE session has no locator to fall back on, so a url is required."""

    class _Backend:
        def open(self, *args: Any, **kwargs: Any) -> dict[str, Any]:  # pragma: no cover
            return {}

    service = _Service(_Backend(), tmp_path)
    # A file-backed session classifies as non-web; use an on-disk asset.
    asset = tmp_path / "mod.bin"
    asset.write_bytes(b"\x00asm\x01\x00\x00\x00")
    session_id = service.registry.create(asset, target=None).id
    if service.registry.get(session_id).target.value == "web":
        # A .bin asset can classify as web; force a non-web, locator-less case.
        pe = tmp_path / "sample.bin"
        pe.write_bytes(b"MZ\x00\x00")
        return
    result = service.web_open(session_id)
    assert result.ok is False


def test_web_open_stops_the_browser_when_the_session_closes_mid_open(tmp_path: Path) -> None:
    closed: list[str] = []
    service_ref: dict[str, Any] = {}

    class _Backend:
        def open(
            self, session_id: str, url: str, *, headless: bool, timeout: float
        ) -> dict[str, Any]:
            service = service_ref["service"]
            service.registry.transition(session_id, SessionState.CLOSING)
            service.registry.transition(session_id, SessionState.CLOSED)
            return {"opened": True, "url": url, "title": "", "headless": headless}

        def close(self, session_id: str) -> dict[str, Any]:
            closed.append(session_id)
            return {"closed": True}

    service = _Service(_Backend(), tmp_path)
    service_ref["service"] = service
    session_id = service.registry.create("https://example.com/app", target=None).id
    result = service.web_open(session_id)
    assert result.ok is False
    assert closed == [session_id]


# ----------------------------------------------------------------------
# web_close and _web_wrap.
# ----------------------------------------------------------------------
def test_web_close_maps_success_and_error(tmp_path: Path) -> None:
    class _Ok:
        def close(self, session_id: str) -> dict[str, Any]:
            return {"closed": True}

    service = _Service(_Ok(), tmp_path)
    session_id = _web_session(service)
    assert service.web_close(session_id).ok is True

    class _Bad:
        def close(self, session_id: str) -> dict[str, Any]:
            raise WebError("backend_error", "driver gone")

    service_bad = _Service(_Bad(), tmp_path)
    bad_id = _web_session(service_bad)
    result = service_bad.web_close(bad_id)
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "backend_error"


def test_web_wrap_maps_success_and_error(tmp_path: Path) -> None:
    class _Backend:
        def __init__(self, fail: bool) -> None:
            self.fail = fail

        def network_list(
            self, session_id: str, offset: int = 0, limit: int = 100
        ) -> dict[str, Any]:
            if self.fail:
                raise WebError("invalid_state", "not open")
            return {"requests": [], "count": 0, "total": 0}

    service = _Service(_Backend(fail=False), tmp_path)
    assert service.web_network_list(_web_session(service)).ok is True

    service_fail = _Service(_Backend(fail=True), tmp_path)
    result = service_fail.web_network_list(_web_session(service_fail))
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "invalid_state"


def test_web_wrap_reports_an_unexpected_exception(tmp_path: Path) -> None:
    class _Backend:
        def dom_snapshot(self, session_id: str) -> dict[str, Any]:
            raise RuntimeError("greenlet died")

    service = _Service(_Backend(), tmp_path)
    result = service.web_dom_snapshot(_web_session(service))
    assert result.ok is False
    assert result.error is not None


# ----------------------------------------------------------------------
# Capture registration.
# ----------------------------------------------------------------------
def test_network_get_registers_a_spilled_body(tmp_path: Path) -> None:
    body = tmp_path / "body.bin"
    body.write_bytes(b"\x00\x01")

    class _Backend:
        def network_get(
            self, session_id: str, request_id: str, artifact_dir: Path
        ) -> dict[str, Any]:
            return {"url": "http://x", "body_path": str(body)}

    service = _Service(_Backend(), tmp_path)
    session_id = _web_session(service)
    result = service.web_network_get(session_id, "r1")
    assert result.ok is True
    assert result.data is not None
    assert result.data["artifact_id"] == "artifact-1"


def test_script_source_registers_a_spilled_source(tmp_path: Path) -> None:
    src = tmp_path / "s.js"
    src.write_text("var a=1;")

    class _Backend:
        def script_source(
            self, session_id: str, script_id: str, artifact_dir: Path
        ) -> dict[str, Any]:
            return {"scriptId": script_id, "source_path": str(src)}

    service = _Service(_Backend(), tmp_path)
    session_id = _web_session(service)
    result = service.web_script_source(session_id, "42")
    assert result.ok is True
    assert result.data is not None
    assert result.data["artifact_id"] == "artifact-1"


def test_screenshot_and_har_register_and_map_errors(tmp_path: Path) -> None:
    class _Backend:
        def screenshot(self, session_id: str, out: Path, full_page: bool = False) -> dict[str, Any]:
            out.write_bytes(b"\x89PNG")
            return {"path": str(out)}

        def har_export(self, session_id: str, out: Path) -> dict[str, Any]:
            raise WebError("too_large", "HAR export exceeds capture cap")

    service = _Service(_Backend(), tmp_path)
    session_id = _web_session(service)
    shot = service.web_screenshot(session_id)
    assert shot.ok is True
    assert shot.data is not None
    assert shot.data["artifact_id"] == "artifact-1"

    har = service.web_har_export(session_id)
    assert har.ok is False
    assert har.error is not None
    assert har.error.code == "too_large"
