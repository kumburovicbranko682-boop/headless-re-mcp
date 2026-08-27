"""The web service mixin must envelope the browser backend and register spills.

``WebAnalysisMixin`` fronts one Playwright-driven ``WebBackend`` per session:
each method returns a ``_success`` payload, maps a ``WebError`` through
``_as_rpc`` (a browser timeout stays retryable), lets anything else fall
through, and spills bodies/scripts/screenshots/HAR into the session artifact
tree as registered captures. No browser exists here, so the backend is faked --
the point is the mixin's gating, translation, and artifact registration, plus
the ``_check_navigation_url`` scheme guard that keeps web.open/web.navigate from
reading local files.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.web import WebError
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.core.service_web import _check_navigation_url

JsonObject = dict[str, Any]


class _FakeWeb:
    """A Playwright-backend stand-in; per-method errors are set per test."""

    def __init__(self) -> None:
        self.errors: dict[str, BaseException] = {}
        self.network_body: Path | None = None
        self.script_source_path: Path | None = None
        self.opened: list[tuple[str, str]] = []
        self.closed: list[str] = []

    def _raise(self, op: str) -> None:
        err = self.errors.get(op)
        if err is not None:
            raise err

    def status(self, session_id: str) -> JsonObject:
        self._raise("status")
        return {"open": True}

    def screenshot(self, session_id: str, out_path: Path, full_page: bool = False) -> JsonObject:
        self._raise("screenshot")
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_bytes(b"\x89PNG\r\n\x1a\n" + b"0" * 64)
        return {"path": str(out_path)}

    def open(
        self, session_id: str, url: str, headless: bool = True, timeout: float = 30.0
    ) -> JsonObject:
        self._raise("open")
        self.opened.append((session_id, url))
        return {"url": url or "https://example.com", "opened": True}

    def navigate(self, session_id: str, url: str, timeout: float = 30.0) -> JsonObject:
        self._raise("navigate")
        return {"url": url}

    def close(self, session_id: str) -> JsonObject:
        self._raise("close")
        self.closed.append(session_id)
        return {"closed": True}

    def network_list(self, session_id: str, offset: int = 0, limit: int = 100) -> JsonObject:
        self._raise("network_list")
        return {"requests": [], "offset": offset, "limit": limit}

    def network_get(self, session_id: str, request_id: str, artifact_dir: Path) -> JsonObject:
        self._raise("network_get")
        data: JsonObject = {"request_id": request_id}
        if self.network_body is not None:
            data["body_path"] = str(self.network_body)
        return data

    def console(self, session_id: str, limit: int = 200) -> JsonObject:
        self._raise("console")
        return {"messages": []}

    def scripts(
        self, session_id: str, wasm_only: bool = False, offset: int = 0, limit: int = 100
    ) -> JsonObject:
        self._raise("scripts")
        return {"scripts": [], "wasm_only": wasm_only}

    def script_source(self, session_id: str, script_id: str, artifact_dir: Path) -> JsonObject:
        self._raise("script_source")
        data: JsonObject = {"scriptId": script_id}
        if self.script_source_path is not None:
            data["source_path"] = str(self.script_source_path)
        return data

    def dom_snapshot(self, session_id: str) -> JsonObject:
        self._raise("dom_snapshot")
        return {"nodes": 0}

    def har_export(self, session_id: str, out_path: Path) -> JsonObject:
        self._raise("har_export")
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text('{"log":{"entries":[]}}', encoding="utf-8")
        return {"path": str(out_path), "entry_count": 0}

    def close_all(self) -> None:
        self.opened.clear()


@pytest.fixture
def web_env(tmp_path: Path) -> Iterator[tuple[AnalysisService, _FakeWeb, str]]:
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    fake = _FakeWeb()
    service._web_backend = fake  # type: ignore[assignment]
    try:
        created = service.create_session("https://example.com/app", target="web")
        assert created.ok and created.data is not None, created.error
        yield service, fake, str(created.data["session"]["id"])
    finally:
        service.close_all()


# --------------------------------------------------------------------------
# _check_navigation_url
# --------------------------------------------------------------------------


@pytest.mark.parametrize("url", ["https://x/y", "http://127.0.0.1:8080/", "data:text/html,<p>x"])
def test_check_navigation_url_accepts_web_schemes(url: str) -> None:
    _check_navigation_url(url)


@pytest.mark.parametrize("url", ["", "   ", 123, None])
def test_check_navigation_url_requires_a_url(url: Any) -> None:
    with pytest.raises(WebError) as exc:
        _check_navigation_url(url)
    assert exc.value.code == "invalid_params"


@pytest.mark.parametrize("url", ["file:///etc/passwd", "javascript:alert(1)", "chrome://version"])
def test_check_navigation_url_refuses_non_web_schemes(url: str) -> None:
    with pytest.raises(WebError) as exc:
        _check_navigation_url(url)
    assert exc.value.code == "invalid_params"


# --------------------------------------------------------------------------
# status / preview
# --------------------------------------------------------------------------


def test_web_status_folds_in_session_metadata(
    web_env: tuple[AnalysisService, _FakeWeb, str],
) -> None:
    service, _, session_id = web_env
    result = service.web_status(session_id)
    assert result.ok, result.error
    assert result.data is not None
    assert result.data["state"] == "created"
    assert result.data["target"] == "web"


def test_web_status_maps_a_web_error(web_env: tuple[AnalysisService, _FakeWeb, str]) -> None:
    service, fake, session_id = web_env
    fake.errors["status"] = WebError("backend_error", "cdp down")
    result = service.web_status(session_id)
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "backend_error"


def test_web_status_surfaces_an_unexpected_exception(
    web_env: tuple[AnalysisService, _FakeWeb, str],
) -> None:
    service, fake, session_id = web_env
    fake.errors["status"] = RuntimeError("playwright exploded")
    result = service.web_status(session_id)
    assert result.ok is False
    assert result.error is not None


def test_web_preview_writes_a_stable_png(web_env: tuple[AnalysisService, _FakeWeb, str]) -> None:
    service, _, session_id = web_env
    result = service.web_preview(session_id)
    assert result.ok, result.error
    assert result.data is not None
    assert result.data["path"].endswith("preview.png")


def test_web_preview_maps_a_web_error(web_env: tuple[AnalysisService, _FakeWeb, str]) -> None:
    service, fake, session_id = web_env
    fake.errors["screenshot"] = WebError("timeout", "screenshot timed out")
    result = service.web_preview(session_id)
    assert result.ok is False
    assert result.error is not None
    assert result.error.retryable is True


# --------------------------------------------------------------------------
# open / navigate / close
# --------------------------------------------------------------------------


def test_web_open_records_the_browser(web_env: tuple[AnalysisService, _FakeWeb, str]) -> None:
    service, fake, session_id = web_env
    result = service.web_open(session_id)
    assert result.ok, result.error
    assert result.data is not None
    assert result.data["opened"] is True
    assert fake.opened and fake.opened[0][0] == session_id
    backends = service.repository.list_backends(session_id)
    assert any(b["kind"] == "web" for b in backends)


def test_web_open_maps_a_web_error(web_env: tuple[AnalysisService, _FakeWeb, str]) -> None:
    service, fake, session_id = web_env
    fake.errors["open"] = WebError("capability_unavailable", "playwright missing")
    result = service.web_open(session_id)
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "capability_unavailable"


def test_web_open_requires_a_url_for_a_locatorless_non_web_session(tmp_path: Path) -> None:
    """A non-web session with no locator and no url has nothing to navigate to."""
    import zipfile

    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    service._web_backend = _FakeWeb()  # type: ignore[assignment]
    apk = tmp_path / "app.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00manifest")
        archive.writestr("classes.dex", b"dex\n035\x00")
    try:
        created = service.create_session(str(apk), target="apk")
        assert created.ok and created.data is not None, created.error
        session_id = str(created.data["session"]["id"])
        # get() hands out deep copies, so blank the stored record itself.
        service.registry._sessions[session_id].locator = None
        result = service.web_open(session_id)
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "invalid_params"
        assert "url is required" in result.error.message
    finally:
        service.close_all()


def test_web_navigate_reaches_the_backend(web_env: tuple[AnalysisService, _FakeWeb, str]) -> None:
    service, _, session_id = web_env
    result = service.web_navigate(session_id, "https://example.com/next")
    assert result.ok, result.error
    assert result.data is not None
    assert result.data["url"] == "https://example.com/next"


def test_web_navigate_rejects_a_hostile_url(web_env: tuple[AnalysisService, _FakeWeb, str]) -> None:
    service, _, session_id = web_env
    result = service.web_navigate(session_id, "file:///etc/passwd")
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "invalid_params"


def test_web_close_reports_success(web_env: tuple[AnalysisService, _FakeWeb, str]) -> None:
    service, fake, session_id = web_env
    result = service.web_close(session_id)
    assert result.ok, result.error
    assert fake.closed == [session_id]


def test_web_close_maps_a_web_error(web_env: tuple[AnalysisService, _FakeWeb, str]) -> None:
    service, fake, session_id = web_env
    fake.errors["close"] = WebError("backend_error", "close failed")
    result = service.web_close(session_id)
    assert result.ok is False
    assert result.error is not None


def test_web_close_surfaces_an_unexpected_exception(
    web_env: tuple[AnalysisService, _FakeWeb, str],
) -> None:
    service, fake, session_id = web_env
    fake.errors["close"] = RuntimeError("browser wedged")
    result = service.web_close(session_id)
    assert result.ok is False
    assert result.error is not None


# --------------------------------------------------------------------------
# network / console / scripts / dom (the _web_wrap siblings)
# --------------------------------------------------------------------------


def test_web_network_list_reports_success(web_env: tuple[AnalysisService, _FakeWeb, str]) -> None:
    service, _, session_id = web_env
    result = service.web_network_list(session_id, offset=3, limit=7)
    assert result.ok, result.error
    assert result.data is not None
    assert result.data["offset"] == 3 and result.data["limit"] == 7


def test_web_network_get_registers_a_body_spill(
    web_env: tuple[AnalysisService, _FakeWeb, str], tmp_path: Path
) -> None:
    service, fake, session_id = web_env
    body = tmp_path / "resp.bin"
    body.write_bytes(b"response-bytes")
    fake.network_body = body
    result = service.web_network_get(session_id, "req-1")
    assert result.ok, result.error
    assert result.data is not None
    assert result.data["artifact_id"]


def test_web_network_get_without_a_body_is_returned_untouched(
    web_env: tuple[AnalysisService, _FakeWeb, str],
) -> None:
    service, fake, session_id = web_env
    fake.network_body = None
    result = service.web_network_get(session_id, "req-2")
    assert result.ok, result.error
    assert result.data is not None
    assert "artifact_id" not in result.data


def test_web_network_get_maps_a_web_error(
    web_env: tuple[AnalysisService, _FakeWeb, str],
) -> None:
    service, fake, session_id = web_env
    fake.errors["network_get"] = WebError("not_found", "no such request")
    result = service.web_network_get(session_id, "missing")
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "not_found"


def test_web_console_scripts_wasm_dom_report_success(
    web_env: tuple[AnalysisService, _FakeWeb, str],
) -> None:
    service, _, session_id = web_env
    assert service.web_console(session_id).ok
    scripts = service.web_scripts(session_id, wasm_only=False)
    assert scripts.ok and scripts.data is not None
    assert scripts.data["wasm_only"] is False
    wasm = service.web_wasm_list(session_id)
    assert wasm.ok and wasm.data is not None
    assert wasm.data["wasm_only"] is True
    assert service.web_dom_snapshot(session_id).ok


def test_web_wrap_maps_a_web_error(web_env: tuple[AnalysisService, _FakeWeb, str]) -> None:
    service, fake, session_id = web_env
    fake.errors["console"] = WebError("invalid_state", "browser not open")
    result = service.web_console(session_id)
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "invalid_state"


def test_web_wrap_surfaces_an_unexpected_exception(
    web_env: tuple[AnalysisService, _FakeWeb, str],
) -> None:
    service, fake, session_id = web_env
    fake.errors["dom_snapshot"] = RuntimeError("cdp protocol error")
    result = service.web_dom_snapshot(session_id)
    assert result.ok is False
    assert result.error is not None


# --------------------------------------------------------------------------
# script source / screenshot / har -- registered captures
# --------------------------------------------------------------------------


def test_web_script_source_registers_a_spill(
    web_env: tuple[AnalysisService, _FakeWeb, str], tmp_path: Path
) -> None:
    service, fake, session_id = web_env
    spill = tmp_path / "script.js"
    spill.write_text("var a=1;", encoding="utf-8")
    fake.script_source_path = spill
    result = service.web_script_source(session_id, "42")
    assert result.ok, result.error
    assert result.data is not None
    assert result.data["artifact_id"]


def test_web_script_source_without_a_spill_is_returned_untouched(
    web_env: tuple[AnalysisService, _FakeWeb, str],
) -> None:
    service, fake, session_id = web_env
    fake.script_source_path = None
    result = service.web_script_source(session_id, "43")
    assert result.ok, result.error
    assert result.data is not None
    assert "artifact_id" not in result.data


def test_web_script_source_maps_a_web_error(
    web_env: tuple[AnalysisService, _FakeWeb, str],
) -> None:
    service, fake, session_id = web_env
    fake.errors["script_source"] = WebError("not_found", "unknown script id")
    result = service.web_script_source(session_id, "nope")
    assert result.ok is False
    assert result.error is not None


def test_web_screenshot_registers_a_capture(
    web_env: tuple[AnalysisService, _FakeWeb, str],
) -> None:
    service, _, session_id = web_env
    result = service.web_screenshot(session_id)
    assert result.ok, result.error
    assert result.data is not None
    assert result.data["artifact_id"]


def test_web_screenshot_maps_a_web_error(web_env: tuple[AnalysisService, _FakeWeb, str]) -> None:
    service, fake, session_id = web_env
    fake.errors["screenshot"] = WebError("timeout", "screenshot timed out")
    result = service.web_screenshot(session_id)
    assert result.ok is False
    assert result.error is not None


def test_web_har_export_registers_a_capture(
    web_env: tuple[AnalysisService, _FakeWeb, str],
) -> None:
    service, _, session_id = web_env
    result = service.web_har_export(session_id)
    assert result.ok, result.error
    assert result.data is not None
    assert result.data["artifact_id"]


def test_web_har_export_maps_a_web_error(web_env: tuple[AnalysisService, _FakeWeb, str]) -> None:
    service, fake, session_id = web_env
    fake.errors["har_export"] = WebError("backend_error", "har write failed")
    result = service.web_har_export(session_id)
    assert result.ok is False
    assert result.error is not None


def test_web_artifact_dir_refuses_an_unsafe_session_id(
    web_env: tuple[AnalysisService, _FakeWeb, str],
) -> None:
    service, _, _ = web_env
    with pytest.raises(WebError) as exc:
        service._web_artifact_dir("../escape")
    assert exc.value.code == "invalid_params"


@pytest.mark.parametrize(
    "method, op, args",
    [
        ("web_preview", "screenshot", ()),
        ("web_network_get", "network_get", ("req-9",)),
        ("web_script_source", "script_source", ("9",)),
        ("web_screenshot", "screenshot", ()),
        ("web_har_export", "har_export", ()),
    ],
)
def test_artifact_writers_surface_an_unexpected_exception(
    web_env: tuple[AnalysisService, _FakeWeb, str],
    method: str,
    op: str,
    args: tuple[Any, ...],
) -> None:
    service, fake, session_id = web_env
    fake.errors[op] = RuntimeError("playwright exploded")
    result = getattr(service, method)(session_id, *args)
    assert result.ok is False
    assert result.error is not None
