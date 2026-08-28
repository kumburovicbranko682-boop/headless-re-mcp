"""Browser service paths: open gates, spill registration, error mapping.

The backend tests bound WebBackend itself; these pin the mixin the tool
surface calls -- web.open's URL requirement for non-web sessions and its
success bookkeeping, spilled network bodies registered as artifacts, and
the envelope that keeps a WebError's code while an unexpected exception
still answers as a failure instead of a traceback.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any

from headless_re_mcp.backends.web import WebError
from headless_re_mcp.config import Settings
from headless_re_mcp.core.models import Session, TargetKind
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.core.service_web import _navigation_target

JsonObject = dict[str, Any]


class _FakeWebBackend:
    """Stands in for WebBackend; each op is scripted per test."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, tuple[Any, ...], dict[str, Any]]] = []
        self.answers: dict[str, JsonObject | BaseException] = {}

    def _answer(self, name: str) -> JsonObject:
        value = self.answers.get(name, {})
        if isinstance(value, BaseException):
            raise value
        return dict(value)

    def _record(self, name: str, *args: Any, **kwargs: Any) -> JsonObject:
        self.calls.append((name, args, kwargs))
        return self._answer(name)

    def status(self, session_id: str) -> JsonObject:
        return self._record("status", session_id)

    def open(self, session_id: str, url: str, *, headless: bool, timeout: float) -> JsonObject:
        return self._record("open", session_id, url, headless=headless, timeout=timeout)

    def close(self, session_id: str) -> JsonObject:
        return self._record("close", session_id)

    def navigate(self, session_id: str, url: str, *, timeout: float) -> JsonObject:
        return self._record("navigate", session_id, url, timeout=timeout)

    def network_list(self, session_id: str, *, offset: int, limit: int) -> JsonObject:
        return self._record("network_list", session_id, offset=offset, limit=limit)

    def network_get(self, session_id: str, request_id: str, artifact_dir: Path) -> JsonObject:
        return self._record("network_get", session_id, request_id, artifact_dir)

    def console(self, session_id: str, *, limit: int) -> JsonObject:
        return self._record("console", session_id, limit=limit)

    def scripts(self, session_id: str, *, wasm_only: bool, offset: int, limit: int) -> JsonObject:
        return self._record("scripts", session_id, wasm_only=wasm_only, offset=offset, limit=limit)

    def script_source(self, session_id: str, script_id: str, artifact_dir: Path) -> JsonObject:
        return self._record("script_source", session_id, script_id, artifact_dir)

    def dom_snapshot(self, session_id: str) -> JsonObject:
        return self._record("dom_snapshot", session_id)

    def screenshot(self, session_id: str, out: Path, *, full_page: bool) -> JsonObject:
        result = self._record("screenshot", session_id, out, full_page=full_page)
        out.write_bytes(b"\x89PNG")
        return {**result, "path": str(out)}

    def har_export(self, session_id: str, out: Path) -> JsonObject:
        result = self._record("har_export", session_id, out)
        out.write_text('{"log": {}}', encoding="utf-8")
        return {**result, "path": str(out)}

    def close_all(self) -> None:
        return None


def _service(tmp_path: Path) -> tuple[AnalysisService, _FakeWebBackend]:
    service = AnalysisService(replace(Settings.load(), artifact_root=tmp_path / "artifacts"))
    web = _FakeWebBackend()
    service._web_backend = web  # type: ignore[assignment]
    return service, web


def _calls(web: _FakeWebBackend, name: str) -> list[tuple[str, tuple[Any, ...], dict[str, Any]]]:
    return [call for call in web.calls if call[0] == name]


def test_web_status_keeps_the_web_error_code_and_survives_a_missing_session(
    tmp_path: Path,
) -> None:
    service, web = _service(tmp_path)
    try:
        session = service.registry.create("https://example.invalid")
        web.answers["status"] = WebError("backend_error", "runner is wedged")
        result = service.web_status(session.id)
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "backend_error"

        result = service.web_status("no-such-session")
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "session_not_found"
    finally:
        service.close_all()


def test_web_preview_overwrites_a_stable_png_without_registering_it(tmp_path: Path) -> None:
    service, web = _service(tmp_path)
    try:
        session = service.registry.create("https://example.invalid")
        result = service.web_preview(session.id)
        assert result.ok is True
        assert result.data is not None
        preview = Path(result.data["path"])
        assert preview.name == "preview.png"
        assert preview.is_file()
        # An inspect preview is a scratch file, not a capture.
        assert "artifact_id" not in result.data

        web.answers["screenshot"] = WebError("invalid_state", "no page is open")
        result = service.web_preview(session.id)
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "invalid_state"
    finally:
        service.close_all()


def test_web_open_success_falls_back_to_the_session_locator(tmp_path: Path) -> None:
    service, web = _service(tmp_path)
    try:
        session = service.registry.create("https://example.invalid")
        web.answers["open"] = {"opened": True, "url": "https://example.invalid/"}
        result = service.web_open(session.id, headless=True, timeout=9.0)
        assert result.ok is True
        assert result.data is not None
        assert result.data["url"] == "https://example.invalid/"
        # No url argument: the session's own locator is what gets opened.
        assert _calls(web, "open") == [
            ("open", (session.id, "https://example.invalid"), {"headless": True, "timeout": 9.0})
        ]
        assert _calls(web, "close") == []
    finally:
        service.close_all()


def test_web_open_requires_a_url_for_a_session_without_a_locator(tmp_path: Path) -> None:
    """A non-web session has no address of its own: web.open with no url has
    nothing to navigate to and must say so instead of opening about:blank."""
    service, web = _service(tmp_path)
    try:
        session = service.registry.adopt(Session(target=TargetKind.PE, locator=None))
        result = service.web_open(session.id)
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "invalid_params"
        assert "url is required" in result.error.message
        assert _calls(web, "open") == []
    finally:
        service.close_all()


def test_web_close_maps_both_error_shapes(tmp_path: Path) -> None:
    service, web = _service(tmp_path)
    try:
        session = service.registry.create("https://example.invalid")
        web.answers["close"] = WebError("invalid_state", "no browser for session")
        result = service.web_close(session.id)
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "invalid_state"

        web.answers["close"] = RuntimeError("playwright crashed")
        result = service.web_close(session.id)
        assert result.ok is False
    finally:
        web.answers["close"] = {"closed": True}
        service.close_all()


def test_web_network_get_registers_a_spilled_body(tmp_path: Path) -> None:
    service, web = _service(tmp_path)
    try:
        session = service.registry.create("https://example.invalid")
        body = tmp_path / "body.bin"
        body.write_bytes(b"d" * 64)
        web.answers["network_get"] = {
            "request_id": "req-1",
            "status": 200,
            "body_path": str(body),
        }
        result = service.web_network_get(session.id, "req-1")
        assert result.ok is True
        assert result.data is not None
        assert result.data["artifact_id"]

        # No spill: the payload passes through with nothing registered.
        web.answers["network_get"] = {"request_id": "req-2", "status": 204}
        result = service.web_network_get(session.id, "req-2")
        assert result.ok is True
        assert result.data is not None
        assert "artifact_id" not in result.data

        web.answers["network_get"] = WebError("not_found", "no request req-3")
        result = service.web_network_get(session.id, "req-3")
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "not_found"
    finally:
        service.close_all()


def test_web_script_source_without_a_spill_passes_through(tmp_path: Path) -> None:
    service, web = _service(tmp_path)
    try:
        session = service.registry.create("https://example.invalid")
        web.answers["script_source"] = {"script_id": "s-1", "source": "console.log(1)"}
        result = service.web_script_source(session.id, "s-1")
        assert result.ok is True
        assert result.data is not None
        assert result.data["source"] == "console.log(1)"
        assert "artifact_id" not in result.data

        web.answers["script_source"] = WebError("not_found", "no script s-2")
        result = service.web_script_source(session.id, "s-2")
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "not_found"
    finally:
        service.close_all()


def test_web_screenshot_and_har_export_keep_web_error_codes(tmp_path: Path) -> None:
    service, web = _service(tmp_path)
    try:
        session = service.registry.create("https://example.invalid")
        web.answers["screenshot"] = WebError("invalid_state", "no page is open")
        result = service.web_screenshot(session.id)
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "invalid_state"

        web.answers["har_export"] = WebError("invalid_state", "no page is open")
        result = service.web_har_export(session.id)
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "invalid_state"
    finally:
        service.close_all()


def test_web_wrap_forwards_arguments_and_maps_unexpected_errors(tmp_path: Path) -> None:
    service, web = _service(tmp_path)
    try:
        session = service.registry.create("https://example.invalid")
        web.answers["navigate"] = {"url": "https://example.invalid/next"}
        result = service.web_navigate(session.id, "https://example.invalid/next", timeout=4.0)
        assert result.ok is True
        assert result.data == {"url": "https://example.invalid/next"}
        assert _calls(web, "navigate") == [
            ("navigate", (session.id, "https://example.invalid/next"), {"timeout": 4.0})
        ]

        web.answers["network_list"] = {"requests": [], "total": 0}
        result = service.web_network_list(session.id, offset=3, limit=9)
        assert result.ok is True
        assert _calls(web, "network_list") == [
            ("network_list", (session.id,), {"offset": 3, "limit": 9})
        ]

        web.answers["console"] = {"messages": []}
        assert service.web_console(session.id, limit=17).ok is True
        assert _calls(web, "console") == [("console", (session.id,), {"limit": 17})]

        web.answers["scripts"] = {"scripts": [], "total": 0}
        assert service.web_scripts(session.id, wasm_only=False).ok is True
        assert service.web_wasm_list(session.id, offset=1, limit=2).ok is True
        assert _calls(web, "scripts") == [
            ("scripts", (session.id,), {"wasm_only": False, "offset": 0, "limit": 100}),
            ("scripts", (session.id,), {"wasm_only": True, "offset": 1, "limit": 2}),
        ]

        web.answers["dom_snapshot"] = RuntimeError("page went away")
        result = service.web_dom_snapshot(session.id)
        assert result.ok is False
        assert result.error is not None
    finally:
        service.close_all()


def test_navigation_target_rewrites_a_local_file_and_leaves_urls_alone(tmp_path: Path) -> None:
    asset = tmp_path / "app.html"
    asset.write_text("<html></html>", encoding="utf-8")
    # A real local asset becomes a file:// URL a browser can open.
    assert _navigation_target(str(asset)) == asset.resolve().as_uri()
    assert _navigation_target(f"  {asset}  ") == asset.resolve().as_uri()
    # Remote URLs, non-http schemes, schemeless hosts and non-files pass through.
    for passthrough in (
        "https://example.com/app",
        "http://example.com",
        "about:blank",
        "file:///already/a/url",
        "example.com/not/a/local/file",
        str(tmp_path / "missing.html"),
        "",
        "   ",
    ):
        assert _navigation_target(passthrough) == passthrough.strip()


def test_navigation_target_never_raises_on_a_hostile_url() -> None:
    """A best-effort normaliser on the web.open/web.navigate input path must not
    itself throw on a caller-supplied url: an embedded null byte, an over-long
    string or a ~ that cannot expand falls back to the raw text (stripped), which
    the browser then rejects with its own navigation error."""
    for hostile in (
        "x\x00y",
        "https://a\x00b",
        "a" * 5000,
        "\x00",
        "  \x00  ",
        "~\x00/evil",
        "ws://h\x00st",
    ):
        assert _navigation_target(hostile) == hostile.strip()


def test_web_open_opens_a_local_asset_locator_as_a_file_url(tmp_path: Path) -> None:
    """A downloaded .html/.js/.wasm classifies as a web session whose locator is
    a filesystem path; web.open with no url must hand the browser a file:// URL,
    not the bare path Playwright cannot navigate to."""
    service, web = _service(tmp_path)
    try:
        asset = tmp_path / "page.html"
        asset.write_text("<html><body>local</body></html>", encoding="utf-8")
        session = service.registry.create(str(asset))
        assert session.target is TargetKind.WEB
        web.answers["open"] = {"opened": True, "url": asset.resolve().as_uri()}
        result = service.web_open(session.id, headless=True, timeout=9.0)
        assert result.ok is True
        assert _calls(web, "open") == [
            ("open", (session.id, asset.resolve().as_uri()), {"headless": True, "timeout": 9.0})
        ]
    finally:
        service.close_all()


def test_web_navigate_rewrites_a_local_file_path_to_a_file_url(tmp_path: Path) -> None:
    service, web = _service(tmp_path)
    try:
        session = service.registry.create("https://example.invalid")
        asset = tmp_path / "next.html"
        asset.write_text("<html></html>", encoding="utf-8")
        web.answers["navigate"] = {"url": asset.resolve().as_uri()}
        result = service.web_navigate(session.id, str(asset), timeout=4.0)
        assert result.ok is True
        assert _calls(web, "navigate") == [
            ("navigate", (session.id, asset.resolve().as_uri()), {"timeout": 4.0})
        ]
    finally:
        service.close_all()
