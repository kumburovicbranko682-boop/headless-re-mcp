"""Guard clauses, failure arms, and capture registration of the web service mixin.

The mixin is exercised against a scripted ``WebBackend`` double so every arm is
reachable deterministically: backend refusals must come back as structured
envelopes (never tracebacks), spilled bodies and captures must be registered as
artifacts, and a session that dies mid-open must get its browser closed again.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any, cast

from headless_re_mcp.backends.web import WebBackend, WebError
from headless_re_mcp.config import Settings
from headless_re_mcp.core.models import Session, SessionState, TargetKind
from headless_re_mcp.core.repository import InMemoryAnalysisRepository
from headless_re_mcp.core.service_web import WebAnalysisMixin
from headless_re_mcp.core.session import InvalidStateTransition, SessionRegistry

JsonObject = dict[str, Any]


class _ScriptedWeb:
    """WebBackend double: records calls, answers from a script, raises on cue."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, tuple[Any, ...], dict[str, Any]]] = []
        self.replies: dict[str, JsonObject] = {}
        self.raises: dict[str, BaseException] = {}
        self.on_open: Callable[[], object] | None = None
        self.spill_writer: Callable[[Path], Path] | None = None

    def _answer(self, op: str, *args: Any, **kwargs: Any) -> JsonObject:
        self.calls.append((op, args, kwargs))
        exc = self.raises.get(op)
        if exc is not None:
            raise exc
        return dict(self.replies.get(op, {"op": op}))

    def called(self, op: str) -> bool:
        return any(name == op for name, _, _ in self.calls)

    def status(self, session_id: str) -> JsonObject:
        return self._answer("status", session_id)

    def open(
        self, session_id: str, target: str, *, headless: bool = True, timeout: float = 30.0
    ) -> JsonObject:
        if self.on_open is not None:
            self.on_open()
        return self._answer("open", session_id, target, headless=headless, timeout=timeout)

    def close(self, session_id: str) -> JsonObject:
        return self._answer("close", session_id)

    def navigate(self, session_id: str, url: str, *, timeout: float = 30.0) -> JsonObject:
        return self._answer("navigate", session_id, url, timeout=timeout)

    def network_list(self, session_id: str, *, offset: int = 0, limit: int = 100) -> JsonObject:
        return self._answer("network_list", session_id, offset=offset, limit=limit)

    def network_get(self, session_id: str, request_id: str, artifact_dir: Path) -> JsonObject:
        reply = self._answer("network_get", session_id, request_id, artifact_dir)
        if self.spill_writer is not None:
            reply["body_path"] = str(self.spill_writer(artifact_dir))
        return reply

    def console(self, session_id: str, *, limit: int = 200) -> JsonObject:
        return self._answer("console", session_id, limit=limit)

    def scripts(
        self,
        session_id: str,
        *,
        wasm_only: bool = False,
        offset: int = 0,
        limit: int = 100,
    ) -> JsonObject:
        return self._answer("scripts", session_id, wasm_only=wasm_only, offset=offset, limit=limit)

    def script_source(self, session_id: str, script_id: str, artifact_dir: Path) -> JsonObject:
        reply = self._answer("script_source", session_id, script_id, artifact_dir)
        if self.spill_writer is not None:
            reply["source_path"] = str(self.spill_writer(artifact_dir))
        return reply

    def dom_snapshot(self, session_id: str) -> JsonObject:
        return self._answer("dom_snapshot", session_id)

    def screenshot(self, session_id: str, out: Path, *, full_page: bool = False) -> JsonObject:
        reply = self._answer("screenshot", session_id, str(out), full_page=full_page)
        out.write_bytes(b"\x89PNG-not-really")
        return reply

    def har_export(self, session_id: str, out: Path) -> JsonObject:
        reply = self._answer("har_export", session_id, str(out))
        out.write_text("{}", encoding="utf-8")
        return reply


class _Service(WebAnalysisMixin):
    def __init__(self, artifact_root: Path) -> None:
        self.settings = Settings(
            ida_home=None,
            x64dbg_source=None,
            x64dbg_headless_x64=None,
            x64dbg_headless_x86=None,
            artifact_root=artifact_root,
        )
        self.registry = SessionRegistry()
        self.repository = InMemoryAnalysisRepository(artifact_root)
        self.fake = _ScriptedWeb()
        self._web_backend = cast(WebBackend, self.fake)

    def web_session(self, session_id: str = "websid") -> str:
        self.registry.adopt(
            Session(id=session_id, target=TargetKind.WEB, locator="https://example.test/")
        )
        return session_id

    def timeline_events(self, session_id: str) -> list[str]:
        listing = self.repository.list_timeline(session_id)
        return [str(item["event"]) for item in listing["events"]]


def test_status_reports_the_session_view(tmp_path: Path) -> None:
    service = _Service(tmp_path)
    sid = service.web_session()
    service.fake.replies["status"] = {"open": True}

    result = service.web_status(sid)

    assert result.ok and result.data is not None
    assert result.data["locator"] == "https://example.test/"
    assert result.data["state"] == "created"
    assert result.data["target"] == "web"
    assert result.meta["backend"] == "web"


def test_status_maps_a_backend_refusal_to_its_structured_code(tmp_path: Path) -> None:
    service = _Service(tmp_path)
    sid = service.web_session()
    service.fake.raises["status"] = WebError("no_browser", "browser is not open", hint="web.open")

    result = service.web_status(sid)

    assert not result.ok and result.error is not None
    assert result.error.code == "no_browser"
    assert result.error.details["hint"] == "web.open"


def test_status_reports_an_unknown_session_as_not_found(tmp_path: Path) -> None:
    result = _Service(tmp_path).web_status("never-created")

    assert not result.ok and result.error is not None
    assert result.error.code == "session_not_found"


def test_preview_overwrites_a_stable_png_without_registering_it(tmp_path: Path) -> None:
    service = _Service(tmp_path)
    sid = service.web_session()

    result = service.web_preview(sid)

    assert result.ok and result.data is not None
    assert "artifact_id" not in result.data
    preview = tmp_path / "web" / sid / "preview.png"
    assert preview.is_file()
    assert service.repository.list_artifacts(sid)["total"] == 0


def test_preview_refuses_a_traversal_session_id(tmp_path: Path) -> None:
    result = _Service(tmp_path).web_preview("..")

    assert not result.ok and result.error is not None
    assert result.error.code == "invalid_params"
    assert not (tmp_path / "web").exists()


def test_preview_reports_an_unknown_session_as_not_found(tmp_path: Path) -> None:
    result = _Service(tmp_path).web_preview("never-created")

    assert not result.ok and result.error is not None
    assert result.error.code == "session_not_found"
    assert not (tmp_path / "web").exists()


def test_open_requires_a_url_for_a_non_web_session(tmp_path: Path) -> None:
    service = _Service(tmp_path)
    binary = tmp_path / "sample.bin"
    binary.write_bytes(b"MZ")
    service.registry.adopt(Session(id="pesid", target=TargetKind.PE, binary=binary))

    result = service.web_open("pesid")

    assert not result.ok and result.error is not None
    assert result.error.code == "invalid_params"
    assert not service.fake.called("open")


def test_open_refuses_a_session_already_in_a_terminal_state(tmp_path: Path) -> None:
    service = _Service(tmp_path)
    sid = service.web_session()
    service.registry.transition(sid, SessionState.FAILED)

    result = service.web_open(sid)

    assert not result.ok and result.error is not None
    assert result.error.code == "invalid_request"
    assert not service.fake.called("open")


def test_open_records_the_backend_and_a_timeline_event(tmp_path: Path) -> None:
    service = _Service(tmp_path)
    sid = service.web_session()
    service.fake.replies["open"] = {"url": "https://example.test/landed"}

    result = service.web_open(sid, headless=False, timeout=12.0)

    assert result.ok and result.data is not None
    assert result.data["url"] == "https://example.test/landed"
    _, args, kwargs = service.fake.calls[0]
    assert args == (sid, "https://example.test/")
    assert kwargs == {"headless": False, "timeout": 12.0}
    backends = service.repository.list_backends(sid)
    assert [item["kind"] for item in backends] == ["web"]
    assert backends[0]["endpoint"] == "https://example.test/landed"
    assert "web.open" in service.timeline_events(sid)


def test_open_maps_a_backend_launch_failure(tmp_path: Path) -> None:
    service = _Service(tmp_path)
    sid = service.web_session()
    service.fake.raises["open"] = WebError("browser_missing", "no chromium install")

    result = service.web_open(sid)

    assert not result.ok and result.error is not None
    assert result.error.code == "browser_missing"
    assert service.repository.list_backends(sid) == []


def test_open_closes_the_browser_when_the_session_dies_mid_open(tmp_path: Path) -> None:
    """A close racing web.open must not leave an untracked browser running."""
    service = _Service(tmp_path)
    sid = service.web_session()
    service.fake.on_open = lambda: service.registry.transition(sid, SessionState.FAILED)

    result = service.web_open(sid)

    assert not result.ok and result.error is not None
    assert result.error.code == "invalid_request"
    assert service.fake.called("close")
    assert service.repository.list_backends(sid) == []


def test_navigate_passes_the_url_and_timeout_through(tmp_path: Path) -> None:
    service = _Service(tmp_path)
    sid = service.web_session()

    result = service.web_navigate(sid, "https://example.test/next", timeout=7.0)

    assert result.ok
    assert service.fake.calls == [
        ("navigate", (sid, "https://example.test/next"), {"timeout": 7.0})
    ]


def test_close_appends_a_timeline_event(tmp_path: Path) -> None:
    service = _Service(tmp_path)
    sid = service.web_session()

    result = service.web_close(sid)

    assert result.ok
    assert "web.close" in service.timeline_events(sid)


def test_close_maps_backend_and_unexpected_errors(tmp_path: Path) -> None:
    service = _Service(tmp_path)
    sid = service.web_session()

    service.fake.raises["close"] = WebError("no_browser", "nothing to close")
    refused = service.web_close(sid)
    assert not refused.ok and refused.error is not None
    assert refused.error.code == "no_browser"

    service.fake.raises["close"] = InvalidStateTransition("interrupted")
    broken = service.web_close(sid)
    assert not broken.ok and broken.error is not None
    assert broken.error.code == "invalid_request"


def test_network_list_passes_paging_through(tmp_path: Path) -> None:
    service = _Service(tmp_path)
    sid = service.web_session()

    result = service.web_network_list(sid, offset=5, limit=9)

    assert result.ok
    assert service.fake.calls == [("network_list", (sid,), {"offset": 5, "limit": 9})]


def test_network_get_registers_a_spilled_response_body(tmp_path: Path) -> None:
    service = _Service(tmp_path)
    sid = service.web_session()

    def spill(artifact_dir: Path) -> Path:
        body = artifact_dir / "body.bin"
        body.write_bytes(b"response payload")
        return body

    service.fake.spill_writer = spill
    result = service.web_network_get(sid, "req-1")

    assert result.ok and result.data is not None
    artifact_id = result.data["artifact_id"]
    described = service.repository.describe_artifact(str(artifact_id))
    assert described is not None
    assert described["kind"] == "web_response_body"


def test_network_get_without_a_spill_returns_the_payload_untouched(tmp_path: Path) -> None:
    service = _Service(tmp_path)
    sid = service.web_session()
    service.fake.replies["network_get"] = {"status": 204}

    result = service.web_network_get(sid, "req-1")

    assert result.ok and result.data is not None
    assert "artifact_id" not in result.data
    assert result.data["status"] == 204


def test_network_get_maps_backend_and_unexpected_errors(tmp_path: Path) -> None:
    service = _Service(tmp_path)
    sid = service.web_session()

    service.fake.raises["network_get"] = WebError("request_not_found", "unknown request id")
    refused = service.web_network_get(sid, "req-404")
    assert not refused.ok and refused.error is not None
    assert refused.error.code == "request_not_found"

    service.fake.raises["network_get"] = InvalidStateTransition("interrupted")
    broken = service.web_network_get(sid, "req-1")
    assert not broken.ok and broken.error is not None
    assert broken.error.code == "invalid_request"


def test_console_scripts_and_wasm_list_pass_their_filters_through(tmp_path: Path) -> None:
    service = _Service(tmp_path)
    sid = service.web_session()

    assert service.web_console(sid, limit=17).ok
    assert service.web_scripts(sid, wasm_only=False, offset=1, limit=2).ok
    assert service.web_wasm_list(sid, offset=3, limit=4).ok

    assert service.fake.calls == [
        ("console", (sid,), {"limit": 17}),
        ("scripts", (sid,), {"wasm_only": False, "offset": 1, "limit": 2}),
        ("scripts", (sid,), {"wasm_only": True, "offset": 3, "limit": 4}),
    ]


def test_script_source_registers_a_spilled_source(tmp_path: Path) -> None:
    service = _Service(tmp_path)
    sid = service.web_session()

    def spill(artifact_dir: Path) -> Path:
        source = artifact_dir / "script.js"
        source.write_text("console.log(1)", encoding="utf-8")
        return source

    service.fake.spill_writer = spill
    result = service.web_script_source(sid, "script-1")

    assert result.ok and result.data is not None
    described = service.repository.describe_artifact(str(result.data["artifact_id"]))
    assert described is not None
    assert described["kind"] == "web_script_source"


def test_script_source_without_a_spill_returns_the_payload_untouched(tmp_path: Path) -> None:
    service = _Service(tmp_path)
    sid = service.web_session()
    service.fake.replies["script_source"] = {"inline": "console.log(1)"}

    result = service.web_script_source(sid, "script-1")

    assert result.ok and result.data is not None
    assert "artifact_id" not in result.data


def test_script_source_maps_backend_and_unexpected_errors(tmp_path: Path) -> None:
    service = _Service(tmp_path)
    sid = service.web_session()

    service.fake.raises["script_source"] = WebError("script_not_found", "unknown script id")
    refused = service.web_script_source(sid, "script-404")
    assert not refused.ok and refused.error is not None
    assert refused.error.code == "script_not_found"

    service.fake.raises["script_source"] = InvalidStateTransition("interrupted")
    broken = service.web_script_source(sid, "script-1")
    assert not broken.ok and broken.error is not None
    assert broken.error.code == "invalid_request"


def test_dom_snapshot_answers_through_the_shared_wrapper(tmp_path: Path) -> None:
    service = _Service(tmp_path)
    sid = service.web_session()
    service.fake.replies["dom_snapshot"] = {"nodes": 3}

    result = service.web_dom_snapshot(sid)

    assert result.ok and result.data is not None
    assert result.data["nodes"] == 3

    service.fake.raises["dom_snapshot"] = WebError("no_browser", "browser is not open")
    refused = service.web_dom_snapshot(sid)
    assert not refused.ok and refused.error is not None
    assert refused.error.code == "no_browser"


def test_screenshot_registers_the_capture_and_a_timeline_event(tmp_path: Path) -> None:
    service = _Service(tmp_path)
    sid = service.web_session()

    result = service.web_screenshot(sid, full_page=True)

    assert result.ok and result.data is not None
    described = service.repository.describe_artifact(str(result.data["artifact_id"]))
    assert described is not None
    assert described["kind"] == "web_screenshot"
    assert "web.screenshot" in service.timeline_events(sid)
    _, _, kwargs = service.fake.calls[0]
    assert kwargs == {"full_page": True}


def test_screenshot_maps_backend_and_unexpected_errors(tmp_path: Path) -> None:
    service = _Service(tmp_path)
    sid = service.web_session()

    service.fake.raises["screenshot"] = WebError("page_crashed", "renderer went away")
    refused = service.web_screenshot(sid)
    assert not refused.ok and refused.error is not None
    assert refused.error.code == "page_crashed"

    service.fake.raises["screenshot"] = InvalidStateTransition("interrupted")
    broken = service.web_screenshot(sid)
    assert not broken.ok and broken.error is not None
    assert broken.error.code == "invalid_request"


def test_har_export_registers_the_capture_and_a_timeline_event(tmp_path: Path) -> None:
    service = _Service(tmp_path)
    sid = service.web_session()

    result = service.web_har_export(sid)

    assert result.ok and result.data is not None
    described = service.repository.describe_artifact(str(result.data["artifact_id"]))
    assert described is not None
    assert described["kind"] == "web_har"
    assert "web.har.export" in service.timeline_events(sid)


def test_har_export_maps_backend_and_unexpected_errors(tmp_path: Path) -> None:
    service = _Service(tmp_path)
    sid = service.web_session()

    service.fake.raises["har_export"] = WebError("no_browser", "browser is not open")
    refused = service.web_har_export(sid)
    assert not refused.ok and refused.error is not None
    assert refused.error.code == "no_browser"

    service.fake.raises["har_export"] = InvalidStateTransition("interrupted")
    broken = service.web_har_export(sid)
    assert not broken.ok and broken.error is not None
    assert broken.error.code == "invalid_request"


def test_the_shared_wrapper_maps_an_unexpected_error(tmp_path: Path) -> None:
    service = _Service(tmp_path)
    sid = service.web_session()
    service.fake.raises["console"] = InvalidStateTransition("interrupted")

    result = service.web_console(sid)

    assert not result.ok and result.error is not None
    assert result.error.code == "invalid_request"
