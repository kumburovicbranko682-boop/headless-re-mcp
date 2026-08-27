"""Web backend boundaries: no arbitrary execution, session scoping, degradation."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from headless_re_mcp.backends.jsre import JsClient, JsReError, WasmClient
from headless_re_mcp.backends.proxy import ProxyBackend, ProxyError
from headless_re_mcp.backends.web import WebBackend, WebError
from headless_re_mcp.backends.web.client import (
    _MAX_NAV_TIMEOUT_S,
    _bound_nav_timeout,
    _Runner,
    _WebSession,
)
from headless_re_mcp.core.models import TargetKind
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.core.session import classify_target
from headless_re_mcp.tools.catalog import COMMAND_CATALOG, CommandTransport


class TestNoArbitraryExecution:
    def test_no_javascript_evaluation_tool_is_exposed(self) -> None:
        """web.evaluate is the browser's dynamic.command; it stays unavailable."""
        names = {spec.name for spec in COMMAND_CATALOG.for_transport(CommandTransport.MCP)}
        assert "web.evaluate" not in names
        assert "web.eval" not in names
        assert "web.run_code" not in names

    def test_web_backend_has_no_public_evaluate_method(self) -> None:
        public = {name for name in dir(WebBackend) if not name.startswith("_")}
        assert not {"evaluate", "eval", "run_code"} & public


class TestWebSessionScoping:
    def test_operations_require_an_open_session(self) -> None:
        backend = WebBackend()
        with pytest.raises(WebError) as info:
            backend.network_list("never-opened")
        assert info.value.code == "invalid_state"

    def test_status_on_unopened_session_does_not_launch(self) -> None:
        backend = WebBackend()
        assert backend.status("never-opened") == {"open": False}

    def test_status_on_a_wedged_session_reports_unresponsive_not_an_error(self) -> None:
        """A wedged worker thread must not turn the health probe into an error.

        Once a call has timed out the runner is marked wedged and every later
        .call() raises. status is meant to report state safely, so it answers
        open-but-unresponsive -- the caller closes the session instead of
        reading a transient failure to retry -- and never touches the page.
        """
        backend = WebBackend()
        handle = _WebSession(object(), object(), object(), object(), object())

        class _WedgedRunner:
            @property
            def wedged(self) -> bool:
                return True

            def call(self, work: object, **kwargs: object) -> object:
                raise AssertionError("status must not dispatch to a wedged runner")

        handle.runner = _WedgedRunner()  # type: ignore[assignment]
        backend._sessions["s"] = handle
        assert backend.status("s") == {"open": True, "responsive": False}

    def test_status_on_a_healthy_session_reports_responsive_with_identity(self) -> None:
        backend = WebBackend()
        page = SimpleNamespace(url="https://example.com/app", title=lambda: "App")
        handle = _WebSession(object(), object(), object(), page, object())

        class _LiveRunner:
            @property
            def wedged(self) -> bool:
                return False

            def call(self, work: Any, **kwargs: object) -> object:
                return work()

        handle.runner = _LiveRunner()  # type: ignore[assignment]
        backend._sessions["s"] = handle
        payload = backend.status("s")
        assert payload["open"] is True
        assert payload["responsive"] is True
        assert payload["url"] == "https://example.com/app"
        assert payload["title"] == "App"

    def test_status_survives_a_fresh_timeout_during_the_probe(self) -> None:
        """A hang that first appears mid-probe is reported, not raised."""
        backend = WebBackend()
        handle = _WebSession(object(), object(), object(), object(), object())

        class _TimingOutRunner:
            @property
            def wedged(self) -> bool:
                return False

            def call(self, work: object, **kwargs: object) -> object:
                raise WebError("timeout", "browser did not respond within 5s")

        handle.runner = _TimingOutRunner()  # type: ignore[assignment]
        backend._sessions["s"] = handle
        assert backend.status("s") == {"open": True, "responsive": False}

    def test_close_on_unopened_session_is_not_an_error(self) -> None:
        backend = WebBackend()
        assert backend.close("never-opened")["closed"] is False

    def test_script_source_requires_an_open_session(self, tmp_path: Path) -> None:
        backend = WebBackend()
        with pytest.raises(WebError):
            backend.script_source("never-opened", "1", tmp_path)


class TestWebTargetClassification:
    def test_urls_and_web_assets_classify_as_web(self, tmp_path: Path) -> None:
        assert classify_target("https://example.com/app") is TargetKind.WEB
        assert classify_target("http://127.0.0.1:8080") is TargetKind.WEB
        js = tmp_path / "bundle.js"
        js.write_text("var a=1;", encoding="utf-8")
        assert classify_target(js) is TargetKind.WEB
        wasm = tmp_path / "mod.bin"
        wasm.write_bytes(b"\x00asm\x01\x00\x00\x00")
        assert classify_target(wasm) is TargetKind.WEB

    def test_url_session_has_locator_but_no_binary(self) -> None:
        service = AnalysisService()
        try:
            created = service.create_session("https://example.com/app", target="web")
            assert created.ok, created.error
            session = created.data["session"]
            assert session["target"] == "web"
            assert session["binary"] is None
            assert session["locator"] == "https://example.com/app"
            assert session["architecture"] is None
        finally:
            service.close_all()

    def test_pe_only_tool_on_a_url_session_reports_target_mismatch(self) -> None:
        service = AnalysisService()
        try:
            created = service.create_session("https://example.com/app", target="web")
            session_id = created.data["session"]["id"]
            result = service.dynamic_launch(session_id)
            assert result.ok is False
            assert result.error is not None
            assert result.error.code == "target_mismatch"
        finally:
            service.close_all()

    def test_static_and_dynamic_open_leave_a_web_session_created(self) -> None:
        service = AnalysisService()
        try:
            created = service.create_session("https://example.com/app", target="web")
            session_id = created.data["session"]["id"]
            static = service.open_static(session_id)
            assert static.ok is False
            assert static.error is not None
            assert static.error.code == "target_mismatch"
            assert service.get_session(session_id).data["session"]["state"] == "created"
            dynamic = service.open_dynamic(session_id)
            assert dynamic.ok is False
            assert dynamic.error is not None
            assert dynamic.error.code == "target_mismatch"
            assert service.get_session(session_id).data["session"]["state"] == "created"
        finally:
            service.close_all()


class _FakeWebBackend:
    """Writes the files a real capture writes, without a browser."""

    def __init__(self, root: Path) -> None:
        self.root = root

    def screenshot(self, session_id: str, out_path: Path, *, full_page: bool = False) -> dict:  # type: ignore[type-arg]
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_bytes(b"\x89PNG\r\n\x1a\n" + b"0" * 512)
        return {"path": str(out_path)}

    def har_export(self, session_id: str, out_path: Path) -> dict:  # type: ignore[type-arg]
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text('{"log":{"entries":[]}}', encoding="utf-8")
        return {"path": str(out_path), "entry_count": 0}

    def script_source(self, session_id: str, script_id: str, artifact_dir: Path) -> dict:  # type: ignore[type-arg]
        artifact_dir.mkdir(parents=True, exist_ok=True)
        spill = artifact_dir / f"script-{script_id}.js"
        spill.write_text("var a=1;" * 100, encoding="utf-8")
        return {"scriptId": script_id, "source_path": str(spill), "truncated": True}

    def dom_snapshot(self, session_id: str, artifact_dir: Path) -> dict:  # type: ignore[type-arg]
        artifact_dir.mkdir(parents=True, exist_ok=True)
        spill = artifact_dir / "dom-abc.html"
        spill.write_text("<html><body>" + "x" * 4096 + "</body></html>", encoding="utf-8")
        return {
            "url": "https://example.com/app",
            "title": "app",
            "html": "<html><body>x",
            "bytes": spill.stat().st_size,
            "truncated": True,
            "html_path": str(spill),
        }

    def close(self, session_id: str) -> dict:  # type: ignore[type-arg]
        return {"closed": False}

    def close_all(self) -> None:
        return None


class TestCapturesAreReachableAndReclaimable:
    """A capture that is only a path on disk is a dead end.

    Nothing on the tool surface opens a bare path, so the agent cannot read back
    what it just captured, and retention only collects registered artifacts, so
    an unattended browser session grows the artifact root with screenshots and
    HARs that nothing can ever reclaim.
    """

    def _service(self, tmp_path: Path) -> AnalysisService:
        from dataclasses import replace

        from headless_re_mcp.config import Settings

        settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
        service = AnalysisService(settings)
        service._web_backend = _FakeWebBackend(tmp_path)  # type: ignore[assignment]
        return service

    def test_screenshot_har_and_spilled_source_are_all_registered(
        self, tmp_path: Path
    ) -> None:
        service = self._service(tmp_path)
        try:
            created = service.create_session("https://example.com/app", target="web")
            session_id = created.data["session"]["id"]

            shot = service.web_screenshot(session_id)
            har = service.web_har_export(session_id)
            source = service.web_script_source(session_id, "42")
            dom = service.web_dom_snapshot(session_id)

            for result in (shot, har, source, dom):
                assert result.ok, result.error
                assert result.data is not None
                assert "artifact_error" not in result.data
                assert result.data["artifact_id"]

            listed = service.repository.list_artifacts(session_id)
            kinds = {item["kind"] for item in listed["artifacts"]}
            assert kinds == {
                "web_screenshot",
                "web_har",
                "web_script_source",
                "web_dom_snapshot",
            }

            # Reachable: the id resolves to bytes the agent can actually read.
            read = service.artifacts_read(str(shot.data["artifact_id"]), offset=0, limit=8)
            assert read.ok and read.data is not None
            assert read.data["data"].startswith("89504e47")
        finally:
            service.close_all()

    def test_a_registration_failure_does_not_fail_the_capture(self, tmp_path: Path) -> None:
        """The file exists either way; losing it would be the worse outcome."""
        service = self._service(tmp_path)
        try:
            created = service.create_session("https://example.com/app", target="web")
            session_id = created.data["session"]["id"]

            def explode(**_: object) -> dict:  # type: ignore[type-arg]
                raise RuntimeError("repository is down")

            service.record_artifact = explode  # type: ignore[assignment]
            result = service.web_screenshot(session_id)

            assert result.ok, result.error
            assert result.data is not None
            assert "artifact_id" not in result.data
            assert "repository is down" in result.data["artifact_error"]
            assert Path(result.data["path"]).is_file()
        finally:
            service.close_all()


class TestJsReDegradation:
    def test_missing_webcrack_degrades(self, tmp_path: Path) -> None:
        source = tmp_path / "a.js"
        source.write_text("var a=1;", encoding="utf-8")
        client = JsClient(None)
        if client.available:
            pytest.skip("webcrack installed — degradation path not exercised (skip != pass)")
        with pytest.raises(JsReError) as info:
            client.deobfuscate(source)
        assert info.value.code == "capability_unavailable"

    def test_missing_wabt_degrades(self, tmp_path: Path) -> None:
        module = tmp_path / "m.wasm"
        module.write_bytes(b"\x00asm\x01\x00\x00\x00")
        client = WasmClient(None)
        if client.available:
            pytest.skip("wabt installed — degradation path not exercised (skip != pass)")
        with pytest.raises(JsReError) as info:
            client.wat(module)
        assert info.value.code == "capability_unavailable"


class TestProxyScoping:
    def test_reads_require_a_running_proxy(self) -> None:
        backend = ProxyBackend()
        with pytest.raises(ProxyError) as info:
            backend.flows("no-such-session")
        assert info.value.code == "invalid_state"

    def test_status_of_unstarted_session_reports_not_running(self) -> None:
        assert ProxyBackend().status("no-such-session") == {"running": False}

    def test_stop_without_start_is_not_an_error(self) -> None:
        assert ProxyBackend().stop("no-such-session")["stopped"] is False

    def test_start_rejects_an_out_of_range_port(self) -> None:
        backend = ProxyBackend()
        try:
            backend._check_available()
        except ProxyError:
            pytest.skip("mitmproxy not installed — port validation not reached (skip != pass)")
        with pytest.raises(ProxyError) as info:
            backend.start("s", port=99999)
        assert info.value.code == "invalid_params"


class _FakeNavPage:
    """Records the timeout Playwright's goto would have received."""

    def __init__(self) -> None:
        self.url = "https://old/"
        self.goto_timeouts: list[float] = []

    def goto(self, url: str, timeout: float = 0.0, wait_until: str = "") -> None:
        self.goto_timeouts.append(timeout)
        self.url = url

    def title(self) -> str:
        return "Example"


class TestWebNavTimeoutIsBounded:
    """A caller navigation timeout is clamped at the backend boundary.

    The web.open / web.navigate schema declares ``0 < timeout <= 120``, but the
    agent transport invokes handlers straight from model arguments with no
    schema enforcement. A non-positive timeout would reach
    ``Future.result(timeout<=0)``, which returns at once and flips the runner to
    ``_wedged`` -- so a single stray value used to brick a healthy live session
    until web.close, unlike frida, which already rejects such timeouts.
    """

    def test_bound_nav_timeout_rejects_nonpositive_and_caps_the_rest(self) -> None:
        assert _bound_nav_timeout(30.0) == 30.0
        assert _bound_nav_timeout(10**9) == _MAX_NAV_TIMEOUT_S
        for bad in (0.0, -1.0, -100.0):
            with pytest.raises(WebError) as info:
                _bound_nav_timeout(bad)
            assert info.value.code == "invalid_params"

    def test_a_negative_navigate_timeout_does_not_wedge_a_live_session(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        backend = WebBackend()
        runner = _Runner("test-nav-runner")
        try:
            page = _FakeNavPage()
            handle = SimpleNamespace(page=page, runner=runner)
            monkeypatch.setattr(backend, "_get", lambda session_id: handle)

            with pytest.raises(WebError) as info:
                backend.navigate("s", "https://example/app", timeout=-100.0)
            assert info.value.code == "invalid_params"
            # The runner never saw the doomed wait, so the session is still usable.
            assert runner.wedged is False
            assert page.goto_timeouts == []

            payload = backend.navigate("s", "https://example/app", timeout=30.0)
            assert payload["url"] == "https://example/app"
            assert runner.wedged is False
        finally:
            runner.shutdown()

    def test_a_huge_navigate_timeout_is_capped_to_the_schema_max(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        backend = WebBackend()
        runner = _Runner("test-nav-cap-runner")
        try:
            page = _FakeNavPage()
            handle = SimpleNamespace(page=page, runner=runner)
            monkeypatch.setattr(backend, "_get", lambda session_id: handle)

            backend.navigate("s", "https://example/app", timeout=10**9)
            # goto receives milliseconds, capped at the schema ceiling.
            assert page.goto_timeouts == [_MAX_NAV_TIMEOUT_S * 1000.0]
        finally:
            runner.shutdown()


class _TrackingWebBackend:
    def __init__(self) -> None:
        self.live: set[str] = set()
        self.opens: list[str] = []

    def open(
        self, session_id: str, url: str, *, headless: bool = True, timeout: float = 30.0
    ) -> dict:  # type: ignore[type-arg]
        self.opens.append(session_id)
        self.live.add(session_id)
        return {
            "opened": True,
            "url": url or "https://example.com",
            "title": "",
            "headless": headless,
        }

    def close(self, session_id: str) -> dict:  # type: ignore[type-arg]
        self.live.discard(session_id)
        return {"closed": True}

    def close_all(self) -> None:
        self.live.clear()


class _TrackingProxyBackend:
    def __init__(self) -> None:
        self.live: set[str] = set()
        self.starts: list[str] = []

    def start(self, session_id: str, host: str = "127.0.0.1", port: int = 8080) -> dict:  # type: ignore[type-arg]
        self.starts.append(session_id)
        self.live.add(session_id)
        return {"running": True, "host": host, "port": port, "endpoint": f"{host}:{port}"}

    def stop(self, session_id: str) -> dict:  # type: ignore[type-arg]
        self.live.discard(session_id)
        return {"stopped": True}

    def close_all(self) -> None:
        self.live.clear()


class TestClosedSessionCannotSpawnBackends:
    """Retained CLOSED sessions used to launch a browser/proxy that close cannot reap."""

    def test_web_open_on_a_closed_session_does_not_launch(self) -> None:
        service = AnalysisService()
        web = _TrackingWebBackend()
        service._web_backend = web  # type: ignore[assignment]
        try:
            created = service.create_session("https://example.com/app", target="web")
            session_id = created.data["session"]["id"]
            closed = service.close_session(session_id)
            assert closed.ok, closed.error

            result = service.web_open(session_id)
            assert result.ok is False
            assert result.error is not None
            assert result.error.code == "invalid_request"
            assert "closed" in result.error.message
            assert web.opens == []
            assert web.live == set()
        finally:
            service.close_all()

    def test_proxy_start_on_a_closed_session_does_not_listen(self) -> None:
        service = AnalysisService()
        proxy = _TrackingProxyBackend()
        service._proxy_backend = proxy  # type: ignore[assignment]
        try:
            created = service.create_session("https://example.com/app", target="web")
            session_id = created.data["session"]["id"]
            closed = service.close_session(session_id)
            assert closed.ok, closed.error

            result = service.proxy_start(session_id, port=18080)
            assert result.ok is False
            assert result.error is not None
            assert result.error.code == "invalid_request"
            assert "closed" in result.error.message
            assert proxy.starts == []
            assert proxy.live == set()
        finally:
            service.close_all()

    def test_web_open_reclaims_if_the_session_closes_during_launch(self) -> None:
        service = AnalysisService()
        web = _TrackingWebBackend()
        service._web_backend = web  # type: ignore[assignment]
        try:
            created = service.create_session("https://example.com/app", target="web")
            session_id = created.data["session"]["id"]

            original_open = web.open

            def open_and_close(
                session_id: str,
                url: str,
                *,
                headless: bool = True,
                timeout: float = 30.0,
            ) -> dict:  # type: ignore[type-arg]
                service.close_session(session_id)
                return original_open(session_id, url, headless=headless, timeout=timeout)

            web.open = open_and_close  # type: ignore[method-assign]
            result = service.web_open(session_id)
            assert result.ok is False
            assert web.live == set()
        finally:
            service.close_all()
