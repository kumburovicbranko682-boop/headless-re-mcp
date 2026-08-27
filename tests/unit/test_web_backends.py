"""Web backend boundaries: no arbitrary execution, session scoping, degradation."""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.backends.jsre import JsClient, JsReError, WasmClient
from headless_re_mcp.backends.proxy import ProxyBackend, ProxyError
from headless_re_mcp.backends.web import WebBackend, WebError
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
        spill = artifact_dir / "dom-x.html"
        spill.write_text("<html>" + "a" * 300_000 + "</html>", encoding="utf-8")
        return {
            "url": "https://x",
            "title": "t",
            "html": "<html>",
            "truncated": True,
            "dom_path": str(spill),
        }

    def network_get(self, session_id: str, request_id: str, artifact_dir: Path) -> dict:  # type: ignore[type-arg]
        artifact_dir.mkdir(parents=True, exist_ok=True)
        resp = artifact_dir / f"body-{request_id}.bin"
        resp.write_bytes(b"r" * 300_000)
        req = artifact_dir / f"request-body-{request_id}.bin"
        req.write_bytes(b"q" * 300_000)
        return {
            "requestId": request_id,
            "url": "https://x",
            "has_post_data": True,
            "body": "r",
            "body_truncated": True,
            "body_path": str(resp),
            "base64_encoded": False,
            "request_body": "q",
            "request_body_truncated": True,
            "request_body_path": str(req),
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

            for result in (shot, har, source):
                assert result.ok, result.error
                assert result.data is not None
                assert "artifact_error" not in result.data
                assert result.data["artifact_id"]

            listed = service.repository.list_artifacts(session_id)
            kinds = {item["kind"] for item in listed["artifacts"]}
            assert kinds == {"web_screenshot", "web_har", "web_script_source"}

            # Reachable: the id resolves to bytes the agent can actually read.
            read = service.artifacts_read(str(shot.data["artifact_id"]), offset=0, limit=8)
            assert read.ok and read.data is not None
            assert read.data["data"].startswith("89504e47")
        finally:
            service.close_all()

    def test_a_spilled_dom_snapshot_is_registered(self, tmp_path: Path) -> None:
        """A large DOM now spills like a script source, so it must be reclaimable."""
        service = self._service(tmp_path)
        try:
            created = service.create_session("https://example.com/app", target="web")
            session_id = created.data["session"]["id"]

            snap = service.web_dom_snapshot(session_id)
            assert snap.ok, snap.error
            assert snap.data is not None
            assert "artifact_error" not in snap.data
            assert snap.data["artifact_id"]

            listed = service.repository.list_artifacts(session_id)
            kinds = {item["kind"] for item in listed["artifacts"]}
            assert "web_dom_snapshot" in kinds
        finally:
            service.close_all()

    def test_a_spilled_request_body_registers_beside_the_response(
        self, tmp_path: Path
    ) -> None:
        """Both bodies spill; each must be reclaimable under its own id.

        The response body lands as web_response_body/artifact_id and the request
        body as web_request_body/request_artifact_id, so the second id does not
        overwrite the first and retention reclaims both.
        """
        service = self._service(tmp_path)
        try:
            created = service.create_session("https://example.com/app", target="web")
            session_id = created.data["session"]["id"]

            got = service.web_network_get(session_id, "r1")
            assert got.ok, got.error
            assert got.data is not None
            assert got.data["artifact_id"]
            assert got.data["request_artifact_id"]
            assert got.data["artifact_id"] != got.data["request_artifact_id"]

            listed = service.repository.list_artifacts(session_id)
            kinds = {item["kind"] for item in listed["artifacts"]}
            assert {"web_response_body", "web_request_body"} <= kinds
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


class TestWebMissingBrowserDegrades:
    """`pip install playwright` never downloads Chromium.

    The module imports and _check_available passes, so the failure only shows
    up at chromium.launch(). The rest of the surface reports an absent optional
    dependency as capability_unavailable (androguard, jadx, mitmproxy); a
    missing browser is the same kind of gap and must not read as a backend
    fault an unattended run would treat as broken rather than unconfigured.
    """

    def test_the_classifier_recognises_playwrights_install_message(self) -> None:
        from headless_re_mcp.backends.web.client import _looks_like_missing_browser

        install = RuntimeError(
            "Executable doesn't exist at ms-playwright/chromium-1/chrome-linux/chrome\n"
            "Looks like Playwright was just installed or updated.\n"
            "Please run the following command to download new browsers:\n"
            "    playwright install"
        )
        assert _looks_like_missing_browser(install) is True
        # A real crash is left as a backend fault, not mislabelled as unconfigured.
        assert _looks_like_missing_browser(RuntimeError("target crashed")) is False

    def test_open_maps_a_missing_browser_to_capability_unavailable(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import playwright.sync_api as pw_api

        class _FakePw:
            class _Chromium:
                def launch(self, *, headless: bool) -> object:
                    del headless
                    raise RuntimeError(
                        "Executable doesn't exist at chrome-linux/chrome\n"
                        "Please run 'playwright install'"
                    )

            @property
            def chromium(self) -> object:
                return self._Chromium()

            def stop(self) -> None:
                return None

        class _FakeFactory:
            def start(self) -> _FakePw:
                return _FakePw()

        monkeypatch.setattr(pw_api, "sync_playwright", lambda: _FakeFactory())

        backend = WebBackend()
        backend._available = True
        with pytest.raises(WebError) as info:
            backend.open("browserless", "https://example.com/", headless=True, timeout=5.0)
        assert info.value.code == "capability_unavailable"
        assert "playwright install" in info.value.message
        # The failed open leaves no session reservation behind to wedge the next call.
        assert backend.status("browserless") == {"open": False}


class TestWebNavigationTimeoutIsRetryable:
    """A slow page is a transient stall, not a backend fault.

    ``page.goto`` raises Playwright's TimeoutError when the wait state is not
    reached in time. Left in the generic except it became a non-retryable
    ``backend_error``; an unattended run honouring ``retryable`` then abandoned a
    page a second navigation might have loaded. It now maps to ``timeout`` like
    the runner's own wall-clock deadline and every other non-PE backend.
    """

    def test_the_classifier_recognises_a_playwright_timeout(self) -> None:
        from headless_re_mcp.backends.web.client import _looks_like_nav_timeout

        # Playwright raises its own type named TimeoutError; match it by name so
        # a message reworded across versions still counts.
        pw_timeout = type("TimeoutError", (Exception,), {})
        assert _looks_like_nav_timeout(pw_timeout("anything")) is True
        # Message shape is the fallback for a differently-typed wrapper.
        assert _looks_like_nav_timeout(RuntimeError("page.goto: Timeout 30000ms exceeded")) is True
        # A real load error stays a backend fault, not a retryable timeout.
        assert _looks_like_nav_timeout(RuntimeError("net::ERR_CONNECTION_REFUSED")) is False

    def test_open_maps_a_navigation_timeout_to_timeout(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import playwright.sync_api as pw_api

        pw_timeout = type("TimeoutError", (Exception,), {})

        class _FakeCdp:
            def send(self, *args: object, **kwargs: object) -> dict:  # type: ignore[type-arg]
                return {}

            def on(self, *args: object, **kwargs: object) -> None:
                return None

        class _FakePage:
            def goto(self, url: str, **kwargs: object) -> object:
                del url, kwargs
                raise pw_timeout("Timeout 5000ms exceeded")

        class _FakeContext:
            def new_page(self) -> _FakePage:
                return _FakePage()

            def new_cdp_session(self, page: object) -> _FakeCdp:
                del page
                return _FakeCdp()

        class _FakeBrowser:
            def new_context(self, **kwargs: object) -> _FakeContext:
                del kwargs
                return _FakeContext()

        class _FakePw:
            class _Chromium:
                def launch(self, *, headless: bool) -> _FakeBrowser:
                    del headless
                    return _FakeBrowser()

            @property
            def chromium(self) -> object:
                return self._Chromium()

            def stop(self) -> None:
                return None

        class _FakeFactory:
            def start(self) -> _FakePw:
                return _FakePw()

        monkeypatch.setattr(pw_api, "sync_playwright", lambda: _FakeFactory())

        backend = WebBackend()
        backend._available = True
        with pytest.raises(WebError) as info:
            backend.open("slow", "https://slow.example/", headless=True, timeout=5.0)
        assert info.value.code == "timeout"
        assert info.value.details.get("url") == "https://slow.example/"
        # The aborted open leaves no reservation to wedge the next call.
        assert backend.status("slow") == {"open": False}


class TestWebNetworkGetPropagatesSessionFaults:
    """A wedged browser is a session fault, not a per-body condition.

    ``network_get`` fetches a response body through the runner, whose ``call``
    raises ``WebError`` when the browser times out (which wedges the session),
    is already wedged, or is closed -- faults where every later call fails too.
    Swallowed into ``body_error`` they read as a successful, body-less fetch, so
    an unattended caller kept hammering a dead browser it had no way to notice.
    The fault now propagates with its own code, exactly as web.script_source
    already does; only a genuine per-body CDP failure stays a soft ``body_error``
    with the entry metadata intact.
    """

    class _Handle:
        def __init__(self, cdp: object) -> None:
            import threading

            self.lock = threading.Lock()
            self.requests = {"r1": {"requestId": "r1", "url": "https://x"}}
            self.cdp = cdp

    class _Runner:
        def __init__(self, work_wrapper: object) -> None:
            self._wrap = work_wrapper

        def call(self, work: object, timeout: float | None = None) -> object:
            del timeout
            return self._wrap(work)  # type: ignore[operator]

    def _backend(self, cdp: object, runner: object) -> WebBackend:
        handle = self._Handle(cdp)
        backend = WebBackend()
        backend._get = lambda session_id: handle  # type: ignore[assignment]
        backend._runner = lambda h: runner  # type: ignore[assignment]
        return backend

    def test_a_wedged_runner_timeout_propagates_not_hidden(self, tmp_path: Path) -> None:
        def _raise_timeout(work: object) -> object:
            del work
            raise WebError("timeout", "browser did not respond within 5s")

        backend = self._backend(cdp=object(), runner=self._Runner(_raise_timeout))
        with pytest.raises(WebError) as info:
            backend.network_get("s", "r1", tmp_path)
        assert info.value.code == "timeout"
        # Nothing was written for a body that was never fetched.
        assert list(tmp_path.iterdir()) == []

    def test_a_per_body_cdp_failure_stays_a_soft_body_error(self, tmp_path: Path) -> None:
        class _Cdp:
            def send(self, method: str, params: dict) -> dict:  # type: ignore[type-arg]
                del method, params
                raise RuntimeError("No resource with given identifier found")

        backend = self._backend(cdp=_Cdp(), runner=self._Runner(lambda work: work()))
        payload = backend.network_get("s", "r1", tmp_path)
        assert "No resource" in str(payload["body_error"])
        # The request metadata survives so the caller still learns what it was.
        assert payload["requestId"] == "r1"
        assert payload["url"] == "https://x"


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
