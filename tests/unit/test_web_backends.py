"""Web backend boundaries: no arbitrary execution, session scoping, degradation."""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.backends.jsre import JsClient, JsReError, WasmClient
from headless_re_mcp.backends.proxy import ProxyBackend, ProxyError
from headless_re_mcp.backends.web import WebBackend, WebError
from headless_re_mcp.backends.web.client import _WebSession
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


class TestWebWasmPaging:
    def test_wasm_list_says_when_more_is_retained(self) -> None:
        """250 wasm modules used to look like a complete 200-item list.

        Measured: scripts(wasm_only=True) default limit 200, total=250,
        has_more True, but web.wasm.list had no limit and its description
        said nothing about a page.
        """
        backend = WebBackend()
        handle = _WebSession(object(), object(), object(), object(), object())
        for index in range(250):
            handle.scripts[str(index)] = {
                "scriptId": str(index),
                "url": f"https://ex/{index}.wasm",
                "language": "WebAssembly",
            }
        backend._sessions["s"] = handle
        result = backend.scripts("s", wasm_only=True, limit=200)
        assert result["count"] == 200
        assert result["total"] == 250
        assert result["has_more"] is True

        from headless_re_mcp.core.service import AnalysisService
        from headless_re_mcp.tools.web import build_web_tools

        service = AnalysisService()
        try:
            tools = {item.name: item for item in build_web_tools(service)}
            doc = tools["web.wasm.list"].handler.__doc__ or ""
            assert "has_more" in doc
            assert "limit" in tools["web.wasm.list"].handler.__code__.co_varnames
        finally:
            service.close_all()


class TestWebNetworkPaging:
    def test_a_network_page_says_when_more_is_retained(self) -> None:
        """A 100-request page used to look complete even with total=250.

        Measured: 250 requests, limit 100, count=100 total=250, no has_more.
        Models that do not subtract still treat the page as the whole capture.
        """
        backend = WebBackend()
        handle = _WebSession(object(), object(), object(), object(), object())
        for index in range(250):
            handle.requests[str(index)] = {
                "requestId": str(index),
                "url": f"https://ex/{index}",
            }
        backend._sessions["s"] = handle
        result = backend.network_list("s", offset=0, limit=100)
        assert result["count"] == 100
        assert result["total"] == 250
        assert result["has_more"] is True
        rest = backend.network_list("s", offset=200, limit=100)
        assert rest["count"] == 50
        assert rest["has_more"] is False


class TestWebScriptPaging:
    def test_a_script_page_says_when_more_is_retained(self) -> None:
        """The full script buffer used to be returned as if it were complete.

        Measured: 80 scripts, one reply, count=80, no total or has_more.
        """
        backend = WebBackend()
        handle = _WebSession(object(), object(), object(), object(), object())
        for index in range(80):
            handle.scripts[str(index)] = {
                "scriptId": str(index),
                "url": f"https://ex/{index}.js",
                "language": "JavaScript",
            }
        backend._sessions["s"] = handle
        result = backend.scripts("s", limit=10)
        assert result["count"] == 10
        assert result["total"] == 80
        assert result["has_more"] is True
        assert result["scripts"][0]["scriptId"] == "70"
        assert result["scripts"][-1]["scriptId"] == "79"

        complete = backend.scripts("s", limit=80)
        assert complete["has_more"] is False
        assert complete["total"] == 80


class TestWebConsolePaging:
    def test_a_console_page_says_when_more_is_retained(self) -> None:
        """A 200-line page used to look like the whole console.

        Measured: 500 retained lines, limit 200, count=200, no total or
        has_more. The first 300 looked like they never happened.
        """
        backend = WebBackend()
        handle = _WebSession(object(), object(), object(), object(), object())
        for index in range(500):
            handle.console.append({"text": f"line {index}"})
        backend._sessions["s"] = handle
        result = backend.console("s", limit=200)
        assert result["count"] == 200
        assert result["total"] == 500
        assert result["has_more"] is True
        assert result["console"][0]["text"] == "line 300"
        assert result["console"][-1]["text"] == "line 499"

        complete = backend.console("s", limit=500)
        assert complete["has_more"] is False
        assert complete["total"] == 500


class TestWebDomSnapshotDescription:
    def test_dom_snapshot_description_says_to_read_truncated(self) -> None:
        """web.dom.snapshot already cuts HTML but its tool text never said so.

        Measured: handler.__doc__ had no truncated while a page over
        200000 characters is cut and marked. A model that never saw the
        field treated a cut DOM as the whole document.
        """
        from headless_re_mcp.core.service import AnalysisService
        from headless_re_mcp.tools.web import build_web_tools

        service = AnalysisService()
        try:
            tools = {item.name: item for item in build_web_tools(service)}
            doc = tools["web.dom.snapshot"].handler.__doc__ or ""
            assert "truncated" in doc
        finally:
            service.close_all()


class TestWebSessionScoping:
    def test_operations_require_an_open_session(self) -> None:
        backend = WebBackend()
        with pytest.raises(WebError) as info:
            backend.network_list("never-opened")
        assert info.value.code == "invalid_state"

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


class TestProxyFlowPaging:
    def test_a_flow_page_says_when_more_is_retained(self) -> None:
        """A 100-flow page used to look complete even with total=250.

        Measured: 250 flows, limit 100, count=100 total=250, no has_more.
        """

        class _Recorder:
            def snapshot(self) -> list[dict[str, int]]:
                return [{"id": index} for index in range(250)]

        class _Inst:
            recorder = _Recorder()

        backend = ProxyBackend()
        backend._get = lambda _sid: _Inst()  # type: ignore[method-assign]
        result = backend.flows("s", offset=0, limit=100)
        assert result["count"] == 100
        assert result["total"] == 250
        assert result["has_more"] is True
        rest = backend.flows("s", offset=200, limit=100)
        assert rest["count"] == 50
        assert rest["has_more"] is False


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
