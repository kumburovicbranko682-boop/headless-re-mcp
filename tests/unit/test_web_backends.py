"""Web backend boundaries: no arbitrary execution, session scoping, degradation."""

from __future__ import annotations

from pathlib import Path
from typing import Any

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


class TestWebNetworkListSaysWhenItStopped:
    """A request page that hit the cap looks exactly like one that ended.

    Measured: 300 captured requests, limit 100, count=100, total=300, no
    has_more -- so a caller that only looks at the page thinks it has the
    whole capture.
    """

    def _backend(self, n: int) -> WebBackend:
        from threading import RLock

        class _FakeHandle:
            def __init__(self) -> None:
                self.lock = RLock()
                self.requests = {
                    f"r{index}": {"requestId": f"r{index}", "url": f"https://x/{index}"}
                    for index in range(n)
                }

        backend = WebBackend()
        handle = _FakeHandle()
        backend._get = lambda session_id: handle  # type: ignore[method-assign]
        return backend

    def test_hitting_the_cap_is_reported(self) -> None:
        result = self._backend(300).network_list("s", offset=0, limit=100)
        assert result["count"] == 100
        assert result["total"] == 300
        assert result["has_more"] is True

    def test_a_complete_answer_is_not_labelled_partial(self) -> None:
        result = self._backend(3).network_list("s", offset=0, limit=100)
        assert result["count"] == 3
        assert result["has_more"] is False

    def test_a_result_that_exactly_fills_the_page_is_complete(self) -> None:
        result = self._backend(100).network_list("s", offset=0, limit=100)
        assert result["count"] == 100
        assert result["has_more"] is False


class TestWebConsoleSaysWhenItStopped:
    """A console page that hit the cap looks exactly like one that ended.

    ``web.console`` returns the most recent N messages and used to set
    ``count`` to the page size with no total. Measured: 800 messages in the
    ring, limit 200, count=200, no has_more -- so the first 600 (often the
    load-time errors) vanished while the reply looked complete.
    """

    def _backend(self, n: int) -> WebBackend:
        from collections import deque
        from threading import RLock

        from headless_re_mcp.backends.web.client import _MAX_CONSOLE

        class _FakeHandle:
            def __init__(self) -> None:
                self.lock = RLock()
                self.console = deque(maxlen=_MAX_CONSOLE)
                for index in range(n):
                    self.console.append({"text": f"msg{index}"})

        backend = WebBackend()
        handle = _FakeHandle()
        backend._get = lambda session_id: handle  # type: ignore[method-assign]
        return backend

    def test_hitting_the_cap_is_reported(self) -> None:
        result = self._backend(800).console("s", limit=200)
        assert result["count"] == 200
        assert result["total"] == 800
        assert result["has_more"] is True
        assert result["console"][0]["text"] == "msg600"

    def test_a_complete_answer_is_not_labelled_partial(self) -> None:
        result = self._backend(3).console("s", limit=200)
        assert result["count"] == 3
        assert result["total"] == 3
        assert result["has_more"] is False

    def test_a_result_that_exactly_fills_the_page_is_complete(self) -> None:
        result = self._backend(200).console("s", limit=200)
        assert result["count"] == 200
        assert result["has_more"] is False


class TestWebWasmListDescriptionMatchesTheCut:
    """web.wasm.list reuses the paged script ring, but the tool text hid that.

    Measured: scripts() now pages (2000 entries, default 200, has_more),
    while this tool's description said "list WebAssembly modules" -- so a
    model treats the first page as every module on the page.
    """

    def test_the_tool_text_says_to_check_has_more(self) -> None:
        from headless_re_mcp.core.service import AnalysisService
        from headless_re_mcp.tools.web import build_web_tools

        service = AnalysisService()
        try:
            tools = {item.name: item for item in build_web_tools(service)}
            doc = tools["web.wasm.list"].handler.__doc__ or ""
        finally:
            service.close_all()
        assert "has_more" in doc


class TestWebDomSnapshotDescriptionMatchesTheCut:
    """web.dom.snapshot already cuts HTML at 200000 bytes, but the tool text hid that.

    Measured: 200001-byte document, 200000 returned, truncated=true, while
    the description said "return the current page HTML" -- so a model treats
    the slice as the whole DOM.
    """

    def test_the_tool_text_says_to_check_truncated(self) -> None:
        from headless_re_mcp.core.service import AnalysisService
        from headless_re_mcp.tools.web import build_web_tools

        service = AnalysisService()
        try:
            tools = {item.name: item for item in build_web_tools(service)}
            doc = tools["web.dom.snapshot"].handler.__doc__ or ""
        finally:
            service.close_all()
        assert "truncated" in doc


class TestWebScriptsSayWhenTheyStopped:
    """A script page that hit the cap looks exactly like one that ended.

    Measured: 2000 parsed scripts, 249 KiB, count=2000, no has_more -- so
    an unattended caller dumps the whole ring in one tool result and cannot
    tell whether the page finished or merely stopped.
    """

    def _backend(self, n: int) -> WebBackend:
        from collections import OrderedDict
        from threading import RLock

        class _FakeHandle:
            def __init__(self) -> None:
                self.lock = RLock()
                self.scripts = OrderedDict(
                    (
                        str(index),
                        {
                            "scriptId": str(index),
                            "url": f"https://cdn.example.com/chunk-{index}.js",
                            "language": "JavaScript",
                        },
                    )
                    for index in range(n)
                )

        backend = WebBackend()
        handle = _FakeHandle()
        backend._get = lambda session_id: handle  # type: ignore[method-assign]
        return backend

    def test_hitting_the_cap_is_reported(self) -> None:
        result = self._backend(2000).scripts("s", offset=0, limit=200)
        assert result["count"] == 200
        assert result["total"] == 2000
        assert result["has_more"] is True

    def test_a_complete_answer_is_not_labelled_partial(self) -> None:
        result = self._backend(3).scripts("s", offset=0, limit=200)
        assert result["count"] == 3
        assert result["has_more"] is False

    def test_a_result_that_exactly_fills_the_page_is_complete(self) -> None:
        result = self._backend(200).scripts("s", offset=0, limit=200)
        assert result["count"] == 200
        assert result["has_more"] is False


class TestJsUnpackSaysWhenItStopped:
    """A files page that hit the cap looks exactly like one that ended.

    Measured: 2500 module files, file_count=2500, files length 2000, no
    has_more -- so the last 500 module names vanished while the reply
    looked like the whole unpack.
    """

    def _result(self, tmp_path: Path, n: int) -> dict[str, Any]:
        exe = tmp_path / "webcrack"
        exe.write_text("x", encoding="utf-8")
        source = tmp_path / "bundle.js"
        source.write_text("module.exports=1;", encoding="utf-8")
        out = tmp_path / "out"
        out.mkdir()
        for index in range(n):
            (out / f"m{index}.js").write_text("x", encoding="utf-8")
        client = JsClient(exe)
        from headless_re_mcp.backends.jsre import client as jsre_mod

        original = jsre_mod._run
        jsre_mod._run = lambda *args, **kwargs: ("", "", 0)  # type: ignore[assignment]
        try:
            return client.unpack_bundle(source, out)
        finally:
            jsre_mod._run = original

    def test_hitting_the_cap_is_reported(self, tmp_path: Path) -> None:
        result = self._result(tmp_path, 2500)
        assert result["file_count"] == 2500
        assert len(result["files"]) == 2000
        assert result["has_more"] is True

    def test_a_complete_answer_is_not_labelled_partial(self, tmp_path: Path) -> None:
        result = self._result(tmp_path, 3)
        assert result["file_count"] == 3
        assert result["has_more"] is False

    def test_a_result_that_exactly_fills_the_page_is_complete(self, tmp_path: Path) -> None:
        result = self._result(tmp_path, 2000)
        assert result["file_count"] == 2000
        assert result["has_more"] is False


class TestJsUnpackDoesNotTrustLeftovers:
    """A failed webcrack used to succeed if the last unpack left files behind.

    Measured: exit 1, leftover old.js still on disk, unpack returned
    file_count=1 as if this run had written it.
    """

    def test_a_failed_unpack_is_not_saved_by_yesterdays_files(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from headless_re_mcp.backends.jsre import client as jsre_mod

        exe = tmp_path / "webcrack"
        exe.write_text("x", encoding="utf-8")
        source = tmp_path / "bundle.js"
        source.write_text("module.exports=1;", encoding="utf-8")
        out = tmp_path / "out"
        out.mkdir()
        leftover = out / "old.js"
        leftover.write_text("yesterday", encoding="utf-8")
        monkeypatch.setattr(jsre_mod, "_run", lambda *args, **kwargs: ("", "webcrack failed", 1))
        with pytest.raises(JsReError) as info:
            JsClient(exe).unpack_bundle(source, out)
        assert info.value.code == "backend_error"
        assert leftover.is_file()


class TestWasmInfoDescriptionMatchesTheCut:
    """wasm.info already cuts at 400000 bytes, but the tool text hid that.

    Measured: 400001-byte stdout, objdump length 400000, truncated=true,
    while the description never mentioned the cut -- so a model treats the
    slice as the whole dump.
    """

    def test_the_tool_text_says_to_check_truncated(self) -> None:
        from headless_re_mcp.core.service import AnalysisService
        from headless_re_mcp.tools.js_wasm import build_js_wasm_tools

        service = AnalysisService()
        try:
            tools = {item.name: item for item in build_js_wasm_tools(service)}
            doc = tools["wasm.info"].handler.__doc__ or ""
        finally:
            service.close_all()
        assert "truncated" in doc


class TestWasmWatDescriptionMatchesTheCut:
    """wasm.wat already cuts at 400000 bytes, but the tool text hid that.

    Measured: 400001-byte stdout, wat length 400000, truncated=true, while
    the description never mentioned the cut -- so a model treats the slice
    as the whole module text.
    """

    def test_the_tool_text_says_to_check_truncated(self) -> None:
        from headless_re_mcp.core.service import AnalysisService
        from headless_re_mcp.tools.js_wasm import build_js_wasm_tools

        service = AnalysisService()
        try:
            tools = {item.name: item for item in build_js_wasm_tools(service)}
            doc = tools["wasm.wat"].handler.__doc__ or ""
        finally:
            service.close_all()
        assert "truncated" in doc


class TestJsBeautifyDescriptionMatchesTheCut:
    """js.beautify is deobfuscate under another name and cuts the same way.

    Measured: 400001-byte stdout, code length 400000, truncated=true, while
    the description said "return a readable form" -- so a model treats the
    slice as the whole file.
    """

    def test_the_tool_text_says_to_check_truncated(self) -> None:
        from headless_re_mcp.core.service import AnalysisService
        from headless_re_mcp.tools.js_wasm import build_js_wasm_tools

        service = AnalysisService()
        try:
            tools = {item.name: item for item in build_js_wasm_tools(service)}
            doc = tools["js.beautify"].handler.__doc__ or ""
        finally:
            service.close_all()
        assert "truncated" in doc


class TestJsDeobfuscateDescriptionMatchesTheCut:
    """js.deobfuscate already cuts at 400000 bytes, but the tool text hid that.

    Measured: 400001-byte stdout, code length 400000, truncated=true, while
    the description said "returns code" -- so a model treats the slice as
    the whole deobfuscation.
    """

    def test_the_tool_text_says_to_check_truncated(self) -> None:
        from headless_re_mcp.core.service import AnalysisService
        from headless_re_mcp.tools.js_wasm import build_js_wasm_tools

        service = AnalysisService()
        try:
            tools = {item.name: item for item in build_js_wasm_tools(service)}
            doc = tools["js.deobfuscate"].handler.__doc__ or ""
        finally:
            service.close_all()
        assert "truncated" in doc


class TestJsDeobfuscateDoesNotTreatStderrAsCode:
    """A failed webcrack used to succeed if it printed anything to stdout.

    Measured: exit 1, stdout "Error: boom\\n", deobfuscate returned that
    string as code. An unattended agent then analyses the error text.
    """

    def test_a_failed_run_is_not_saved_by_error_text(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from headless_re_mcp.backends.jsre import client as jsre_mod

        exe = tmp_path / "webcrack"
        exe.write_text("x", encoding="utf-8")
        source = tmp_path / "a.js"
        source.write_text("var a=1;", encoding="utf-8")
        monkeypatch.setattr(
            jsre_mod, "_run", lambda *args, **kwargs: ("Error: boom\n", "failed", 1)
        )
        with pytest.raises(JsReError) as info:
            JsClient(exe).deobfuscate(source)
        assert info.value.code == "backend_error"


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


class TestProxyFlowsSayWhenTheyStopped:
    """A flow page that hit the cap looks exactly like one that ended.

    Measured: 300 captured flows, limit 100, count=100, total=300, no
    has_more -- so a caller that only looks at the page thinks it has the
    whole capture.
    """

    def _backend(self, n: int) -> ProxyBackend:
        class _Rec:
            def __init__(self) -> None:
                self._items = [
                    {
                        "id": f"f{index}",
                        "method": "GET",
                        "url": f"https://example.com/{index}",
                    }
                    for index in range(n)
                ]

            def snapshot(self) -> list[dict[str, Any]]:
                return list(self._items)

        class _Inst:
            recorder = _Rec()

        backend = ProxyBackend()
        backend._get = lambda session_id: _Inst()  # type: ignore[method-assign]
        return backend

    def test_hitting_the_cap_is_reported(self) -> None:
        result = self._backend(300).flows("s", offset=0, limit=100)
        assert result["count"] == 100
        assert result["total"] == 300
        assert result["has_more"] is True

    def test_a_complete_answer_is_not_labelled_partial(self) -> None:
        result = self._backend(3).flows("s", offset=0, limit=100)
        assert result["count"] == 3
        assert result["has_more"] is False

    def test_a_result_that_exactly_fills_the_page_is_complete(self) -> None:
        result = self._backend(100).flows("s", offset=0, limit=100)
        assert result["count"] == 100
        assert result["has_more"] is False


class TestProxyFlowBodyIsRegistered:
    """proxy.flow.get spills bodies over 200 KiB and never registered them.

    Measured: 250000-byte body written to disk, 0 artifact rows, no
    artifact_id -- so the agent cannot read the capture back and retention
    cannot reclaim it.
    """

    def test_spilled_body_is_a_readable_artifact(self, tmp_path: Path) -> None:
        from dataclasses import replace

        from headless_re_mcp.config import Settings
        from headless_re_mcp.core.service import AnalysisService

        class _Req:
            method = "GET"
            pretty_url = "https://example.com/big"
            headers = {"accept": "*/*"}

        class _Resp:
            status_code = 200
            headers = {"content-type": "application/octet-stream"}
            raw_content = b"B" * 250_000

        class _Flow:
            request = _Req()
            response = _Resp()

        class _Rec:
            def raw(self, flow_id: str) -> object:
                return _Flow()

        class _Inst:
            recorder = _Rec()

        settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
        service = AnalysisService(settings)
        try:
            created = service.create_session("https://example.com", target="web")
            session_id = str(created.data["session"]["id"])
            service._proxy._get = lambda sid: _Inst()  # type: ignore[method-assign]
            result = service.proxy_flow_get(session_id, "flow-1")
            assert result.ok, result.error
            assert result.data is not None
            assert result.data.get("artifact_id")
            assert Path(result.data["response"]["body_path"]).is_file()

            listed = service.artifacts_list(session_id)
            assert listed.ok and listed.data is not None
            assert listed.data["total"] == 1
            assert listed.data["artifacts"][0]["kind"] == "proxy_flow_body"

            read = service.artifacts_read(str(result.data["artifact_id"]), offset=0, limit=1)
            assert read.ok and read.data is not None
            assert read.data["data"].startswith("42")
        finally:
            service.close_all()


class TestProxyReplayWaitsForTheLoop:
    """Scheduling a replay is not the same as the proxy having done it.

    Measured: call_soon_threadsafe queued the command and returned
    replayed=True while the command never ran. An unattended agent then
    treats a request that never left the process as captured.
    """

    def _backend(self, loop: object, master: object) -> ProxyBackend:
        class _Flow:
            def copy(self) -> _Flow:
                return self

        class _Rec:
            def raw(self, flow_id: str) -> object:
                del flow_id
                return _Flow()

        class _Inst:
            recorder = _Rec()
            _loop = loop
            _master = master

        backend = ProxyBackend()
        backend._get = lambda session_id: _Inst()  # type: ignore[method-assign]
        return backend

    def test_a_command_that_never_runs_is_not_replayed(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from headless_re_mcp.backends.proxy import client as proxy_mod

        class _Loop:
            def call_soon_threadsafe(self, fn: object, *args: object) -> None:
                del fn, args

        class _Master:
            commands = type("C", (), {"call": staticmethod(lambda *a: None)})()

        monkeypatch.setattr(proxy_mod, "_REPLAY_WAIT_S", 0.2)
        with pytest.raises(ProxyError) as info:
            self._backend(_Loop(), _Master()).replay("s", "flow-1")
        assert info.value.code == "timeout"

    def test_a_command_that_fails_on_the_loop_is_not_replayed(self) -> None:
        class _Loop:
            def call_soon_threadsafe(self, fn: object, *args: object) -> None:
                del args
                fn()  # type: ignore[operator]

        class _Master:
            class commands:
                @staticmethod
                def call(name: str, args: object) -> None:
                    del name, args
                    raise RuntimeError("no such flow to replay")

        with pytest.raises(ProxyError) as info:
            self._backend(_Loop(), _Master()).replay("s", "flow-1")
        assert info.value.code == "backend_error"

    def test_a_command_that_ran_is_replayed(self) -> None:
        ran: list[str] = []

        class _Loop:
            def call_soon_threadsafe(self, fn: object, *args: object) -> None:
                del args
                fn()  # type: ignore[operator]

        class _Master:
            class commands:
                @staticmethod
                def call(name: str, args: object) -> None:
                    del args
                    ran.append(name)

        result = self._backend(_Loop(), _Master()).replay("s", "flow-1")
        assert result == {"replayed": True, "flow_id": "flow-1"}
        assert ran == ["replay.client"]


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
