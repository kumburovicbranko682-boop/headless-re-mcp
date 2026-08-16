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

    def test_close_on_unopened_session_is_not_an_error(self) -> None:
        backend = WebBackend()
        assert backend.close("never-opened")["closed"] is False

    def test_script_source_requires_an_open_session(self, tmp_path: Path) -> None:
        backend = WebBackend()
        with pytest.raises(WebError):
            backend.script_source("never-opened", "1", tmp_path)


class TestNetworkGetDoesNotInventSuccess:
    """A CDP body fetch that failed used to look like a fetched response.

    Measured: Network.getResponseBody raising
    ``No resource with given identifier found`` still answered
    ``{..., 'body_error': '...'}`` with no exception, so an agent treated a
    missing body as captured evidence.
    """

    def _backend(self, exc: Exception) -> WebBackend:
        import threading
        from collections import OrderedDict

        class _CDP:
            def send(self, method: str, params: dict[str, object]) -> dict[str, object]:
                raise exc

        class _Runner:
            def call(self, work: object, timeout: float = 60.0) -> object:
                return work()  # type: ignore[operator]

        class _Handle:
            def __init__(self) -> None:
                self.requests = OrderedDict(
                    {
                        "req1": {
                            "requestId": "req1",
                            "url": "https://example.com/a",
                            "method": "GET",
                        }
                    }
                )
                self.lock = threading.RLock()
                self.runner = _Runner()
                self.cdp = _CDP()

        backend = WebBackend()
        backend._sessions["s"] = _Handle()  # type: ignore[assignment]
        return backend

    def test_a_cdp_failure_is_not_a_fetched_body(self, tmp_path: Path) -> None:
        with pytest.raises(WebError) as info:
            self._backend(RuntimeError("No resource with given identifier found")).network_get(
                "s", "req1", tmp_path
            )
        assert info.value.code == "backend_error"
        assert "response body" in info.value.message
        assert info.value.details.get("request_id") == "req1"

    def test_a_fetched_body_is_success(self, tmp_path: Path) -> None:
        import threading
        from collections import OrderedDict

        class _CDP:
            def send(self, method: str, params: dict[str, object]) -> dict[str, object]:
                return {"body": "hello", "base64Encoded": False}

        class _Runner:
            def call(self, work: object, timeout: float = 60.0) -> object:
                return work()  # type: ignore[operator]

        class _Handle:
            def __init__(self) -> None:
                self.requests = OrderedDict(
                    {"req1": {"requestId": "req1", "url": "https://example.com/a"}}
                )
                self.lock = threading.RLock()
                self.runner = _Runner()
                self.cdp = _CDP()

        backend = WebBackend()
        backend._sessions["s"] = _Handle()  # type: ignore[assignment]
        result = backend.network_get("s", "req1", tmp_path)
        assert result["body"] == "hello"
        assert result["body_truncated"] is False
        assert "body_error" not in result


class TestScreenshotDoesNotInventAFile:
    """A screenshot that wrote nothing used to look like a captured image.

    Measured: page.screenshot returning without creating the file still
    answered ``{'path': <missing>}``. An unattended agent then treats a
    missing capture as evidence.
    """

    def _backend(self, write: bool) -> WebBackend:
        class _Page:
            def screenshot(self, path: str, full_page: bool = False) -> None:
                if write:
                    Path(path).write_bytes(b"\x89PNG\r\n\x1a\n")

        class _Runner:
            def call(self, work: object, timeout: float = 60.0) -> object:
                return work()  # type: ignore[operator]

        class _Handle:
            def __init__(self) -> None:
                self.page = _Page()
                self.runner = _Runner()

        backend = WebBackend()
        backend._sessions["s"] = _Handle()  # type: ignore[assignment]
        return backend

    def test_a_missing_file_is_not_a_screenshot(self, tmp_path: Path) -> None:
        out = tmp_path / "shot.png"
        with pytest.raises(WebError) as info:
            self._backend(False).screenshot("s", out)
        assert info.value.code == "backend_error"
        assert "did not write" in info.value.message
        assert not out.exists()

    def test_a_written_file_is_a_screenshot(self, tmp_path: Path) -> None:
        out = tmp_path / "shot.png"
        result = self._backend(True).screenshot("s", out)
        assert result["path"] == str(out)
        assert out.is_file()


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


class TestWebConsoleSaysWhenItWasCut:
    """A console page that hit the cap used to look like every message."""

    def _backend(self, n: int) -> WebBackend:
        import threading
        from collections import deque

        from headless_re_mcp.backends.web.client import _MAX_CONSOLE

        class _Handle:
            def __init__(self) -> None:
                self.lock = threading.Lock()
                self.console = deque(
                    ({"type": "log", "text": str(index)} for index in range(n)),
                    maxlen=_MAX_CONSOLE,
                )
                self.runner = object()

        backend = WebBackend()
        backend._sessions["s"] = _Handle()  # type: ignore[assignment]
        return backend

    def test_a_full_buffer_is_not_returned_as_one_page(self) -> None:
        result = self._backend(500).console("s", limit=200)
        assert result["count"] == 200
        assert result["total"] == 500
        assert result["has_more"] is True

    def test_a_short_buffer_is_not_labelled_partial(self) -> None:
        result = self._backend(3).console("s", limit=200)
        assert result["count"] == 3
        assert result["has_more"] is False


class TestWebNetworkListSaysWhenItWasCut:
    """A request page that filled used to look like every capture if count was all you read."""

    def _backend(self, n: int) -> WebBackend:
        import threading
        from collections import OrderedDict

        class _Handle:
            def __init__(self) -> None:
                self.lock = threading.Lock()
                self.requests = OrderedDict(
                    (str(index), {"requestId": str(index), "url": f"https://ex/{index}"})
                    for index in range(n)
                )
                self.runner = object()

        backend = WebBackend()
        backend._sessions["s"] = _Handle()  # type: ignore[assignment]
        return backend

    def test_a_full_page_is_marked(self) -> None:
        result = self._backend(500).network_list("s", offset=0, limit=100)
        assert result["count"] == 100
        assert result["total"] == 500
        assert result["has_more"] is True

    def test_a_short_list_is_not_labelled_partial(self) -> None:
        result = self._backend(3).network_list("s", offset=0, limit=100)
        assert result["has_more"] is False
        assert result["total"] == 3


class TestWebWasmListSaysWhenItWasCut:
    """web.wasm.list shares the script buffer and used to hide that it stopped at 200."""

    def _backend(self, n: int) -> WebBackend:
        import threading
        from collections import OrderedDict

        class _Handle:
            def __init__(self) -> None:
                self.lock = threading.Lock()
                self.scripts = OrderedDict(
                    (
                        str(index),
                        {
                            "scriptId": str(index),
                            "url": f"m{index}.wasm",
                            "language": "WebAssembly",
                        },
                    )
                    for index in range(n)
                )
                self.runner = object()

        backend = WebBackend()
        backend._sessions["s"] = _Handle()  # type: ignore[assignment]
        return backend

    def test_a_full_page_is_marked(self) -> None:
        result = self._backend(300).scripts("s", wasm_only=True, limit=200)
        assert result["count"] == 200
        assert result["total"] == 300
        assert result["has_more"] is True

    def test_a_short_list_is_not_labelled_partial(self) -> None:
        result = self._backend(3).scripts("s", wasm_only=True, limit=200)
        assert result["has_more"] is False
        assert result["total"] == 3


class TestWebScriptsSayWhenTheyWereCut:
    """A script list that filled the debugger buffer used to look like every script."""

    def _backend(self, n: int) -> WebBackend:
        import threading
        from collections import OrderedDict

        class _Handle:
            def __init__(self) -> None:
                self.lock = threading.Lock()
                self.scripts = OrderedDict(
                    (
                        str(index),
                        {
                            "scriptId": str(index),
                            "url": f"https://ex/{index}.js",
                            "language": "JavaScript",
                        },
                    )
                    for index in range(n)
                )
                self.runner = object()

        backend = WebBackend()
        backend._sessions["s"] = _Handle()  # type: ignore[assignment]
        return backend

    def test_a_full_buffer_is_not_returned_as_one_page(self) -> None:
        result = self._backend(2000).scripts("s", limit=200)
        assert result["count"] == 200
        assert result["total"] == 2000
        assert result["has_more"] is True
        assert len(result["scripts"]) == 200

    def test_a_short_buffer_is_not_labelled_partial(self) -> None:
        result = self._backend(3).scripts("s", limit=200)
        assert result["count"] == 3
        assert result["has_more"] is False

    def test_a_page_that_exactly_fills_is_complete(self) -> None:
        result = self._backend(200).scripts("s", limit=200)
        assert result["count"] == 200
        assert result["has_more"] is False


class TestJsUnpackSaysWhenTheFileListWasCut:
    """file_count used to be the whole tree while the list silently stopped at 2000."""

    def test_a_cut_list_is_marked(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from headless_re_mcp.backends.jsre import client as jsre

        source = tmp_path / "bundle.js"
        source.write_text("x", encoding="utf-8")
        out = tmp_path / "out"
        out.mkdir()
        for index in range(2500):
            (out / f"f{index}.js").write_text("x", encoding="utf-8")
        monkeypatch.setattr(jsre, "_run", lambda cmd, timeout=0: ("", "", 0))
        result = JsClient(Path("/bin/true")).unpack_bundle(source, out)

        assert result["file_count"] == 2500
        assert len(result["files"]) == 2000
        assert result["has_more"] is True

    def test_a_short_tree_is_not_labelled_partial(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from headless_re_mcp.backends.jsre import client as jsre

        source = tmp_path / "bundle.js"
        source.write_text("x", encoding="utf-8")
        out = tmp_path / "out"
        out.mkdir()
        (out / "a.js").write_text("x", encoding="utf-8")
        monkeypatch.setattr(jsre, "_run", lambda cmd, timeout=0: ("", "", 0))
        result = JsClient(Path("/bin/true")).unpack_bundle(source, out)

        assert result["file_count"] == 1
        assert result["has_more"] is False


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


class TestProxyFlowsSayWhenTheyWereCut:
    """A flow page that filled used to look like every capture if count was all you read."""

    def _backend(self, n: int) -> ProxyBackend:
        class _Recorder:
            def snapshot(self) -> list[dict[str, str]]:
                return [{"id": str(index)} for index in range(n)]

        class _Inst:
            recorder = _Recorder()

        backend = ProxyBackend()
        backend._get = lambda session_id: _Inst()  # type: ignore[method-assign]
        return backend

    def test_a_full_page_is_marked(self) -> None:
        result = self._backend(500).flows("s", offset=0, limit=100)
        assert result["count"] == 100
        assert result["total"] == 500
        assert result["has_more"] is True

    def test_a_short_list_is_not_labelled_partial(self) -> None:
        result = self._backend(3).flows("s", offset=0, limit=100)
        assert result["has_more"] is False
        assert result["total"] == 3


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
