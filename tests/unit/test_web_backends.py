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


class TestBinaryResponseBodySpill:
    """CDP base64 bodies must reach disk as the decoded resource, not base64 text.

    ``Network.getResponseBody`` returns binary bodies base64-encoded; the spill
    path used to write that base64 *text* into the ``.bin`` artifact, handing the
    caller a file 4/3 the real size that still needed decoding. These pin the
    corrected contract without a browser.
    """

    def test_small_base64_body_stays_inline_and_round_trips(self, tmp_path: Path) -> None:
        import base64

        from headless_re_mcp.backends.web.client import _spill_base64_body

        raw = bytes(range(256)) * 4  # 1024 bytes; base64 well under the inline cap
        b64 = base64.b64encode(raw).decode("ascii")
        inline, spill, cut = _spill_base64_body(b64, artifact_dir=tmp_path, filename="b.bin")
        assert spill is None
        assert cut is False
        assert inline == b64
        assert base64.b64decode(inline) == raw

    def test_large_base64_body_spills_decoded_bytes_not_text(self, tmp_path: Path) -> None:
        import base64

        from headless_re_mcp.backends.web.client import _spill_base64_body

        # 200 KB raw -> ~266 KB base64, above the 200 KB inline cap, so it spills.
        raw = bytes((i * 5 + 1) & 0xFF for i in range(200_000))
        b64 = base64.b64encode(raw).decode("ascii")
        inline, spill, cut = _spill_base64_body(b64, artifact_dir=tmp_path, filename="body.bin")
        assert spill is not None
        assert cut is True
        assert spill.read_bytes() == raw  # the resource, byte-for-byte
        assert spill.read_bytes() != b64.encode("ascii")  # explicitly not base64 text
        assert inline == b64[:200_000]  # inline stays a base64 prefix

    def test_undecodable_base64_falls_back_to_text(self, tmp_path: Path) -> None:
        from headless_re_mcp.backends.web.client import _spill_base64_body

        inline, spill, cut = _spill_base64_body("abc", artifact_dir=tmp_path, filename="x.bin")
        assert spill is None
        assert cut is False
        assert inline == "abc"


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


class TestWasmInfoFailureChannel:
    """wasm-objdump prints its errors to stdout, so a non-zero exit is the truth.

    Unlike wasm2wat (errors -> stderr, empty stdout), wasm-objdump writes its
    diagnostic to STDOUT and exits non-zero on a malformed module. The old
    ``code != 0 and not stdout`` guard never fired -- stdout held the error text
    -- so WasmClient.info returned that error string as a *successful* objdump
    payload. These pin the corrected contract: a non-zero exit faults, and the
    diagnostic (from whichever stream carried it) is surfaced, not passed off as
    analysis.
    """

    def _client(self, tmp_path: Path) -> tuple[WasmClient, Path]:
        module = tmp_path / "m.wasm"
        module.write_bytes(b"\x00asm\x01\x00\x00\x00")
        client = WasmClient(None)
        # Force "available" independent of whether wabt is installed here; _run
        # is stubbed per-test so the fake path is never actually launched.
        client._objdump = Path("/does/not/matter/wasm-objdump")
        return client, module

    def test_stdout_error_with_nonzero_exit_faults(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from headless_re_mcp.backends.jsre import client as jsre_client

        client, module = self._client(tmp_path)
        diagnostic = "0000004: error: bad magic value\n"
        monkeypatch.setattr(jsre_client, "_run", lambda *a, **k: (diagnostic, "", 1))
        with pytest.raises(JsReError) as raised:
            client.info(module)
        assert raised.value.code == "backend_error"
        # The real reason must reach the caller even though it came on stdout.
        assert "bad magic value" in str(raised.value.details.get("stderr"))

    def test_stderr_error_with_nonzero_exit_also_faults(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from headless_re_mcp.backends.jsre import client as jsre_client

        client, module = self._client(tmp_path)
        monkeypatch.setattr(jsre_client, "_run", lambda *a, **k: ("", "some stderr diag", 1))
        with pytest.raises(JsReError) as raised:
            client.info(module)
        assert raised.value.code == "backend_error"
        assert "some stderr diag" in str(raised.value.details.get("stderr"))

    def test_zero_exit_returns_the_objdump_payload(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from headless_re_mcp.backends.jsre import client as jsre_client

        client, module = self._client(tmp_path)
        listing = "m.wasm:\tfile format wasm 0x1\n\nSections:\n"
        monkeypatch.setattr(jsre_client, "_run", lambda *a, **k: (listing, "", 0))
        payload = client.info(module)
        assert payload["objdump"] == listing
        assert payload["truncated"] is False


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
