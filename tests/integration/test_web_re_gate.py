"""Web RE gate: CDP browser driving, plus webcrack / wabt when configured.

Each capability skips independently with an explicit "skip != pass" message when
its backend is unavailable, so the gate is honest on a bare machine and real
when Chrome / webcrack / wabt are present.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.backends.jsre import JsClient, WasmClient
from headless_re_mcp.backends.web import WebBackend
from headless_re_mcp.core.service import AnalysisService

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_JS_FIXTURE = _PROJECT_ROOT / "fixtures" / "web" / "obfuscated_sample.js"
_WASM_FIXTURE = _PROJECT_ROOT / "fixtures" / "web" / "add_module.wasm"

_DATA_URL = (
    "data:text/html,"
    "<html><head><title>gate</title>"
    "<script>window.__x=1;console.log('gate-ready');</script>"
    "</head><body>hello</body></html>"
)


def _browser_available() -> bool:
    backend = WebBackend()
    try:
        backend._check_available()
    except Exception:
        return False
    return True


@pytest.mark.integration
def test_web_cdp_open_and_inspect() -> None:
    if not _browser_available():
        pytest.skip("playwright not installed — Web CDP Gate not run (skip != pass)")
    service = AnalysisService()
    try:
        created = service.create_session(_DATA_URL, target="web")
        assert created.ok, created.error
        session_id = created.data["session"]["id"]

        opened = service.web_open(session_id, headless=True, timeout=30.0)
        if not opened.ok:
            pytest.skip(
                f"chromium could not launch (browser not installed?): "
                f"{opened.error.code if opened.error else 'unknown'} — skip != pass"
            )
        try:
            scripts = service.web_scripts(session_id)
            assert scripts.ok, scripts.error
            assert isinstance(scripts.data["scripts"], list)

            console = service.web_console(session_id)
            assert console.ok, console.error

            dom = service.web_dom_snapshot(session_id)
            assert dom.ok, dom.error
            assert "gate" in dom.data["title"]
        finally:
            service.web_close(session_id)
    finally:
        service.close_all()


@pytest.mark.integration
def test_js_deobfuscate_when_webcrack_present() -> None:
    if not JsClient().available:
        pytest.skip("webcrack not installed — JS Gate not run (skip != pass)")
    assert _JS_FIXTURE.is_file(), f"fixture missing: {_JS_FIXTURE}"
    service = AnalysisService()
    try:
        result = service.js_deobfuscate(str(_JS_FIXTURE))
        assert result.ok, result.error
        assert isinstance(result.data["code"], str)
        assert result.data["bytes"] > 0
    finally:
        service.close_all()


@pytest.mark.integration
def test_js_unpack_bundle_when_webcrack_present() -> None:
    if not JsClient().available:
        pytest.skip("webcrack not installed — JS Gate not run (skip != pass)")
    assert _JS_FIXTURE.is_file(), f"fixture missing: {_JS_FIXTURE}"
    service = AnalysisService()
    try:
        result = service.js_unpack_bundle(str(_JS_FIXTURE))
        # webcrack owns the output directory: the service pre-creates a unique
        # tree for retention, so unpack has to pass --force or webcrack aborts
        # with "output directory already exists". A green here proves the whole
        # write path, not just deobfuscation to stdout.
        assert result.ok, result.error
        assert result.data["file_count"] >= 1
        assert result.data["files"], "webcrack produced no files"
    finally:
        service.close_all()


@pytest.mark.integration
def test_wasm_wat_when_wabt_present() -> None:
    if not WasmClient().available:
        pytest.skip("wabt (wasm2wat) not installed — WASM Gate not run (skip != pass)")
    assert _WASM_FIXTURE.is_file(), f"fixture missing: {_WASM_FIXTURE}"
    service = AnalysisService()
    try:
        result = service.wasm_wat(str(_WASM_FIXTURE))
        assert result.ok, result.error
        wat = result.data["wat"]
        # A real module round-trips to a function definition and its named export,
        # not just the bare "(module" wrapper an empty module would yield.
        assert "(func" in wat
        assert '(export "add"' in wat
        assert result.data["bytes"] > 0
    finally:
        service.close_all()


@pytest.mark.integration
def test_wasm_info_when_wabt_present() -> None:
    if not WasmClient().available:
        pytest.skip("wabt (wasm-objdump) not installed — WASM Gate not run (skip != pass)")
    assert _WASM_FIXTURE.is_file(), f"fixture missing: {_WASM_FIXTURE}"
    service = AnalysisService()
    try:
        result = service.wasm_info(str(_WASM_FIXTURE))
        assert result.ok, result.error
        objdump = result.data["objdump"]
        # wasm-objdump -h -x enumerates the section headers and details; the
        # export table names the "add" function the module deliberately exposes.
        assert "Export" in objdump
        assert "add" in objdump
    finally:
        service.close_all()


@pytest.mark.integration
def test_wasm_wat_accepts_minimal_module(tmp_path: Path) -> None:
    if not WasmClient().available:
        pytest.skip("wabt (wasm2wat) not installed — WASM Gate not run (skip != pass)")
    # Boundary case: the smallest valid module is magic + version, no sections.
    module = tmp_path / "empty.wasm"
    module.write_bytes(b"\x00asm\x01\x00\x00\x00")
    service = AnalysisService()
    try:
        result = service.wasm_wat(str(module))
        assert result.ok, result.error
        assert "module" in result.data["wat"]
    finally:
        service.close_all()


@pytest.mark.integration
def test_wasm_readers_fault_soft_on_a_malformed_module(tmp_path: Path) -> None:
    """A bad .wasm must fault with a structured error, not smuggle it as output.

    wasm2wat writes its error to stderr and empties stdout, but wasm-objdump
    writes the diagnostic to STDOUT and exits non-zero -- so wasm_info used to
    return ok with "error: bad magic value" as the objdump payload, dressing a
    failed inspection up as analysis. Both readers must now come back
    backend_error (never internal_error, never a false success), and the actual
    diagnostic must be reachable so an agent learns why the module was rejected.
    """
    if not WasmClient().available:
        pytest.skip("wabt not installed — WASM Gate not run (skip != pass)")
    bad = tmp_path / "bad.wasm"
    bad.write_bytes(b"NOPE\x01\x00\x00\x00garbage-past-the-magic")
    service = AnalysisService()
    try:
        info = service.wasm_info(str(bad))
        assert not info.ok and info.error is not None
        assert info.error.code == "backend_error", info.error
        assert "magic" in str(info.error.details.get("stderr", "")).lower()

        wat = service.wasm_wat(str(bad))
        assert not wat.ok and wat.error is not None
        assert wat.error.code == "backend_error", wat.error

        # And a valid module through the same reader still succeeds, so the fix
        # rejects only genuine failures rather than every non-zero-looking run.
        good = tmp_path / "min.wasm"
        good.write_bytes(b"\x00asm\x01\x00\x00\x00")
        ok = service.wasm_info(str(good))
        assert ok.ok and ok.data is not None, ok.error
        assert "wasm" in ok.data["objdump"].lower()
    finally:
        service.close_all()
