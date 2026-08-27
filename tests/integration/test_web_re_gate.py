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
_WASM_FIXTURE = _PROJECT_ROOT / "fixtures" / "web" / "sample_module.wasm"

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
def test_wasm_wat_disassembles_a_real_module_when_wabt_present() -> None:
    """wasm2wat lifts the fixture's exported functions back to WAT.

    An empty (magic + version) module only proves the tool runs; the committed
    fixture has real type/function/export/code sections, so a regression that
    dropped section decoding would fail here instead of passing on an empty
    module.
    """
    if not WasmClient().available:
        pytest.skip("wabt (wasm2wat) not installed — WASM Gate not run (skip != pass)")
    assert _WASM_FIXTURE.is_file(), f"fixture missing: {_WASM_FIXTURE}"
    service = AnalysisService()
    try:
        result = service.wasm_wat(str(_WASM_FIXTURE))
        assert result.ok, result.error
        wat = result.data["wat"]
        assert "module" in wat
        assert '"add"' in wat
        assert "i32.add" in wat
    finally:
        service.close_all()


@pytest.mark.integration
def test_wasm_info_reports_sections_when_wabt_present() -> None:
    """wasm-objdump enumerates the fixture's sections and exported names."""
    if not WasmClient().available:
        pytest.skip("wabt (wasm-objdump) not installed — WASM Gate not run (skip != pass)")
    assert _WASM_FIXTURE.is_file(), f"fixture missing: {_WASM_FIXTURE}"
    service = AnalysisService()
    try:
        result = service.wasm_info(str(_WASM_FIXTURE))
        assert result.ok, result.error
        objdump = result.data["objdump"]
        assert "Export" in objdump
        assert "Code" in objdump
        assert "add" in objdump
    finally:
        service.close_all()
