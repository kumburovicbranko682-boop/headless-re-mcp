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


def _build_wasm_module() -> bytes:
    """A minimal but non-empty module: exports one function returning i32 42.

    The empty-module check below proves the smallest valid input still parses;
    this gives wasm2wat and wasm-objdump real sections (type, function, export,
    code) so their output is asserted on content, not just non-emptiness. Bytes
    follow the WebAssembly binary format, where each section is {id, size, body}
    and the small sizes here are single-byte LEB128.
    """

    def _section(section_id: int, body: bytes) -> bytes:
        return bytes([section_id, len(body)]) + body

    type_section = _section(0x01, bytes([0x01, 0x60, 0x00, 0x01, 0x7F]))  # () -> i32
    function_section = _section(0x03, bytes([0x01, 0x00]))  # func 0 has type 0
    name = b"answer"
    export_section = _section(0x07, bytes([0x01, len(name)]) + name + bytes([0x00, 0x00]))
    func_body = bytes([0x00, 0x41, 0x2A, 0x0B])  # 0 locals; i32.const 42; end
    code_section = _section(0x0A, bytes([0x01, len(func_body)]) + func_body)
    return (
        b"\x00asm\x01\x00\x00\x00"
        + type_section
        + function_section
        + export_section
        + code_section
    )

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
def test_wasm_wat_when_wabt_present(tmp_path: Path) -> None:
    if not WasmClient().available:
        pytest.skip("wabt (wasm2wat) not installed — WASM Gate not run (skip != pass)")
    # The smallest valid module: magic + version, no sections.
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
def test_wasm_wat_reads_a_real_module(tmp_path: Path) -> None:
    """wasm2wat on a module with a real exported function, asserted on content."""
    if not WasmClient().available:
        pytest.skip("wabt (wasm2wat) not installed — WASM Gate not run (skip != pass)")
    module = tmp_path / "answer.wasm"
    module.write_bytes(_build_wasm_module())
    service = AnalysisService()
    try:
        result = service.wasm_wat(str(module))
        assert result.ok, result.error
        wat = result.data["wat"]
        assert "func" in wat
        assert "answer" in wat
    finally:
        service.close_all()


@pytest.mark.integration
def test_wasm_info_lists_sections_and_exports(tmp_path: Path) -> None:
    """wasm-objdump has no other gate; prove it reports the module's sections.

    Skips honestly when wasm2wat is absent, and again when wasm-objdump in
    particular is missing (wabt can be split so one tool is present without the
    other) -- skip != pass for either.
    """
    if not WasmClient().available:
        pytest.skip("wabt (wasm2wat) not installed — WASM Gate not run (skip != pass)")
    module = tmp_path / "answer.wasm"
    module.write_bytes(_build_wasm_module())
    service = AnalysisService()
    try:
        info = service.wasm_info(str(module))
        if not info.ok and info.error and info.error.code == "capability_unavailable":
            pytest.skip("wasm-objdump not available — objdump Gate not run (skip != pass)")
        assert info.ok, info.error
        dump = info.data["objdump"]
        assert "Export" in dump
        assert "answer" in dump
    finally:
        service.close_all()
