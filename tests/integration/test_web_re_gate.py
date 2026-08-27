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

_DATA_URL = (
    "data:text/html,"
    "<html><head><title>gate</title>"
    "<script>window.__x=1;console.log('gate-ready');</script>"
    "</head><body>hello</body></html>"
)

# A 41-byte hand-assembled module exporting one function, so the WASM gate checks
# real structure (a function body and a named export) instead of an empty module.
# Equivalent WAT:
#   (module
#     (type (;0;) (func (param i32 i32) (result i32)))
#     (func (;0;) (type 0) (param i32 i32) (result i32)
#       local.get 0
#       local.get 1
#       i32.add)
#     (export "add" (func 0)))
_ADD_WASM = bytes(
    (
        0x00,
        0x61,
        0x73,
        0x6D,
        0x01,
        0x00,
        0x00,
        0x00,  # magic + version
        0x01,
        0x07,
        0x01,
        0x60,
        0x02,
        0x7F,
        0x7F,
        0x01,
        0x7F,  # functype (i32,i32)->i32
        0x03,
        0x02,
        0x01,
        0x00,  # func section: one function, type 0
        0x07,
        0x07,
        0x01,
        0x03,
        0x61,
        0x64,
        0x64,
        0x00,
        0x00,  # export "add" -> func 0
        0x0A,
        0x09,
        0x01,
        0x07,
        0x00,
        0x20,
        0x00,
        0x20,
        0x01,
        0x6A,
        0x0B,  # code: add + end
    )
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
    raw = _JS_FIXTURE.read_text(encoding="utf-8")
    # The secret is hidden behind \x hex escapes in the source, so its readable
    # form must not already be present -- otherwise the assertion below would
    # prove nothing about what webcrack actually did.
    assert "H3adl3ss" not in raw
    service = AnalysisService()
    try:
        result = service.js_deobfuscate(str(_JS_FIXTURE))
        assert result.ok, result.error
        code = result.data["code"]
        assert isinstance(code, str) and result.data["bytes"] > 0
        # webcrack must have decoded the hex-escaped string array: the hidden
        # secret and the member names it concealed now read as plain literals.
        assert "H3adl3ss" in code, code
        assert "charCodeAt" in code and "reduce" in code, code
        # A clean pass on this tiny script is not a partial/aborted run.
        assert "tool_failed" not in result.data, result.data
    finally:
        service.close_all()


@pytest.mark.integration
def test_js_unpack_bundle_when_webcrack_present() -> None:
    # Regression guard: unpack_bundle used to pre-create webcrack's -o directory,
    # which made webcrack abort with "output directory already exists" on every
    # call. A live run proves the capability actually produces files.
    if not JsClient().available:
        pytest.skip("webcrack not installed — JS unpack Gate not run (skip != pass)")
    assert _JS_FIXTURE.is_file(), f"fixture missing: {_JS_FIXTURE}"
    service = AnalysisService()
    try:
        result = service.js_unpack_bundle(str(_JS_FIXTURE))
        assert result.ok, result.error
        assert result.data["file_count"] >= 1, result.data
        assert result.data["files"], result.data
        assert Path(result.data["output_dir"]).is_dir()
        assert "tool_failed" not in result.data, result.data
    finally:
        service.close_all()


@pytest.mark.integration
def test_wasm_wat_when_wabt_present(tmp_path: Path) -> None:
    if not WasmClient().available:
        pytest.skip("wabt (wasm2wat) not installed — WASM Gate not run (skip != pass)")
    module = tmp_path / "add.wasm"
    module.write_bytes(_ADD_WASM)
    service = AnalysisService()
    try:
        result = service.wasm_wat(str(module))
        assert result.ok, result.error
        wat = result.data["wat"]
        assert "(module" in wat
        # Real structure, not just the module header: the exported function, its
        # body opcode, and a local access all survive the round trip to WAT.
        assert '(export "add"' in wat, wat
        assert "i32.add" in wat and "local.get" in wat, wat
        assert "tool_failed" not in result.data, result.data
    finally:
        service.close_all()


@pytest.mark.integration
def test_wasm_info_when_wabt_present(tmp_path: Path) -> None:
    # wasm.info (wasm-objdump) had no gate at all; drive it against the same real
    # module and assert it reports the sections and the export by name.
    if WasmClient()._objdump is None:
        pytest.skip("wabt (wasm-objdump) not installed — WASM info Gate not run (skip != pass)")
    module = tmp_path / "add.wasm"
    module.write_bytes(_ADD_WASM)
    service = AnalysisService()
    try:
        result = service.wasm_info(str(module))
        assert result.ok, result.error
        objdump = result.data["objdump"]
        assert "Export" in objdump and "Function" in objdump, objdump
        assert "add" in objdump, objdump
        assert "tool_failed" not in result.data, result.data
    finally:
        service.close_all()
