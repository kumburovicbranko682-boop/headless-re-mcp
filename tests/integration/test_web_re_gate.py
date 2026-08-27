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
_BUNDLE_FIXTURE = _PROJECT_ROOT / "fixtures" / "web" / "webpack_bundle.js"

_DATA_URL = (
    "data:text/html,"
    "<html><head><title>gate</title>"
    "<script>window.__x=1;console.log('gate-ready');</script>"
    "</head><body>hello</body></html>"
)

# A real module: one exported ``add(i32, i32) -> i32``. Assembled by hand so the
# WASM gate checks actual disassembly instead of an empty module's boilerplate.
_WASM_ADD = bytes((
    0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00,  # magic + version
    0x01, 0x07, 0x01, 0x60, 0x02, 0x7F, 0x7F, 0x01, 0x7F,  # type sec: (i32, i32) -> i32
    0x03, 0x02, 0x01, 0x00,  # function section: one func of type 0
    0x07, 0x07, 0x01, 0x03, 0x61, 0x64, 0x64, 0x00, 0x00,  # export "add" -> func 0
    0x0A, 0x09, 0x01, 0x07, 0x00, 0x20, 0x00, 0x20, 0x01, 0x6A, 0x0B,  # code: get0 get1 i32.add end
))


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
        code = result.data["code"]
        assert isinstance(code, str)
        assert result.data["bytes"] > 0
        # webcrack must actually decode the hex-escaped string array: the raw
        # fixture only carries "\x48\x33\x61...", so seeing the plain text proves
        # deobfuscation ran rather than the tool merely echoing the input.
        assert "H3adl3ss" in code, code[:400]
        assert "\\x48" not in code, "hex escapes should be decoded, not passed through"
    finally:
        service.close_all()


@pytest.mark.integration
def test_js_unpack_bundle_when_webcrack_present() -> None:
    if not JsClient().available:
        pytest.skip("webcrack not installed — JS unpack Gate not run (skip != pass)")
    assert _BUNDLE_FIXTURE.is_file(), f"fixture missing: {_BUNDLE_FIXTURE}"
    service = AnalysisService()
    try:
        result = service.js_unpack_bundle(str(_BUNDLE_FIXTURE))
        assert result.ok, result.error
        data = result.data
        # Unbundling splits the webpack runtime into one file per module, so a
        # real unpack lands more than a single output file.
        assert data["file_count"] >= 2, data
        output_dir = Path(data["output_dir"])
        emitted = list(output_dir.rglob("*"))
        assert emitted, f"webcrack wrote nothing to {output_dir}"
        # The helper module must come back out as extracted source, with its
        # body intact -- proof the bundle was taken apart, not just reformatted.
        blob = "\n".join(
            path.read_text(encoding="utf-8", errors="replace")
            for path in emitted
            if path.is_file()
        )
        assert "webpack-gate-module" in blob, sorted(p.name for p in emitted)
    finally:
        service.close_all()


@pytest.mark.integration
def test_wasm_wat_when_wabt_present(tmp_path: Path) -> None:
    if not WasmClient().available:
        pytest.skip("wabt (wasm2wat) not installed — WASM Gate not run (skip != pass)")
    module = tmp_path / "add.wasm"
    module.write_bytes(_WASM_ADD)
    service = AnalysisService()
    try:
        result = service.wasm_wat(str(module))
        assert result.ok, result.error
        wat = result.data["wat"]
        assert "module" in wat
        # A real disassembly names the exported function and its opcode; an empty
        # module would only ever yield "(module)".
        assert 'export "add"' in wat, wat
        assert "i32.add" in wat, wat
    finally:
        service.close_all()


@pytest.mark.integration
def test_wasm_info_when_wabt_present(tmp_path: Path) -> None:
    if not WasmClient().available:
        pytest.skip("wabt (wasm-objdump) not installed — WASM Gate not run (skip != pass)")
    module = tmp_path / "add.wasm"
    module.write_bytes(_WASM_ADD)
    service = AnalysisService()
    try:
        result = service.wasm_info(str(module))
        assert result.ok, result.error
        objdump = result.data["objdump"]
        assert "Export" in objdump, objdump
        assert "add" in objdump, objdump
    finally:
        service.close_all()
