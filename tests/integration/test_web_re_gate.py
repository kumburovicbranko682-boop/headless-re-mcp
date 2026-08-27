"""Web RE gate: CDP browser driving, plus webcrack / wabt when configured.

Each capability skips independently with an explicit "skip != pass" message when
its backend is unavailable, so the gate is honest on a bare machine and real
when Chrome / webcrack / wabt are present.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from headless_re_mcp.backends.jsre import JsClient, WasmClient
from headless_re_mcp.backends.web import WebBackend
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_JS_FIXTURE = _PROJECT_ROOT / "fixtures" / "web" / "obfuscated_sample.js"

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
def test_js_unpack_bundle_when_webcrack_present(tmp_path: Path) -> None:
    """webcrack's bundle unpack writes a tree and the service pages over it.

    js.deobfuscate returns text, but unpack_bundle is the only JS op that writes
    files, so its whole result surface -- _capped_file_listing, the pagination
    fields, the service's own out_dir creation and pruning -- had only unit-stub
    coverage. webcrack always emits at least the deobfuscated entry into -o, so a
    real run must come back with a non-empty tree the window agrees with.
    """
    if not JsClient().available:
        pytest.skip("webcrack not installed — JS unpack Gate not run (skip != pass)")
    assert _JS_FIXTURE.is_file(), f"fixture missing: {_JS_FIXTURE}"
    service = AnalysisService(replace(Settings.load(), artifact_root=tmp_path / "artifacts"))
    try:
        result = service.js_unpack_bundle(str(_JS_FIXTURE), limit=50)
        assert result.ok, result.error
        data = result.data
        assert data["file_count"] >= 1
        assert data["total"] == data["file_count"]
        assert isinstance(data["files"], list) and data["files"]
        assert data["count"] == len(data["files"])
        assert data["offset"] == 0
        # The window and the count have to tell the same story about whether more
        # files are behind the page -- the has_more contract the unit tests pin.
        assert data["has_more"] is (data["offset"] + data["count"] < data["total"])
        assert Path(data["output_dir"]).is_dir()
    finally:
        service.close_all()


# A minimal but non-empty valid module, hand-assembled so the gate needs no
# WASM toolchain to produce it: one function () -> i32 that returns 42, exported
# as "add". This drives the type/function/export/code sections through both
# wasm2wat and wasm-objdump -- a header-only module round-trips to just
# "(module)" and proves nothing about real disassembly.
_WASM_MODULE = (
    b"\x00asm\x01\x00\x00\x00"  # magic + version
    b"\x01\x05\x01\x60\x00\x01\x7f"  # type section: 1 type, () -> i32
    b"\x03\x02\x01\x00"  # function section: 1 func of type 0
    b"\x07\x07\x01\x03add\x00\x00"  # export section: "add" -> func 0
    b"\x0a\x06\x01\x04\x00\x41\x2a\x0b"  # code section: i32.const 42; end
)


@pytest.mark.integration
def test_wasm_wat_when_wabt_present(tmp_path: Path) -> None:
    if not WasmClient().available:
        pytest.skip("wabt (wasm2wat) not installed — WASM Gate not run (skip != pass)")
    module = tmp_path / "mini.wasm"
    module.write_bytes(_WASM_MODULE)
    service = AnalysisService()
    try:
        result = service.wasm_wat(str(module))
        assert result.ok, result.error
        wat = result.data["wat"]
        # Real disassembly of the sections, not just an empty module envelope.
        assert "(module" in wat
        assert "func" in wat
        assert 'export "add"' in wat
        assert "i32" in wat
    finally:
        service.close_all()


@pytest.mark.integration
def test_wasm_info_when_wabt_present(tmp_path: Path) -> None:
    # wasm-objdump ships with wabt alongside wasm2wat; the objdump path had no
    # live coverage at all, so its -h -x wiring could rot unnoticed.
    if WasmClient()._objdump is None:
        pytest.skip("wabt (wasm-objdump) not installed — WASM info Gate not run (skip != pass)")
    module = tmp_path / "mini.wasm"
    module.write_bytes(_WASM_MODULE)
    service = AnalysisService()
    try:
        result = service.wasm_info(str(module))
        assert result.ok, result.error
        objdump = result.data["objdump"]
        # The section headers -h lists and the -x details for the export.
        for section in ("Type", "Function", "Export", "Code"):
            assert section in objdump, f"{section} section missing from objdump"
        assert "add" in objdump
    finally:
        service.close_all()
