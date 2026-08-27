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

# A real (not empty) WebAssembly module: exports add(i32, i32) -> i32 whose body
# is `local.get 0; local.get 1; i32.add`. Hand-assembled so the gate needs no
# wat2wasm (wabt's apt package ships wasm2wat/wasm-objdump but not wat2wasm).
# Sections: type (0x01), function (0x03), export (0x07), code (0x0a). Driving a
# module with a typed, named, bodied function is what lets wasm.wat/wasm.info
# assert real decoded content instead of just "module", so a wabt that runs but
# decodes nothing fails the gate.
_WASM_ADD_MODULE = bytes.fromhex(
    # bytes.fromhex ignores the spaces; each line is one WebAssembly section.
    "0061736d 01000000"  # magic "\0asm" + version 1
    "01 07 01 60 02 7f7f 01 7f"  # type section: (i32, i32) -> i32
    "03 02 01 00"  # function section: one func of type 0
    "07 07 01 03 616464 00 00"  # export section: "add" -> func 0
    "0a 09 01 07 00 2000 2001 6a 0b"  # code: local.get 0; local.get 1; i32.add
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
        code = result.data["code"]
        assert isinstance(code, str)
        assert result.data["bytes"] > 0
        # Prove webcrack actually deobfuscated rather than echoing the input.
        # The fixture stores the secret as a \x-escaped entry in a rotated string
        # array ("\x48\x33\x61\x64\x6c\x33\x73\x73") and reaches String methods
        # through computed ["split"] accesses. A webcrack that ran but transformed
        # nothing -- a broken install, an upstream behaviour change -- would leave
        # the \x escapes and the bracket access untouched and still sail past the
        # bytes>0 check above, reading green on zero deobfuscation. Requiring the
        # recovered literal plus the bracket-to-dot member simplification (both
        # core webcrack transforms, verified against webcrack 2.16.0) makes that
        # empty pass fail here instead.
        assert "H3adl3ss" in code
        assert ".split(" in code
        assert '["split"]' not in code
    finally:
        service.close_all()


@pytest.mark.integration
def test_js_unpack_bundle_when_webcrack_present() -> None:
    """js.unpack_bundle had no live gate, and it was broken on every call.

    The JS smoke path only exercised js.deobfuscate, which streams to stdout and
    never touches -o. unpack_bundle takes the -o path: the service pre-creates the
    output directory and hands it to webcrack, but webcrack 2.x aborts with
    "output directory already exists" on an existing -o dir unless -f is passed --
    so every unpack failed (verified against webcrack 2.16.0: backend_error,
    "output directory already exists") behind a deobfuscate-only smoke test. Drive
    the real -o/-f path end to end so that regression fails here, not in production.
    """
    if not JsClient().available:
        pytest.skip("webcrack not installed — JS unpack Gate not run (skip != pass)")
    assert _JS_FIXTURE.is_file(), f"fixture missing: {_JS_FIXTURE}"
    service = AnalysisService()
    try:
        result = service.js_unpack_bundle(str(_JS_FIXTURE))
        # result.ok is the whole point: without -f this is backend_error.
        assert result.ok, result.error
        assert result.data["file_count"] >= 1
        assert result.data["output_dir"]
        assert isinstance(result.data["files"], list)
    finally:
        service.close_all()


@pytest.mark.integration
def test_wasm_wat_when_wabt_present(tmp_path: Path) -> None:
    if not WasmClient().available:
        pytest.skip("wabt (wasm2wat) not installed — WASM Gate not run (skip != pass)")
    # A real module, not the 8-byte empty one: asserting only "module" in the wat
    # passes for an empty header and proves nothing about decoding. Drive the
    # add(i32,i32)->i32 module and require the recovered signature, export name,
    # and body instructions -- verified against wabt's wasm2wat -- so a wabt that
    # runs but decodes nothing fails here instead of reading green.
    module = tmp_path / "add.wasm"
    module.write_bytes(_WASM_ADD_MODULE)
    service = AnalysisService()
    try:
        result = service.wasm_wat(str(module))
        assert result.ok, result.error
        wat = result.data["wat"]
        assert result.data["bytes"] > 0
        assert "(func" in wat  # a function was decompiled, not just "(module)"
        assert "(param i32 i32)" in wat  # the type signature was recovered
        assert "(result i32)" in wat
        assert "add" in wat  # the export name survived
        assert "i32.add" in wat  # the body instructions were decoded
    finally:
        service.close_all()


@pytest.mark.integration
def test_wasm_info_when_wabt_present(tmp_path: Path) -> None:
    """wasm.info (wasm-objdump) had no live gate at all.

    The WASM smoke path only exercised wasm.wat; wasm.info runs a different tool
    (wasm-objdump -h -x) with its own argument shape and output, so a break in it
    -- a wabt packaging that ships wasm2wat but not wasm-objdump, an argument the
    installed objdump rejects -- would ship unseen. Drive the same real module
    and require the section headers wasm-objdump prints for it.
    """
    if not WasmClient().available:
        pytest.skip("wabt (wasm-objdump) not installed — WASM info Gate not run (skip != pass)")
    module = tmp_path / "add.wasm"
    module.write_bytes(_WASM_ADD_MODULE)
    service = AnalysisService()
    try:
        result = service.wasm_info(str(module))
        assert result.ok, result.error
        dump = result.data["objdump"]
        assert isinstance(dump, str)
        # -h -x prints a Sections listing; this module carries Type and Export
        # sections, so both must appear or the dump did not really parse it.
        assert "Type" in dump
        assert "Export" in dump
    finally:
        service.close_all()
