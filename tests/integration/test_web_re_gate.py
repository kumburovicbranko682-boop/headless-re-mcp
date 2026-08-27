"""Web RE gate: CDP browser driving, plus webcrack / wabt when configured.

Each capability skips independently with an explicit "skip != pass" message when
its backend is unavailable, so the gate is honest on a bare machine and real
when Chrome / webcrack / wabt are present.
"""

from __future__ import annotations

import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest

from headless_re_mcp.backends.jsre import JsClient, WasmClient
from headless_re_mcp.backends.web import WebBackend
from headless_re_mcp.core.service import AnalysisService

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_JS_FIXTURE = _PROJECT_ROOT / "fixtures" / "web" / "obfuscated_sample.js"

# A real module -- imported host function, exported memory, a global, and two
# exported functions with actual instructions -- so wasm2wat/wasm-objdump have
# structure to surface rather than an empty header. wat2wasm ships in the same
# wabt package as wasm2wat/wasm-objdump, so any machine that can run the gate can
# also assemble the fixture; the gate skips honestly when it cannot.
_WASM_WAT_SOURCE = textwrap.dedent(
    """
    (module
      (import "env" "log" (func $log (param i32)))
      (memory (export "mem") 1)
      (global $answer i32 (i32.const 42))
      (func $add (export "add") (param $a i32) (param $b i32) (result i32)
        local.get $a
        local.get $b
        i32.add)
      (func $announce (export "announce")
        global.get $answer
        call $log))
    """
)


def _build_wasm(tmp_path: Path) -> Path:
    """Assemble the real module above into a .wasm via wat2wasm, or skip."""
    wat2wasm = shutil.which("wat2wasm")
    if wat2wasm is None:
        pytest.skip("wat2wasm (wabt) not installed — WASM Gate not run (skip != pass)")
    wat = tmp_path / "sample.wat"
    wat.write_text(_WASM_WAT_SOURCE, encoding="utf-8")
    wasm = tmp_path / "sample.wasm"
    subprocess.run([wat2wasm, str(wat), "-o", str(wasm)], check=True, capture_output=True)
    return wasm

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
        # Prove webcrack actually deobfuscated rather than echoing the input:
        # the fixture hides its secret as the escaped literal "\x48\x33..." and
        # only a real unminify pass rewrites it to the readable "H3adl3ss".
        assert "H3adl3ss" in code, code[:400]
        assert "\\x48" not in code
    finally:
        service.close_all()


@pytest.mark.integration
def test_js_unpack_bundle_when_webcrack_present() -> None:
    if not JsClient().available:
        pytest.skip("webcrack not installed — JS unpack Gate not run (skip != pass)")
    assert _JS_FIXTURE.is_file(), f"fixture missing: {_JS_FIXTURE}"
    service = AnalysisService()
    try:
        result = service.js_unpack_bundle(str(_JS_FIXTURE))
        assert result.ok, result.error
        # webcrack always writes at least the deobfuscated entry file; a bare
        # pre-create with no run would leave the tree empty.
        assert result.data["file_count"] >= 1
        assert result.data["files"], "unpack produced no files"
        # The emitted entry file must carry the real deobfuscated program, not
        # an empty placeholder, so read it back and look for the recovered
        # secret -- this is what also catches the webcrack "output directory
        # already exists" failure mode (missing -f) that leaves the tree empty.
        out_dir = Path(result.data["output_dir"])
        emitted = sorted(out_dir.rglob("*.js"))
        assert emitted, "unpack wrote no .js file"
        recovered = emitted[0].read_text(encoding="utf-8", errors="replace")
        assert "H3adl3ss" in recovered, recovered[:400]
    finally:
        service.close_all()


@pytest.mark.integration
def test_wasm_wat_disassembles_a_real_module(tmp_path: Path) -> None:
    if not WasmClient().available:
        pytest.skip("wabt (wasm2wat) not installed — WASM Gate not run (skip != pass)")
    module = _build_wasm(tmp_path)
    service = AnalysisService()
    try:
        result = service.wasm_wat(str(module))
        assert result.ok, result.error
        wat = result.data["wat"]
        # A real disassembly, not just the "(module" header: the function body's
        # instruction, the imported host function, all three exports, and the
        # global initialiser must round-trip back out of the compiled binary.
        assert "i32.add" in wat, wat
        assert '"env"' in wat and '"log"' in wat, wat
        assert '(export "add"' in wat, wat
        assert '(export "announce"' in wat, wat
        assert '(export "mem"' in wat, wat
        assert "i32.const 42" in wat, wat
    finally:
        service.close_all()


@pytest.mark.integration
def test_wasm_info_enumerates_sections_of_a_real_module(tmp_path: Path) -> None:
    if not WasmClient().available:
        pytest.skip("wabt (wasm-objdump) not installed — WASM info Gate not run (skip != pass)")
    module = _build_wasm(tmp_path)
    service = AnalysisService()
    try:
        result = service.wasm_info(str(module))
        assert result.ok, result.error
        objdump = result.data["objdump"]
        # wasm-objdump -h -x lists every section and annotates the named
        # functions/imports/exports; require the structural pieces a real module
        # carries, not just a bare "Type" header.
        for section in ("Type", "Import", "Function", "Memory", "Global", "Export", "Code"):
            assert section in objdump, f"missing section {section}:\n{objdump}"
        assert "env.log" in objdump, objdump
        for name in ('"add"', '"announce"', '"mem"'):
            assert name in objdump, f"missing export {name}:\n{objdump}"
    finally:
        service.close_all()
