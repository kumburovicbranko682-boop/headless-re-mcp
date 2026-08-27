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
        # Prove webcrack transformed the sample rather than merely re-printing it.
        # The fixture hides "H3adl3ss" in a \x-escaped string array and reaches
        # its methods through computed ["split"] / ["push"] accesses. Requiring
        # the recovered string plus the bracket-to-dot member simplification --
        # webcrack's core deobfuscation -- means an install that ran but decoded
        # nothing fails here instead of reading green on the earlier bytes>0 check.
        assert "H3adl3ss" in code
        assert ".split(" in code
        assert '["split"]' not in code
    finally:
        service.close_all()


@pytest.mark.integration
def test_js_unpack_bundle_when_webcrack_present() -> None:
    # js.unpack_bundle had no live gate. The JS smoke path only exercised
    # js.deobfuscate, which streams to stdout and never touches -o. unpack_bundle
    # takes the -o path: the service pre-creates the output directory and then
    # hands it to webcrack, but webcrack 2.x aborts with "output directory
    # already exists" on an existing -o dir unless -f is passed, so every unpack
    # failed unseen behind a deobfuscate-only smoke test. Drive the real path end
    # to end so that regression fails here rather than in production.
    if not JsClient().available:
        pytest.skip("webcrack not installed — JS unpack Gate not run (skip != pass)")
    assert _JS_FIXTURE.is_file(), f"fixture missing: {_JS_FIXTURE}"
    service = AnalysisService()
    try:
        result = service.js_unpack_bundle(str(_JS_FIXTURE))
        assert result.ok, result.error
        # webcrack wrote into the pre-created directory instead of aborting on it,
        # which is the whole point: file_count>=1 means the -o/-f path produced
        # output rather than failing the "already exists" check.
        assert result.data["file_count"] >= 1
        assert result.data["output_dir"]
        assert isinstance(result.data["files"], list)
    finally:
        service.close_all()


def _wasm_module_with_a_function_and_exports() -> bytes:
    """A hand-assembled module that is more than magic + version.

    The gate used to hand wasm2wat the four-byte empty module, which only proves
    the tool launches. A module with a typed function, a memory, a global and
    three named exports makes wasm2wat render real bytecode (i32.add) and
    wasm-objdump list real sections, so the WASM path is exercised end to end
    rather than merely started. Every section body here is well under 128 bytes,
    so each length is a single-byte LEB128, which is why bytes([len]) is exact.
    """

    def section(section_id: int, body: bytes) -> bytes:
        return bytes([section_id, len(body)]) + body

    magic_and_version = b"\x00asm\x01\x00\x00\x00"
    type_section = section(1, b"\x01\x60\x02\x7f\x7f\x01\x7f")  # one (i32, i32) -> i32
    function_section = section(3, b"\x01\x00")  # func 0 uses type 0
    memory_section = section(5, b"\x01\x00\x01")  # one memory, min 1 page
    global_section = section(6, b"\x01\x7f\x00\x41\x2a\x0b")  # i32 global = 42
    export_section = section(
        7,
        b"\x03"  # three exports
        b"\x03add\x00\x00"  # func 0 as "add"
        b"\x03mem\x02\x00"  # memory 0 as "mem"
        b"\x06answer\x03\x00",  # global 0 as "answer"
    )
    body = b"\x00\x20\x00\x20\x01\x6a\x0b"  # no locals; local.get 0/1; i32.add; end
    code_section = section(10, b"\x01" + bytes([len(body)]) + body)
    return (
        magic_and_version
        + type_section
        + function_section
        + memory_section
        + global_section
        + export_section
        + code_section
    )


@pytest.mark.integration
def test_wasm_wat_when_wabt_present(tmp_path: Path) -> None:
    if not WasmClient().available:
        pytest.skip("wabt (wasm2wat) not installed — WASM Gate not run (skip != pass)")
    module = tmp_path / "module.wasm"
    module.write_bytes(_wasm_module_with_a_function_and_exports())
    service = AnalysisService()
    try:
        result = service.wasm_wat(str(module))
        assert result.ok, result.error
        wat = result.data["wat"]
        # Not just "(module)": the function body and a named export must render,
        # proving wasm2wat decoded the code and export sections rather than
        # merely emitting a shell for an empty module.
        assert "i32.add" in wat
        assert '(export "add"' in wat
        assert result.data["bytes"] > 0
    finally:
        service.close_all()


@pytest.mark.integration
def test_wasm_info_when_wabt_present(tmp_path: Path) -> None:
    # wasm-objdump had no live gate at all; the tool was installed but never
    # exercised, so a break in the info path would only surface in production.
    if not WasmClient().available:
        pytest.skip("wabt (wasm-objdump) not installed — WASM info Gate not run (skip != pass)")
    module = tmp_path / "module.wasm"
    module.write_bytes(_wasm_module_with_a_function_and_exports())
    service = AnalysisService()
    try:
        result = service.wasm_info(str(module))
        assert result.ok, result.error
        objdump = result.data["objdump"]
        # wasm-objdump -h -x lists the sections and resolves the export names.
        for section_name in ("Type", "Function", "Export", "Code"):
            assert section_name in objdump, section_name
        assert '"add"' in objdump
    finally:
        service.close_all()
