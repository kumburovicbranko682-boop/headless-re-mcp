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

# The obfuscated fixture hides this string as \x-escapes inside a rotated string
# array; a real webcrack pass decodes it back to this literal, which the raw
# source never contains. That difference is the proof the tool transformed its
# input rather than echoing it -- "bytes > 0" alone a passthrough would satisfy.
_DECODED_SECRET = "H3adl3ss"

# A real WebAssembly module: one exported function add(i32,i32)->i32 returning
# their sum. Built with wat2wasm from
#   (module (func (export "add") (param i32 i32) (result i32)
#            local.get 0  local.get 1  i32.add))
# and embedded as bytes so the WASM gates exercise real sections, a real export
# table and real instructions -- not the empty magic+version header, which has
# no function, export or code section to inspect at all.
_ADD_WASM = bytes.fromhex(
    "0061736d0100000001070160027f7f017f030201000707010361646400000a09010700200020016a0b"
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
    raw = _JS_FIXTURE.read_text(encoding="utf-8")
    # If the literal were already in the source the decode assertion below would
    # prove nothing; the fixture must carry it only in \x-escaped form.
    assert _DECODED_SECRET not in raw, "fixture already contains the plain literal"
    service = AnalysisService()
    try:
        result = service.js_deobfuscate(str(_JS_FIXTURE))
        assert result.ok, result.error
        code = result.data["code"]
        assert isinstance(code, str)
        assert result.data["bytes"] > 0
        assert result.data["truncated"] is False
        # The escaped string array was decoded back to a readable literal: real
        # deobfuscation happened, not a copy of the input.
        assert _DECODED_SECRET in code, "webcrack did not decode the string array"
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
        assert result.ok, result.error
        data = result.data
        # webcrack always writes the deobfuscated module even for a single
        # non-bundled file, so the unpack must have produced at least that.
        assert data["file_count"] >= 1
        assert data["count"] == len(data["files"])
        assert data["offset"] == 0
        assert any(name.endswith(".js") for name in data["files"]), data["files"]
        # A full page (count == total) must not claim there is more to fetch.
        assert data["has_more"] is (data["offset"] + data["count"] < data["total"])
        assert data.get("tool_failed") is None
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
        assert result.data["truncated"] is False
        # The disassembly must reflect the real module: its exported function,
        # its signature and its one arithmetic instruction.
        assert "(module" in wat
        assert '(export "add"' in wat
        assert "(param i32 i32) (result i32)" in wat
        assert "i32.add" in wat
    finally:
        service.close_all()


@pytest.mark.integration
def test_wasm_info_when_wabt_present(tmp_path: Path) -> None:
    if not WasmClient().available:
        pytest.skip("wabt (wasm-objdump) not installed — WASM Gate not run (skip != pass)")
    module = tmp_path / "add.wasm"
    module.write_bytes(_ADD_WASM)
    service = AnalysisService()
    try:
        result = service.wasm_info(str(module))
        assert result.ok, result.error
        objdump = result.data["objdump"]
        assert result.data["truncated"] is False
        # wasm-objdump -h -x lists every section and resolves the export name;
        # each of these is present only because the module really has them.
        for section in ("Type", "Function", "Export", "Code"):
            assert section in objdump, f"section {section} missing from objdump"
        assert "add" in objdump, "export name missing from objdump"
    finally:
        service.close_all()


@pytest.mark.integration
def test_wasm_session_metadata_needs_no_wabt(tmp_path: Path) -> None:
    """The tool-free WASM identity facts flow through session creation.

    Unlike the wat/info gates above, this needs no wabt: create_session walks
    the module's section table itself, so a bare machine still gets the version,
    section list and vector counts. It is the WASM analogue of the APK metadata
    a session already carries.
    """
    module = tmp_path / "add.wasm"
    module.write_bytes(_ADD_WASM)
    service = AnalysisService()
    try:
        created = service.create_session(str(module))
        assert created.ok, created.error
        session = created.data["session"]
        assert session["target"] == "web"
        wasm = session["metadata"]["wasm"]
        assert wasm["version"] == 1
        assert wasm["well_formed"] is True
        assert wasm["function_count"] == 1
        assert wasm["export_count"] == 1
        assert set(wasm["section_counts"]) == {"type", "function", "export", "code"}
    finally:
        service.close_all()
