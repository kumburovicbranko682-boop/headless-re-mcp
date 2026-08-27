"""Web RE gate: CDP browser driving, plus webcrack / wabt when configured.

Each capability skips independently with an explicit "skip != pass" message when
its backend is unavailable, so the gate is honest on a bare machine and real
when Chrome / webcrack / wabt are present.
"""

from __future__ import annotations

import re
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

# A valid module with a real interface -- two imports (env.log func, env.mem
# memory), three exports (add func, g global, mem memory), one global and a
# start function -- so the tool-free reader's import/export/count/start facts
# have something to disagree with wabt about. Hand-assembled and wasm-validate
# clean; see the WASM cross-check below for the section-by-section layout.
_RICH_WASM = bytes.fromhex(
    "0061736d01000000"  # magic + version
    "010a0260000060027f7f017f"  # types: () -> (), (i32,i32) -> i32
    "02160203656e76036c6f67000003656e76036d656d020001"  # imports: env.log func, env.mem memory
    "03020101"  # function section: one func of type 1
    "0606017f0041000b"  # global section: one i32 = 0
    "07110303616464000101670300036d656d0200"  # exports: add(func), g(global), mem(memory)
    "080100"  # start section: func 0
    "0a09010700200020016a0b"  # code: local.get 0, local.get 1, i32.add
)

# wasm2wat renders imports as (import "M" "N" (KIND ...)) and exports as
# (export "N" (KIND ...)); KIND is func/memory/global/table -- the same
# vocabulary describe_wasm reports, so the two views compare directly.
_WAT_IMPORT_RE = re.compile(r'\(import "([^"]+)" "([^"]+)" \((func|memory|global|table)\b')
_WAT_EXPORT_RE = re.compile(r'\(export "([^"]+)" \((func|memory|global|table)\b')


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
def test_wasm_tool_free_facts_agree_with_wabt(tmp_path: Path) -> None:
    """The stdlib WASM reader and wabt must describe the same module interface.

    describe_wasm walks the section table itself to report imports, exports,
    counts and the start function with no wabt -- but that reader and the
    fixture it reads are both ours, so nothing proved its view of a module's
    interface matches an independent decoder. This drives a module with a real
    interface (two imports, three exports, a global, a start) through both:
    create_session for the tool-free facts, wasm2wat for wabt's canonical
    disassembly, and requires they agree import-for-import and export-for-export.
    It is the WASM analogue of the .NET gate cross-checking the reader against
    monodis. Needs wabt; skip != pass when it is absent.
    """
    if not WasmClient().available:
        pytest.skip("wabt (wasm2wat) not installed — WASM cross-check not run (skip != pass)")
    module = tmp_path / "rich.wasm"
    module.write_bytes(_RICH_WASM)
    service = AnalysisService()
    try:
        # Tool-free facts, straight off the section table at session creation.
        created = service.create_session(str(module))
        assert created.ok, created.error
        wasm = created.data["session"]["metadata"]["wasm"]
        reader_imports = {(i["module"], i["name"], i["kind"]) for i in wasm["imports"]}
        reader_exports = {(e["name"], e["kind"]) for e in wasm["exports"]}

        # wabt's independent decode of the same bytes.
        result = service.wasm_wat(str(module))
        assert result.ok, result.error
        wat = result.data["wat"]
        wabt_imports = set(_WAT_IMPORT_RE.findall(wat))
        wabt_exports = set(_WAT_EXPORT_RE.findall(wat))

        # The two readers must agree on the module's entire interface.
        expected_imports = {("env", "log", "func"), ("env", "mem", "memory")}
        expected_exports = {("add", "func"), ("g", "global"), ("mem", "memory")}
        assert reader_imports == expected_imports
        assert wabt_imports == expected_imports
        assert reader_exports == expected_exports
        assert wabt_exports == expected_exports
        # And on the counts and the start function wabt renders as (start ...).
        assert wasm["import_count"] == 2
        assert wasm["export_count"] == 3
        assert wasm["global_count"] == 1
        assert wasm["has_start"] is True
        assert re.search(r"\(start\b", wat), wat
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
        assert wasm["exports"] == [{"name": "add", "kind": "func"}]
        assert set(wasm["section_counts"]) == {"type", "function", "export", "code"}
    finally:
        service.close_all()


@pytest.mark.integration
def test_js_session_metadata_needs_no_webcrack() -> None:
    """The tool-free JS identity facts flow through session creation.

    Like the wasm metadata gate, this needs no webcrack: create_session reads the
    script's size, line shape and any source-map directive itself, so a bare
    machine still gets a first read on the fixture.
    """
    if not _JS_FIXTURE.is_file():
        pytest.skip(f"fixture missing: {_JS_FIXTURE}")
    service = AnalysisService()
    try:
        created = service.create_session(str(_JS_FIXTURE), target="web")
        assert created.ok, created.error
        session = created.data["session"]
        assert session["target"] == "web"
        js = session["metadata"]["js"]
        assert js["size"] == _JS_FIXTURE.stat().st_size
        assert js["line_count"] >= 1
        assert js["max_line_length"] > 0
        assert isinstance(js["source_map_inline"], bool)
    finally:
        service.close_all()
