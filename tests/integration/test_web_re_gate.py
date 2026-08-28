"""Web RE gate: CDP browser driving, plus webcrack / wabt when configured.

Each capability skips independently with an explicit "skip != pass" message when
its backend is unavailable, so the gate is honest on a bare machine and real
when Chrome / webcrack / wabt are present.
"""

from __future__ import annotations

import re
import shutil
import subprocess
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

# The same rich module rebuilt by ``wat2wasm --debug-names``, which appends
# the "name" custom section: module name "demo", function names host_log
# (imported, index 0) and add_impl (defined, index 1), plus local- and
# global-name subsections the tool-free reader must skip by size. Everything
# before the name section is byte-identical to _RICH_WASM.
_NAMED_WASM = _RICH_WASM + bytes.fromhex(
    "0036046e616d65"  # custom section, name "name"
    "00050464656d6f"  # subsec 0: module name "demo"
    "0115020008686f73745f6c6f6701086164645f696d706c"  # subsec 1: 2 function names
    "02050200000100"  # subsec 2: local names (none) -- skipped
    "070a010007636f756e746572"  # subsec 7: global name "counter" -- skipped
)

# The same rich module with a "target_features" custom section appended (where
# LLVM and rustc record which engine features the build assumed): two used
# ('+') features and one required ('='). wasm-validate clean; everything
# before the custom section is byte-identical to _RICH_WASM.
_FEATURED_WASM = _RICH_WASM + bytes.fromhex(
    "00350f7461726765745f6665617475726573"  # custom section, name "target_features"
    "03"  # three feature entries
    "2b0f6d757461626c652d676c6f62616c73"  # [+] mutable-globals
    "2b087369676e2d657874"  # [+] sign-ext
    "3d0761746f6d696373"  # [=] atomics
)

# wasm2wat renders imports as (import "M" "N" (KIND ...)) and exports as
# (export "N" (KIND ...)); KIND is func/memory/global/table -- the same
# vocabulary describe_wasm reports, so the two views compare directly.
_WAT_IMPORT_RE = re.compile(r'\(import "([^"]+)" "([^"]+)" \((func|memory|global|table)\b')
_WAT_EXPORT_RE = re.compile(r'\(export "([^"]+)" \((func|memory|global|table)\b')
# wasm2wat renders any memory -- imported or defined -- as "(memory (;N;) MIN
# [MAX] [shared])", the same min/max pages describe_wasm reports as its footprint.
_WAT_MEMORY_RE = re.compile(r"\(memory \(;\d+;\) (\d+)(?: (\d+))?")
# And any table -- imported or defined, inside an (import ...) or standalone --
# as "(table (;N;) MIN [MAX] ELEM)", the same element type and slot bounds
# describe_wasm reports. In index order, which is imported tables first: the
# order call_indirect numbers them and the order the reader lists them.
_WAT_TABLE_RE = re.compile(r"\(table \(;\d+;\) (\d+)(?: (\d+))? (funcref|externref)")
# With a name section present, wasm2wat names the module ``(module $demo`` and
# every function ``(func $name`` -- imported or defined -- straight from the
# same subsections the tool-free reader parses. Declaration sites carry a
# ``(type N)`` right after the name; export lines like (export "add" (func
# $add_impl)) do not, so anchoring on it matches each function exactly once,
# in index order (imports first).
_WAT_MODULE_NAME_RE = re.compile(r"\(module \$([^\s()]+)")
_WAT_FUNC_NAME_RE = re.compile(r"\(func \$([^\s()]+) \(type\b")
# wasm-objdump -x renders the target_features section as one "- [P] name" line
# per entry (P is the +/-/= prefix byte), directly under its Custom heading --
# the same prefix and feature the tool-free reader reports.
_OBJDUMP_FEATURE_RE = re.compile(r"^\s*- \[([-+=])\] (\S+)\s*$", re.MULTILINE)


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
        # The entry point, index for index: the reader reports func 0 (the
        # imported env.log, which is what runs at instantiation) and wabt's
        # (start N) must name the same function.
        assert wasm["start_function"] == {"index": 0}
        start_match = re.search(r"\(start (\d+)\)", wat)
        assert start_match, wat
        assert int(start_match.group(1)) == wasm["start_function"]["index"]

        # The memory footprint: the module imports one memory of min 1 page and
        # no maximum. wabt decodes the same limits from the same bytes, so the
        # tool-free (min, max) pairs must match wabt's (min, max) pairs.
        reader_memory = [(m["min"], m["max"]) for m in wasm["memories"]]
        assert reader_memory == [(1, None)]
        wabt_memory = [
            (int(lo), int(hi) if hi else None) for lo, hi in _WAT_MEMORY_RE.findall(wat)
        ]
        assert wabt_memory == reader_memory
    finally:
        service.close_all()


# A module carrying every table shape wasm2wat can render: an imported funcref
# table (min 3, max 9), a defined funcref table (min 2, max 10) and a defined
# externref table (min 1, no max) -- exercising the imported/defined split, the
# bounded/unbounded split and both reference types in one decode.
_TABLES_WASM = bytes.fromhex(
    "0061736d01000000020e0103656e760374626c01700103090408027001020a6f0001"
)


@pytest.mark.integration
def test_wasm_table_facts_agree_with_wabt(tmp_path: Path) -> None:
    """The tool-free table footprint and wabt's decode must match, table for table.

    describe_wasm now reports each table's element type and slot limits the way
    it already reports each memory's pages -- and a funcref table's size is the
    reach of every call_indirect, so it is the control-flow pair to a memory's
    address-space bound. The reader walks the Table section (and the imported
    tables the Import section leads with) itself; this drives a module carrying
    an imported funcref table, a bounded defined funcref table and an unbounded
    externref table through both create_session and wasm2wat, and requires the
    (element_type, min, max) triples to agree in index order -- imported first,
    the order call_indirect numbers them. The WASM analogue of the memory gate
    just above. Needs wabt; skip != pass when it is absent.
    """
    if not WasmClient().available:
        pytest.skip("wabt (wasm2wat) not installed — WASM table gate not run (skip != pass)")
    module = tmp_path / "tables.wasm"
    module.write_bytes(_TABLES_WASM)
    service = AnalysisService()
    try:
        created = service.create_session(str(module))
        assert created.ok, created.error
        wasm = created.data["session"]["metadata"]["wasm"]
        reader_tables = [(t["element_type"], t["min"], t["max"]) for t in wasm["tables"]]

        result = service.wasm_wat(str(module))
        assert result.ok, result.error
        wat = result.data["wat"]
        wabt_tables = [
            (elem, int(lo), int(hi) if hi else None)
            for lo, hi, elem in _WAT_TABLE_RE.findall(wat)
        ]

        expected = [("funcref", 3, 9), ("funcref", 2, 10), ("externref", 1, None)]
        assert reader_tables == expected
        assert wabt_tables == expected
        # The imported table leads the footprint, tagged by origin: the reader's
        # import/define split must line up with wabt's (import ...) placement.
        assert [t["imported"] for t in wasm["tables"]] == [True, False, False]
        # And the enriched import entry carries the same element type and bounds.
        assert wasm["imports"] == [
            {
                "module": "env",
                "name": "tbl",
                "kind": "table",
                "element_type": "funcref",
                "min": 3,
                "max": 9,
            }
        ]
    finally:
        service.close_all()


@pytest.mark.integration
def test_wasm_debug_names_agree_with_wabt(tmp_path: Path) -> None:
    """The tool-free name-section reader and wabt must recover the same names.

    The "name" custom section is WASM's debug-symbol store; describe_wasm now
    parses it itself for the module name and the function-index -> name map.
    But that parser and the unit fixtures are both ours, so nothing proved its
    walk of the subsections matches an independent decoder. wasm2wat applies
    the very same section when it names the module ``(module $demo`` and each
    function ``(func $host_log`` / ``(func $add_impl``; this drives a real
    ``wat2wasm --debug-names`` build through both and requires they agree name
    for name -- including that the reader skipped the local- and global-name
    subsections without corruption. Needs wabt; skip != pass when absent.
    """
    if not WasmClient().available:
        pytest.skip("wabt (wasm2wat) not installed — WASM name cross-check not run (skip != pass)")
    module = tmp_path / "named.wasm"
    module.write_bytes(_NAMED_WASM)
    service = AnalysisService()
    try:
        # Tool-free facts, straight off the name section at session creation.
        created = service.create_session(str(module))
        assert created.ok, created.error
        wasm = created.data["session"]["metadata"]["wasm"]
        assert "name" in wasm["custom_sections"]
        reader_names = {(n["index"], n["name"]) for n in wasm["function_names"]}

        # wabt's independent decode of the same bytes.
        result = service.wasm_wat(str(module))
        assert result.ok, result.error
        wat = result.data["wat"]
        module_match = _WAT_MODULE_NAME_RE.search(wat)
        assert module_match, wat

        # Both readers must agree on the module's own name...
        assert wasm["module_name"] == "demo"
        assert module_match.group(1) == "demo"
        # ...and on every function name, index for index: wasm2wat prints
        # functions in index order (imports first), so its $names line up with
        # the reader's (index, name) pairs exactly.
        wabt_names = set(enumerate(_WAT_FUNC_NAME_RE.findall(wat)))
        expected = {(0, "host_log"), (1, "add_impl")}
        assert reader_names == expected
        assert wabt_names == expected
        assert wasm["function_name_count"] == 2
        # The entry point picks up its debug name from the same map: the
        # reader resolves start -> host_log and wasm2wat renders the identical
        # resolution as (start $host_log).
        assert wasm["start_function"] == {"index": 0, "name": "host_log"}
        assert re.search(r"\(start \$host_log\)", wat), wat
    finally:
        service.close_all()


@pytest.mark.integration
def test_wasm_target_features_agree_with_wabt(tmp_path: Path) -> None:
    """The tool-free target_features reader and wabt must list the same features.

    The target_features custom section is WASM's minimum-runtime fact: the
    engine features (simd128, atomics, ...) the module was built to assume,
    each marked used ('+'), required ('=') or disallowed ('-') -- the analogue
    of an ELF DT_VERNEED or a Mach-O min_os. describe_wasm now parses it
    itself, but that parser and the unit fixtures are both ours, so nothing
    proved its walk matches an independent decoder. wasm-objdump -x decodes
    the very same section into one "- [P] name" line per entry; this drives a
    module carrying three features through both and requires they agree entry
    for entry, prefix and name and order alike. Needs wabt; skip != pass when
    it is absent.
    """
    if not WasmClient().available:
        pytest.skip(
            "wabt (wasm-objdump) not installed — WASM feature cross-check not run (skip != pass)"
        )
    module = tmp_path / "featured.wasm"
    module.write_bytes(_FEATURED_WASM)
    service = AnalysisService()
    try:
        # Tool-free facts, straight off the custom section at session creation.
        created = service.create_session(str(module))
        assert created.ok, created.error
        wasm = created.data["session"]["metadata"]["wasm"]
        assert "target_features" in wasm["custom_sections"]
        reader_features = [(f["prefix"], f["feature"]) for f in wasm["target_features"]]

        # wabt's independent decode of the same bytes. The bracket-prefix lines
        # are unique to the target_features rendering, so matching them across
        # the whole dump reads exactly that section's entries, in order.
        result = service.wasm_info(str(module))
        assert result.ok, result.error
        objdump = result.data["objdump"]
        assert '- name: "target_features"' in objdump, objdump
        wabt_features = _OBJDUMP_FEATURE_RE.findall(objdump)

        # Both readers must list the same features -- prefix, name and order.
        expected = [("+", "mutable-globals"), ("+", "sign-ext"), ("=", "atomics")]
        assert reader_features == expected
        assert wabt_features == expected
    finally:
        service.close_all()


@pytest.mark.integration
def test_wasm_overlay_marks_bytes_wabt_also_rejects(tmp_path: Path) -> None:
    """The reader's overlay bound and wabt's strict decode must agree.

    describe_wasm now reports bytes past the last well-formed section as an
    overlay -- the WASM analogue of the PE/ELF/Mach-O appended-data fact, and a
    classic payload-smuggling spot. The parser and its unit fixtures are both
    ours, so two independent checks anchor the bound to wabt's decoder: the
    pristine module must dump cleanly under wasm-objdump with the reader
    seeing no overlay, and the padded copy must be rejected by the same strict
    decoder -- proving the residue the reader flagged really is outside any
    valid section, at exactly the offset where the clean module ends. Needs
    wabt; skip != pass when it is absent.
    """
    if not WasmClient().available:
        pytest.skip("wabt (wasm-objdump) not installed — WASM overlay gate not run (skip != pass)")
    objdump = shutil.which("wasm-objdump")
    if objdump is None:
        pytest.skip("wasm-objdump not on PATH — WASM overlay gate not run (skip != pass)")

    service = AnalysisService()
    try:
        # The pristine module: wabt dumps it cleanly, the reader sees no
        # overlay -- every byte is the header or a section.
        pristine = tmp_path / "clean.wasm"
        pristine.write_bytes(_ADD_WASM)
        info = service.wasm_info(str(pristine))
        assert info.ok, info.error
        created = service.create_session(str(pristine))
        assert created.ok, created.error
        wasm = created.data["session"]["metadata"]["wasm"]
        assert wasm["overlay"] is None
        assert wasm["well_formed"] is True

        # The same module with a payload glued on. The reader must place the
        # overlay exactly at the clean module's end and cover every appended
        # byte, and the module stops being well-formed.
        payload = b"SMUGGLED-PAYLOAD"
        padded = tmp_path / "padded.wasm"
        padded.write_bytes(_ADD_WASM + payload)
        created = service.create_session(str(padded))
        assert created.ok, created.error
        wasm = created.data["session"]["metadata"]["wasm"]
        # Magicless prose is not any known format, so ``kind`` is None -- a
        # real answer (the encrypted/opaque payload), not a parse failure.
        assert wasm["overlay"] == {"offset": len(_ADD_WASM), "size": len(payload), "kind": None}
        assert wasm["well_formed"] is False
        # The real sections still read: the payload hides after the module,
        # not instead of it.
        assert wasm["exports"] == [{"name": "add", "kind": "func"}]

        # wabt's verdict on the same bytes: the strict decoder refuses the
        # padded file outright, confirming the flagged residue is not some
        # valid section shape the tool-free walk merely failed to recognize.
        result = subprocess.run(
            [objdump, "-h", str(padded)], capture_output=True, text=True, timeout=60
        )
        assert result.returncode != 0, result.stdout
        assert "error" in (result.stderr + result.stdout).lower()

        # And when the smuggled bytes do carry a magic, the overlay names it:
        # a nested ZIP (PK\x03\x04) past the module reads as kind "zip", the
        # same sniff every format's overlay fact runs.
        zip_payload = b"PK\x03\x04nested-container-bytes"
        zipped = tmp_path / "with_zip.wasm"
        zipped.write_bytes(_ADD_WASM + zip_payload)
        created = service.create_session(str(zipped))
        assert created.ok, created.error
        wasm = created.data["session"]["metadata"]["wasm"]
        assert wasm["overlay"] == {
            "offset": len(_ADD_WASM),
            "size": len(zip_payload),
            "kind": "zip",
        }
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
