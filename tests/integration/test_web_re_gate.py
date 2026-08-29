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

# A valid module exporting "answer" () -> i32 returning 42. Same bytes the wat
# gate disassembles; wasm-objdump must name the export and the section headers.
_WASM_ANSWER_MODULE = bytes(
    [
        0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00,  # magic + version
        0x01, 0x05, 0x01, 0x60, 0x00, 0x01, 0x7F,  # type: () -> i32
        0x03, 0x02, 0x01, 0x00,  # function: uses type 0
        # export "answer" (func 0)
        0x07, 0x0A, 0x01, 0x06, 0x61, 0x6E, 0x73, 0x77, 0x65, 0x72, 0x00, 0x00,
        0x0A, 0x06, 0x01, 0x04, 0x00, 0x41, 0x2A, 0x0B,  # code: i32.const 42; end
    ]
)

# A minimal webpack bundle: module 0 requires module 1, whose export carries a
# marker that appears nowhere as a top-level statement in the packed form.
# Unpacking must split it into per-module files that surface the marker.
_WEBPACK_BUNDLE = (
    "(function(modules){var installed={};"
    "function __webpack_require__(id){"
    "if(installed[id])return installed[id].exports;"
    "var module=installed[id]={exports:{}};"
    "modules[id].call(module.exports,module,module.exports,__webpack_require__);"
    "return module.exports;}"
    "__webpack_require__(0);})(["
    "function(module,exports,__webpack_require__){"
    "var msg=__webpack_require__(1);console.log(msg);},"
    'function(module,exports){module.exports="unbundled-marker";}]);\n'
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

            # The page logs 'gate-ready' during load; asserting only console.ok
            # would let console capture regress silently (the reason that log is
            # in the fixture at all). Prove the message the page emitted came
            # back, carrying the documented type/text entry shape.
            console = service.web_console(session_id)
            assert console.ok, console.error
            entries = console.data["console"]
            gate_logs = [
                entry
                for entry in entries
                if "gate-ready" in entry.get("text", "")
            ]
            assert gate_logs, f"console.log('gate-ready') was not captured: {entries}"
            assert gate_logs[0]["type"] == "log"

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
        # The fixture hides "H3adl3ss" as \x-escapes inside a rotated string
        # array; recovering it is webcrack's whole job. Asserting only bytes>0
        # would pass on a no-op that deobfuscated nothing. The marker never
        # appears as plain text in the input (guarded here so a fixture edit
        # cannot quietly weaken the check), so its presence in the output proves
        # real string decoding happened.
        assert "H3adl3ss" not in _JS_FIXTURE.read_text(encoding="utf-8")
        assert "H3adl3ss" in code
    finally:
        service.close_all()


@pytest.mark.integration
def test_wasm_wat_when_wabt_present(tmp_path: Path) -> None:
    if not WasmClient().available:
        pytest.skip("wabt (wasm2wat) not installed — WASM Gate not run (skip != pass)")
    # A module with real sections rather than the empty magic+version: it
    # exports a function "answer" that returns i32.const 42. An empty module
    # disassembles to "(module)", so asserting only "module" proved nothing was
    # decoded; a content-bearing module makes wabt walk the type, function,
    # export and code sections, and the WAT must name what it found.
    module = tmp_path / "answer.wasm"
    module.write_bytes(
        bytes(
            [
                0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00,  # magic + version
                0x01, 0x05, 0x01, 0x60, 0x00, 0x01, 0x7F,  # type: () -> i32
                0x03, 0x02, 0x01, 0x00,  # function: uses type 0
                # export "answer" (func 0)
                0x07, 0x0A, 0x01, 0x06, 0x61, 0x6E, 0x73, 0x77, 0x65, 0x72, 0x00, 0x00,
                0x0A, 0x06, 0x01, 0x04, 0x00, 0x41, 0x2A, 0x0B,  # code: i32.const 42; end
            ]
        )
    )
    service = AnalysisService()
    try:
        result = service.wasm_wat(str(module))
        assert result.ok, result.error
        wat = result.data["wat"]
        assert "module" in wat
        # The export name and the instruction come from two different sections,
        # so together they prove wabt decoded the module rather than echoing a
        # header.
        assert "answer" in wat
        assert "i32.const 42" in wat
    finally:
        service.close_all()


def _uleb(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def _sleb(value: int) -> bytes:
    out = bytearray()
    more = True
    while more:
        byte = value & 0x7F
        value >>= 7
        if (value == 0 and not byte & 0x40) or (value == -1 and byte & 0x40):
            more = False
        else:
            byte |= 0x80
        out.append(byte)
    return bytes(out)


def _many_function_wasm(function_count: int) -> bytes:
    """A valid wasm of N no-arg i32 functions, each returning its own index.

    Hand-built rather than compiled so the fixture needs only wasm2wat (the tool
    under test), not wat2wasm too. N functions disassemble to well over the
    400 KiB inline cap, which is the whole point: a module this size is exactly
    what the output_path spill exists to recover.
    """
    section_type = _uleb(1) + b"\x60\x00\x01\x7f"  # one type: () -> i32
    section_func = _uleb(function_count) + b"\x00" * function_count  # all type 0
    bodies = bytearray(_uleb(function_count))
    for index in range(function_count):
        body = b"\x00\x41" + _sleb(index) + b"\x0b"  # 0 locals; i32.const index; end
        bodies += _uleb(len(body)) + body
    return (
        b"\x00asm\x01\x00\x00\x00"
        + bytes([1]) + _uleb(len(section_type)) + section_type
        + bytes([3]) + _uleb(len(section_func)) + section_func
        + bytes([10]) + _uleb(len(bodies)) + bytes(bodies)
    )


@pytest.mark.integration
def test_wasm_wat_truncation_spills_the_full_module_to_output_path(tmp_path: Path) -> None:
    """A WAT over the inline cap must spill the complete text to output_path.

    The small-module wat gate above only ever exercises the inline path; the
    recovery an agent relies on for a real (large) module -- truncated set, the
    full disassembly written to output_path so the functions past the cut are
    not lost -- had no live coverage. Build a module whose WAT clears the 400 KiB
    cap, then prove the spill file holds every byte and begins with the inline
    prefix. skip != pass: skips when wasm2wat is not installed.
    """
    if not WasmClient().available:
        pytest.skip("wabt (wasm2wat) not installed — WASM truncation Gate not run (skip != pass)")
    from headless_re_mcp.backends.jsre.client import _MAX_INLINE

    module = tmp_path / "big.wasm"
    module.write_bytes(_many_function_wasm(12000))
    service = AnalysisService()
    try:
        result = service.wasm_wat(str(module))
        assert result.ok, result.error
        data = result.data
        assert data["truncated"] is True
        # The inline text is capped; the full size is larger and is the length
        # the spill must match.
        assert len(data["wat"].encode("utf-8")) <= _MAX_INLINE
        assert data["bytes"] > _MAX_INLINE
        spill = data.get("output_path")
        assert isinstance(spill, str) and spill, data
        spilled = Path(spill).read_bytes()
        assert len(spilled) == data["bytes"]
        # The inline field is the leading buffer of the spilled file, not a
        # separate rendering: an agent reading output_path continues where wat
        # was cut, it does not get a different disassembly.
        assert spilled.decode("utf-8", "ignore").startswith(data["wat"][:1000])
    finally:
        service.close_all()


@pytest.mark.integration
def test_wasm_info_reports_sections_and_the_export(tmp_path: Path) -> None:
    """wasm.info runs wasm-objdump; the header dump must name real sections.

    Distinct from the wat gate: wat is the textual disassembly, info is the
    section/symbol summary from a different wabt tool, and it had no coverage.
    Asserting the section headers and the export name proves objdump parsed the
    module rather than only echoing the file name. skip != pass: skips when
    wasm-objdump is not configured.
    """
    if WasmClient()._objdump is None:
        pytest.skip("wasm-objdump (wabt) not installed — WASM info Gate not run (skip != pass)")
    module = tmp_path / "answer.wasm"
    module.write_bytes(_WASM_ANSWER_MODULE)
    service = AnalysisService()
    try:
        result = service.wasm_info(str(module))
        assert result.ok, result.error
        dump = result.data["objdump"]
        assert "Export" in dump
        assert "Code" in dump
        assert "answer" in dump
    finally:
        service.close_all()


@pytest.mark.integration
def test_js_unpack_bundle_splits_modules_when_webcrack_present(tmp_path: Path) -> None:
    """webcrack must split a webpack bundle into its per-module files.

    This is the surface the --force fix repaired: before it, every unpack
    failed on the pre-created output directory. A no-op that returned the whole
    bundle in one file would satisfy file_count>0, so assert the marker (held in
    module 1's export, not a top-level statement) is recovered in a module file
    -- proof the bundle was actually taken apart. skip != pass.
    """
    if not JsClient().available:
        pytest.skip("webcrack not installed — JS unpack Gate not run (skip != pass)")
    bundle = tmp_path / "bundle.js"
    bundle.write_text(_WEBPACK_BUNDLE, encoding="utf-8")
    service = AnalysisService()
    try:
        result = service.js_unpack_bundle(str(bundle))
        assert result.ok, result.error
        assert result.data["file_count"] >= 1
        out_dir = Path(result.data["output_dir"])
        carriers = [
            name
            for name in result.data["files"]
            if "unbundled-marker" in (out_dir / name).read_text(encoding="utf-8", errors="ignore")
        ]
        assert carriers, f"the module marker was not recovered in any file: {result.data['files']}"
    finally:
        service.close_all()


@pytest.mark.integration
def test_js_deobfuscate_truncation_recovers_via_unpack_bundle(tmp_path: Path) -> None:
    """A deobfuscation past the inline buffer must be recoverable in full.

    js.deobfuscate returns code capped at the inline buffer with truncated set
    and bytes carrying the true length, so a large result silently loses its
    tail in the reply. The documented recovery is js.unpack_bundle, which writes
    the complete output to disk. Build an input whose unminified form clears the
    cap, prove deobfuscate truncates (bytes > the returned code, truncated True),
    then prove unpack_bundle on the same file recovers every byte -- the sum of
    the written files equals bytes. Summing files rather than naming
    deobfuscated.js keeps this robust across webcrack's plain-file vs bundle
    layout. skip != pass.
    """
    if not JsClient().available:
        pytest.skip("webcrack not installed — JS truncation-recovery Gate not run (skip != pass)")
    from headless_re_mcp.backends.jsre.client import _MAX_INLINE

    src = tmp_path / "big.js"
    # Many independent functions: webcrack unminifies each, so the output clears
    # the inline buffer by a wide margin without any single huge token.
    body = "\n".join(f"function f{i}(a,b){{var c=a+b;return c*{i};}}" for i in range(20000))
    src.write_text(body, encoding="utf-8")
    service = AnalysisService()
    try:
        deob = service.js_deobfuscate(str(src))
        assert deob.ok, deob.error
        total_bytes = deob.data["bytes"]
        assert deob.data["truncated"] is True, "a result over the buffer must be flagged truncated"
        assert total_bytes > _MAX_INLINE, total_bytes
        assert len(deob.data["code"].encode("utf-8")) <= _MAX_INLINE
        # The tail really is missing from the inline reply.
        assert total_bytes > len(deob.data["code"].encode("utf-8"))

        recovered = service.js_unpack_bundle(str(src))
        assert recovered.ok, recovered.error
        out_dir = Path(recovered.data["output_dir"])
        on_disk = sum(p.stat().st_size for p in out_dir.rglob("*") if p.is_file())
        # The tail deobfuscate dropped is really on disk: the written output far
        # exceeds the inline cap and recovers essentially the whole reported
        # length. A byte or two of slack absorbs webcrack writing a file without
        # the trailing newline its stdout carried -- not a lost tail.
        assert on_disk > _MAX_INLINE, on_disk
        assert on_disk >= total_bytes - 4, f"lost the tail: {on_disk} vs {total_bytes}"
    finally:
        service.close_all()


@pytest.mark.integration
def test_js_beautify_expands_a_minified_one_liner_when_webcrack_present(tmp_path: Path) -> None:
    """js.beautify must reformat packed code into multiple readable lines.

    beautify shares webcrack with deobfuscate but had no coverage of its own.
    The input is a single dense line; a genuine beautify expands it across
    lines and drops the semicolon-crammed packing, so assert the output gained
    line breaks rather than only that some string came back. skip != pass.
    """
    if not JsClient().available:
        pytest.skip("webcrack not installed — JS beautify Gate not run (skip != pass)")
    minified = tmp_path / "min.js"
    one_liner = "function f(a,b){var c=a+b;if(c>10){return c*2;}else{return c-1;}}f(3,4);"
    assert "\n" not in one_liner
    minified.write_text(one_liner, encoding="utf-8")
    service = AnalysisService()
    try:
        result = service.js_beautify(str(minified))
        assert result.ok, result.error
        code = result.data["code"]
        assert result.data["bytes"] > 0
        assert code.count("\n") >= 3, f"beautify did not expand the one-liner: {code!r}"
    finally:
        service.close_all()
