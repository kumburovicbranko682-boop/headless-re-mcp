"""Web static line live gate: wabt on a real module, webcrack on real code.

``test_web_re_gate`` covers the web static tools only shallowly -- js.deobfuscate
asserts the output is a non-empty string, and wasm.wat runs on an *empty* module
(magic + version, no sections). That leaves the interesting behaviour untested:
whether the tools recover real facts, and whether the guards fire. This gate:

* builds a genuine WebAssembly module at test time (wat2wasm from a WAT with an
  exported ``add`` function, so nothing binary is tracked) and asserts wasm.wat
  round-trips it back to text carrying the export and ``i32.add``, and wasm.info
  (wasm-objdump) reports the Type/Function/Export/Code sections and the ``add``
  symbol;
* pins the wasm guards: a file without the ``\\0asm`` magic is refused
  ``invalid_params`` before wabt launches, and an oversized input is refused
  ``too_large``;
* drives webcrack on real code: a minified one-liner comes back multi-line, and
  ``console["log"]("\\x68...")`` deobfuscates to ``console.log("hello")``;
* guards a real regression: js.unpack_bundle must not pre-create its output
  directory (webcrack 2.x aborts on a pre-existing ``-o`` dir), so unpacking a
  script writes ``deobfuscated.js`` rather than failing.

skip != pass: each half skips with an explicit reason when wabt / webcrack (or the
wat2wasm needed to assemble the module) is not installed.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from headless_re_mcp.backends.jsre import JsClient, WasmClient
from headless_re_mcp.backends.jsre.client import _resolve_wabt_tool
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService

_WAT_SOURCE = (
    "(module\n"
    '  (func $add (export "add") (param $a i32) (param $b i32) (result i32)\n'
    "    local.get $a\n"
    "    local.get $b\n"
    "    i32.add))\n"
)

_MINIFIED_JS = "function f(a,b){return a+b;}var x=f(1,2);console.log(x);"
# A computed member access plus a hex-escaped string: webcrack rewrites both,
# so the recovered source is plain readable JavaScript.
_OBFUSCATED_JS = 'console["log"]("\\x68\\x65\\x6c\\x6c\\x6f");'
_MAX_INPUT_BYTES = 16 * 1024 * 1024


def _wasm_available() -> bool:
    return WasmClient(getattr(Settings.load(), "wabt", None)).available


def _js_available() -> bool:
    return JsClient(getattr(Settings.load(), "webcrack", None)).available


def _build_wasm(tmp_path: Path) -> Path | None:
    """Assemble a real module from WAT, or None when wat2wasm is unavailable."""
    wat2wasm = _resolve_wabt_tool(getattr(Settings.load(), "wabt", None), "wat2wasm")
    if wat2wasm is None:
        return None
    wat = tmp_path / "add.wat"
    wat.write_text(_WAT_SOURCE, encoding="utf-8")
    wasm = tmp_path / "add.wasm"
    subprocess.run(
        [str(wat2wasm), str(wat), "-o", str(wasm)],
        check=True,
        capture_output=True,
    )
    return wasm


@pytest.mark.integration
def test_wasm_module_wat_and_info_via_wabt(tmp_path: Path) -> None:
    if not _wasm_available():
        pytest.skip("wabt (wasm2wat) not installed — WASM Gate not run (skip != pass)")
    wasm = _build_wasm(tmp_path)
    if wasm is None:
        pytest.skip("wat2wasm not available to assemble the module — not run (skip != pass)")

    service = AnalysisService()
    try:
        wat = service.wasm_wat(str(wasm))
        assert wat.ok, wat.error
        text = wat.data["wat"]
        assert "(module" in text
        assert '(export "add"' in text
        assert "i32.add" in text
        assert not wat.data.get("tool_failed")

        info = service.wasm_info(str(wasm))
        assert info.ok, info.error
        objdump = info.data["objdump"]
        for section in ("Type", "Function", "Export", "Code"):
            assert section in objdump, f"wasm-objdump omitted the {section} section"
        assert "add" in objdump
        assert not info.data.get("tool_failed")
    finally:
        service.close_all()


@pytest.mark.integration
def test_wasm_static_rejects_bad_input(tmp_path: Path) -> None:
    if not _wasm_available():
        pytest.skip("wabt (wasm2wat) not installed — WASM Gate not run (skip != pass)")
    service = AnalysisService()
    try:
        # No \0asm magic: refused before wabt is launched.
        not_wasm = tmp_path / "not.wasm"
        not_wasm.write_bytes(b"this is plainly not a WebAssembly module")
        rejected = service.wasm_wat(str(not_wasm))
        assert rejected.ok is False
        assert rejected.error is not None
        assert rejected.error.code == "invalid_params"

        # Oversized: refused up front by the size cap (checked before the magic),
        # so a sparse file with the right magic is still too_large.
        oversized = tmp_path / "big.wasm"
        with oversized.open("wb") as handle:
            handle.write(b"\x00asm\x01\x00\x00\x00")
            handle.truncate(_MAX_INPUT_BYTES + 1)
        too_big = service.wasm_wat(str(oversized))
        assert too_big.ok is False
        assert too_big.error is not None
        assert too_big.error.code == "too_large"
    finally:
        service.close_all()


@pytest.mark.integration
def test_js_beautify_and_deobfuscate_via_webcrack(tmp_path: Path) -> None:
    if not _js_available():
        pytest.skip("webcrack not installed — JS Gate not run (skip != pass)")
    service = AnalysisService()
    try:
        minified = tmp_path / "mini.js"
        minified.write_text(_MINIFIED_JS, encoding="utf-8")
        beautified = service.js_beautify(str(minified))
        assert beautified.ok, beautified.error
        code = beautified.data["code"]
        # A single input line comes back as a formatted, multi-line function.
        assert len(code.splitlines()) > 1
        assert "function" in code
        assert not beautified.data.get("tool_failed")

        obfuscated = tmp_path / "obf.js"
        obfuscated.write_text(_OBFUSCATED_JS, encoding="utf-8")
        deobfuscated = service.js_deobfuscate(str(obfuscated))
        assert deobfuscated.ok, deobfuscated.error
        recovered = deobfuscated.data["code"]
        # The computed member and the hex string are both resolved.
        assert 'console.log("hello")' in recovered
    finally:
        service.close_all()


@pytest.mark.integration
def test_js_unpack_bundle_writes_modules(tmp_path: Path) -> None:
    """Regression guard: unpack must not pre-create webcrack's -o directory.

    webcrack 2.x aborts with "output directory already exists" when handed a
    pre-existing ``-o`` dir, which used to make every js.unpack_bundle fail.
    """
    if not _js_available():
        pytest.skip("webcrack not installed — JS Gate not run (skip != pass)")
    service = AnalysisService()
    try:
        script = tmp_path / "app.js"
        script.write_text(_MINIFIED_JS, encoding="utf-8")
        unpacked = service.js_unpack_bundle(str(script))
        assert unpacked.ok, unpacked.error
        assert unpacked.data["file_count"] >= 1
        assert "deobfuscated.js" in unpacked.data["files"]
        assert not unpacked.data.get("tool_failed")
    finally:
        service.close_all()
