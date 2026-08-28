"""Web RE gate: CDP browser driving, plus webcrack / wabt when configured.

Each capability skips independently with an explicit "skip != pass" message when
its backend is unavailable, so the gate is honest on a bare machine and real
when Chrome / webcrack / wabt are present.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from headless_re_mcp.backends.jsre import JsClient, WasmClient
from headless_re_mcp.backends.jsre.client import _resolve_wabt_tool
from headless_re_mcp.backends.web import WebBackend
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_JS_FIXTURE = _PROJECT_ROOT / "fixtures" / "web" / "obfuscated_sample.js"

# The plaintext the fixture hides behind the "\x48\x33..." escapes; it must not
# appear literally in the source (asserted below), so finding it in webcrack's
# output is proof the escapes were actually decoded, not merely reformatted.
_DECODED_SECRET = "H3adl3ss"

# A real module built at test time via wat2wasm (which ships with wabt, right
# next to the wasm2wat under test). The empty magic-only module the old gate
# used proved wasm2wat could open a file; it never proved wasm2wat disassembles
# real instructions or recovers exports, which is the whole point of the tool.
_WAT_SOURCE = """\
(module
  (func $add (export "add") (param $a i32) (param $b i32) (result i32)
    local.get $a
    local.get $b
    i32.add)
  (func $triple (export "triple") (param $n i32) (result i32)
    local.get $n
    i32.const 3
    i32.mul)
  (memory (export "mem") 1))
"""


def _wat2wasm() -> Path | None:
    """Locate wat2wasm the same way the client resolves wasm2wat.

    Reusing ``_resolve_wabt_tool`` means a HEADLESS_RE_WABT that points at a bin
    directory (no PATH entry) still finds the assembler, so the gate builds its
    own module wherever the disassembler under test was found.
    """
    return _resolve_wabt_tool(getattr(Settings.load(), "wabt", None), "wat2wasm")


def _build_real_wasm(tmp_path: Path) -> Path | None:
    """Assemble ``_WAT_SOURCE`` into a real .wasm module, or None if unbuildable."""
    assembler = _wat2wasm()
    if assembler is None:
        return None
    wat = tmp_path / "mod.wat"
    wat.write_text(_WAT_SOURCE, encoding="utf-8")
    module = tmp_path / "mod.wasm"
    proc = subprocess.run(
        [str(assembler), str(wat), "-o", str(module)],
        capture_output=True,
        timeout=60,
    )
    if proc.returncode != 0 or not module.is_file():
        return None
    return module


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
    # The fixture hides the string behind hex escapes, so the plaintext must not
    # be there yet -- otherwise the assertion below would pass without webcrack
    # doing anything.
    raw = _JS_FIXTURE.read_text(encoding="utf-8")
    assert _DECODED_SECRET not in raw, "fixture is not obfuscated; test would be vacuous"
    assert "\\x48" in raw, "fixture no longer carries the hex escapes it is meant to"
    service = AnalysisService()
    try:
        result = service.js_deobfuscate(str(_JS_FIXTURE))
        assert result.ok, result.error
        code = result.data["code"]
        assert isinstance(code, str)
        assert result.data["bytes"] > 0
        # webcrack decoded the "\x48\x33..." string escapes into readable text,
        # so the plaintext secret now appears and the escape form is gone.
        assert _DECODED_SECRET in code, "webcrack did not decode the hidden string"
        assert "\\x48" not in code, "hex escapes survived deobfuscation"
        # It also rewrites string-keyed member access to dot access while
        # unminifying, another change the input plainly needed.
        assert ".push(" in code, "bracket member access was not simplified"
    finally:
        service.close_all()


@pytest.mark.integration
def test_wasm_wat_when_wabt_present(tmp_path: Path) -> None:
    if not WasmClient().available:
        pytest.skip("wabt (wasm2wat) not installed — WASM Gate not run (skip != pass)")
    module = _build_real_wasm(tmp_path)
    if module is None:
        pytest.skip("wat2wasm (wabt) unavailable to build a module — skip != pass")
    service = AnalysisService()
    try:
        result = service.wasm_wat(str(module))
        assert result.ok, result.error
        wat = result.data["wat"]
        # Real instructions were disassembled, not just the module header.
        assert "i32.add" in wat, wat
        assert "i32.mul" in wat, wat
        assert "local.get" in wat, wat
        # Both named exports were recovered from the export section.
        assert '"add"' in wat and '"triple"' in wat, wat
        assert "(export" in wat, wat
    finally:
        service.close_all()


@pytest.mark.integration
def test_wasm_info_when_wabt_present(tmp_path: Path) -> None:
    if not WasmClient()._objdump:
        pytest.skip("wabt (wasm-objdump) not installed — WASM info Gate not run (skip != pass)")
    module = _build_real_wasm(tmp_path)
    if module is None:
        pytest.skip("wat2wasm (wabt) unavailable to build a module — skip != pass")
    service = AnalysisService()
    try:
        result = service.wasm_info(str(module))
        assert result.ok, result.error
        objdump = result.data["objdump"]
        # wasm-objdump enumerates the sections and the exported function symbols.
        assert "Export" in objdump and "Code" in objdump, objdump
        assert "Function" in objdump, objdump
        assert "add" in objdump and "triple" in objdump, objdump
    finally:
        service.close_all()
