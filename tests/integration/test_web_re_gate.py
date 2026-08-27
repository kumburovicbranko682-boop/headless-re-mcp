"""Web RE gate: CDP browser driving, plus webcrack / wabt when configured.

Each capability skips independently with an explicit "skip != pass" message when
its backend is unavailable, so the gate is honest on a bare machine and real
when Chrome / webcrack / wabt are present. For the static tools skip != pass is
not enough on its own: a tool that ran but decoded nothing would still pass a
"bytes > 0" check, so these assert the tool actually transformed the input --
webcrack must surface a string the fixture only holds hex-escaped, and wabt must
name a function/export the module actually defines.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.backends.jsre import JsClient, WasmClient
from headless_re_mcp.backends.web import WebBackend
from headless_re_mcp.core.service import AnalysisService

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_JS_FIXTURE = _PROJECT_ROOT / "fixtures" / "web" / "obfuscated_sample.js"
# The fixture hides this string as a hex-escaped array entry
# ("\\x48\\x33\\x61..."), so its readable form appears only if webcrack decoded
# the escapes -- it is not present as plain text in the source on disk.
_JS_SECRET = "H3adl3ss"

# A hand-encoded WebAssembly module: one function () -> i32 returning 42,
# exported as "gate_add". Encoded as raw bytes (not compiled with wat2wasm) so
# the fixture is self-contained, yet rich enough that a real wasm2wat /
# wasm-objdump must name the export and the constant -- an empty module would
# only prove the tool emitted "(module)".
_RICH_WASM = bytes.fromhex(
    "0061736d01000000"  # magic + version
    "0105016000017f"  # type section: () -> i32
    "03020100"  # function section: one func of type 0
    "070c0108676174655f6164640000"  # export section: "gate_add" -> func 0
    "0a06010400412a0b"  # code section: i32.const 42; end
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
    source = _JS_FIXTURE.read_text(encoding="utf-8")
    # The readable secret must be hidden in the source, so finding it in the
    # output can only mean webcrack decoded the escapes -- not that it echoed.
    assert _JS_SECRET not in source, "fixture no longer hides the secret; assertion is void"

    service = AnalysisService()
    try:
        result = service.js_deobfuscate(str(_JS_FIXTURE))
        assert result.ok, result.error
        code = result.data["code"]
        assert isinstance(code, str)
        assert result.data["bytes"] > 0
        # Proof of work: webcrack turned the hex-escaped array entry back into a
        # readable string, and the escaped form is gone from the output.
        assert _JS_SECRET in code, code
        assert "\\x48" not in code, "hex escapes survived; deobfuscation did nothing"
        assert code != source, "output is byte-identical to the input"
    finally:
        service.close_all()


@pytest.mark.integration
def test_wasm_wat_when_wabt_present(tmp_path: Path) -> None:
    if not WasmClient().available:
        pytest.skip("wabt (wasm2wat) not installed — WASM Gate not run (skip != pass)")
    module = tmp_path / "gate.wasm"
    module.write_bytes(_RICH_WASM)
    service = AnalysisService()
    try:
        result = service.wasm_wat(str(module))
        assert result.ok, result.error
        wat = result.data["wat"]
        assert "module" in wat
        # The module's real content, not just the wrapper: the export it
        # declares and the constant its one function returns.
        assert "gate_add" in wat, wat
        assert "i32.const 42" in wat, wat
    finally:
        service.close_all()


@pytest.mark.integration
def test_wasm_info_when_wabt_present(tmp_path: Path) -> None:
    """wasm-objdump (wasm.info) had no live coverage; prove it reads sections."""
    if WasmClient()._objdump is None:
        pytest.skip("wabt (wasm-objdump) not installed — WASM info Gate not run (skip != pass)")
    module = tmp_path / "gate.wasm"
    module.write_bytes(_RICH_WASM)
    service = AnalysisService()
    try:
        result = service.wasm_info(str(module))
        assert result.ok, result.error
        objdump = result.data["objdump"]
        # The section table and the named export must both come back, proving
        # wasm-objdump walked the module rather than merely opening it.
        for section in ("Type", "Function", "Export", "Code"):
            assert section in objdump, (section, objdump)
        assert "gate_add" in objdump, objdump
    finally:
        service.close_all()
