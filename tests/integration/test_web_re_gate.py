"""Web RE gate: CDP browser driving, plus webcrack / wabt when configured.

Each capability skips independently with an explicit "skip != pass" message when
its backend is unavailable, so the gate is honest on a bare machine and real
when Chrome / webcrack / wabt are present.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from headless_re_mcp.backends.jsre import JsClient, WasmClient
from headless_re_mcp.backends.web import WebBackend
from headless_re_mcp.core.service import AnalysisService

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_JS_FIXTURE = _PROJECT_ROOT / "fixtures" / "web" / "obfuscated_sample.js"
_WAT_FIXTURE = _PROJECT_ROOT / "fixtures" / "web" / "sample.wat"
# The fixture stores this string hex-escaped ("\x48\x33..."), so it is absent
# from the raw source; webcrack recovering it as readable text is the signal
# that real string decoding happened, not just a whitespace re-format.
_HIDDEN_STRING = "H3adl3ss"

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
    # Guard the premise: if the fixture ever stops hiding the string, the
    # recovered-string assertion below would pass for the wrong reason.
    assert _HIDDEN_STRING not in raw, "fixture must store the secret hex-escaped, not in cleartext"

    service = AnalysisService()
    try:
        result = service.js_deobfuscate(str(_JS_FIXTURE))
        assert result.ok, result.error
        code = result.data["code"]
        assert isinstance(code, str)
        assert result.data["bytes"] > 0
        # webcrack actually deobfuscated: it decoded the hex-escaped literal back
        # to readable text (absent from the raw source) and normalised the code
        # (bracket member access -> dot, hex numbers -> decimal), so the output
        # is not merely the input echoed back.
        assert _HIDDEN_STRING in code, "webcrack must decode the hex-escaped string"
        assert '["push"]' not in code, "webcrack must normalise bracket member access"
        assert code.strip() != raw.strip(), "output must differ from the obfuscated input"
    finally:
        service.close_all()


def _wat2wasm(wat: Path, out: Path) -> None:
    """Compile a .wat fixture with wat2wasm, or skip when wabt's builder is absent."""
    wat2wasm = shutil.which("wat2wasm")
    if wat2wasm is None:
        pytest.skip("wat2wasm (wabt) not installed — WASM Gate not run (skip != pass)")
    completed = subprocess.run(  # noqa: S603
        [wat2wasm, str(wat), "-o", str(out)], capture_output=True, text=True, timeout=60
    )
    if completed.returncode != 0 or not out.is_file():
        pytest.skip(
            f"wat2wasm could not build the fixture ({completed.returncode}) — "
            f"Gate not run (skip != pass):\n{completed.stderr[-400:]}"
        )


@pytest.mark.integration
def test_wasm_wat_and_info_on_a_real_module(tmp_path: Path) -> None:
    if not WasmClient().available:
        pytest.skip("wabt (wasm2wat) not installed — WASM Gate not run (skip != pass)")
    assert _WAT_FIXTURE.is_file(), f"fixture missing: {_WAT_FIXTURE}"
    module = tmp_path / "sample.wasm"
    _wat2wasm(_WAT_FIXTURE, module)

    service = AnalysisService()
    try:
        # wasm2wat round trips the binary back to text: the exported function,
        # its body, the constant global, and the exports must all reappear.
        wat_result = service.wasm_wat(str(module))
        assert wat_result.ok, wat_result.error
        wat = wat_result.data["wat"]
        assert "(func" in wat
        assert "i32.add" in wat
        assert '(export "add"' in wat
        assert "i32.const 42" in wat

        # wasm-objdump reports the section table and symbol details, so the
        # exported names and the function's section must show up.
        info_result = service.wasm_info(str(module))
        assert info_result.ok, info_result.error
        objdump = info_result.data["objdump"]
        assert "Export" in objdump
        assert "<add>" in objdump
        assert '-> "add"' in objdump
        assert "Code" in objdump
    finally:
        service.close_all()
