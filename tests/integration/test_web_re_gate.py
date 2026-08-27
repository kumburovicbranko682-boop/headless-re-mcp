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
        # The fixture hides "H3adl3ss" behind a rotated array of \x-escaped
        # strings and reaches members through _0xarr["split"] indirection.
        # Deobfuscation that actually ran restores the literal and the plain
        # member names; a pass that merely reprinted the source would not.
        assert "H3adl3ss" in code, code
        for member in ("charCodeAt", "split", "reduce"):
            assert member in code, code
    finally:
        service.close_all()


def _assemble_wasm(tmp_path: Path) -> Path | None:
    """Assemble a one-function module with wat2wasm, or None if it is absent."""
    wat2wasm = shutil.which("wat2wasm")
    if wat2wasm is None:
        return None
    wat = tmp_path / "add.wat"
    wat.write_text(
        '(module (func $add (export "add") '
        "(param i32 i32) (result i32) local.get 0 local.get 1 i32.add))",
        encoding="utf-8",
    )
    module = tmp_path / "add.wasm"
    try:
        subprocess.run(
            [wat2wasm, str(wat), "-o", str(module)],
            check=True,
            capture_output=True,
            timeout=60.0,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
        return None
    return module if module.is_file() else None


@pytest.mark.integration
def test_wasm_wat_when_wabt_present(tmp_path: Path) -> None:
    if not WasmClient().available:
        pytest.skip("wabt (wasm2wat) not installed — WASM Gate not run (skip != pass)")
    # The smallest valid module: magic + version, no sections.
    module = tmp_path / "empty.wasm"
    module.write_bytes(b"\x00asm\x01\x00\x00\x00")
    service = AnalysisService()
    try:
        result = service.wasm_wat(str(module))
        assert result.ok, result.error
        assert "module" in result.data["wat"]
    finally:
        service.close_all()


@pytest.mark.integration
def test_wasm_wat_and_info_recover_a_real_function(tmp_path: Path) -> None:
    if not WasmClient().available:
        pytest.skip("wabt (wasm2wat) not installed — WASM Gate not run (skip != pass)")
    module = _assemble_wasm(tmp_path)
    if module is None:
        pytest.skip("wat2wasm not available to assemble a fixture — skip != pass")
    service = AnalysisService()
    try:
        wat = service.wasm_wat(str(module))
        assert wat.ok, wat.error
        text = wat.data["wat"]
        # The disassembly must show the function, its export, and the opcode --
        # not just that the file parsed as a module.
        assert "(func" in text
        assert "i32.add" in text
        assert "add" in text

        info = service.wasm_info(str(module))
        assert info.ok, info.error
        dump = info.data["objdump"]
        # wasm-objdump enumerates the sections and resolves the export name.
        assert "Type" in dump
        assert "Export" in dump
        assert "add" in dump
    finally:
        service.close_all()
