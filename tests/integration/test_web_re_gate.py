"""Web RE gate: CDP browser driving, plus webcrack / wabt when configured.

Each capability skips independently with an explicit "skip != pass" message when
its backend is unavailable, so the gate is honest on a bare machine and real
when Chrome / webcrack / wabt are present.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from headless_re_mcp.backends.jsre import JsClient, WasmClient
from headless_re_mcp.backends.web import WebBackend
from headless_re_mcp.config import Settings
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
        # Prove webcrack actually deobfuscated rather than echoing the input:
        # the fixture hides "H3adl3ss" as the escape sequence \x48\x33..., which
        # only reads back decoded if the string array was resolved, and rewrites
        # bracket-notation member access like ["push"] to plain .push.
        assert "H3adl3ss" in code
        assert "\\x48" not in code
        assert '["push"]' not in code
    finally:
        service.close_all()


# A hand-rolled webpack runtime with two modules: the entry logs the result of
# calling the second module's exported greeter. webcrack recognises the runtime
# and splits it back into per-module files.
_WEBPACK_BUNDLE = """(function (modules) {
  var installedModules = {};
  function __webpack_require__(moduleId) {
    if (installedModules[moduleId]) return installedModules[moduleId].exports;
    var module = (installedModules[moduleId] = { i: moduleId, l: false, exports: {} });
    modules[moduleId].call(module.exports, module, module.exports, __webpack_require__);
    module.l = true;
    return module.exports;
  }
  return __webpack_require__(0);
})([
  function (module, exports, __webpack_require__) {
    var greet = __webpack_require__(1);
    console.log(greet("world"));
  },
  function (module, exports) {
    module.exports = function (name) {
      return "hello " + name;
    };
  },
]);
"""


@pytest.mark.integration
def test_js_unpack_bundle_splits_a_webpack_bundle(tmp_path: Path) -> None:
    if not JsClient().available:
        pytest.skip("webcrack not installed — JS bundle Gate not run (skip != pass)")
    bundle = tmp_path / "bundle.js"
    bundle.write_text(_WEBPACK_BUNDLE, encoding="utf-8")
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    try:
        result = service.js_unpack_bundle(str(bundle))
        # This is the leg that regressed: the client pre-creates the output dir,
        # and without --force webcrack 2.x refuses it and the call fails.
        assert result.ok, result.error
        assert result.data["file_count"] >= 2
        out_dir = Path(result.data["output_dir"])
        carriers = [
            path for path in out_dir.rglob("*.js") if "hello " in path.read_text(encoding="utf-8")
        ]
        assert carriers, "no unpacked module carried the bundled function body"
    finally:
        service.close_all()


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
