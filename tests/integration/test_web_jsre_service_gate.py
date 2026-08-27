"""Web static gate: the js.*/wasm.* service surface end to end through the service.

The existing JS/WASM gates prove the backends: the deobfuscate gate feeds a real
obfuscator.io payload to JsClient directly, the objdump/static-chain gates drive
WasmClient directly, and the bundle-graph gate is the only one that reaches
AnalysisService (js.unpack_bundle). The other four service endpoints --
js.deobfuscate, js.beautify, wasm.wat, wasm.info -- are exercised only by unit
tests with a mocked run_bounded. So the service plumbing on those paths is
unproven end to end: config-resolved executables (Settings.webcrack / .wabt)
actually running, the ok/data/meta envelope with its backend label, and
JsReError codes crossing _as_rpc into the envelope intact rather than being
reclassified as internal_error.

This gate drives AnalysisService with the real tools and asserts:

- js.deobfuscate decodes, not merely reformats: a compact script whose member
  access and payload string are hex-escaped comes back with console.log and the
  plain "H3adl3ss-svc" literal and 1+0x2 folded to 3 -- through the envelope,
  labelled backend "webcrack", with the bounded-output bytes/truncated fields,
- js.beautify (the same webcrack pass under a formatting name) does likewise,
- wasm.wat and wasm.info render / structure a wat2wasm-assembled module through
  the envelope, labelled backend "wabt",
- the error contracts cross _as_rpc at the service layer: a missing path is
  not_found, a non-wasm file handed to wasm.wat is backend_error (never
  internal_error), and an input past the byte cap is too_large -- refused
  before the child is launched.

Each half skips honestly when its CLI is missing (webcrack needs Node; wabt
needs wat2wasm/wasm2wat/wasm-objdump). skip != pass.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import replace
from pathlib import Path

import pytest

from headless_re_mcp.backends.jsre import JsClient, WasmClient
from headless_re_mcp.backends.jsre.client import _MAX_INPUT_BYTES
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService

# Member access and payload string are hex-escaped, and the arithmetic is
# unfolded: none of "console.log", "H3adl3ss-svc" or "3" appear as plaintext,
# so recovering them proves decoding rather than reformatting.
_MARKER = "H3adl3ss-svc"
_OBFUSCATED = (
    "function reveal(){var s=console['\\x6c\\x6f\\x67'];"
    "s('H3adl3ss\\x2dsvc');return 1+0x2;}reveal();"
)

_WAT = """(module
  (memory (export "memory") 1)
  (func $add (export "add") (param i32 i32) (result i32)
    local.get 0
    local.get 1
    i32.add)
)
"""


def _settings(tmp_path: Path) -> Settings:
    return replace(Settings.load(), artifact_root=tmp_path / "artifacts")


def _assemble(dest: Path) -> Path | None:
    wat2wasm = shutil.which("wat2wasm")
    if wat2wasm is None:
        return None
    wat_path = dest / "module.wat"
    wat_path.write_text(_WAT, encoding="utf-8")
    wasm_path = dest / "module.wasm"
    try:
        subprocess.run(
            [wat2wasm, str(wat_path), "-o", str(wasm_path)],
            check=True,
            capture_output=True,
            timeout=60.0,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
        return None
    return wasm_path if wasm_path.is_file() else None


@pytest.mark.integration
def test_web_js_service_deobfuscates_and_maps_errors(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    if not JsClient(getattr(settings, "webcrack", None)).available:
        pytest.skip("webcrack not installed (needs Node) — skip != pass")

    source = tmp_path / "obf.js"
    source.write_text(_OBFUSCATED, encoding="utf-8")
    # The fixture really is escaped: the recovered forms are absent as plaintext.
    assert "console.log" not in _OBFUSCATED and _MARKER not in _OBFUSCATED

    service = AnalysisService(settings)
    try:
        deob = service.js_deobfuscate(str(source))
        assert deob.ok and deob.data is not None, deob.error
        assert deob.meta.get("backend") == "webcrack"
        code = str(deob.data["code"])
        # Decoded, not reformatted: hidden string, member access and folded
        # constant all recovered.
        assert _MARKER in code, code
        assert "console.log" in code, code
        assert "\\x6c" not in code and "\\x2d" not in code, code
        assert "return 3" in code, code
        # Bounded-output companions survive the envelope.
        assert deob.data["truncated"] is False
        assert int(deob.data["bytes"]) == len(code.encode("utf-8"))

        # beautify is the same pass under a formatting name; the marker survives.
        beaut = service.js_beautify(str(source))
        assert beaut.ok and beaut.data is not None, beaut.error
        assert beaut.meta.get("backend") == "webcrack"
        assert _MARKER in str(beaut.data["code"])

        # A missing path is not_found through _as_rpc, not internal_error.
        missing = service.js_deobfuscate(str(tmp_path / "nope.js"))
        assert missing.ok is False and missing.error is not None
        assert missing.error.code == "not_found", missing.error

        # An input past the byte cap is too_large, refused before node launches.
        big = tmp_path / "big.js"
        with big.open("wb") as sink:
            sink.truncate(_MAX_INPUT_BYTES + 1)
        oversized = service.js_deobfuscate(str(big))
        assert oversized.ok is False and oversized.error is not None
        assert oversized.error.code == "too_large", oversized.error
        assert oversized.error.details.get("max_file_size") == _MAX_INPUT_BYTES
    finally:
        service.close_all()


@pytest.mark.integration
def test_web_wasm_service_disassembles_and_maps_errors(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    if not WasmClient(getattr(settings, "wabt", None)).available:
        pytest.skip("wabt (wasm2wat) not installed — skip != pass")
    if shutil.which("wasm-objdump") is None:
        pytest.skip("wabt wasm-objdump not installed — skip != pass")
    module = _assemble(tmp_path)
    if module is None:
        pytest.skip("wat2wasm missing — cannot assemble the WASM fixture (skip != pass)")

    service = AnalysisService(settings)
    try:
        wat = service.wasm_wat(str(module))
        assert wat.ok and wat.data is not None, wat.error
        assert wat.meta.get("backend") == "wabt"
        wat_text = str(wat.data["wat"])
        assert "(module" in wat_text and '(export "add"' in wat_text, wat_text
        assert "(param i32 i32) (result i32)" in wat_text, wat_text
        assert int(wat.data["bytes"]) == len(wat_text.encode("utf-8"))
        assert wat.data["truncated"] is False

        info = service.wasm_info(str(module))
        assert info.ok and info.data is not None, info.error
        assert info.meta.get("backend") == "wabt"
        dump = str(info.data["objdump"])
        assert "file format wasm" in dump, dump
        assert '"add"' in dump and '"memory"' in dump, dump

        # A missing path is not_found through _as_rpc.
        missing = service.wasm_wat(str(tmp_path / "nope.wasm"))
        assert missing.ok is False and missing.error is not None
        assert missing.error.code == "not_found", missing.error

        # A file that is not WASM makes wasm2wat fail: the service must report
        # backend_error, never internal_error with a logged incident.
        junk = tmp_path / "not.wasm"
        junk.write_bytes(b"this is definitely not a wasm module\n" * 4)
        broken = service.wasm_wat(str(junk))
        assert broken.ok is False and broken.error is not None
        assert broken.error.code == "backend_error", broken.error
    finally:
        service.close_all()
