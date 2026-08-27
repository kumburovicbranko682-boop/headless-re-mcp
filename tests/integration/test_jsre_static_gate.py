"""Live Gate for the JavaScript / WebAssembly static surface (webcrack + wabt).

The existing web gate touches these two backends only shallowly and skips both
on any machine without the CLIs: ``js.deobfuscate`` there merely asserts the
result is a non-empty string, and ``wasm.wat`` runs against an empty module and
checks the word ``module`` appears. Neither proves the tool actually transformed
anything, and ``wasm.info`` (wasm-objdump) had no coverage at all.

This gate drives the real tools end-to-end against committed fixtures and checks
recovered content a regression would visibly break:

- webcrack turns the obfuscator.io-style ``obfuscated_sample.js`` back into
  readable code -- the ``\\x48\\x33..`` escapes decode to the literal
  ``"H3adl3ss"``, bracket member access (``["push"]``) becomes dot access, and
  hex literals (``0x1a4``) become decimals -- and ``js.beautify`` is the same
  unminify. ``js.unpack_bundle`` on a non-bundle fails honestly rather than
  reporting an empty success.
- wabt's ``wasm2wat`` recovers the module text (exported ``add`` / ``checksum``,
  the memory and global) and ``wasm-objdump`` lists the section table, the
  export symbols, and the embedded data string from ``gate_module.wasm``.
- guards stay honest: a non-``\\0asm`` file is ``invalid_params``, oversized
  input is ``too_large``, and with neither a configured path nor a tool on
  ``PATH`` the surface degrades to ``capability_unavailable`` instead of
  pretending it ran.

Each capability skips independently with an explicit message when its CLI is
absent; skip is never a pass. On the Linux reference machine webcrack is on
``PATH`` (``npm i -g webcrack``, Node 22) and wabt's ``wasm2wat`` /
``wasm-objdump`` are on ``PATH`` (official wabt release).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.backends.jsre import JsClient, WasmClient
from headless_re_mcp.backends.jsre import client as jsre_client
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService

_REPO = Path(__file__).resolve().parents[2]
_JS_FIXTURE = _REPO / "fixtures" / "web" / "obfuscated_sample.js"
_WASM_FIXTURE = _REPO / "fixtures" / "web" / "gate_module.wasm"


def _service(tmp_path: Path) -> AnalysisService:
    return AnalysisService(
        Settings(
            ida_home=None,
            x64dbg_source=None,
            x64dbg_headless_x64=None,
            x64dbg_headless_x86=None,
            artifact_root=tmp_path / "artifacts",
        )
    )


def _require_webcrack() -> None:
    if not JsClient().available:
        pytest.skip("webcrack not on PATH (needs Node 22/24); skip is not a pass")


def _require_wabt() -> None:
    if not WasmClient().available:
        pytest.skip("wabt (wasm2wat/wasm-objdump) not on PATH; skip is not a pass")


def _require_fixture(path: Path) -> None:
    if not path.is_file():
        pytest.skip(f"fixture missing: {path}")


@pytest.mark.integration
def test_webcrack_deobfuscates_the_obfuscated_sample(tmp_path: Path) -> None:
    _require_webcrack()
    _require_fixture(_JS_FIXTURE)
    service = _service(tmp_path)

    result = service.js_deobfuscate(str(_JS_FIXTURE))
    assert result.ok and result.data is not None, result.error
    code = result.data["code"]
    assert isinstance(code, str) and code.strip()
    assert result.data["bytes"] > 0
    assert result.data["truncated"] is False
    # A clean pass must not carry the child-failed marker.
    assert result.data.get("tool_failed") is not True

    raw = _JS_FIXTURE.read_text()
    assert code != raw, "webcrack returned the input unchanged"

    # The hex-escaped string-array entry is decoded back to a real literal.
    assert "H3adl3ss" in code
    # Bracket member access is normalised to dot access.
    assert ".push" in code
    assert '["push"]' not in code
    # Hex numeric literals are rewritten in decimal (0x1a4 == 420).
    assert "420" in code
    assert "0x1a4" not in code


@pytest.mark.integration
def test_webcrack_beautify_is_the_same_unminify(tmp_path: Path) -> None:
    _require_webcrack()
    _require_fixture(_JS_FIXTURE)
    service = _service(tmp_path)

    beautified = service.js_beautify(str(_JS_FIXTURE))
    deobfuscated = service.js_deobfuscate(str(_JS_FIXTURE))
    assert beautified.ok and deobfuscated.ok
    assert beautified.data is not None and deobfuscated.data is not None
    # beautify() is documented to route through the same unminify pass.
    assert beautified.data["code"] == deobfuscated.data["code"]
    assert beautified.data["code"] != _JS_FIXTURE.read_text()


@pytest.mark.integration
def test_webcrack_unpack_bundle_fails_honestly_on_a_non_bundle(tmp_path: Path) -> None:
    _require_webcrack()
    _require_fixture(_JS_FIXTURE)
    service = _service(tmp_path)

    # The sample is a plain script, not a webpack/browserify bundle: unpack must
    # report a real failure, never an empty output tree reported as success.
    result = service.js_unpack_bundle(str(_JS_FIXTURE))
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "backend_error"


@pytest.mark.integration
def test_wasm_wat_recovers_the_module_text(tmp_path: Path) -> None:
    _require_wabt()
    _require_fixture(_WASM_FIXTURE)
    service = _service(tmp_path)

    result = service.wasm_wat(str(_WASM_FIXTURE))
    assert result.ok and result.data is not None, result.error
    wat = result.data["wat"]
    assert result.data["bytes"] > 0
    assert result.data["truncated"] is False
    assert result.data.get("tool_failed") is not True
    assert "(module" in wat
    # The two exported functions and their names survive the round-trip.
    assert '"add"' in wat
    assert '"checksum"' in wat
    # Memory and global definitions are present in the recovered text.
    assert "(memory" in wat
    assert "(global" in wat


@pytest.mark.integration
def test_wasm_info_lists_sections_and_symbols(tmp_path: Path) -> None:
    _require_wabt()
    _require_fixture(_WASM_FIXTURE)
    service = _service(tmp_path)

    result = service.wasm_info(str(_WASM_FIXTURE))
    assert result.ok and result.data is not None, result.error
    objdump = result.data["objdump"]
    assert result.data.get("tool_failed") is not True
    # wasm-objdump -h -x prints a section table; the fixture has all of these.
    for section in ("Type", "Function", "Memory", "Global", "Export", "Code", "Data"):
        assert section in objdump, f"objdump missing section {section}:\n{objdump[:400]}"
    # Export symbols and the embedded data string are recovered by name.
    assert "add" in objdump
    assert "checksum" in objdump
    assert "answer" in objdump
    assert "H3adl3ss-wasm" in objdump


@pytest.mark.integration
def test_wasm_tools_reject_a_non_wasm_file(tmp_path: Path) -> None:
    _require_wabt()
    service = _service(tmp_path)

    not_wasm = tmp_path / "not_a_module.bin"
    not_wasm.write_bytes(b"MZ\x90\x00 this is clearly not a wasm module")

    wat = service.wasm_wat(str(not_wasm))
    assert wat.ok is False and wat.error is not None
    assert wat.error.code == "invalid_params"

    info = service.wasm_info(str(not_wasm))
    assert info.ok is False and info.error is not None
    assert info.error.code == "invalid_params"


@pytest.mark.integration
def test_wasm_wat_refuses_oversized_input(tmp_path: Path) -> None:
    _require_wabt()
    service = _service(tmp_path)

    # Valid magic, but past the 16 MiB input cap: size is checked before the
    # tool is launched, so this returns too_large rather than running wasm2wat.
    big = tmp_path / "big.wasm"
    with big.open("wb") as handle:
        handle.write(b"\x00asm\x01\x00\x00\x00")
        handle.truncate(17 * 1024 * 1024)

    result = service.wasm_wat(str(big))
    assert result.ok is False and result.error is not None
    assert result.error.code == "too_large"


@pytest.mark.integration
def test_jsre_degrades_to_capability_unavailable_without_tools(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _require_fixture(_JS_FIXTURE)
    _require_fixture(_WASM_FIXTURE)
    # Neither a configured path (Settings defaults are None) nor a PATH lookup
    # finds a tool: the surface must say capability_unavailable, not error out
    # as if the input were the problem.
    monkeypatch.setattr(jsre_client, "_discover_webcrack", lambda: None)
    monkeypatch.setattr(jsre_client.shutil, "which", lambda _name: None)
    service = _service(tmp_path)

    js = service.js_deobfuscate(str(_JS_FIXTURE))
    assert js.ok is False and js.error is not None
    assert js.error.code == "capability_unavailable"

    wat = service.wasm_wat(str(_WASM_FIXTURE))
    assert wat.ok is False and wat.error is not None
    assert wat.error.code == "capability_unavailable"
