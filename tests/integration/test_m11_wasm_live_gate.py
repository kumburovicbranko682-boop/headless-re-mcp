"""M11 WASM live gate: wasm2wat / wasm-objdump against a real module.

The jsre WASM path (wabt) had no live coverage: the unit tests mock the CLI, so
a wabt whose wasm2wat / wasm-objdump output drifted would pass them while the
real tool returned something the client mishandled. This drives both tools
against a tiny embedded module -- an exported ``add`` function plus a memory --
and asserts the WAT round-trips with that export and the objdump lists the
sections. Portable: it resolves wabt from settings/PATH exactly as the service
does and skips (skip != pass) when wabt is absent.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.backends.jsre import WasmClient
from headless_re_mcp.config import Settings

# wat2wasm of:
#   (module
#     (func $add (export "add") (param i32 i32) (result i32)
#       local.get 0
#       local.get 1
#       i32.add)
#     (memory (export "mem") 1))
# Embedded as bytes so the gate needs only wasm2wat/wasm-objdump, not wat2wasm.
_WASM = bytes.fromhex(
    "0061736d0100000001070160027f7f017f030201000503010001"
    "070d02036164640000036d656d02000a09010700200020016a0b"
)


def _wasm_client() -> WasmClient:
    return WasmClient(getattr(Settings.load(), "wabt", None))


@pytest.mark.integration
def test_m11_wasm_live_wat_and_objdump(tmp_path: Path) -> None:
    client = _wasm_client()
    if not client.available:
        pytest.skip("wabt (wasm2wat) not installed/configured — WASM Gate not run (skip != pass)")
    fixture = tmp_path / "module.wasm"
    fixture.write_bytes(_WASM)

    wat = client.wat(fixture)
    assert wat.get("truncated") is False
    # A clean module must not be flagged as a tool failure.
    assert "tool_failed" not in wat
    text = wat["wat"]
    assert "(module" in text
    assert 'export "add"' in text
    assert "i32.add" in text

    # wasm-objdump ships alongside wasm2wat in a real wabt install; a partial
    # PATH with only wasm2wat still exercises the wat path above.
    if client._objdump is not None:
        info = client.info(fixture)
        assert "tool_failed" not in info
        dump = info["objdump"]
        assert "Export" in dump
        assert "add" in dump
        # -h lists section headers and -x expands them; Type and Code prove the
        # section walk parsed rather than only the file header being read.
        assert "Type" in dump
        assert "Code" in dump
