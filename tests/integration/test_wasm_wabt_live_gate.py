"""wabt live gate: wasm.wat / wasm.info over the real wasm2wat & wasm-objdump.

Every wasm.* test mocks ``run_bounded`` -- the backend has never run real wabt.
That leaves the load-bearing CLI contract unverified: wasm.wat reads the text
form from ``wasm2wat``'s stdout, and wasm.info reads section/detail output from
``wasm-objdump -h -x``'s stdout. Both are version-sensitive wabt behaviors -- a
CLI change (output moved to a file, a renamed flag, a required ``-o``) would
pass every mock-based test and only break against the real tools, exactly the
class of runtime-only break that bit js.unpack_bundle's ``-o`` handling.

The fixture ``fixtures/wasm/gate_sample.wasm`` is built once and committed (like
the APK fixtures) so the gate depends only on the tools under test, not on
``wat2wasm``. It was produced with::

    wat2wasm m.wat -o gate_sample.wasm

from a module exporting a memory ``mem``, a function ``add_marker`` (i32,i32)->i32
that adds its two params, and a global ``answer`` = i32 42. The gate asserts the
real tools decoded exactly those facts. It also pins that a non-wasm input is
refused as invalid_params before either tool is launched.

Skip != pass: the gate skips with a reason when wabt is absent and runs for real
when present. CI installs it (apt wabt), so a skip there is a genuine regression.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.backends.jsre import JsReError, WasmClient

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_FIXTURE = _PROJECT_ROOT / "fixtures" / "wasm" / "gate_sample.wasm"


def _wabt_or_skip() -> WasmClient:
    client = WasmClient()
    if not client.available:
        pytest.skip("wabt (wasm2wat) not on PATH — WASM Gate not run (skip != pass)")
    assert _FIXTURE.is_file(), f"fixture missing: {_FIXTURE}"
    return client


@pytest.mark.integration
def test_wasm_wat_reads_real_wasm2wat_stdout() -> None:
    client = _wabt_or_skip()
    data = client.wat(_FIXTURE, timeout=120.0)

    wat = data["wat"]
    assert wat, "wasm2wat emitted no text on stdout"
    assert "tool_failed" not in data, data.get("stderr")
    assert data["truncated"] is False
    assert data["bytes"] == len(wat.encode("utf-8"))
    # The text form names the module and the facts we compiled in.
    assert "(module" in wat
    assert "add_marker" in wat
    assert "answer" in wat
    assert "i32.add" in wat


@pytest.mark.integration
def test_wasm_info_reads_real_objdump_stdout() -> None:
    client = _wabt_or_skip()
    data = client.info(_FIXTURE, timeout=120.0)

    dump = data["objdump"]
    assert dump, "wasm-objdump emitted no text on stdout"
    assert "tool_failed" not in data, data.get("stderr")
    assert data["truncated"] is False
    # -h prints the section table; -x prints the details, including our export.
    assert "Sections:" in dump
    assert "Export" in dump
    assert "add_marker" in dump


@pytest.mark.integration
def test_non_wasm_input_is_refused_before_launching_the_tool(tmp_path: Path) -> None:
    client = _wabt_or_skip()
    bogus = tmp_path / "not.wasm"
    bogus.write_bytes(b"MZ\x90\x00not a wasm module")
    with pytest.raises(JsReError) as caught:
        client.wat(bogus, timeout=120.0)
    assert caught.value.code == "invalid_params"
