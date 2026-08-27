"""wasm.summary gate: the pure-Python parser driven through the real service.

wasm.summary needs no external tool, so the service-level test here always runs
-- it builds a valid module by hand (the same technique the wabt spill gate
trusts) and drives ``AnalysisService.wasm_summary`` end to end, proving both the
success envelope carries the structured surface and a non-module comes back as
an ``invalid_params`` envelope rather than an internal error. A second test
cross-checks against a genuinely toolchain-built module when wat2wasm is
installed, and skips with "skip != pass" when it is not.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from headless_re_mcp.core.service import AnalysisService


def _leb128(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def _vec(items: list[bytes]) -> bytes:
    return _leb128(len(items)) + b"".join(items)


def _name(text: str) -> bytes:
    raw = text.encode("utf-8")
    return _leb128(len(raw)) + raw


def _section(section_id: int, body: bytes) -> bytes:
    return bytes([section_id]) + _leb128(len(body)) + body


def _module_with_surface() -> bytes:
    """A section-framed module with an imported func, exports and a memory."""
    magic = b"\x00asm\x01\x00\x00\x00"
    type_sec = _section(1, _vec([b"\x60\x00\x00"]))
    import_sec = _section(
        2, _vec([_name("env") + _name("log") + b"\x00" + _leb128(0)])
    )
    func_sec = _section(3, _vec([_leb128(0)]))
    mem_sec = _section(5, _vec([b"\x01" + _leb128(4) + _leb128(64)]))
    export_sec = _section(
        7,
        _vec(
            [
                _name("run") + b"\x00" + _leb128(1),
                _name("mem") + b"\x02" + _leb128(0),
            ]
        ),
    )
    return magic + type_sec + import_sec + func_sec + mem_sec + export_sec


def _find(items: list[dict], **fields: object) -> dict | None:
    for item in items:
        if all(item.get(key) == value for key, value in fields.items()):
            return item
    return None


@pytest.mark.integration
def test_wasm_summary_drives_the_service_end_to_end(tmp_path: Path) -> None:
    module = tmp_path / "surface.wasm"
    module.write_bytes(_module_with_surface())

    service = AnalysisService()
    try:
        result = service.wasm_summary(str(module))
        assert result.ok, result.error
        data = result.data
        assert data is not None
        assert _find(data["imports"], module="env", name="log", kind="func") is not None
        assert _find(data["exports"], name="run", kind="func") is not None
        assert _find(data["exports"], name="mem", kind="memory") is not None
        assert data["memory"] == {"initial": 4, "maximum": 64}
        assert data["counts"]["imported_functions"] == 1
        assert data["counts"]["functions"] == 1

        # A file that is not a module must come back as a clean error envelope,
        # not an internal error: this is the hostile-input contract the whole
        # tool surface holds to.
        bogus = tmp_path / "not.wasm"
        bogus.write_bytes(b"PK\x03\x04 this is a zip, not wasm")
        failed = service.wasm_summary(str(bogus))
        assert failed.ok is False
        assert failed.error is not None
        assert failed.error.code == "invalid_params"
    finally:
        service.close_all()


@pytest.mark.integration
def test_wasm_summary_reads_a_wat2wasm_built_module(tmp_path: Path) -> None:
    """Cross-check the parser against a module a real toolchain produced."""
    wat2wasm = shutil.which("wat2wasm")
    if wat2wasm is None:
        pytest.skip("wat2wasm (wabt) not installed — toolchain gate not run (skip != pass)")
    wat = tmp_path / "mod.wat"
    wat.write_text(
        "(module\n"
        '  (import "env" "log" (func $log (param i32)))\n'
        '  (import "js" "flag" (global $flag i32))\n'
        '  (memory (export "mem") 2 16)\n'
        '  (func (export "run") (param i32) (result i32) local.get 0)\n'
        "  (func $init)\n"
        "  (start $init))\n",
        encoding="utf-8",
    )
    module = tmp_path / "mod.wasm"
    built = subprocess.run(  # noqa: S603 - fixed argv, tool discovered on PATH
        [wat2wasm, str(wat), "-o", str(module)],
        capture_output=True,
        timeout=60,
    )
    if built.returncode != 0 or not module.is_file():
        detail = built.stderr.decode("utf-8", "replace")[:200]
        pytest.skip(f"wat2wasm could not build the fixture ({detail}) — skip != pass")

    service = AnalysisService()
    try:
        result = service.wasm_summary(str(module))
        assert result.ok, result.error
        data = result.data
        assert data is not None
        assert _find(data["imports"], module="env", name="log", kind="func") is not None
        assert _find(data["imports"], module="js", name="flag", kind="global") is not None
        assert _find(data["exports"], name="run", kind="func") is not None
        assert _find(data["exports"], name="mem", kind="memory") is not None
        assert data["memory"] == {"initial": 2, "maximum": 16}
        assert data["has_start"] is True
        # One function is imported; the two defined ($run, $init) come from the
        # module's own function section.
        assert data["counts"]["imported_functions"] == 1
        assert data["counts"]["functions"] == 2
    finally:
        service.close_all()
