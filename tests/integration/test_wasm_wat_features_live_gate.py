"""wasm.wat live gate: a real post-MVP module decodes instead of bailing.

The bug: ``WasmClient.wat`` used to run ``wasm2wat`` with no feature flags, so
wasm2wat parsed only the MVP subset and exited with "unexpected opcode" on the
first post-MVP feature -- tail calls, exceptions, threads, GC, memory64, all off
by default in wabt and all common in emscripten / Rust / Kotlin output that a
reverse engineer captures. The fix passes ``--enable-all``.

This gate builds a real module that uses an off-by-default feature (with
``wat2wasm``), proves plain ``wasm2wat`` rejects it (so a pass means the flag did
the work, not that the feature happened to be MVP), then drives the real
``WasmClient`` and asserts it returns the decoded WAT. skip != pass: it skips
only when wabt is genuinely absent.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from headless_re_mcp.backends.jsre.client import WasmClient

# (name, wat2wasm flag, source using the feature, a token the decoded WAT keeps).
# All are off by default in wabt; the gate uses the first one this wabt can both
# assemble and then reject without the flag.
_CANDIDATES: tuple[tuple[str, str, str, str], ...] = (
    (
        "tail-call",
        "--enable-tail-call",
        '(module (func $g (result i32) i32.const 42)'
        ' (func $f (result i32) return_call $g) (export "f" (func $f)))',
        "return_call",
    ),
    (
        "exceptions",
        "--enable-exceptions",
        '(module (tag $e (param i32)) (func $f i32.const 5 throw $e)'
        ' (export "f" (func $f)))',
        "throw",
    ),
    (
        "memory64",
        "--enable-memory64",
        '(module (memory i64 1))',
        "i64",
    ),
)


def _plain_wasm2wat_rejects(wasm2wat: str, module: Path) -> bool:
    """True when wasm2wat with no feature flags fails to parse the module."""
    completed = subprocess.run(
        [wasm2wat, str(module)],
        capture_output=True,
        timeout=30,
        check=False,
    )
    return completed.returncode != 0


@pytest.mark.integration
def test_wasm_wat_decodes_a_real_post_mvp_module(tmp_path: Path) -> None:
    wasm2wat = shutil.which("wasm2wat")
    wat2wasm = shutil.which("wat2wasm")
    if not wasm2wat or not wat2wasm:
        pytest.skip("wabt (wasm2wat/wat2wasm) not installed — feature Gate not run (skip != pass)")

    # Find a feature this wabt builds AND plain wasm2wat rejects, so the gate
    # demonstrates the flag rather than a coincidence. A future wabt that made
    # every candidate default would leave none -- then the flag is a proven
    # no-op here and the gate honestly has nothing to assert.
    chosen: tuple[str, str] | None = None
    module = tmp_path / "feature.wasm"
    for name, flag, source, token in _CANDIDATES:
        wat_path = tmp_path / f"{name}.wat"
        wat_path.write_text(source, encoding="utf-8")
        built = subprocess.run(
            [wat2wasm, flag, str(wat_path), "-o", str(module)],
            capture_output=True,
            timeout=30,
            check=False,
        )
        if built.returncode != 0 or not module.is_file():
            continue
        if _plain_wasm2wat_rejects(wasm2wat, module):
            chosen = (name, token)
            break
    if chosen is None:
        pytest.skip(
            "this wabt assembles no off-by-default feature that plain wasm2wat rejects — "
            "--enable-all is a proven no-op here (skip != pass)"
        )
    name, token = chosen

    # Sanity: the module really is a WebAssembly module the client will accept.
    assert module.read_bytes()[:4] == b"\x00asm"

    payload = WasmClient().wat(module, timeout=60.0)

    # The fix: wasm2wat ran with --enable-all, so the feature module decoded to
    # WAT text instead of failing with "unexpected opcode".
    assert payload.get("tool_failed") is not True, payload.get("stderr")
    wat_text = str(payload.get("wat") or "")
    assert wat_text.startswith("(module"), wat_text[:200]
    assert token in wat_text, f"decoded WAT for {name} lacked {token!r}: {wat_text[:200]}"
