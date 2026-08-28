"""Cross-validate the WASM data-segment payload census against wabt.

describe_wasm lists data segments whose bytes open with executable/container
magic -- a module carrying a PE/ELF/DEX/ZIP (or a nested WASM) in its linear
memory, the dropper shape that copies the segment out for the host to run.
The segment parser (mode flags, offset expressions, byte vectors) and the
magic table are both ours, so two wabt tools referee them over a module built
from source text, not a hand-packed fixture:

* wat2wasm assembles the module from a .wat, so the binary the reader parses
  is what a real toolchain emits;
* wasm-objdump -x lists the Data section independently -- each segment's index
  and size -- and disassembles the payloads. The reader's census must name the
  same segments wasm-objdump shows carrying executable magic, with the same
  sizes, and stay silent on the benign segment wasm-objdump also shows.

skip != pass: the gate skips, naming the missing piece, only when wat2wasm or
wasm-objdump is absent (CI installs wabt for the JS/WASM gates).
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

from headless_re_mcp.core.session import describe_wasm

# wasm-objdump -x prints, per segment: " - segment[N] memory=0 size=S - init ..."
_OBJDUMP_SEGMENT_RE = re.compile(r"segment\[(\d+)\].*?size=(\d+)")


def _wat_escape(data: bytes) -> str:
    return "".join(f"\\{byte:02x}" for byte in data)


def _dropper_wat() -> tuple[str, dict[int, tuple[str, int]]]:
    """A module with four executable-magic segments and one benign segment.

    Returns the .wat text and the expected {segment_index: (kind, size)} for
    the flagged segments (the benign one is deliberately absent).
    """
    pe = b"MZ" + b"\x90" * 62
    elf = b"\x7fELF" + b"\x00" * 12
    nested_wasm = b"\x00asm\x01\x00\x00\x00"
    dex = b"dex\n035\x00" + b"\x00" * 8
    benign = b"benign configuration payload, nothing to run here"
    segments = [
        (0, pe, "pe"),
        (256, elf, "elf"),
        (512, nested_wasm, "wasm"),
        (768, dex, "dex"),
        (1024, benign, None),
    ]
    lines = ["(module", "  (memory 1)"]
    expected: dict[int, tuple[str, int]] = {}
    for index, (offset, payload, kind) in enumerate(segments):
        lines.append(f'  (data (i32.const {offset}) "{_wat_escape(payload)}")')
        if kind is not None:
            expected[index] = (kind, len(payload))
    lines.append(")")
    return "\n".join(lines), expected


def _objdump_segments(objdump: str, wasm: Path) -> dict[int, int]:
    result = subprocess.run(
        [objdump, "-x", str(wasm)], capture_output=True, text=True, timeout=120
    )
    assert result.returncode == 0, result.stderr
    sizes: dict[int, int] = {}
    for match in _OBJDUMP_SEGMENT_RE.finditer(result.stdout):
        sizes[int(match.group(1))] = int(match.group(2))
    return sizes


@pytest.mark.integration
def test_wasm_data_payload_census_agrees_with_wabt(tmp_path: Path) -> None:
    wat2wasm = shutil.which("wat2wasm")
    if wat2wasm is None:
        pytest.skip("wabt (wat2wasm) not installed — WASM payload gate not run (skip != pass)")
    objdump = shutil.which("wasm-objdump")
    if objdump is None:
        pytest.skip("wabt (wasm-objdump) not installed — WASM payload gate not run (skip != pass)")

    wat_text, expected = _dropper_wat()
    wat_path = tmp_path / "dropper.wat"
    wat_path.write_text(wat_text, encoding="utf-8")
    wasm_path = tmp_path / "dropper.wasm"
    build = subprocess.run(
        [wat2wasm, str(wat_path), "-o", str(wasm_path)],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert build.returncode == 0, build.stderr

    # wabt's independent view of every data segment and its size.
    objdump_sizes = _objdump_segments(objdump, wasm_path)
    assert len(objdump_sizes) == 5, objdump_sizes

    # The reader's census over the same module.
    info = describe_wasm(wasm_path)["wasm"]
    census = {entry["segment"]: (entry["kind"], entry["size"]) for entry in info["data_payloads"]}

    # The reader flags exactly the executable-magic segments -- not the benign
    # one -- and its kinds and sizes match wabt's per-segment sizes.
    assert census == expected
    assert info["data_payload_count"] == len(expected)
    for index, (_kind, size) in expected.items():
        assert objdump_sizes[index] == size, (index, objdump_sizes[index], size)

    # The benign segment exists in wabt's listing but the reader stayed silent
    # on it -- the census is the lie about *contents*, not a segment count.
    benign_index = 4
    assert benign_index in objdump_sizes
    assert benign_index not in census
