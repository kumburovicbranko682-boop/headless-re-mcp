"""Cross-validate the WASM high-entropy segment census against wabt and radare2.

describe_wasm now flags data segments whose bytes measure near-random with no
magic to explain them -- an encrypted or compressed payload staged in linear
memory for the module to inflate at runtime, which the data-payload census
cannot see because an encrypted payload opens with no magic at all. The
segment parser and the measure are both ours, so two independent tools referee
them over a module built from source text:

* wat2wasm assembles the module from a .wat, so the binary the reader parses
  is what a real toolchain emits -- and its strict validation is the
  well-formedness check;
* wasm-objdump -x lists the Data section independently (each segment's index
  and size), fixing the structure the reader claims to have walked;
* radare2's ``ph entropy`` measures the planted payload bytes on disk: the
  census's flagged entropy must equal radare2's number, rounded through the
  census's own published contract.

The module also carries a PNG-magic segment with the same random tail as the
flagged one: radare2 confirms it *is* near-random and the census must still
skip it -- the media-magic rule at work, not a missed measurement. A module
whose segments hold plain text is the negative: an empty census is the shared
answer.

wabt comes from the workflow's wabt install, radare2 from its r2 deb.
skip != pass: the gate skips, naming the missing piece, only when a referee
is unavailable.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import zlib
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.core.session import describe_wasm

_THRESHOLD = 7.2

# wasm-objdump -x prints, per segment: " - segment[N] memory=0 size=S - init ..."
_OBJDUMP_SEGMENT_RE = re.compile(r"segment\[(\d+)\].*?size=(\d+)")


def _wat_escape(data: bytes) -> str:
    return "".join(f"\\{byte:02x}" for byte in data)


def _module_wat(segments: list[bytes]) -> str:
    lines = ["(module", "  (memory 1)"]
    offset = 0
    for payload in segments:
        lines.append(f'  (data (i32.const {offset}) "{_wat_escape(payload)}")')
        offset += len(payload) + 256
    lines.append(")")
    return "\n".join(lines)


def _wat2wasm(wat2wasm: str, wat: str, tmp_path: Path, stem: str) -> Path:
    source = tmp_path / f"{stem}.wat"
    source.write_text(wat)
    module = tmp_path / f"{stem}.wasm"
    subprocess.run(
        [wat2wasm, str(source), "-o", str(module)],
        check=True,
        capture_output=True,
        timeout=120,
    )
    return module


def _objdump_segments(objdump: str, module: Path) -> dict[int, int]:
    result = subprocess.run(
        [objdump, "-x", str(module)], capture_output=True, text=True, timeout=120
    )
    assert result.returncode == 0, result.stderr
    return {
        int(match.group(1)): int(match.group(2))
        for match in _OBJDUMP_SEGMENT_RE.finditer(result.stdout)
    }


def _r2_entropy(r2: str, blob: Path) -> float:
    size = blob.stat().st_size
    result = subprocess.run(
        [r2, "-q", "-n", "-c", f"b {size}; ph entropy", str(blob)],
        capture_output=True,
        text=True,
        timeout=120,
        check=True,
    )
    return float(result.stdout.strip())


def _census(module: Path) -> tuple[list[dict[str, Any]], int]:
    info = describe_wasm(module)["wasm"]
    return info["high_entropy_segments"], info["high_entropy_segment_count"]


@pytest.mark.integration
def test_a_staged_payload_measures_like_radare2_in_a_wat2wasm_module(tmp_path: Path) -> None:
    wat2wasm = shutil.which("wat2wasm")
    if wat2wasm is None:
        pytest.skip("wat2wasm (wabt) not installed — WASM entropy gate not run (skip != pass)")
    objdump = shutil.which("wasm-objdump")
    if objdump is None:
        pytest.skip("wasm-objdump (wabt) not installed — structure referee missing (skip != pass)")
    r2 = shutil.which("r2")
    if r2 is None:
        pytest.skip("radare2 not installed — measurement referee missing (skip != pass)")

    # A real deflate stream is what a packer actually stages; the PNG decoy
    # carries the same random tail but declares itself in its magic.
    corpus = " ".join(f"record {i} value {i * i}" for i in range(4000)).encode()
    blob = zlib.compress(corpus, level=9)
    segments = [blob, b"\x89PNG\r\n\x1a\n" + blob, b"plain configuration text " * 40]
    module = _wat2wasm(wat2wasm, _module_wat(segments), tmp_path, "staged")

    # wasm-objdump fixes the structure independently: three segments, these
    # exact sizes -- the layout the census claims to have walked.
    assert _objdump_segments(objdump, module) == {
        index: len(payload) for index, payload in enumerate(segments)
    }

    flags, count = _census(module)
    assert count == 1
    (flag,) = flags
    assert flag["segment"] == 0
    assert flag["size"] == len(blob)
    # radare2 measures the same payload bytes from disk: same number, through
    # the census's own rounding.
    blob_file = tmp_path / "blob.bin"
    blob_file.write_bytes(blob)
    assert flag["entropy"] == round(_r2_entropy(r2, blob_file), 2)
    assert flag["entropy"] >= _THRESHOLD
    # The decoy is genuinely near-random -- radare2 says so -- and the census
    # still skips it: the media-magic rule at work, not a missed measurement.
    decoy_file = tmp_path / "decoy.bin"
    decoy_file.write_bytes(segments[1])
    assert _r2_entropy(r2, decoy_file) >= _THRESHOLD


@pytest.mark.integration
def test_a_module_of_plain_text_segments_is_clean(tmp_path: Path) -> None:
    wat2wasm = shutil.which("wat2wasm")
    if wat2wasm is None:
        pytest.skip("wat2wasm (wabt) not installed — WASM entropy gate not run (skip != pass)")

    wat = _module_wat([b"hello wasm data segment " * 40, b"another honest string table " * 30])
    module = _wat2wasm(wat2wasm, wat, tmp_path, "clean")
    flags, count = _census(module)
    assert flags == []
    assert count == 0
