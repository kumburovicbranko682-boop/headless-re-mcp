"""r2.xrefs live gate: the answer must be about the queried address.

The shipped ``axj @ addr`` ignored the seek, so r2.xrefs returned the
program's entire xref table for every address (measured on r2 5.5.0: the
identical 820-entry list for the entry point and for 0x1). No unit test can
catch that class of bug -- they fake the r2 process and encode whatever
command contract the author believed -- so this gate compiles a two-function
program, asks radare2 for the callee's xrefs, and checks the answer actually
involves the callee. skip != pass when r2 or a C compiler is missing.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from headless_re_mcp.backends.r2.client import R2Client

_SOURCE = """
int callee(int value) { return value + 1; }
int main(void) { return callee(41); }
"""


def _compile_fixture(tmp_path: Path) -> Path:
    compiler = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if compiler is None:
        pytest.skip("no C compiler — r2 xrefs live Gate not run (skip != pass)")
    source = tmp_path / "callgraph.c"
    source.write_text(_SOURCE, encoding="utf-8")
    binary = tmp_path / "callgraph.bin"
    built = subprocess.run(
        [compiler, "-O0", "-o", str(binary), str(source)],
        capture_output=True,
        text=True,
        timeout=120,
    )
    if built.returncode != 0:
        pytest.skip(f"fixture did not compile: {built.stderr[:200]}")
    return binary


@pytest.mark.integration
def test_r2_xrefs_answers_about_the_queried_address(tmp_path: Path) -> None:
    client = R2Client()
    if not client.available:
        pytest.skip("radare2/rizin not installed — live Gate not run (skip != pass)")
    binary = _compile_fixture(tmp_path)

    functions = client.run(binary, ["aa", "aflj"], timeout=60.0)
    assert functions.get("parsed") is True, functions.get("raw", "")[:200]
    callee = next(
        (
            item
            for item in functions.get("items", [])
            if str(item.get("name", "")).endswith("callee")
        ),
        None,
    )
    assert callee is not None, [item.get("name") for item in functions.get("items", [])]
    callee_va = callee.get("offset")
    assert isinstance(callee_va, int)

    payload = client.xrefs(binary, callee_va, timeout=60.0)
    assert payload.get("parsed") is True
    items = payload.get("items", [])
    assert items, "main calls callee; radare2 must report at least that ref"

    # Every item must touch the queried address. With the whole-table bug the
    # list also carried refs between unrelated libc stubs, which fails here.
    for item in items:
        assert callee_va in (item.get("from"), item.get("to")), item

    # And the incoming call from main is among them, endpoints mapped.
    incoming = [item for item in items if item.get("to") == callee_va]
    assert incoming, items
    assert any(item.get("from") != callee_va for item in incoming)
    assert incoming[0].get("to_address", {}).get("va") == callee_va
