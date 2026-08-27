"""M11 r2 data xrefs gate: axtj answers "who references this string".

The targeted-xref gates so far seek to *function* entries and assert the inbound
CALL edges, so the data side of axtj is unproven: the single most common triage
move -- "find every place this suspicious string is used" -- runs xrefs_to on a
string's address and expects DATA references, not calls. This gate compiles an
ELF where one string literal is loaded from two different functions, locates the
literal with izj, and asserts xrefs_to(string) returns exactly those two DATA
edges, each an address load (lea) inside its enclosing function's body.

It also seeks xrefs_to at a *function* in the same binary and gets a CALL edge
instead -- proving the reference type is driven by what the target is (a string
vs a function), not by the tool. skip != pass when radare2/rizin or a C compiler
is missing.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.r2.client import R2Client

_MARKER = "r2-dataxref-secret-3e9f"
# The same literal is referenced from two functions; the compiler merges the two
# occurrences into one .rodata string, so each function's lea is a DATA xref to
# that single address -- exactly the "who uses this string" question.
_SRC = r"""
#include <stdio.h>
#include <string.h>

__attribute__((noinline))
int alpha(void) { return puts("r2-dataxref-secret-3e9f"); }

__attribute__((noinline))
int beta(const char *s) { return strcmp(s, "r2-dataxref-secret-3e9f") == 0; }

int main(int argc, char **argv) {
    if (argc > 1) return beta(argv[1]);
    return alpha();
}
"""


def _compiler() -> str | None:
    return shutil.which("cc") or shutil.which("gcc")


def _build_elf(dest: Path) -> Path:
    compiler = _compiler()
    assert compiler is not None
    src = dest / "fixture.c"
    src.write_text(_SRC, encoding="utf-8")
    binary = dest / "fixture"
    subprocess.run(  # noqa: S603 - fixed args, local compiler
        [compiler, "-O0", "-fno-inline", "-no-pie", "-o", str(binary), str(src)],
        check=True,
        capture_output=True,
        timeout=120,
    )
    return binary


def _within(addr: int, entry: int, size: int) -> bool:
    return entry <= addr < entry + size


@pytest.mark.integration
def test_m11_r2_xrefs_to_a_string_lists_its_referring_code() -> None:
    client = R2Client()
    if not client.available:
        pytest.skip("radare2/rizin not installed — data xrefs Gate not run (skip != pass)")
    if _compiler() is None:
        pytest.skip("no C compiler (cc/gcc) — cannot build the ELF fixture (skip != pass)")

    with tempfile.TemporaryDirectory() as tmp:
        binary = _build_elf(Path(tmp))

        # Locate the string literal in .rodata via izj.
        strings = client.run(binary, ["izj"], timeout=60.0)
        assert strings.get("parsed") is True
        marker = [s for s in strings["items"] if s.get("string") == _MARKER]
        assert marker, [s.get("string") for s in strings["items"]]
        string_va = marker[0].get("vaddr")
        assert isinstance(string_va, int)

        # Map the two functions that load it so edges can be attributed by body.
        funcs = client.run(binary, ["aa", "aflj"], timeout=60.0)
        by_name = {str(f.get("name")): f for f in funcs["items"]}
        alpha = next((f for n, f in by_name.items() if "alpha" in n), None)
        beta = next((f for n, f in by_name.items() if "beta" in n), None)
        assert alpha is not None and beta is not None, list(by_name)

        # The decisive query: xrefs_to at a string returns DATA references, one
        # per loading site, not calls.
        to = client.xrefs_to(binary, string_va, timeout=60.0)
        assert to.get("parsed") is True
        assert to.get("address_va") == string_va
        assert to.get("count") == 2, to.get("items")
        assert all(e.get("type") == "DATA" for e in to["items"]), to["items"]

        # Each edge names the string, is an address load (lea), maps its site,
        # and sits inside the body of exactly one of the two functions.
        by_fcn: dict[str, dict[str, Any]] = {}
        for edge in to["items"]:
            assert _MARKER.replace("-", "_") in str(edge.get("refname")), edge
            assert "lea" in str(edge.get("opcode")).split(), edge
            assert isinstance(edge.get("from"), int)
            assert isinstance(edge.get("from_address"), dict), edge
            by_fcn[str(edge.get("fcn_name"))] = edge
        assert {str(alpha["name"]), str(beta["name"])} == set(by_fcn), by_fcn
        alpha_edge = by_fcn[str(alpha["name"])]
        beta_edge = by_fcn[str(beta["name"])]
        assert _within(alpha_edge["from"], alpha["offset"], alpha["size"]), alpha_edge
        assert _within(beta_edge["from"], beta["offset"], beta["size"]), beta_edge
        # No CALL edge is present -- a string is loaded, never called.
        assert not any(e.get("type") == "CALL" for e in to["items"]), to["items"]

        # Same method, different target kind: xrefs_to at the *function* alpha
        # returns a CALL from main, proving the edge type follows the target.
        to_alpha = client.xrefs_to(binary, int(alpha["offset"]), timeout=60.0)
        call_edges = [e for e in to_alpha.get("items", []) if e.get("type") == "CALL"]
        assert call_edges, to_alpha.get("items")
        assert any(str(e.get("fcn_name")) == "main" for e in call_edges), call_edges
