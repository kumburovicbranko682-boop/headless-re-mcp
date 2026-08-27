"""M11 r2 targeted xrefs gate: axtj answers "who calls this address".

``r2.xrefs`` runs ``axj``, whose list is the whole binary's cross-reference
graph and is the same no matter which address is seeked -- it cannot answer the
first question of inbound analysis, "who calls this function". ``r2.xrefs_to``
runs ``axtj`` at the address and returns only the references that point at it.
This gate compiles a tiny ELF where ``main`` is the sole caller of a named
function, then proves ``xrefs_to`` narrows to exactly that one CALL (naming the
enclosing function and its call site) while the global ``xrefs`` returns the
whole graph. skip != pass when radare2/rizin or a C compiler is missing.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

from headless_re_mcp.backends.r2.client import R2Client

_SRC = r"""
#include <stdio.h>
#include <string.h>

__attribute__((noinline))
int check_password(const char *s) {
    if (strcmp(s, "r2-xrefs-secret-marker-9d1e") == 0) {
        puts("access granted");
        return 1;
    }
    puts("access denied");
    return 0;
}

int main(int argc, char **argv) {
    const char *pw = argc > 1 ? argv[1] : "nope";
    return check_password(pw) ? 0 : 2;
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
        [compiler, "-O0", "-fno-inline", "-o", str(binary), str(src)],
        check=True,
        capture_output=True,
        timeout=120,
    )
    return binary


@pytest.mark.integration
def test_m11_r2_xrefs_to_narrows_to_the_single_caller() -> None:
    client = R2Client()
    if not client.available:
        pytest.skip("radare2/rizin not installed — live Gate not run (skip != pass)")
    if _compiler() is None:
        pytest.skip("no C compiler (cc/gcc) — cannot build the ELF fixture (skip != pass)")

    with tempfile.TemporaryDirectory() as tmp:
        binary = _build_elf(Path(tmp))

        funcs = client.run(binary, ["aa", "aflj"], timeout=60.0)
        assert funcs.get("parsed") is True
        by_name = {str(f.get("name")): f for f in funcs["items"]}
        check = next((f for n, f in by_name.items() if "check_password" in n), None)
        main = next((f for n, f in by_name.items() if n == "main" or n.endswith(".main")), None)
        assert check is not None, list(by_name)
        assert main is not None, list(by_name)
        check_va = check["offset"]
        main_va = main["offset"]
        assert isinstance(check_va, int)
        assert isinstance(main_va, int)

        # Targeted: axtj at check_password returns only the references that
        # point at it. The fixture has exactly one -- the CALL from main.
        to = client.xrefs_to(binary, check_va, timeout=60.0)
        assert to.get("parsed") is True
        assert to.get("count") == 1, [i for i in to.get("items", [])]
        assert isinstance(to.get("address"), dict)
        assert to.get("address_va") == check_va

        edge = to["items"][0]
        assert edge.get("type") == "CALL", edge
        # The reference names its target function ...
        assert "check_password" in str(edge.get("refname")) or "check_password" in str(
            edge.get("opcode")
        ), edge
        # ... and identifies the enclosing caller as main, at main's address.
        assert str(edge.get("fcn_name")) == "main", edge
        assert edge.get("fcn_addr") == main_va, edge
        # The call site lives inside main's body and maps to an Address object.
        assert isinstance(edge.get("from"), int)
        assert edge["from"] >= main_va, (edge["from"], main_va)
        assert isinstance(edge.get("from_address"), dict), edge

        # Contrast: the global graph (axj) returns far more than this one edge
        # and is not a who-calls-me answer -- it is the same list wherever the
        # address points. xrefs_to is a strict, targeted subset of it.
        glob = client.xrefs(binary, check_va, timeout=60.0)
        assert glob.get("parsed") is True
        assert glob.get("count", 0) >= 5, glob.get("count")
        assert glob["count"] > to["count"], (glob["count"], to["count"])

        # Asking who calls main returns a different (and here, non-CALL) set --
        # proving the address genuinely selects the reference set.
        to_main = client.xrefs_to(binary, main_va, timeout=60.0)
        assert to_main.get("parsed") is True
        main_call_sites = [
            x.get("from") for x in to_main.get("items", []) if x.get("type") == "CALL"
        ]
        assert check_va not in main_call_sites, main_call_sites


@pytest.mark.integration
def test_m11_r2_xrefs_from_lists_the_functions_call_targets() -> None:
    client = R2Client()
    if not client.available:
        pytest.skip("radare2/rizin not installed — live Gate not run (skip != pass)")
    if _compiler() is None:
        pytest.skip("no C compiler (cc/gcc) — cannot build the ELF fixture (skip != pass)")

    with tempfile.TemporaryDirectory() as tmp:
        binary = _build_elf(Path(tmp))

        funcs = client.run(binary, ["aa", "aflj"], timeout=60.0)
        assert funcs.get("parsed") is True
        by_name = {str(f.get("name")): f for f in funcs["items"]}
        check = next((f for n, f in by_name.items() if "check_password" in n), None)
        main = next((f for n, f in by_name.items() if n == "main" or n.endswith(".main")), None)
        assert check is not None and main is not None, list(by_name)
        check_va = check["offset"]
        main_va = main["offset"]

        # Outbound: axffj walks the whole function body. check_password calls
        # strcmp and puts and loads its literal, so those targets appear by name.
        frm = client.xrefs_from(binary, check_va, timeout=60.0)
        assert frm.get("parsed") is True
        assert frm.get("count", 0) >= 3, frm.get("count")
        assert frm.get("address_va") == check_va
        names = [str(i.get("name")) for i in frm["items"]]
        calls = {
            str(i.get("name"))
            for i in frm["items"]
            if str(i.get("type")) == "CALL"
        }
        assert any("strcmp" in n for n in calls), names
        assert any("puts" in n for n in calls), names
        # The string constant the code compares against is referenced as data.
        assert any(
            "secret_marker" in str(i.get("name")) and str(i.get("type")) == "DATA"
            for i in frm["items"]
        ), names
        # Each edge maps both endpoints: the referencing site and the target.
        for item in frm["items"]:
            assert isinstance(item.get("at_address"), dict), item
            assert isinstance(item.get("ref_address"), dict), item

        # The per-instruction axfj would be empty at a function entry; axffj is
        # what makes the outbound list non-trivial. (Contract, not just count.)
        assert frm["commands"][-1] == f"axffj @ {check_va}"

        # Bidirectional consistency: main's outbound set contains the CALL into
        # check_password, and that same edge is what xrefs_to(check_password)
        # reports inbound -- the two directions describe one call edge.
        frm_main = client.xrefs_from(binary, main_va, timeout=60.0)
        call_to_check = [
            i
            for i in frm_main.get("items", [])
            if str(i.get("type")) == "CALL" and i.get("ref") == check_va
        ]
        assert call_to_check, [
            (str(i.get("name")), i.get("type"), i.get("ref")) for i in frm_main.get("items", [])
        ]
        assert "check_password" in str(call_to_check[0].get("name")), call_to_check[0]

        to_check = client.xrefs_to(binary, check_va, timeout=60.0)
        inbound_sites = {
            i.get("from") for i in to_check.get("items", []) if i.get("type") == "CALL"
        }
        # The call site main uses to reach check_password (axffj "at") is the
        # same address axtj reports as the inbound edge's "from".
        assert call_to_check[0].get("at") in inbound_sites, (
            call_to_check[0].get("at"),
            inbound_sites,
        )
