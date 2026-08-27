"""M11 r2 live gate: Address-mapped functions. skip≠pass when r2 missing.

Portable across the platforms radare2 runs on. Windows analyses its committed
PE sample and checks module-relative RVAs; elsewhere a tiny ELF is compiled on
the fly so the gate exercises r2 on this platform's own object format. The
address mapping degrades honestly for a PIE ELF -- with no PE ImageBase there is
nothing to make addresses module-relative, so items keep absolute VAs -- which
is exactly what this asserts. It skips, never fails, when r2 or a C compiler is
absent.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from headless_re_mcp.backends.r2.client import R2Client

_PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _r2_fixture(tmp_path: Path) -> Path:
    """A binary radare2 can analyse on this platform.

    Windows uses the committed x64 PE sample; elsewhere any C toolchain builds a
    small ELF with a couple of real functions to analyse. Skips when the sample
    or a compiler is unavailable rather than failing.
    """
    if os.name == "nt":
        fixture = _PROJECT_ROOT / "artifacts" / "fixtures-x64" / "headless_fixture.exe"
        if not fixture.is_file():
            pytest.skip(f"fixture missing: {fixture}")
        return fixture

    compiler = next((name for name in ("cc", "gcc", "clang") if shutil.which(name)), None)
    if compiler is None:
        pytest.skip("no C compiler to build an ELF fixture — r2 Gate not run (skip != pass)")
    source = tmp_path / "r2fix.c"
    source.write_text(
        "#include <stdio.h>\n"
        "static int secret(int x){ return x * 3 + 1; }\n"
        "int helper(int a){ return secret(a) + a; }\n"
        # The literal is deliberately >= 4 chars so r2's izj string scan (which
        # skips shorter runs by default) reports it for the listing gate.
        'int main(void){ printf("r2 live result = %d\\n", helper(7)); return 0; }\n',
        encoding="utf-8",
    )
    binary = tmp_path / "r2fix.elf"
    try:
        built = subprocess.run(  # noqa: S603 - fixed local toolchain, fixed args
            [compiler, "-O0", "-o", str(binary), str(source)],
            capture_output=True,
            timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        pytest.skip(f"C compiler could not build an ELF fixture ({exc}) — skip != pass")
    if built.returncode != 0 or not binary.is_file():
        pytest.skip("C compiler produced no ELF fixture — r2 Gate not run (skip != pass)")
    return binary


@pytest.mark.integration
def test_m11_r2_live_address_mapping(tmp_path: Path) -> None:
    client = R2Client()
    if not client.available:
        pytest.skip("radare2/rizin not installed — live Gate not run (skip≠pass)")
    fixture = _r2_fixture(tmp_path)

    opened = client.open(fixture, timeout=60.0)
    assert opened.get("opened") is True

    funcs = client.run(fixture, ["aa", "aflj"], timeout=60.0)
    assert funcs.get("parsed") is True
    assert funcs.get("count", 0) >= 1
    item = funcs["items"][0]
    assert isinstance(item.get("address"), dict)
    assert "va" in item["address"] or "rva" in item["address"]
    if "rva" in item["address"]:
        # A PE carries a preferred base, so addresses map to module-relative RVAs.
        assert item["address"].get("module") == fixture.name


@pytest.mark.integration
def test_m11_r2_live_xrefs_resolve_a_real_call(tmp_path: Path) -> None:
    """r2.xrefs must return the real caller of a function.

    This guards the ``axtj``/``axfj`` fix: modern radare2's bare ``axj`` is a
    write ("add jmp reference"), not a listing, so the old command returned
    nothing (``parsed: False``) for every address. Against the compiled ELF,
    ``main`` calls ``helper`` -- so asking for references *to* helper must yield
    the CALL edge, with ``to`` pointing at helper. POSIX only: it needs the
    named symbols of the compiled ELF, which the committed PE sample does not
    share.
    """
    if os.name == "nt":
        pytest.skip("xref edge assertions target the compiled ELF fixture (skip != pass)")
    client = R2Client()
    if not client.available:
        pytest.skip("radare2/rizin not installed — live Gate not run (skip≠pass)")
    fixture = _r2_fixture(tmp_path)

    funcs = client.run(fixture, ["aa", "aflj"], timeout=60.0)
    va_by_name = {
        str(entry.get("name")): entry.get("address", {}).get("va")
        for entry in funcs.get("items", [])
        if isinstance(entry.get("address"), dict)
    }
    helper_va = next(
        (va for name, va in va_by_name.items() if "helper" in name and va is not None), None
    )
    assert helper_va is not None, f"no helper function among {sorted(va_by_name)}"

    xrefs = client.xrefs(fixture, helper_va, timeout=60.0)
    assert xrefs.get("parsed") is True
    assert xrefs.get("count", 0) >= 1
    call_edges = [
        item
        for item in xrefs["items"]
        if item.get("type") == "CALL"
        and isinstance(item.get("to_address"), dict)
        and item["to_address"].get("va") == helper_va
    ]
    assert call_edges, f"no CALL edge into helper@{helper_va:#x}: {xrefs['items']}"
    assert isinstance(call_edges[0].get("from_address"), dict)
    assert isinstance(call_edges[0]["from_address"].get("va"), int)


@pytest.mark.integration
def test_m11_r2_live_listing_commands_parse_on_this_r2(tmp_path: Path) -> None:
    """strings/imports/exports/disasm must still return on the installed r2.

    Unit tests mock r2's JSON, so they cannot catch a command a newer r2 stops
    emitting a listing for -- exactly how the bare ``axj`` regression hid, where
    the tool returned nothing on modern r2 yet every mocked unit test passed.
    Only a live run guards that class of drift. Against the compiled ELF this
    asserts each listing parses and carries its expected content: the "%d"
    format string, the printf import, at least one export, and a disassembly at
    a real function that maps to addresses. POSIX only -- it names the compiled
    ELF's own symbols and strings, which the committed PE sample does not share.
    """
    if os.name == "nt":
        pytest.skip("listing assertions target the compiled ELF fixture (skip != pass)")
    client = R2Client()
    if not client.available:
        pytest.skip("radare2/rizin not installed — live Gate not run (skip≠pass)")
    fixture = _r2_fixture(tmp_path)

    strings = client.run(fixture, ["izj"], timeout=60.0)
    assert strings.get("parsed") is True
    assert any(
        "result" in str(item.get("string", "")) for item in strings.get("items", [])
    ), f"format string missing from izj: {strings.get('items')}"

    imports = client.run(fixture, ["iij"], timeout=60.0)
    assert imports.get("parsed") is True
    import_names = {str(item.get("name", "")) for item in imports.get("items", [])}
    assert any("printf" in name for name in import_names), f"printf not imported: {import_names}"

    exports = client.run(fixture, ["iEj"], timeout=60.0)
    assert exports.get("parsed") is True
    assert exports.get("count", 0) >= 1

    funcs = client.run(fixture, ["aa", "aflj"], timeout=60.0)
    secret_va = next(
        (
            entry.get("address", {}).get("va")
            for entry in funcs.get("items", [])
            if isinstance(entry.get("address"), dict) and "secret" in str(entry.get("name", ""))
        ),
        None,
    )
    assert secret_va is not None, f"no secret function among {funcs.get('items')}"

    disasm = client.disasm(fixture, secret_va, count=8, timeout=60.0)
    assert disasm.get("parsed") is True
    assert disasm.get("count", 0) >= 1
    assert any(isinstance(item.get("address"), dict) for item in disasm.get("items", []))
