"""M11 r2 live gate: Address-mapped functions. skip≠pass when r2 missing.

Two live paths cover the one portable backend. The first opens the Windows PE
fixture (present only on a Windows build); the second compiles a tiny ELF so the
same open/analyse/address-map contract is exercised on Linux, where r2 is most
often installed and where CI actually runs. Before the ELF path existed the whole
gate skipped on Linux for want of a .exe, so radare2 had no live coverage on the
platform it ships on. A third path drives the disassembly, xref, string, and
import commands whose JSON shapes r2 reworks between versions.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from headless_re_mcp.backends.r2.client import R2Client

_PROJECT_ROOT = Path(__file__).resolve().parents[2]

# The marker string is deliberately long: r2's `iz` skips literals shorter than
# bin.minstr (a few chars), so "%d" alone never appears in the string list.
_ELF_FIXTURE_SOURCE = """\
#include <stdio.h>
int r2gate_adder(int a, int b) { return a + b; }
int r2gate_muler(int a, int b) { return a * b; }
int main(void) {
    printf("r2gate_marker_string %d\\n", r2gate_adder(2, 3));
    printf("%d\\n", r2gate_muler(2, 3));
    return 0;
}
"""


def _build_native_fixture(tmp_path: Path) -> Path:
    """Compile a small binary with named functions, or skip if no toolchain.

    A skip here means the machine has no C compiler, not that r2 is missing --
    which is why r2 availability is checked first and this stays a build-tool
    skip rather than a backend one.
    """
    compiler = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if compiler is None:
        pytest.skip("no C compiler (cc/gcc/clang) to build a native fixture (skip≠pass)")
    source = tmp_path / "r2gate_fixture.c"
    source.write_text(_ELF_FIXTURE_SOURCE, encoding="utf-8")
    out = tmp_path / "r2gate_fixture.bin"
    # -no-pie keeps symbols at a fixed VA, which is easier to reason about; fall
    # back to a plain build when the toolchain rejects the flag (some clang/mac).
    for extra in (["-no-pie"], []):
        try:
            completed = subprocess.run(
                [compiler, "-O0", *extra, "-o", str(out), str(source)],
                capture_output=True,
                timeout=120,
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        if completed.returncode == 0 and out.is_file():
            return out
    pytest.skip("C compiler present but could not build the native fixture (skip≠pass)")


@pytest.mark.integration
def test_m11_r2_live_address_mapping() -> None:
    client = R2Client()
    if not client.available:
        pytest.skip("radare2/rizin not installed — live Gate not run (skip≠pass)")
    fixture = _PROJECT_ROOT / "artifacts" / "fixtures-x64" / "headless_fixture.exe"
    if not fixture.is_file():
        pytest.skip(f"fixture missing: {fixture}")

    opened = client.open(fixture, timeout=60.0)
    assert opened.get("opened") is True

    funcs = client.run(fixture, ["aa", "aflj"], timeout=60.0)
    assert funcs.get("parsed") is True
    assert funcs.get("count", 0) >= 1
    item = funcs["items"][0]
    assert isinstance(item.get("address"), dict)
    assert "va" in item["address"] or "rva" in item["address"]
    if "rva" in item["address"]:
        assert item["address"].get("module") == fixture.name


@pytest.mark.integration
def test_m11_r2_live_address_mapping_native_elf(tmp_path: Path) -> None:
    """The portable path: r2 opens a freshly built binary and maps its functions.

    This is the coverage the PE-only case could never give on Linux. It asserts
    the same open/analyse/address-map contract and additionally that r2 recovered
    the fixture's own symbols, so a backend that opened the file but analysed
    nothing cannot pass.
    """
    client = R2Client()
    if not client.available:
        pytest.skip("radare2/rizin not installed — live Gate not run (skip≠pass)")
    fixture = _build_native_fixture(tmp_path)

    opened = client.open(fixture, timeout=60.0)
    assert opened.get("opened") is True

    funcs = client.run(fixture, ["aa", "aflj"], timeout=60.0)
    assert funcs.get("parsed") is True
    assert funcs.get("count", 0) >= 1

    items = funcs["items"]
    assert all(isinstance(item.get("address"), dict) for item in items)
    assert all("va" in item["address"] or "rva" in item["address"] for item in items)

    # aa on a non-stripped build must recover the functions we defined; a client
    # that opened the file but ran no analysis would return only entry/imports.
    names = " ".join(str(item.get("name", "")) for item in items)
    assert "main" in names
    assert "r2gate_adder" in names


def _function_va(items: list[dict], needle: str) -> int:
    for item in items:
        if needle in str(item.get("name", "")):
            va = item.get("offset")
            if isinstance(va, int):
                return va
    raise AssertionError(f"no function matching {needle!r} in r2 output")


@pytest.mark.integration
def test_m11_r2_live_disasm_strings_imports_native_elf(tmp_path: Path) -> None:
    """The disassembly/xref/string/import commands, each a JSON shape r2 moves.

    open/aflj cover the function list; pdj (disasm), axj (xrefs), izj (strings)
    and iij (imports) return their own array shapes that enrich_r2_payload has to
    parse into items, and none ran live before. Point each at a freshly built ELF
    with a known marker string and a printf import, and assert the parsed items
    carry the content r2 actually recovered -- so a version whose JSON drifts (the
    reason parse_r2_json exists) fails here instead of returning empty items with
    parsed=True.
    """
    client = R2Client()
    if not client.available:
        pytest.skip("radare2/rizin not installed — live Gate not run (skip≠pass)")
    fixture = _build_native_fixture(tmp_path)

    funcs = client.run(fixture, ["aa", "aflj"], timeout=60.0)
    items = funcs["items"]
    main_va = _function_va(items, "main")
    adder_va = _function_va(items, "r2gate_adder")

    # pdj: disassembling main returns real instruction rows, each with decoded
    # text and a mapped address -- not just parsed=True over an empty list.
    disasm = client.disasm(fixture, main_va, count=8, timeout=60.0)
    assert disasm.get("parsed") is True
    assert disasm.get("count", 0) >= 1
    row = disasm["items"][0]
    assert isinstance(row.get("address"), dict)
    assert str(row.get("disasm") or row.get("opcode") or "").strip() != ""

    # axj: r2gate_adder is called from main, so cross-references at its address
    # parse into a non-empty item list.
    xrefs = client.xrefs(fixture, adder_va, timeout=60.0)
    assert xrefs.get("parsed") is True
    assert xrefs.get("count", 0) >= 1

    # izj: the marker literal must show up among the recovered strings.
    strings = client.run(fixture, ["izj"], timeout=60.0)
    assert strings.get("parsed") is True
    joined_strings = strings.get("raw", "") + "".join(
        str(item.get("string", "")) for item in strings.get("items", [])
    )
    assert "r2gate_marker_string" in joined_strings

    # iij: the binary links printf, which must appear in the import list.
    imports = client.run(fixture, ["iij"], timeout=60.0)
    assert imports.get("parsed") is True
    import_names = {str(item.get("name", "")) for item in imports.get("items", [])}
    assert any("printf" in name for name in import_names) or "printf" in imports.get("raw", "")
