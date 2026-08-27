"""M11 r2 live gate: Address-mapped functions. skip≠pass when r2 missing.

Two live paths, one per binary format. The PE path proves the rva/module
mapping the mature Windows pipeline depends on and only runs where the PE
fixture was built. The ELF path proves the same client on the platform the
project now calls a first-class core -- radare2 is fully cross-platform, but
until this the r2 line had *no* live coverage on Linux/macOS because the only
fixture was a Windows PE, so a regression in the non-PE (va-only) mapping would
have sailed through every green run there. It compiles a tiny fixture with the
system C compiler so it needs no committed binary; skip != pass when neither r2
nor a compiler is present.

A third gate drives the r2 *service* surface (``r2.open`` / ``functions`` /
``strings`` / ``imports`` / ``disasm``) through a real session created from that
ELF -- the path that was impossible before the native target kind, because an
ELF was classified PE and rejected as "not a PE file". It also proves the
architecture ``describe_native`` read from the header reaches the r2 output:
before it was threaded from the session, ``enrich_r2_payload`` derived arch only
from the PE header, so a PE listed ``x64`` while the same tool on an ELF listed
nothing.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from headless_re_mcp.backends.r2.client import R2Client
from headless_re_mcp.core.service import AnalysisService

_PROJECT_ROOT = Path(__file__).resolve().parents[2]

# Distinct, non-inlined functions with a clear call graph so ``aflj`` finds
# more than one function and ``axj`` finds real cross-references. Kept portable
# (no OS headers) so it builds to an ELF on Linux and a Mach-O on macOS.
_ELF_FIXTURE_C = """
#include <stdio.h>

__attribute__((noinline)) int r2_gate_leaf(int x) { return (x ^ 0x5a) + 3; }

__attribute__((noinline)) int r2_gate_middle(int n) {
    int total = 0;
    for (int i = 0; i < n; i++) total += r2_gate_leaf(i);
    return total;
}

__attribute__((noinline)) int r2_gate_root(int n) {
    return r2_gate_middle(n) + r2_gate_leaf(n);
}

int main(void) {
    volatile int result = r2_gate_root(11);
    printf("r2-gate %d\\n", result);
    return 0;
}
"""


def _build_elf_fixture(tmp_path: Path) -> Path:
    """Compile the portable fixture, or skip when no C compiler is available."""
    compiler = next(
        (shutil.which(name) for name in ("cc", "gcc", "clang") if shutil.which(name)),
        None,
    )
    if compiler is None:
        pytest.skip("no C compiler (cc/gcc/clang) to build an r2 ELF fixture (skip != pass)")
    source = tmp_path / "r2_gate_fixture.c"
    source.write_text(_ELF_FIXTURE_C, encoding="utf-8")
    out = tmp_path / "r2_gate_fixture"
    # -O0 keeps the helpers as separate functions; -no-pie fixes the load base
    # so the reported va is stable, with a fallback for toolchains that reject
    # it (some clang targets). Neither is required for the mapping under test.
    for extra in (["-no-pie"], []):
        completed = subprocess.run(  # noqa: S603 - fixed argv, no shell
            [compiler, "-O0", *extra, "-o", str(out), str(source)],
            capture_output=True,
            text=True,
            timeout=120.0,
        )
        if completed.returncode == 0 and out.is_file():
            return out
    pytest.skip(
        f"C compiler present but could not build the r2 ELF fixture (skip != pass): "
        f"{completed.stderr.strip()[:400]}"
    )


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
def test_m11_r2_live_elf_maps_functions_disasm_and_xrefs(tmp_path: Path) -> None:
    """The portable path: same client, ELF binary, va-only mapping.

    A PE carries a preferred ImageBase, so its addresses map to rva+module. An
    ELF does not go through that header read, so ``address`` must be a bare va
    with no rva/module invented for it. Exercising functions, disasm and xrefs
    covers every ``enrich_r2_payload`` branch a caller hits on a non-PE target.
    """
    client = R2Client()
    if not client.available:
        pytest.skip("radare2/rizin not installed — live Gate not run (skip != pass)")
    fixture = _build_elf_fixture(tmp_path)

    opened = client.open(fixture, timeout=60.0)
    assert opened.get("opened") is True

    funcs = client.run(fixture, ["aa", "aflj"], timeout=60.0)
    assert funcs.get("parsed") is True
    assert funcs.get("count", 0) >= 1
    first = funcs["items"][0]
    assert isinstance(first.get("address"), dict)
    va = first["address"].get("va")
    assert isinstance(va, int) and va > 0
    # ELF has no PE ImageBase, so the mapping must not fabricate rva/module.
    assert "rva" not in first["address"]
    assert "module" not in first["address"]

    disasm = client.disasm(fixture, va, count=8, timeout=60.0)
    assert disasm.get("parsed") is True
    assert disasm.get("items")
    assert disasm.get("address", {}).get("va") == va
    assert disasm.get("address_va") == va

    xrefs = client.xrefs(fixture, va, timeout=60.0)
    assert xrefs.get("parsed") is True
    assert xrefs.get("address", {}).get("va") == va


@pytest.mark.integration
def test_r2_tool_surface_reachable_for_a_native_elf_session(tmp_path: Path) -> None:
    """The whole point of the native target kind: r2 tools work end to end.

    The gate above drives ``R2Client`` directly because, until the native target
    kind, an ELF could not even get a session -- ``classify_target`` mapped it to
    PE and creation rejected it as "not a PE file", so ``r2.open`` /
    ``r2.functions`` / ``r2.strings`` / ``r2.imports`` were unreachable for the
    binary format Linux/macOS actually ship. This drives that service surface:
    a session is created straight from the ELF, and each tool must return the
    facts the fixture was built with (the gate functions, the format string, the
    printf import). A PE-only tool on the same session must still be refused, so
    the kind does not quietly turn every debugger loose on a non-PE image.
    """
    if not R2Client().available:
        pytest.skip("radare2/rizin not installed — live Gate not run (skip != pass)")
    fixture = _build_elf_fixture(tmp_path)

    service = AnalysisService()
    try:
        created = service.create_session(str(fixture))
        assert created.ok, created.error
        session_id = created.data["session"]["id"]
        # The ELF must be bound as a native (portable-static) session, carrying
        # the identity describe_native read from its header. Arch/bits are left
        # to the runner (x86-64 on CI), so assert they were populated, not a
        # specific value; the unit tests pin the exact parsing.
        assert created.data["session"]["target"] == "native"
        native_meta = created.data["session"]["metadata"]["native"]
        assert native_meta["format"] == "elf"
        assert native_meta["bits"] in (32, 64)
        assert isinstance(native_meta["arch"], str) and native_meta["arch"]

        opened = service.r2_open(session_id)
        assert opened.ok, opened.error
        assert opened.data.get("opened") is True

        funcs = service.r2_functions(session_id)
        assert funcs.ok, funcs.error
        assert funcs.data["count"] >= 1
        names = {str(item.get("name", "")) for item in funcs.data["items"]}
        assert any("r2_gate" in name for name in names), names

        strings = service.r2_strings(session_id)
        assert strings.ok, strings.error
        found = [str(item.get("string", "")) for item in strings.data["items"]]
        assert any("r2-gate" in text for text in found), found

        imports = service.r2_imports(session_id)
        assert imports.ok, imports.error
        imported = {str(item.get("name", "")) for item in imports.data["items"]}
        assert any("printf" in name for name in imported), imported

        # The architecture describe_native read from the header must now flow
        # into the r2 tool output. Before it was threaded from the session,
        # enrich_r2_payload derived arch only from the PE header (None for an
        # ELF), so native r2 output silently dropped the architecture the
        # session already knew -- a PE listed "x64", the same tool on an ELF
        # listed nothing. On CI the fixture is x86-64 (a modelled Architecture);
        # a non-modelled arch (e.g. aarch64) stays None and is skipped, not
        # asserted false, so the gate does not pin the runner's ISA.
        session_arch = created.data["session"].get("architecture")
        if session_arch:
            assert funcs.data.get("architecture") == session_arch
            mapped = [it for it in funcs.data["items"] if isinstance(it.get("address"), dict)]
            assert mapped, "no function came back with a mapped address"
            assert all(it["address"].get("architecture") == session_arch for it in mapped)

            # disasm/xrefs enrich twice (inner run + outer shaping); prove the
            # architecture survives that path too, at a real function address.
            va = next(it["address"]["va"] for it in mapped if "va" in it["address"])
            dis = service.r2_disasm(session_id, va, count=8)
            assert dis.ok, dis.error
            assert dis.data.get("architecture") == session_arch
            assert dis.data.get("address", {}).get("architecture") == session_arch

        # A PE-only tool must reject the native session with target_mismatch,
        # not crash inside the debugger backend.
        launched = service.dynamic_launch(session_id)
        assert not launched.ok
        assert launched.error.code == "target_mismatch"
    finally:
        service.close_all()
