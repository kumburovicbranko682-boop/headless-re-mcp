"""radare2 over the service on a native ELF. skip != pass when r2 is absent.

The existing r2 live gate drives ``R2Client`` directly against a Windows PE
fixture. It could not prove the thing the native target kind is for: that an
ELF/Mach-O reaches the ``r2.*`` *service* surface at all. Before
``TargetKind.NATIVE``, ``classify_target`` mapped an ELF to PE and
``create_session`` rejected it in ``detect_pe_architecture`` as "not a PE file",
so ``r2.open`` / ``r2.functions`` / ``r2.strings`` / ``r2.imports`` /
``r2.exports`` / ``r2.disasm`` / ``r2.xrefs`` were unreachable for the binary
format Linux and macOS ship.

This compiles a tiny ELF with the system C compiler, opens a session straight
from it, and asserts each tool returns the facts the fixture was built with (the
``gate_*`` functions, the printf import, the marker string, the real CALL
references to a function that is called more than once). It also pins the
architecture thread: a native session knows it is x86-64 from
``describe_native``, and that machine type must reach the r2 output the same way
a PE's does. A PE-only tool on the same session must still be refused, so the
kind does not quietly turn the debugger loose on a non-PE image. Skips honestly
when radare2 or a C compiler is not installed.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import replace
from pathlib import Path

import pytest

from headless_re_mcp.backends.r2.client import R2Client
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService

# Distinct, non-inlined functions and a marker string long enough for ``izj``
# (r2 ignores runs shorter than four bytes, so "%d\n" alone never shows).
_ELF_FIXTURE_C = """
#include <stdio.h>

__attribute__((noinline)) int gate_leaf(int x) { return (x ^ 0x5a) + 3; }

__attribute__((noinline)) int gate_mid(int n) {
    int total = 0;
    for (int i = 0; i < n; i++) total += gate_leaf(i);
    return total;
}

__attribute__((noinline)) int gate_root(int n) {
    return gate_mid(n) + gate_leaf(n);
}

int main(void) {
    volatile int result = gate_root(11);
    printf("native-r2-gate-marker %d\\n", result);
    return 0;
}
"""
_MARKER = "native-r2-gate-marker"


def _build_elf_fixture(tmp_path: Path) -> Path:
    compiler = next(
        (shutil.which(name) for name in ("cc", "gcc", "clang") if shutil.which(name)),
        None,
    )
    if compiler is None:
        pytest.skip("no C compiler (cc/gcc/clang) to build a native fixture (skip != pass)")
    source = tmp_path / "native_r2_fixture.c"
    source.write_text(_ELF_FIXTURE_C, encoding="utf-8")
    out = tmp_path / "native_r2_fixture"
    # -no-pie fixes the load base so addresses are stable; -O0 keeps the helpers
    # as separate functions. Neither is required for the tools under test.
    completed = subprocess.run(  # noqa: S603 - compiler from which(), fixed argv
        [compiler, "-O0", "-no-pie", "-o", str(out), str(source)],
        capture_output=True,
        text=True,
        timeout=120.0,
    )
    if completed.returncode != 0 or not out.is_file():
        pytest.skip(
            f"C compiler present but could not build the native fixture (skip != pass): "
            f"{completed.stderr.strip()[:400]}"
        )
    return out


def _names(items: list[dict]) -> list[str]:
    return [str(item.get("name") or "") for item in items]


@pytest.mark.integration
@pytest.mark.skipif(os.name == "nt", reason="native ELF/Mach-O fixture uses the POSIX toolchain")
def test_r2_tool_surface_reachable_for_a_native_elf_session(tmp_path: Path) -> None:
    if not R2Client().available:
        pytest.skip("radare2/rizin not installed — native r2 Gate not run (skip != pass)")
    fixture = _build_elf_fixture(tmp_path)

    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    try:
        created = service.create_session(str(fixture))
        assert created.ok, created.error
        session = created.data["session"]
        session_id = session["id"]
        # The native target kind is what makes any of this reachable: an ELF
        # used to be classified PE and rejected before a session ever existed.
        assert session["target"] == "native"
        assert session["metadata"]["native"]["format"] == "elf"
        session_arch = session.get("architecture")

        opened = service.r2_open(session_id, timeout=120.0)
        assert opened.ok, opened.error
        assert opened.data.get("opened") is True

        funcs = service.r2_functions(session_id, timeout=120.0)
        assert funcs.ok, funcs.error
        assert funcs.data.get("parsed") is True
        assert funcs.data.get("count", 0) >= 1
        names = _names(funcs.data["items"])
        # r2 names symbols ``sym.gate_root`` etc.; match by substring.
        assert any("gate_root" in name for name in names), names
        assert any("gate_leaf" in name for name in names), names
        assert "main" in names, names

        # The session knows its machine type from describe_native; on an ELF
        # there is no PE header for enrich to read, so this is the only source.
        if session_arch:
            assert funcs.data.get("architecture") == session_arch
            mapped = [it for it in funcs.data["items"] if isinstance(it.get("address"), dict)]
            assert mapped, "no function came back with a mapped address"
            assert all(it["address"].get("architecture") == session_arch for it in mapped)

            va = next(it["address"]["va"] for it in mapped if "va" in it["address"])
            dis = service.r2_disasm(session_id, va, count=8, timeout=120.0)
            assert dis.ok, dis.error
            assert dis.data.get("architecture") == session_arch
            assert dis.data.get("address", {}).get("architecture") == session_arch

        imports = service.r2_imports(session_id, timeout=120.0)
        assert imports.ok, imports.error
        assert "printf" in _names(imports.data["items"]), _names(imports.data["items"])

        strings = service.r2_strings(session_id, timeout=120.0)
        assert strings.ok, strings.error
        found = [str(item.get("string") or "") for item in strings.data["items"]]
        assert any(_MARKER in text for text in found), found

        # exports: the fixture's global functions are exported (they are not
        # static), so r2 lists gate_root/gate_leaf by name; the architecture
        # rides along the same way it does for functions.
        exports = service.r2_exports(session_id, timeout=120.0)
        assert exports.ok, exports.error
        export_names = _names(exports.data["items"])
        assert "gate_root" in export_names, export_names
        assert "gate_leaf" in export_names, export_names
        if session_arch:
            assert exports.data.get("architecture") == session_arch

        # xrefs: gate_leaf is called from gate_mid (in a loop) and gate_root, so
        # there must be real CALL references to its entry -- proof the mode
        # resolves edges, each ``from`` endpoint carrying the threaded arch, not
        # an empty list.
        leaf_va = next(
            (
                it["address"]["va"]
                for it in funcs.data["items"]
                if "gate_leaf" in str(it.get("name") or "")
                and isinstance(it.get("address"), dict)
                and "va" in it["address"]
            ),
            None,
        )
        assert leaf_va is not None, "gate_leaf has no mapped entry to ask xrefs about"
        xrefs = service.r2_xrefs(session_id, leaf_va, timeout=120.0)
        assert xrefs.ok, xrefs.error
        assert xrefs.data.get("count", 0) >= 1, "no references to gate_leaf, which is called"
        assert any(str(it.get("type")) == "CALL" for it in xrefs.data["items"]), xrefs.data["items"]
        if session_arch:
            assert xrefs.data.get("architecture") == session_arch
            assert xrefs.data.get("address", {}).get("architecture") == session_arch
            edges = [it for it in xrefs.data["items"] if isinstance(it.get("from_address"), dict)]
            assert edges, "no xref came back with a mapped from endpoint"
            assert all(it["from_address"].get("architecture") == session_arch for it in edges)

        # A PE-only tool must reject the native session with target_mismatch,
        # not analyse it -- the native kind does not loosen the debugger guard.
        launched = service.dynamic_launch(session_id)
        assert not launched.ok
        assert launched.error.code == "target_mismatch"
    finally:
        service.close_all()
