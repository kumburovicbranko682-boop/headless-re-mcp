"""radare2 exports and info live gate: iEj / i on a real ELF on Linux.

The r2 line has two commands that no live gate has ever run against real output.
``r2.exports`` (``iEj``) and ``r2.info`` (``i``) were only exercised against
synthetic JSON in unit tests, and the one r2 integration gate on this branch
drives a Windows PE fixture that is absent on Linux, so it skips here. The other
r2 commands (aflj/izj/iij/disasm/xrefs) are covered elsewhere; exports and info
are the remaining blind spots.

Exports is the more interesting of the two: ``iEj`` returns a JSON array that
``enrich_r2_payload`` turns into ``items`` with unified ``address`` fields, and
nothing proved that mapping against a real symbol table -- only that it worked on
a hand-written dict. This gate compiles a shared object with a known, controlled
export set (three visibility-default functions; one static helper that must stay
hidden) and asserts:

  * ``iEj`` parses to items carrying the three exported names, each with a
    ``FUNC``/``GLOBAL`` symbol and an ``address`` holding a real ``va`` -- and the
    hidden static helper is absent, so the listing is the export table and not
    every symbol; and
  * ``i`` returns the binary identity as raw text (it is not a JSON command, so
    ``parsed`` is False and there are no items), naming this an ELF64 image.

Skip != pass: the gate skips with a reason when radare2 or a C compiler is
missing. CI installs both, so a skip there is a real regression, not a bare
machine.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from headless_re_mcp.backends.r2.client import R2Client

# -fvisibility=hidden makes the export set exactly the functions marked below,
# so the assertions do not depend on the toolchain's default symbol visibility.
_SOURCE = """
#include <stdio.h>
#define EXPORT __attribute__((visibility("default")))

EXPORT int gate_exported_add(int a, int b) { return a + b; }
EXPORT const char *gate_exported_name(void) { return "r2-export-gate-marker"; }

static int gate_hidden_helper(int x) { return x * 3; }

EXPORT int gate_exported_calc(int x) {
    printf("calc %d\\n", gate_hidden_helper(x));
    return gate_hidden_helper(x);
}
"""

_EXPORTED = {"gate_exported_add", "gate_exported_name", "gate_exported_calc"}


@pytest.fixture(scope="module")
def shared_object(tmp_path_factory: pytest.TempPathFactory) -> Path:
    gcc = shutil.which("gcc") or shutil.which("cc")
    if gcc is None:
        pytest.skip("no C compiler (gcc/cc) — r2 exports/info gate not run (skip != pass)")
    workdir = tmp_path_factory.mktemp("r2-exports")
    source = workdir / "libgate.c"
    source.write_text(_SOURCE, encoding="utf-8")
    library = workdir / "libgate.so"
    result = subprocess.run(
        [gcc, "-shared", "-fPIC", "-O0", "-fvisibility=hidden", "-o", str(library), str(source)],
        capture_output=True,
        text=True,
        timeout=120,
    )
    if result.returncode != 0 or not library.is_file():
        pytest.skip(f"could not build shared object: {result.stderr.strip()[:200]}")
    return library


@pytest.mark.integration
def test_r2_exports_lists_visibility_default_symbols(shared_object: Path) -> None:
    client = R2Client()
    if not client.available:
        pytest.skip("radare2 not installed — r2 exports gate not run (skip != pass)")

    exports = client.run(shared_object, ["iEj"], timeout=60.0)
    assert exports.get("parsed") is True
    items = exports.get("items")
    assert isinstance(items, list) and items, "iEj produced no export items"

    names = {str(item.get("name")) for item in items}
    # The three functions marked visibility-default are the export table.
    assert names >= _EXPORTED, f"missing exports; got {sorted(names)}"
    # The static helper has hidden visibility and must not surface as an export;
    # a listing that included it would be dumping the symbol table, not exports.
    assert "gate_hidden_helper" not in names

    exported_items = [item for item in items if str(item.get("name")) in _EXPORTED]
    for item in exported_items:
        assert item.get("type") == "FUNC", item
        assert item.get("bind") == "GLOBAL", item
        assert item.get("is_imported") is False, item
        # enrich_r2_payload mapped vaddr into a unified Address. The ELF has no
        # PE image_base, so the mapping keeps va (no rva) -- the field that was
        # only ever exercised against a synthetic dict before.
        address = item.get("address")
        assert isinstance(address, dict), item
        assert isinstance(address.get("va"), int) and address["va"] > 0, item


@pytest.mark.integration
def test_r2_info_reports_elf_identity(shared_object: Path) -> None:
    client = R2Client()
    if not client.available:
        pytest.skip("radare2 not installed — r2 info gate not run (skip != pass)")

    info = client.run(shared_object, ["i"], timeout=60.0)
    # ``i`` is plain text, not JSON, so there is no item list to parse.
    assert info.get("parsed") is False
    assert "items" not in info
    raw = str(info.get("raw") or "")
    assert raw, "r2 info returned no text"
    lowered = raw.lower()
    # The identity r2 prints for this image: a 64-bit little-endian ELF.
    assert "elf64" in lowered
    assert "bits" in lowered and "64" in raw
    assert "endian" in lowered and "little" in lowered
