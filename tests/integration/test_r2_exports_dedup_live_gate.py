"""r2 exports dedup live gate: a real .so's merged symbol tables collapse to one.

radare2's ``iEj`` reads exports from both ``.dynsym`` and ``.symtab``, so a
non-stripped shared object lists every export twice (identical but for the
``ordinal``). This gate builds a real ELF shared object with gcc, runs the
actual radare2 over it, and asserts that (a) each export appears once after
``enrich_r2_payload`` collapses the duplicates and (b) when radare2 did emit the
merged duplicates, ``items_deduplicated`` reports how many were dropped.

skip != pass: it skips only when radare2 or a C toolchain is genuinely absent.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from headless_re_mcp.backends.r2.client import R2Client
from headless_re_mcp.backends.r2.mapping import parse_r2_json

_SOURCE = """
int exported_add(int a, int b) { return a + b; }
int exported_mul(int a, int b) { return a * b; }
const char *exported_msg = "gate-export-string";
"""


def _build_shared_object(tmp_path: Path) -> Path:
    gcc = shutil.which("gcc") or shutil.which("cc")
    if gcc is None:
        pytest.skip("no C compiler (gcc/cc) — live gate not run (skip != pass)")
    source = tmp_path / "exports.c"
    source.write_text(_SOURCE, encoding="utf-8")
    out = tmp_path / "libexports.so"
    proc = subprocess.run(
        [gcc, "-O0", "-shared", "-fPIC", "-o", str(out), str(source)],
        capture_output=True,
    )
    if proc.returncode != 0 or not out.is_file():
        pytest.skip(f"could not build a shared object: {proc.stderr.decode('utf-8', 'replace')}")
    return out


@pytest.mark.integration
def test_r2_exports_dedup_on_a_real_shared_object(tmp_path: Path) -> None:
    client = R2Client()
    if not client.available:
        pytest.skip("radare2/rizin not installed — live gate not run (skip != pass)")
    so = _build_shared_object(tmp_path)

    result = client.run(so, ["iEj"], timeout=60.0)
    assert result.get("parsed") is True, result
    items = result.get("items", [])

    names = {item.get("name") for item in items}
    assert "exported_add" in names, names
    assert "exported_mul" in names, names

    # The core invariant, true no matter what radare2 emitted: our processing
    # never hands back the same export (name at an address) twice.
    seen: set[tuple[object, object]] = set()
    for item in items:
        key = (item.get("name"), (item.get("address") or {}).get("va"))
        assert key not in seen, f"export listed twice after dedup: {key}"
        seen.add(key)

    # Confirm the bug is actually present on this radare2 (the .so's tables were
    # merged) and that the fix fired. If a stripped or single-table build did
    # not duplicate, there is nothing to dedup -- assert only when it did.
    raw_list = parse_r2_json(result.get("raw", ""))
    raw_names = [e.get("name") for e in raw_list if isinstance(e, dict)]
    if raw_names.count("exported_add") > 1:
        assert result.get("items_deduplicated", 0) >= 1, result
        # exported_add appeared once in items even though raw listed it twice.
        assert [i.get("name") for i in items].count("exported_add") == 1
