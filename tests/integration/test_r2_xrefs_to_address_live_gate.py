"""r2.xrefs live gate: it answers "references TO address", not the global dump.

radare2's ``axj`` prints the whole binary's cross-reference table and ignores
the ``@`` seek, so ``R2Client.xrefs`` -- which ran ``axj @ address`` -- answered
"who references this address?" with every xref in the file, the callers of the
target buried in unrelated init/plt/tm_clones noise. The seek-relative command
is ``axtj`` (references to the current address); the backend now runs that.

Every r2.xrefs unit test drives ``enrich_r2_payload`` with hand-written JSON, so
only a real radare2 proves the command switch: that ``axtj`` returns the callers
of the address and that its entries carry the ``opcode``/``fcn_name`` shape
(which ``axj`` entries lack, carrying ``addr`` instead), which is how the gate
tells the two commands apart without reading the spawned argv.

The fixture ``fixtures/elf/xref_sample`` is a tiny freestanding ELF (rebuildable
from ``xref_sample.c`` beside it) whose ``helper`` is called exactly twice from
``entry0``. The gate first reads the callers radare2 itself reports for
``axtj @ helper`` and confirms ``axj`` returns a different set -- empty on
radare2 6.2+, the whole-binary dump on older builds, never the two callers
(guarding the guard: if these ever coincide the command switch proves nothing)
-- then pins that ``r2.xrefs`` returned exactly the ``axtj`` callers in the
enriched shape.

Skip != pass: the gate skips with a reason when radare2 is absent. CI installs
it, so a skip there is a genuine regression rather than a bare machine.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from headless_re_mcp.backends.r2.client import R2Client

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_FIXTURE = _PROJECT_ROOT / "fixtures" / "elf" / "xref_sample"


def _r2_json(executable: Path, binary: Path, command: str) -> list[dict[str, object]]:
    """Run one analysis command through r2 and decode its JSON array."""
    completed = subprocess.run(
        [str(executable), "-q0", "-c", f"aa\n{command}", str(binary)],
        capture_output=True,
        timeout=60,
    )
    text = completed.stdout.decode("utf-8", errors="replace").replace("\x00", "").strip()
    if not text:
        # radare2 6.2+ prints nothing for ``axj @ addr`` (it ignores the seek and
        # has no whole-binary xref table to emit for this address) instead of an
        # empty array. Treat empty output as an empty xref set, not a parse error:
        # ``json.loads("")`` would otherwise crash the gate on modern radare2.
        return []
    value = json.loads(text)
    assert isinstance(value, list)
    return value


@pytest.mark.integration
def test_r2_xrefs_returns_callers_of_the_address_not_the_whole_binary() -> None:
    client = R2Client()
    if not client.available or client.executable is None:
        pytest.skip("radare2 not installed — r2.xrefs Gate not run (skip != pass)")
    assert _FIXTURE.is_file(), f"fixture missing: {_FIXTURE}"

    executable = client.executable

    # Resolve helper's VA from r2 itself rather than hardcoding it.
    helper_va_raw = (
        subprocess.run(
            [str(executable), "-q0", "-c", "aa\n?v sym.helper", str(_FIXTURE)],
            capture_output=True,
            timeout=60,
        )
        .stdout.decode("utf-8", errors="replace")
        .replace("\x00", "")
        .strip()
    )
    helper_va = int(helper_va_raw, 0)
    assert helper_va > 0, helper_va_raw

    # Guard the guard: axtj (references to helper) is the two calls from entry0,
    # while axj @ addr (the old command) returns a different set entirely --
    # empty on radare2 6.2+, the whole-binary dump on older builds -- never the
    # two callers. If these ever coincide, the command switch proves nothing.
    raw_axtj = _r2_json(executable, _FIXTURE, f"axtj @ {helper_va}")
    raw_axj = _r2_json(executable, _FIXTURE, f"axj @ {helper_va}")
    assert raw_axtj, "radare2 reported no references to helper; fixture/analysis changed"
    assert all(str(e.get("type")) == "CALL" for e in raw_axtj), raw_axtj
    caller_from = sorted(int(e["from"]) for e in raw_axtj)  # type: ignore[arg-type]
    assert len(caller_from) == 2, caller_from
    assert len(raw_axj) != len(raw_axtj), (len(raw_axj), len(raw_axtj))

    # The fix: r2.xrefs runs axtj, so it returns exactly helper's callers, each
    # in the axtj shape (from/opcode/fcn_name, enriched from_address/fcn_address),
    # not the global axj dump.
    payload = client.xrefs(_FIXTURE, helper_va, timeout=60)
    assert payload["commands"] == ["aa", f"axtj @ {helper_va}"]
    items = payload["items"]
    returned_from = sorted(int(item["from"]) for item in items)
    assert returned_from == caller_from

    for item in items:
        assert item["type"] == "CALL"
        # axtj entries carry opcode + fcn_name; axj entries carry addr and no
        # opcode, so this shape is what tells the two commands apart.
        assert "opcode" in item and item["opcode"].startswith("call")
        assert item["fcn_name"] == "entry0"
        assert "addr" not in item  # an axj entry would have this target field
        assert "to_address" not in item  # axtj has no forward edge
        assert item["from_address"]["va"] == int(item["from"])
        assert item["fcn_address"]["va"] == int(item["fcn_addr"])
