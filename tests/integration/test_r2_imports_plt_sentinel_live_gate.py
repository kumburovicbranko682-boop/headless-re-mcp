"""r2.imports live gate: a stub-less import is not rendered at the null address.

radare2's ``iij`` reports every import, and it marks one with no PLT stub in a
way that is not an address: older radare2 sets ``plt`` to 0, while radare2 6.2+
omits ``plt`` entirely. The loader entry ``__libc_start_main`` and a weak
``__gmon_start__`` on any glibc-linked ELF are both stub-less like this. That 0
(or absence) is a marker, not a location. ``enrich_r2_payload`` used to feed a
``plt`` of 0 straight into an ``Address``, so those imports came back as living
at ``va 0``: an invented call target a reverse engineer could chase into
nothing. The mapping now skips r2's sentinels, so a stub-less import carries no
``address`` while a real stub keeps its VA.

Every unit test drives ``enrich_r2_payload`` with hand-written JSON, so only a
real radare2 proves that its own ``iij`` marks these imports stub-less (however
the installed version spells it) and that the backend surfaces them without a
fabricated address. The fixture ``fixtures/elf/imports_sample`` is a tiny
stripped ELF (rebuildable from ``imports_sample.c`` beside it) linked against
libc, so ``iij`` reports a mix: ``printf``/``strlen`` resolve through the PLT
(a non-zero ``plt``) and ``__libc_start_main``/``__gmon_start__`` do not
(``plt`` 0 on older radare2, omitted on 6.2+).

Skip != pass: the gate skips with a reason only when radare2 is absent. CI
installs it, so a skip there is a genuine regression rather than a bare machine.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.backends.r2.client import R2Client

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_FIXTURE = _PROJECT_ROOT / "fixtures" / "elf" / "imports_sample"


@pytest.mark.integration
def test_r2_imports_omits_address_for_stubless_imports() -> None:
    client = R2Client()
    if not client.available or client.executable is None:
        pytest.skip("radare2 not installed — r2.imports Gate not run (skip != pass)")
    assert _FIXTURE.is_file(), f"fixture missing: {_FIXTURE}"

    payload = client.run(_FIXTURE, ["iij"], timeout=60)
    items = payload["items"]
    assert items, "radare2 reported no imports; fixture/toolchain changed"

    by_name = {str(entry.get("name")): entry for entry in items}

    # Guard the guard: the fixture must actually exercise both cases, or a pass
    # proves nothing. A stub-less import has no truthy ``plt`` (older radare2
    # sets it to 0, radare2 6.2+ omits it); a stubbed one has a non-zero ``plt``.
    # Every glibc-linked ELF gives this mix.
    stubless = [name for name, entry in by_name.items() if not entry.get("plt")]
    with_stub = [name for name, entry in by_name.items() if entry.get("plt")]
    assert stubless, f"no stub-less import in fixture: {sorted(by_name)}"
    assert with_stub, f"no stubbed import in fixture: {sorted(by_name)}"

    # The fix: a stub-less import carries no fabricated address. radare2's own
    # sentinel (a ``plt`` of 0, or an omitted ``plt`` on 6.2+) never becomes va 0.
    for name in stubless:
        entry = by_name[name]
        assert "address" not in entry, (name, entry.get("address"))
        assert not entry.get("plt"), (name, entry.get("plt"))

    # An import with a real PLT stub still resolves to a va matching its plt.
    for name in with_stub:
        entry = by_name[name]
        assert entry["address"]["va"] == entry["plt"], (name, entry)
