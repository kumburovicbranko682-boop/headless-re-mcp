"""apk.xrefs discrimination gate: xrefs must reflect the real call graph.

androguard's DEX analysis has live coverage that a *called* method resolves to
its caller. The failure mode that positive check cannot see is xrefs that stops
discriminating -- returning every method, or an empty list, regardless of the
call graph -- which still satisfies "the known caller is present". This gate
pins the other side: on a DEX whose call graph is known exactly, a called
method reports precisely its call sites while methods nobody calls report none,
so an implementation that lost the ability to tell them apart fails here.

The fixture is a real ``classes.dex`` (assembled once with smali, embedded as
base64 so the gate needs only androguard at run time -- no smali, no aapt2, no
Android SDK). Its call graph::

    class com.gate.Helper { static int doWork(); static int unused(); }
    class com.gate.Main   { static int run() { doWork(); doWork(); } }

so ``doWork`` has exactly two call sites (both in ``Main.run``), while
``unused`` and ``run`` have none. androguard's ``AnalyzeAPK`` analyses the DEX
inside the archive without needing a binary manifest, so a lone ``classes.dex``
in a zip exercises the whole path. Skip != pass: skips only when androguard is
absent, and CI installs it.
"""

from __future__ import annotations

import base64
import zipfile
from pathlib import Path

import pytest

from headless_re_mcp.backends.apk.client import ApkClient

# smali-assembled DEX for the two classes in the module docstring. Real Dalvik
# bytecode, not a hand-rolled blob: doWork() is invoked twice by run(), unused()
# and run() by nobody -- the asymmetry the assertions below depend on.
_DEX_B64 = (
    "ZGV4CjAzNQDcPad/LSzO7hoU8edTO/sJAZ3t3ByE+0BAAgAAcAAAAHhWNBIAAAAAAAAAALgBAAAHAAAAcAAAAAQAAACMAAAA"
    "AQAAAJwAAAAAAAAAAAAAAAMAAACoAAAAAgAAAMAAAABAAQAAAAEAAAABAAADAQAAFgEAACcBAAA7AQAAQwEAAEgBAAAAAAAA"
    "AQAAAAIAAAADAAAAAAAAAAAAAAAAAAAAAQAAAAQAAAABAAAABgAAAAIAAAAFAAAAAQAAAAEAAAADAAAAAAAAAP////8AAAAA"
    "pAEAAAAAAAACAAAAAQAAAAMAAAAAAAAA/////wAAAACwAQAAAAAAAAFJABFMY29tL2dhdGUvSGVscGVyOwAPTGNvbS9nYXRl"
    "L01haW47ABJMamF2YS9sYW5nL09iamVjdDsABmRvV29yawADcnVuAAZ1bnVzZWQAAAAAAAAAAAABAAAAAAAAAAAAAAACAAAA"
    "EnAPAAEAAAAAAAAAAAAAAAIAAAASAA8AAgAAAAAAAAAAAAAACgAAAHEAAAAAAAoAcQAAAAAACgGwEA8AAAACAAAJ2AIBCewC"
    "AAABAAIJgAMLAAAAAAAAAAEAAAAAAAAAAQAAAAcAAABwAAAAAgAAAAQAAACMAAAAAwAAAAEAAACcAAAABQAAAAMAAACoAAAA"
    "BgAAAAIAAADAAAAAAiAAAAcAAAAAAQAAAxAAAAIAAABQAQAAASAAAAMAAABYAQAAACAAAAIAAACkAQAAABAAAAEAAAC4AQAA"
)


def _quiet_androguard() -> None:
    # androguard logs every parsed DEX map item at DEBUG through loguru;
    # silencing its namespace keeps the gate readable without touching handlers
    # other tests rely on.
    try:
        from loguru import logger

        logger.disable("androguard")
    except Exception:  # noqa: BLE001 - quiet logging is best-effort
        pass


@pytest.mark.integration
def test_apk_xrefs_reflect_the_real_call_graph(tmp_path: Path) -> None:
    client = ApkClient()
    if not client.available:
        pytest.skip("androguard not installed — xrefs discrimination Gate not run (skip != pass)")
    _quiet_androguard()

    apk = tmp_path / "fixture.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("classes.dex", base64.b64decode(_DEX_B64))

    # Sanity: the two internal classes are recovered (framework classes filtered)
    # and the method name resolves in both dotted and smali form.
    assert set(client.classes(apk)["classes"]) == {"Lcom/gate/Helper;", "Lcom/gate/Main;"}
    dotted = {m["name"] for m in client.methods(apk, "com.gate.Helper")["methods"]}
    smali = {m["name"] for m in client.methods(apk, "Lcom/gate/Helper;")["methods"]}
    assert dotted == smali == {"doWork", "unused"}

    # doWork is called twice, both from Main.run: exactly two call sites, and
    # every caller is that one method (not a smeared list of everything).
    called = client.xrefs(apk, "doWork")
    assert called["count"] == 2
    assert {(c["class"], c["method"]) for c in called["callers"]} == {("Lcom/gate/Main;", "run")}

    # The discriminator a positive-only check misses: methods nobody calls must
    # report zero callers. xrefs that returned everything (or a fixed list)
    # would fail here while still "finding" doWork's caller above.
    for uncalled in ("unused", "run"):
        result = client.xrefs(apk, uncalled)
        assert result["count"] == 0, uncalled
        assert result["callers"] == []
        assert result["has_more"] is False

    # A method that exists nowhere is also empty, not an error.
    absent = client.xrefs(apk, "no_such_method")
    assert absent["count"] == 0

    # limit is honoured and admitted: the second call site is withheld with
    # has_more True rather than silently dropped.
    capped = client.xrefs(apk, "doWork", limit=1)
    assert capped["count"] == 1
    assert capped["has_more"] is True
