"""apk.xrefs live gate: an empty caller list is "uncalled" only if a method matched.

apk.xrefs enumerates the callers of every internal method sharing a name. When
it found none it returned an empty list either way -- for a real method nobody
calls *and* for a name that matches no method at all (a typo, a renamed or
obfuscated method, the dotted-vs-smali confusion). Those are different findings:
"this method is dead code" versus "you asked about something that is not here".
The backend now reports ``matched_methods`` -- 0 means the name resolved to
nothing, so an empty list is not read as "never called".

Every unit test drives a hand-written fake analysis, so only real androguard
proves that its own cross-reference pass resolves a genuine call graph the way
the count claims. The fixture ``fixtures/apk/xref_sample.apk`` carries a real
``classes.dex`` (rebuildable from ``xref_sample.smali`` via ``xref_sample_gen.py``)
where ``callee`` is invoked by two methods, ``lonely`` exists but is never
called, and no method is named ``doesNotExist``.

Skip != pass: the gate skips with a reason only when androguard is absent. CI
installs it, so a skip there is a genuine regression rather than a bare machine.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.backends.apk.client import ApkClient

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_FIXTURE = _PROJECT_ROOT / "fixtures" / "apk" / "xref_sample.apk"


def _androguard_available() -> bool:
    try:
        import androguard  # noqa: F401
        from androguard.misc import AnalyzeAPK  # noqa: F401
    except Exception:
        return False
    return True


@pytest.mark.integration
def test_apk_xrefs_distinguishes_called_uncalled_and_absent() -> None:
    if not _androguard_available():
        pytest.skip("androguard not installed — apk.xrefs Gate not run (skip != pass)")
    assert _FIXTURE.is_file(), f"fixture missing: {_FIXTURE}"

    client = ApkClient()

    # A method that is really called: two callers, and the name resolved to it.
    called = client.xrefs(_FIXTURE, "callee", limit=100)
    assert called["matched_methods"] == 1, called
    assert called["count"] == 2, called
    caller_methods = sorted(c["method"] for c in called["callers"])
    assert caller_methods == ["alsoCallsCallee", "caller"], called
    # The callers live in the fixture's own class, resolved by androguard.
    assert all(c["class"] == "Lcom/example/re/Sample;" for c in called["callers"]), called

    # A method that exists but nobody calls: the name resolved (matched 1), yet
    # there are no callers. This is the case that used to look identical to a
    # name that is simply not there.
    uncalled = client.xrefs(_FIXTURE, "lonely", limit=100)
    assert uncalled["matched_methods"] == 1, uncalled
    assert uncalled["count"] == 0, uncalled
    assert uncalled["callers"] == [], uncalled

    # A name that matches no method at all: matched 0 says the empty list is not
    # "never called" but "no such method".
    absent = client.xrefs(_FIXTURE, "doesNotExist", limit=100)
    assert absent["matched_methods"] == 0, absent
    assert absent["count"] == 0, absent
    assert absent["callers"] == [], absent

    # The fix's whole point: uncalled and absent are no longer the same answer.
    assert uncalled["matched_methods"] != absent["matched_methods"]
