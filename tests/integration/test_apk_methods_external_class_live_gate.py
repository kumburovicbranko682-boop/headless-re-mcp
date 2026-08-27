"""apk.methods live gate: a class only referenced (external) is not listed as ours.

androguard's ``get_classes()`` yields not only the classes the APK defines but
also the framework/library types it merely references (``Ljava/lang/Object;``,
``Landroid/...``). A ``ClassAnalysis`` for one of those carries just the handful
of methods the app happened to call, so ``apk.methods`` used to answer a request
for such a class with that referenced subset -- reading as "these are the
class's methods" when the class is not in this APK at all. ``apk.classes``
already hides external classes; ``apk.methods`` now agrees, refusing an external
class with ``not_found`` / ``external: true`` while still listing a real defined
class.

Every unit test drives a hand-written fake analysis, so only real androguard
proves that its own analysis marks a referenced type external and defines the
fixture's own class. The fixture ``fixtures/apk/xref_sample.apk`` carries a real
``classes.dex`` whose ``Lcom/example/re/Sample;`` is defined (and calls
``Ljava/lang/Object;-><init>()V``, making Object a referenced/external class).

Skip != pass: the gate skips with a reason only when androguard is absent. CI
installs it, so a skip there is a genuine regression rather than a bare machine.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.backends.apk.client import ApkClient, ApkError

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
def test_apk_methods_lists_defined_class_but_refuses_external_one() -> None:
    if not _androguard_available():
        pytest.skip("androguard not installed — apk.methods Gate not run (skip != pass)")
    assert _FIXTURE.is_file(), f"fixture missing: {_FIXTURE}"

    client = ApkClient()

    # A class the APK actually defines lists its real methods.
    defined = client.methods(_FIXTURE, "com.example.re.Sample", limit=100)
    assert defined["class_name"] == "Lcom/example/re/Sample;", defined
    names = {m["name"] for m in defined["methods"]}
    # The smali source defines exactly these five.
    assert {"<init>", "caller", "callee", "alsoCallsCallee", "lonely"} <= names, defined

    # java.lang.Object is only referenced (Sample's <init> calls it), so
    # androguard marks it external. The fix refuses it rather than returning the
    # one referenced <init> as if it were the class's method list.
    for form in ("java.lang.Object", "Ljava/lang/Object;"):
        with pytest.raises(ApkError) as caught:
            client.methods(_FIXTURE, form, limit=100)
        assert caught.value.code == "not_found", form
        assert caught.value.details.get("external") is True, form

    # Guard the guard: confirm androguard really classes Object as external, so
    # a future version that started defining it would not silently pass this.
    from androguard.misc import AnalyzeAPK

    _, _, dx = AnalyzeAPK(str(_FIXTURE))
    externing = {
        klass.name: klass.is_external()
        for klass in dx.get_classes()
        if klass.name in {"Lcom/example/re/Sample;", "Ljava/lang/Object;"}
    }
    assert externing.get("Lcom/example/re/Sample;") is False, externing
    assert externing.get("Ljava/lang/Object;") is True, externing
