"""apk.open live gate: numeric SDK/version fields come back as ints.

androguard reads every AndroidManifest.xml attribute out of the binary AXML as
a *string*, so ``get_androidversion_code()``, ``get_min_sdk_version()`` and
``get_target_sdk_version()`` return "7", "21", "34" -- not the integers Android
defines those fields to be. Handed back verbatim, a caller comparing SDK levels
numerically ("is targetSdk >= 23?") either raises str-vs-int or, worse, compares
lexicographically, where "9" > "34" and "100" < "99" -- a silent wrong answer.
The backend now coerces the numeric ones to ``int`` while leaving ``version_name``
("1.4") a string. Every apk.open unit test fakes the parser with hand-written
strings, so only real androguard proves both that it emits strings and that the
backend turns the numeric ones into ints.

The fixture ``fixtures/android/signed_sample.apk`` is a real APK whose manifest
declares versionCode 7, versionName "1.4", minSdkVersion 21 and targetSdkVersion
34; it depends only on androguard -- no Android SDK, no emulator. The gate first
confirms androguard itself hands the SDK fields back as strings (guarding the
guard: if a future androguard starts returning ints, the coercion is moot and
this says so instead of passing vacuously), then pins that apk.open returned
them as the matching integers and kept version_name a string.

Skip != pass: the gate skips with a reason when androguard is absent and runs
for real when present. CI installs it, so a skip there is a genuine regression.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.backends.apk.client import ApkClient

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_FIXTURE = _PROJECT_ROOT / "fixtures" / "android" / "signed_sample.apk"


def _quiet_androguard() -> None:
    try:
        from loguru import logger

        logger.disable("androguard")
    except Exception:  # noqa: BLE001 - logging quiet is best-effort
        pass


@pytest.mark.integration
def test_apk_open_numeric_sdk_fields_are_ints() -> None:
    client = ApkClient()
    if not client.available:
        pytest.skip("androguard not installed — apk.open SDK Gate not run (skip != pass)")
    assert _FIXTURE.is_file(), f"fixture missing: {_FIXTURE}"
    _quiet_androguard()

    # Guard the guard: androguard really returns these as strings today. If a
    # future release starts returning ints, the coercion is a no-op and this
    # makes the test say so rather than pass for the wrong reason.
    from androguard.core.apk import APK

    raw = APK(str(_FIXTURE))
    assert isinstance(raw.get_androidversion_code(), str)
    assert isinstance(raw.get_min_sdk_version(), str)
    assert isinstance(raw.get_target_sdk_version(), str)

    payload = client.open(_FIXTURE)

    # The fix: the numeric manifest fields come back as ints with the right
    # values, so an SDK comparison is arithmetic, not lexicographic.
    assert payload["version_code"] == 7
    assert payload["min_sdk"] == 21
    assert payload["target_sdk"] == 34
    for field in ("version_code", "min_sdk", "target_sdk"):
        assert isinstance(payload[field], int) and not isinstance(payload[field], bool), (
            field,
            payload[field],
        )

    # version_name is a genuine string and is left alone.
    assert payload["version_name"] == "1.4"
    assert isinstance(payload["version_name"], str)

    # The rest of the identity still resolves.
    assert payload["opened"] is True
    assert payload["package"] == "com.example.gate"
