"""apk.permissions live gate: requested vs declared permissions from real AXML.

androguard's ``APK`` exposes two different permission sets:

* ``get_permissions()`` -- the ``<uses-permission>`` entries, i.e. the
  permissions the app *requests*; surfaced as ``permissions``.
* ``get_declared_permissions()`` -- the app's own ``<permission>`` elements,
  i.e. custom permissions the app *defines* for others; surfaced as
  ``declared_permissions``.

It has no ``get_requested_permissions()``. The old client called that
nonexistent getter, swallowed the ``AttributeError``, and echoed the requested
list under a bogus ``requested_permissions`` field -- so the declared set was
never shown and the extra field was a pure duplicate. A unit fake that
implemented the missing method hid the divergence; this gate parses a real
binary manifest instead.

The fixture ``fixtures/android/permission_sample.apk`` is built once and
committed (binary AXML needs the Android build tools). It was produced with::

    aapt2 link --manifest AndroidManifest.xml -I android.jar \
        --min-sdk-version 21 --target-sdk-version 34 -o permission_sample.apk

from a manifest for package ``com.example.permgate`` that requests
``android.permission.INTERNET`` (a ``<uses-permission>``) and declares
``com.example.permgate.CUSTOM_ACCESS`` (a ``<permission>``). The gate asserts
androguard pulled those two into the two distinct fields, so it depends only on
androguard -- no Android SDK, no emulator.

Skip != pass: the gate skips with a reason when androguard is absent and runs
for real when present. CI installs it, so a skip there is a real regression.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.backends.apk.client import ApkClient

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_FIXTURE = _PROJECT_ROOT / "fixtures" / "android" / "permission_sample.apk"

_REQUESTED = "android.permission.INTERNET"
_DECLARED = "com.example.permgate.CUSTOM_ACCESS"


def _quiet_androguard() -> None:
    try:
        from loguru import logger

        logger.disable("androguard")
    except Exception:  # noqa: BLE001 - logging quiet is best-effort
        pass


@pytest.mark.integration
def test_declared_and_requested_permissions_are_distinct() -> None:
    client = ApkClient()
    if not client.available:
        pytest.skip("androguard not installed — permissions Gate not run (skip != pass)")
    assert _FIXTURE.is_file(), f"fixture missing: {_FIXTURE}"
    _quiet_androguard()

    payload = client.permissions(_FIXTURE)

    # The <uses-permission> the app requests lands in `permissions`.
    assert _REQUESTED in payload["permissions"]
    assert payload["count"] == len(payload["permissions"])

    # The app's own <permission> definition lands in `declared_permissions`,
    # and is genuinely a different string than the requested one.
    assert _DECLARED in payload["declared_permissions"]
    assert payload["declared_count"] == len(payload["declared_permissions"])

    # The two sets do not bleed into each other: the custom permission is not a
    # uses-permission, and INTERNET is not a declared one.
    assert _DECLARED not in payload["permissions"]
    assert _REQUESTED not in payload["declared_permissions"]

    # The removed duplicate field must not reappear.
    assert "requested_permissions" not in payload
