"""apk inspection tools refuse a zip that has no Android manifest (not an APK).

androguard parses any zip; a manifest-less one (a renamed archive, a truncated
download, a path pointing at the wrong file) yields an object whose package is
empty and whose permission / component / certificate / DEX views are all empty
-- indistinguishable from a real APK that declares none. apk.open already
rejected exactly this, but it is not a prerequisite for the inspection tools,
which each re-parse through _apk / _parsed independently and used to answer
"unsigned, no permissions, no components, no classes" off a non-APK. The parse
boundary now rejects it once, up front, so no reader reports the deceptive
empty-success.
"""

from __future__ import annotations

import zipfile
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.apk.client import ApkClient, ApkError


class _NoManifest:
    def get_package(self) -> None:
        return None


class _WithPackage:
    def get_package(self) -> str:
        return "com.example.app"


def test_the_guard_rejects_a_parse_with_no_manifest_package() -> None:
    with pytest.raises(ApkError) as caught:
        ApkClient._require_apk_manifest(_NoManifest(), Path("not-an.apk"))
    assert caught.value.code == "backend_error"
    assert "not an APK" in caught.value.message
    assert caught.value.details["package"] is None


def test_the_guard_passes_a_parse_that_declares_a_package() -> None:
    # A real APK always declares a package; the guard must be a no-op for it.
    ApkClient._require_apk_manifest(_WithPackage(), Path("app.apk"))


@pytest.mark.skipif(not ApkClient().available, reason="androguard not installed")
def test_inspection_tools_reject_a_non_apk_zip(tmp_path: Path) -> None:
    """The reproduced defect: a valid zip that is not an APK.

    Each tool used to return an empty-but-successful payload
    (``{certificates: [], v1_signed: False}``, ``{permissions: []}``,
    ``{classes: []}`` ...). They must now all fail with backend_error rather
    than let an agent     read those empties as facts about a real app.
    """
    apk = tmp_path / "fake.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("hello.txt", b"this is not an apk")
    client = ApkClient()
    calls: tuple[Any, ...] = (
        lambda: client.open(apk),
        lambda: client.certificates(apk),
        lambda: client.components(apk),
        lambda: client.native_libs(apk),
        lambda: client.permissions(apk),
        lambda: client.classes(apk),
        lambda: client.strings(apk),
        lambda: client.methods(apk, "Lcom/example/Main;"),
        lambda: client.xrefs(apk, "decrypt"),
    )
    for call in calls:
        with pytest.raises(ApkError) as caught:
            call()
        assert caught.value.code == "backend_error"
