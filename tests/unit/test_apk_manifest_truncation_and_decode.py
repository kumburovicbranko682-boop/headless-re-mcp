"""``apk.manifest`` returns the decoded AXML whole, cuts only past the cap, and fails cleanly.

``manifest`` decodes the binary ``AndroidManifest.xml`` to text, then bounds it::

    try:
        xml = apk.get_android_manifest_axml().get_xml().decode("utf-8", "replace");
    except Exception as exc:
        raise ApkError("backend_error", f"failed to decode manifest: {exc}") from exc;
    return {
        "package": apk.get_package(),
        "manifest_xml": xml[:_MAX_MANIFEST_CHARS],
        "truncated": len(xml) > _MAX_MANIFEST_CHARS,
    };

Both existing ``manifest`` tests (the field-names test and the resource-bounds
test) feed the *same* oversized body -- ``b"<manifest/>" * (_MAX//10 + 20)`` --
so they only ever observe the truncated branch: ``truncated`` is always True and
the XML is always cut to exactly the cap. Four behaviours a single oversized
fixture cannot show:

* **A normal manifest comes back whole and unflagged.** The overwhelming common
  case is a manifest far under the 200 000-char cap; it must return verbatim with
  ``truncated`` False. Nothing observes the False side, so hardcoding ``truncated``
  True -- or otherwise always cutting -- would pass the existing tests while
  silently claiming every manifest was truncated.

* **The cut is ``>``, not ``>=``: a manifest exactly at the cap is not truncated.**
  ``len(xml) > _MAX`` means a body of exactly ``_MAX`` chars is complete, not cut.
  A body 200 000 chars over the cap can never tell ``>`` from ``>=``; the boundary
  is only visible at exactly the cap and one past it.

* **A manifest that cannot be decoded is a structured ``backend_error``.** A repacked
  or corrupt APK can make ``get_android_manifest_axml`` or ``get_xml`` throw; the
  ``except`` turns that into an ``ApkError`` naming the cause rather than letting a
  raw androguard exception escape the tool. The existing fixtures never raise.

* **Undecodable bytes become replacement chars, not a failure.** ``decode(...,
  "replace")`` means stray non-UTF-8 bytes in the manifest yield U+FFFD and the
  call still succeeds; a strict decode would instead route a readable manifest
  into the error path. The existing bodies are pure ASCII.

These drive ``ApkClient.manifest`` through fake APKs -- no androguard, no AXML --
using the real ``_MAX_MANIFEST_CHARS`` so the boundary is the true one.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.backends.apk.client import _MAX_MANIFEST_CHARS, ApkClient, ApkError


class _ManifestApk:
    """A fake APK whose manifest bytes (or a raising accessor) the test chooses."""

    def __init__(self, xml_bytes: bytes, *, raise_at: str | None = None) -> None:
        self._xml_bytes = xml_bytes
        self._raise_at = raise_at

    def get_android_manifest_axml(self) -> object:
        if self._raise_at == "axml":
            raise RuntimeError("no AndroidManifest.xml in this archive")
        body = self

        class _Body:
            def get_xml(self) -> bytes:
                if body._raise_at == "get_xml":
                    raise ValueError("corrupt AXML string pool")
                return body._xml_bytes

        return _Body()

    def get_package(self) -> str:
        return "com.example.app"


def _manifest(xml_bytes: bytes, *, raise_at: str | None = None) -> dict:
    client = ApkClient()
    client._apk = lambda _path: _ManifestApk(xml_bytes, raise_at=raise_at)  # type: ignore[method-assign]
    return client.manifest(Path("app.apk"))


def test_a_small_manifest_is_returned_whole_and_not_flagged_truncated() -> None:
    """A manifest well under the cap comes back verbatim with truncated False.

    This is the common case the oversized fixtures never exercise: the returned
    text is the entire manifest, byte for byte, and ``truncated`` is False.
    """
    body = b'<manifest xmlns:android="..." package="com.example.app"><application/></manifest>'
    payload = _manifest(body)

    assert payload["truncated"] is False
    assert payload["manifest_xml"] == body.decode("utf-8")
    assert payload["package"] == "com.example.app"


def test_a_manifest_exactly_at_the_cap_is_not_truncated() -> None:
    """A body of exactly ``_MAX_MANIFEST_CHARS`` is complete, not cut.

    ``len(xml) > _MAX`` (strictly greater) means the cap itself is still the whole
    manifest -- the boundary a ``>=`` mutation would get wrong.
    """
    body = ("a" * _MAX_MANIFEST_CHARS).encode("utf-8")
    payload = _manifest(body)

    assert payload["truncated"] is False
    assert len(payload["manifest_xml"]) == _MAX_MANIFEST_CHARS


def test_a_manifest_one_char_over_the_cap_is_cut_and_flagged() -> None:
    """One character past the cap flips ``truncated`` True and cuts to the cap.

    The mirror of the exact-cap case: at ``_MAX + 1`` the ``>`` fires, the text is
    sliced to the cap, and the flag is set.
    """
    body = ("a" * (_MAX_MANIFEST_CHARS + 1)).encode("utf-8")
    payload = _manifest(body)

    assert payload["truncated"] is True
    assert len(payload["manifest_xml"]) == _MAX_MANIFEST_CHARS


@pytest.mark.parametrize("raise_at", ["axml", "get_xml"])
def test_a_manifest_that_cannot_be_decoded_is_a_backend_error(raise_at: str) -> None:
    """A raising axml accessor or ``get_xml`` becomes a structured backend_error.

    A corrupt/repacked APK must not leak a raw androguard exception out of the
    tool; the ``except`` wraps it in an ApkError that names the failure.
    """
    with pytest.raises(ApkError) as caught:
        _manifest(b"<manifest/>", raise_at=raise_at)

    assert caught.value.code == "backend_error"
    assert "failed to decode manifest" in caught.value.message


def test_undecodable_bytes_become_replacement_chars_not_a_crash() -> None:
    """Stray non-UTF-8 bytes yield U+FFFD and the call still succeeds.

    ``decode(..., "replace")`` keeps a manifest with a few bad bytes readable
    instead of routing it into the error path a strict decode would trigger.
    """
    body = b'<manifest \xff\xfe package="com.example.app"/>'
    payload = _manifest(body)

    assert "\ufffd" in payload["manifest_xml"]
    assert payload["truncated"] is False
    assert payload["package"] == "com.example.app"
