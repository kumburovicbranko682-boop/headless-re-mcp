"""Android package validation must be identical across the adb and frida backends.

``device.packages`` / ``device.launch`` / ``force_stop`` / ``uninstall`` (adb) and
``frida.spawn`` (frida) all take an Android package id, and each backend validates
it with its *own copy* of the same regex -- adb ``_PACKAGE_RE``, frida
``_ANDROID_PACKAGE_RE`` -- after the same ``.strip()``. The two are byte-identical
today but live in separate files with no link, so tightening or loosening one
silently drifts from the other:

* workflow continuity -- an agent lists installs with ``device.packages`` (adb
  validates every name it returns) and then ``frida.spawn``s one; if frida's copy
  rejects a name adb accepts, the obvious next step fails on a value the platform
  itself produced;
* security -- both values reach an ``adb shell`` / ``su -c`` command line, so the
  regex is the injection boundary. If one copy stops rejecting a metacharacter the
  other still forbids, the two Android backends disagree on what is safe to run.

No test bound them. This pins the pattern equal (they are meant to be the same
constant) and pins the accept/reject contract -- valid ids through, malformed and
shell-metacharacter names out -- for *both* regexes, so a drift on either side is
a failing test rather than a workflow break or an injection gap.
"""

from __future__ import annotations

import pytest

from headless_re_mcp.backends.adb.client import _PACKAGE_RE as _ADB_PACKAGE_RE
from headless_re_mcp.backends.frida.client import _ANDROID_PACKAGE_RE as _FRIDA_PACKAGE_RE

# Well-formed Android package ids: a letter-led first segment, at least one dot,
# each further segment [A-Za-z0-9_]+.
_ACCEPTED = (
    "com.example.app",
    "a.b",
    "com.example.app_name",
    "com.a1.b2.c3",
    "A.B.C",
)

# Malformed ids and shell-metacharacter payloads that must never reach a command
# line. Trailing-newline cases are omitted deliberately: the real validators
# ``.strip()`` first, and ``$`` matching before a final newline is a re quirk the
# strip neutralises, not a property of the shared regex under test.
_REJECTED = (
    "",
    "android",
    "1com.example",
    "com..example",
    "com.example.",
    "com.example app",
    "com.example;rm -rf /",
    "com.example|cat",
    "com.example&&id",
    "com.example$(whoami)",
    "com.example`id`",
    "com.example/../etc",
    "com.example\n.evil",
    "com.example'q",
)


def test_the_two_backends_share_one_package_pattern() -> None:
    assert _ADB_PACKAGE_RE.pattern == _FRIDA_PACKAGE_RE.pattern, (
        "adb._PACKAGE_RE and frida._ANDROID_PACKAGE_RE are meant to be the same "
        "Android package validator but their patterns diverged; a name one accepts "
        "the other may reject across the device.packages -> frida.spawn workflow"
    )


@pytest.mark.parametrize("name", _ACCEPTED)
def test_a_valid_package_is_accepted_by_both(name: str) -> None:
    assert _ADB_PACKAGE_RE.match(name) is not None
    assert _FRIDA_PACKAGE_RE.match(name) is not None


@pytest.mark.parametrize("name", _REJECTED)
def test_a_malformed_or_injecting_package_is_rejected_by_both(name: str) -> None:
    assert _ADB_PACKAGE_RE.match(name) is None
    assert _FRIDA_PACKAGE_RE.match(name) is None
