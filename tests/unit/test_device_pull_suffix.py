"""device.pull's local filename must not be steerable by the remote path.

The remote path handed to ``device.pull`` is device-controlled -- an attacker
who can influence what is on the device (or the device id it is pulled from)
influences it. ``_safe_pull_suffix`` derives only the *extension* of the local
capture name from that string, and everything else about the name is fixed by
the service, so the remote side cannot inject a path component, an absolute
path, or an NTFS alternate-data-stream into where the pulled bytes land. Pin
that: a short, plain, ASCII-alphanumeric extension is kept for readability, and
anything else -- a separator, a stream, punctuation, an over-long or non-ASCII
run, or no extension at all -- collapses to the inert ``.bin``.
"""

from __future__ import annotations

import pytest

from headless_re_mcp.core.service_device import _safe_pull_suffix


@pytest.mark.parametrize(
    ("remote", "expected"),
    [
        ("/sdcard/app.apk", ".apk"),
        ("/sdcard/log.txt", ".txt"),
        ("/data/local/tmp/lib.so", ".so"),
        # Case is preserved; the check is on the character class, not the value.
        ("photo.PNG", ".PNG"),
        # Only the final component's final extension is ever considered.
        ("/sdcard/a.tar.gz", ".gz"),
        ("libc.so.6", ".6"),
    ],
)
def test_a_plain_short_extension_is_kept(remote: str, expected: str) -> None:
    assert _safe_pull_suffix(remote) == expected


@pytest.mark.parametrize(
    "remote",
    [
        # No extension at all -- a bare name, a directory, an empty string.
        "/sdcard/dumpfile",
        "/sdcard/",
        "",
        # A leading-dot name is a hidden file, not an extension.
        ".bashrc",
        # An absolute or traversal path whose final component has no extension
        # must not smuggle path structure into the suffix.
        "/etc/passwd",
        "../../etc/passwd",
    ],
)
def test_no_usable_extension_collapses_to_bin(remote: str) -> None:
    assert _safe_pull_suffix(remote) == ".bin"


@pytest.mark.parametrize(
    "remote",
    [
        # An NTFS alternate-data-stream must never reach the local name.
        "/sdcard/x.txt:evil",
        "data.bin:$DATA",
        # A backslash is a separator on the local (Windows) side; the extension
        # must not carry one.
        r"weird.a\b",
        # Punctuation that is not alphanumeric is refused, even when short.
        "/sdcard/f.a-b",
        "/sdcard/f.a_b",
        "/sdcard/f.a b",
        # An over-long run (17 chars) is past the 16-char ceiling.
        "/sdcard/x." + "a" * 17,
        # Non-ASCII, even if it looks like a tidy extension, is refused.
        "/sdcard/note.caf\u00e9",
        "/sdcard/f.\u65e5\u672c",
    ],
)
def test_a_hostile_or_unusable_suffix_collapses_to_bin(remote: str) -> None:
    assert _safe_pull_suffix(remote) == ".bin"


def test_an_extension_exactly_at_the_length_ceiling_is_kept() -> None:
    """16 alnum characters is the boundary the guard still accepts."""
    assert _safe_pull_suffix("/sdcard/f." + "a" * 16) == "." + "a" * 16
    # One past the ceiling is refused, proving the bound is 16, not "roughly".
    assert _safe_pull_suffix("/sdcard/f." + "a" * 17) == ".bin"
