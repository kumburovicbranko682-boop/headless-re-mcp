"""classify_target routes an incoming target to the PE / APK / WEB line.

It is the front door of the multi-line analyzer: the wrong verdict hands a
target to the wrong backend, and because a stated suffix is trusted over
content, a misjudged name can send a file down the wrong line before anything
reads it. Existing tests pin a .apk, a manifest-bearing zip named .bin, a plain
zip, two URLs, .js, and an \\x00asm blob; this fills the rest of the matrix:

* the full APK and WEB suffix sets (only .apk / .js were pinned before), case
  folded so ``.APK`` still lands on the APK line;
* the ``MZ`` magic-byte fallback used when the name carries no known suffix,
  which must stay PE (the original, most-specific "not a PE" error);
* the unreadable / missing path guard that fails to PE rather than raising;
* the documented extension-first precedence -- a stated suffix wins even when
  the bytes say otherwise, so content is never read for a named target;
* ``is_http_url``'s scheme gate: http(s) in any case is web, and nothing else
  is (the primitive behind the browser's file://-and-friends refusal).
"""

from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from headless_re_mcp.core.session import TargetKind, classify_target, is_http_url


@pytest.mark.parametrize("suffix", [".apk", ".aab", ".apks", ".xapk", ".APK", ".Xapk"])
def test_every_apk_suffix_routes_to_the_apk_line(suffix: str) -> None:
    # Suffix routing reads only the name, so no file needs to exist on disk.
    assert classify_target(f"/some/where/app{suffix}") is TargetKind.APK


@pytest.mark.parametrize(
    "suffix", [".js", ".mjs", ".cjs", ".wasm", ".html", ".htm", ".har", ".JS", ".Html"]
)
def test_every_web_suffix_routes_to_the_web_line(suffix: str) -> None:
    assert classify_target(f"/some/where/asset{suffix}") is TargetKind.WEB


def test_mz_magic_without_a_known_suffix_stays_pe(tmp_path: Path) -> None:
    blob = tmp_path / "payload.bin"
    blob.write_bytes(b"MZ\x90\x00\x03\x00\x00\x00")
    assert classify_target(blob) is TargetKind.PE


def test_unknown_content_without_a_known_suffix_defaults_to_pe(tmp_path: Path) -> None:
    """Bytes matching no magic (not MZ, not \\x00asm, not a PK archive) fall to
    the PE default so the original "not a PE file" error is what a caller sees."""
    blob = tmp_path / "mystery.bin"
    blob.write_bytes(b"\xde\xad\xbe\xef not a known header")
    assert classify_target(blob) is TargetKind.PE


def test_a_missing_unreadable_path_falls_back_to_pe(tmp_path: Path) -> None:
    """A name with no known suffix that cannot be opened must not raise; the
    OSError is swallowed into the PE default."""
    assert classify_target(tmp_path / "does-not-exist.bin") is TargetKind.PE


def test_a_stated_web_suffix_wins_over_pe_content(tmp_path: Path) -> None:
    """Extension is the caller's stated intent, so a .js file is the web line
    even when its bytes are a PE image -- the content is never sniffed."""
    bundle = tmp_path / "bundle.js"
    bundle.write_bytes(b"MZ\x90\x00 this is really a PE, but named .js")
    assert classify_target(bundle) is TargetKind.WEB


def test_a_stated_apk_suffix_wins_over_non_zip_content(tmp_path: Path) -> None:
    """A .apk that is not even a zip still routes to the APK line on its name;
    the APK backend then fails closed on its own not-a-zip guard, rather than
    the file being silently handed to the PE line."""
    fake = tmp_path / "app.apk"
    fake.write_text("plain text, not a zip", encoding="utf-8")
    assert classify_target(fake) is TargetKind.APK


def test_a_manifest_zip_named_apk_is_apk_by_suffix_before_content(tmp_path: Path) -> None:
    """Sanity: a real APK-shaped zip under an APK suffix is APK. Paired with the
    unnamed-zip case elsewhere, this shows suffix and magic agree here."""
    archive = tmp_path / "real.apk"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("AndroidManifest.xml", "x")
    assert classify_target(archive) is TargetKind.APK


def test_http_urls_classify_as_web_in_any_case() -> None:
    assert classify_target("https://example.com/app") is TargetKind.WEB
    assert classify_target("HTTPS://EXAMPLE.COM") is TargetKind.WEB
    assert classify_target("HtTp://127.0.0.1:8080/x") is TargetKind.WEB


def test_is_http_url_accepts_only_http_schemes() -> None:
    assert is_http_url("http://x") is True
    assert is_http_url("https://x") is True
    assert is_http_url("HTTP://x") is True
    # Everything the browser guard exists to refuse must read as not-a-web-URL.
    assert is_http_url("file:///etc/passwd") is False
    assert is_http_url("ftp://host/f") is False
    assert is_http_url("chrome://version") is False
    assert is_http_url("javascript:alert(1)") is False
    assert is_http_url("data:text/html,<b>") is False
    assert is_http_url("") is False
