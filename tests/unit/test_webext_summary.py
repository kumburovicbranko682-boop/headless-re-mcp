"""The stdlib browser-extension reader (summarize_webext) and js.webext routing.

Browser extensions are a real Web-RE target -- a common malware vector -- yet
nothing here could open one. A Chrome .crx is a small header plus a ZIP; a
Firefox .xpi is a ZIP; both carry a manifest.json whose permission surface an
analyst reads first. These tests pin that reader across the CRX2, CRX3 and
plain-zip (.xpi) framings, the manifest subset it extracts, its read-not-extract
discipline (names and sizes without decompressing), its precise handling of a
missing or malformed manifest, its refusal of a non-archive, and the service
routing that turns a bad file into an envelope rather than a fault.
"""

from __future__ import annotations

import io
import json
import struct
import zipfile
from dataclasses import replace
from pathlib import Path

import pytest

from headless_re_mcp.backends.common.webext import WebExtParseError, summarize_webext
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService

_CHROME_MANIFEST = {
    "manifest_version": 3,
    "name": "Demo Ext",
    "version": "1.2.3",
    "description": "a demo",
    "permissions": ["storage", "tabs", "cookies"],
    "host_permissions": ["https://*/*"],
    "optional_permissions": ["bookmarks"],
    "background": {"service_worker": "background.js"},
    "content_scripts": [{"matches": ["https://example.com/*"], "js": ["content.js"]}],
    "content_security_policy": {"extension_pages": "script-src 'self'"},
}


def _zip_bytes(manifest: dict | str | None, extra: dict | None = None) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as archive:
        if isinstance(manifest, str):
            archive.writestr("manifest.json", manifest)
        elif manifest is not None:
            archive.writestr("manifest.json", json.dumps(manifest))
        archive.writestr("background.js", "console.log(1)")
        archive.writestr("content.js", "// cs")
        archive.writestr("popup.html", "<html></html>")
        archive.writestr("lib/vendor.wasm", b"\x00asm\x01\x00\x00\x00")
        for name, body in (extra or {}).items():
            archive.writestr(name, body)
    return buf.getvalue()


def _crx3(zip_bytes: bytes, header: bytes = b"\x0a\x04demo") -> bytes:
    return b"Cr24" + struct.pack("<I", 3) + struct.pack("<I", len(header)) + header + zip_bytes


def _crx2(zip_bytes: bytes, pubkey: bytes = b"PUBKEY", sig: bytes = b"SIG") -> bytes:
    return (
        b"Cr24"
        + struct.pack("<I", 2)
        + struct.pack("<I", len(pubkey))
        + struct.pack("<I", len(sig))
        + pubkey
        + sig
        + zip_bytes
    )


def test_crx3_manifest_and_listing() -> None:
    out = summarize_webext(_crx3(_zip_bytes(_CHROME_MANIFEST)))
    assert out["format"] == "crx"
    assert out["crx_version"] == 3
    assert out["is_extension"] is True
    assert out["entry_count"] == 5
    assert out["suffix_counts"]["js"] == 2
    assert out["suffix_counts"]["wasm"] == 1
    manifest = out["manifest"]
    assert manifest["name"] == "Demo Ext"
    assert manifest["version"] == "1.2.3"
    assert manifest["manifest_version"] == 3
    assert manifest["permissions"] == ["storage", "tabs", "cookies"]
    assert manifest["host_permissions"] == ["https://*/*"]
    assert manifest["optional_permissions"] == ["bookmarks"]
    assert manifest["background"] == {"type": "service_worker", "value": "background.js"}
    assert manifest["content_security_policy"] == {"extension_pages": "script-src 'self'"}
    assert manifest["content_scripts"] == [
        {"matches": ["https://example.com/*"], "js": ["content.js"]}
    ]
    assert manifest["content_scripts_count"] == 1


def test_crx2_framing() -> None:
    out = summarize_webext(_crx2(_zip_bytes(_CHROME_MANIFEST)))
    assert out["format"] == "crx"
    assert out["crx_version"] == 2
    assert out["is_extension"] is True
    assert out["manifest"]["name"] == "Demo Ext"


def test_plain_zip_xpi_and_firefox_id() -> None:
    manifest = dict(_CHROME_MANIFEST)
    manifest["browser_specific_settings"] = {"gecko": {"id": "demo@example.org"}}
    out = summarize_webext(_zip_bytes(manifest))
    assert out["format"] == "zip"
    assert out["crx_version"] is None
    assert out["is_extension"] is True
    assert out["manifest"]["firefox_id"] == "demo@example.org"


def test_mv2_background_scripts_and_string_csp() -> None:
    manifest = {
        "manifest_version": 2,
        "name": "Legacy",
        "version": "0.1",
        "background": {"scripts": ["bg1.js", "bg2.js"]},
        "content_security_policy": "script-src 'self'; object-src 'self'",
    }
    out = summarize_webext(_zip_bytes(manifest))
    assert out["manifest"]["background"] == {"type": "scripts", "value": ["bg1.js", "bg2.js"]}
    assert out["manifest"]["content_security_policy"] == "script-src 'self'; object-src 'self'"


def test_archive_without_manifest_is_not_an_extension() -> None:
    out = summarize_webext(_zip_bytes(None))
    assert out["is_extension"] is False
    assert out["manifest"] is None
    assert out["manifest_error"] is None
    assert out["entry_count"] == 4  # background/content/popup/wasm, no manifest


def test_malformed_manifest_is_a_precise_error_not_a_crash() -> None:
    out = summarize_webext(_zip_bytes("<<<not json>>>"))
    assert out["is_extension"] is False
    assert out["manifest"] is None
    assert out["manifest_error"] and "manifest.json" in out["manifest_error"]


def test_manifest_that_is_a_json_array_is_rejected_cleanly() -> None:
    out = summarize_webext(_zip_bytes("[1, 2, 3]"))
    assert out["is_extension"] is False
    assert out["manifest_error"] == "manifest.json is not a JSON object"


def test_wrong_typed_manifest_members_do_not_raise() -> None:
    manifest = {"manifest_version": "3", "name": 123, "permissions": "nope",
                "content_scripts": "nope", "background": "nope"}
    out = summarize_webext(_zip_bytes(manifest))
    assert out["manifest"]["manifest_version"] is None
    assert out["manifest"]["permissions"] == []
    assert out["manifest"]["content_scripts"] == []
    assert out["manifest"]["background"] is None


@pytest.mark.parametrize(
    "blob",
    [
        b"",
        b"abc",
        b"hello world, not an archive",
        b"Cr24" + struct.pack("<I", 3),  # truncated CRX header
        b"Cr24" + struct.pack("<I", 3) + struct.pack("<I", 999999) + b"xx",  # bad offset
        b"Cr24" + struct.pack("<I", 9) + struct.pack("<I", 0),  # unsupported version
    ],
)
def test_non_archives_raise(blob: bytes) -> None:
    with pytest.raises(WebExtParseError):
        summarize_webext(blob)


# --- service routing ----------------------------------------------------------


def _service(tmp_path: Path) -> AnalysisService:
    return AnalysisService(replace(Settings.load(), artifact_root=tmp_path / "artifacts"))


def test_service_reads_a_crx(tmp_path: Path) -> None:
    ext = tmp_path / "demo.crx"
    ext.write_bytes(_crx3(_zip_bytes(_CHROME_MANIFEST)))
    result = _service(tmp_path).js_webext(str(ext))
    assert result.ok, result.model_dump(mode="json")
    assert result.data["is_extension"] is True
    assert result.data["manifest"]["name"] == "Demo Ext"


def test_service_reads_an_xpi(tmp_path: Path) -> None:
    ext = tmp_path / "demo.xpi"
    ext.write_bytes(_zip_bytes(_CHROME_MANIFEST))
    result = _service(tmp_path).js_webext(str(ext))
    assert result.ok, result.model_dump(mode="json")
    assert result.data["format"] == "zip"


def test_service_refuses_a_non_archive(tmp_path: Path) -> None:
    ext = tmp_path / "demo.crx"
    ext.write_bytes(b"not an archive at all")
    result = _service(tmp_path).js_webext(str(ext))
    assert not result.ok
    assert result.error.code == "invalid_params"


def test_service_reports_missing_file(tmp_path: Path) -> None:
    result = _service(tmp_path).js_webext(str(tmp_path / "nope.crx"))
    assert not result.ok
    assert result.error.code == "not_found"


def test_service_refuses_oversized_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import headless_re_mcp.backends.jsre.client as client

    monkeypatch.setattr(client, "_MAX_INPUT_BYTES", 8)
    ext = tmp_path / "demo.crx"
    ext.write_bytes(_crx3(_zip_bytes(_CHROME_MANIFEST)))
    result = _service(tmp_path).js_webext(str(ext))
    assert not result.ok
    assert result.error.code == "too_large"
