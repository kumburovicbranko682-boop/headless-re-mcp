"""Pure-stdlib inspector for a packaged browser extension (.crx / .xpi / .zip).

Browser extensions are a real Web reverse-engineering target -- a common malware
vector -- yet nothing here could open one. A Chrome ``.crx`` is a small header
followed by a plain ZIP; a Firefox ``.xpi`` is a plain ZIP; both carry a
``manifest.json`` whose permissions, host permissions, background worker,
content scripts and CSP are the security-critical surface an analyst reads
first. summarize_webext cracks that open with the stdlib alone -- no unzip, no
browser -- reporting the manifest subset and the archive's file listing so the
analyst can see the attack surface (which scripts, whether there is WASM or an
obfuscated bundle) before extracting anything.

It reads, it does not extract: the file names and sizes come from the ZIP
central directory without decompressing, and only ``manifest.json`` is inflated
(under a size cap). The CRX2 and CRX3 headers are decoded exactly to find the
embedded ZIP; a file that is neither is refused as a precise error. Every list
is bounded.
"""

from __future__ import annotations

import io
import json
import zipfile
from collections import Counter
from posixpath import splitext
from typing import Any

JsonObject = dict[str, Any]

_CRX_MAGIC = b"Cr24"

# A stringy field, and the number of names/permissions listed, are bounded so a
# pathological archive or manifest cannot inflate a reply.
_MAX_FIELD = 4096
_MAX_LISTED = 2048
_MAX_PERMS = 256
_MAX_CONTENT_SCRIPTS = 64
_MAX_INNER = 64
_MAX_SUFFIXES = 64
# The central directory is walked, never fully decompressed, but a crafted
# archive could still claim an enormous entry count; cap the scan.
_MAX_SCAN_ENTRIES = 200_000
# manifest.json is the one entry inflated; refuse a bomb-sized one up front.
_MANIFEST_MAX_BYTES = 8 * 1024 * 1024


class WebExtParseError(ValueError):
    """Bytes that are not a browser extension package.

    A ValueError subclass so a caller that funnels ValueError into an
    ``invalid_request`` envelope keeps working, while one that wants the more
    precise ``invalid_params`` can catch this type by name.
    """


def _clip(value: object) -> str:
    text = str(value if value is not None else "")
    return text[:_MAX_FIELD] if len(text) > _MAX_FIELD else text


def _clip_list(value: object, cap: int) -> list[str]:
    if not isinstance(value, list):
        return []
    return [_clip(item) for item in value[:cap]]


def _zip_offset(data: bytes) -> int:
    """Byte offset of the embedded ZIP in a CRX, decoding the v2 or v3 header.

    Raises WebExtParseError when the header is truncated or the version is one
    this does not model.
    """
    if len(data) < 12:
        raise WebExtParseError("truncated CRX header")
    version = int.from_bytes(data[4:8], "little")
    if version == 2:
        if len(data) < 16:
            raise WebExtParseError("truncated CRX2 header")
        pubkey_len = int.from_bytes(data[8:12], "little")
        sig_len = int.from_bytes(data[12:16], "little")
        offset = 16 + pubkey_len + sig_len
    elif version == 3:
        header_size = int.from_bytes(data[8:12], "little")
        offset = 12 + header_size
    else:
        raise WebExtParseError(f"unsupported CRX version {version}")
    if offset > len(data):
        raise WebExtParseError("CRX header points past the end of the file")
    return offset


def _manifest_background(value: object) -> JsonObject | None:
    """The manifest's background entry point, whichever of the three forms it uses."""
    if not isinstance(value, dict):
        return None
    worker = value.get("service_worker")
    if isinstance(worker, str):
        return {"type": "service_worker", "value": _clip(worker)}
    scripts = value.get("scripts")
    if isinstance(scripts, list):
        return {"type": "scripts", "value": _clip_list(scripts, _MAX_INNER)}
    page = value.get("page")
    if isinstance(page, str):
        return {"type": "page", "value": _clip(page)}
    return None


def _manifest_csp(value: object) -> Any:
    """content_security_policy, an object in MV3 and a bare string in MV2."""
    if isinstance(value, dict):
        return {k: _clip(v) for k, v in list(value.items())[:16] if isinstance(v, str)}
    if isinstance(value, str):
        return _clip(value)
    return None


def _gecko_id(document: JsonObject) -> str:
    """The Firefox add-on id from either settings key, or '' when absent."""
    for key in ("browser_specific_settings", "applications"):
        block = document.get(key)
        if isinstance(block, dict):
            gecko = block.get("gecko")
            if isinstance(gecko, dict) and isinstance(gecko.get("id"), str):
                return _clip(gecko["id"])
    return ""


def _summarize_manifest(document: JsonObject) -> JsonObject:
    """The security-relevant subset of a WebExtension manifest, defensively read."""
    scripts = document.get("content_scripts")
    content_scripts: list[JsonObject] = []
    if isinstance(scripts, list):
        for item in scripts[:_MAX_CONTENT_SCRIPTS]:
            if not isinstance(item, dict):
                continue
            content_scripts.append(
                {
                    "matches": _clip_list(item.get("matches"), _MAX_INNER),
                    "js": _clip_list(item.get("js"), _MAX_INNER),
                }
            )
    manifest_version = document.get("manifest_version")
    return {
        "name": _clip(document.get("name")),
        "version": _clip(document.get("version")),
        "manifest_version": manifest_version if isinstance(manifest_version, int) else None,
        "description": _clip(document.get("description")),
        "permissions": _clip_list(document.get("permissions"), _MAX_PERMS),
        "host_permissions": _clip_list(document.get("host_permissions"), _MAX_PERMS),
        "optional_permissions": _clip_list(document.get("optional_permissions"), _MAX_PERMS),
        "content_scripts": content_scripts,
        "content_scripts_count": len(scripts) if isinstance(scripts, list) else 0,
        "background": _manifest_background(document.get("background")),
        "content_security_policy": _manifest_csp(document.get("content_security_policy")),
        "firefox_id": _gecko_id(document),
    }


def summarize_webext(data: bytes) -> JsonObject:
    """Structural summary of a .crx / .xpi / .zip browser-extension package.

    A CRX header (if present) is decoded to locate the embedded ZIP; otherwise
    the bytes are treated as a plain ZIP (an .xpi). The central directory gives
    the file listing and sizes without decompressing; only manifest.json is
    inflated, under a size cap, to read the permission surface. Raises
    WebExtParseError when the bytes are not a readable archive; the caller turns
    that into the transport's invalid-input envelope.
    """
    if len(data) < 4:
        raise WebExtParseError("not a browser extension: file is too short")

    warnings: list[str] = []
    fmt = "zip"
    crx_version: int | None = None
    zip_bytes = data
    if data[:4] == _CRX_MAGIC:
        fmt = "crx"
        crx_version = int.from_bytes(data[4:8], "little")
        zip_bytes = data[_zip_offset(data) :]

    try:
        archive = zipfile.ZipFile(io.BytesIO(zip_bytes))
    except (zipfile.BadZipFile, OSError, EOFError) as exc:
        raise WebExtParseError(f"not a readable zip/crx archive: {exc}") from exc

    entries: list[str] = []
    entries_truncated = False
    total_uncompressed = 0
    entry_count = 0
    suffix_counts: Counter[str] = Counter()
    names: set[str] = set()
    with archive:
        infos = archive.infolist()
        for index, info in enumerate(infos):
            if index >= _MAX_SCAN_ENTRIES:
                warnings.append("archive has more entries than scanned; listing truncated")
                entries_truncated = True
                break
            name = info.filename
            names.add(name)
            if name.endswith("/"):
                continue
            entry_count += 1
            total_uncompressed += max(0, int(info.file_size))
            suffix = splitext(name)[1].lower().lstrip(".") or "(none)"
            if len(suffix_counts) < _MAX_SUFFIXES or suffix in suffix_counts:
                suffix_counts[suffix] += 1
            if len(entries) < _MAX_LISTED:
                entries.append(_clip(name))
            else:
                entries_truncated = True

        manifest: JsonObject | None = None
        manifest_error: str | None = None
        if "manifest.json" in names:
            try:
                info = archive.getinfo("manifest.json")
                if info.file_size > _MANIFEST_MAX_BYTES:
                    manifest_error = (
                        f"manifest.json is {info.file_size} bytes, over the "
                        f"{_MANIFEST_MAX_BYTES}-byte cap"
                    )
                else:
                    document = json.loads(
                        archive.read("manifest.json").decode("utf-8", errors="replace")
                    )
                    if isinstance(document, dict):
                        manifest = _summarize_manifest(document)
                    else:
                        manifest_error = "manifest.json is not a JSON object"
            except (
                KeyError,
                zipfile.BadZipFile,
                OSError,
                json.JSONDecodeError,
                UnicodeError,
            ) as exc:
                manifest_error = f"unreadable manifest.json: {exc}"

    return {
        "format": fmt,
        "crx_version": crx_version,
        "is_extension": manifest is not None,
        "entry_count": entry_count,
        "entries": entries,
        "entries_truncated": entries_truncated,
        "total_uncompressed_size": total_uncompressed,
        "suffix_counts": dict(suffix_counts.most_common(_MAX_SUFFIXES)),
        "manifest": manifest,
        "manifest_error": manifest_error,
        "warnings": warnings,
    }
