"""In-process APK static analysis via androguard.

androguard is an optional dependency: importing it lazily keeps the whole
Android surface usable-but-degraded when it is absent, exactly like the Frida
backend. DEX analysis is expensive, so a small process-wide cache keyed by path
and mtime keeps repeated tool calls within one session from re-parsing.
"""

from __future__ import annotations

import threading
import zipfile
from collections import OrderedDict
from collections.abc import Callable
from concurrent.futures import Future
from concurrent.futures import TimeoutError as FutureTimeout
from pathlib import Path
from typing import Any, ClassVar, TypeVar
from uuid import uuid4

from headless_re_mcp.core.limits import UNREGISTERED_CAPTURE_MAX_BYTES, capped_file_size

JsonObject = dict[str, Any]
T = TypeVar("T")

# DEX analysis of a large app can take seconds and tens of MB; keep only a few
# parsed apps resident and evict the oldest.
_CACHE_LIMIT = 4
_MAX_STRING_LEN = 2000
_MAX_STRINGS_COLLECT = 5000
_MAX_CLASSES_COLLECT = 10_000
_MAX_METHODS_COLLECT = 2000
_MAX_XREFS_COLLECT = 5000
# Each string-xref caller echoes the matched constant to disambiguate a
# fragment that hit several strings; clip that echo so a page of callers to a
# long (up to _MAX_STRING_LEN) URL cannot bloat the answer.
_MAX_XREF_STRING_ECHO = 256
_MAX_NATIVE_LIBS = 256
_MAX_COMPONENT_NAMES = 256
_MAX_PERMISSIONS = 256
# The manifest attribute namespace, and the tags that declare a component whose
# export state defines the app's cross-app attack surface.
_ANDROID_NS = "{http://schemas.android.com/apk/res/android}"
_COMPONENT_TAGS = ("activity", "activity-alias", "service", "receiver", "provider")
# Per exported component, cap how many distinct intent-filter action/category
# names are listed so one filter-heavy component cannot bloat the answer.
_MAX_INTENT_NAMES = 64
_MAX_CERTIFICATES = 32
_MAX_MANIFEST_CHARS = 200_000
# Page ceilings mirror the MCP input-schema Field(le=...) bounds. They are
# enforced in the backend, not only in the schema, because the agent transport
# reaches these methods through catalog.invoke -> handler(**arguments), which
# does not run pydantic value validation: an agent's offset and limit arrive
# here unchecked. The sibling web/proxy/frida backends already clamp for the
# same reason.
_MAX_CLASSES_PAGE = 1000
_MAX_METHODS_PAGE = 1000
_MAX_STRINGS_PAGE = 2000
_MAX_XREFS_PAGE = 1000
# androguard parses and analyses in-process with no timeout of its own, unlike
# the jadx/apktool subprocess tools which take one. A hostile or pathologically
# large APK handed to APK()/AnalyzeAPK() would otherwise park the calling MCP
# worker thread for as long as the parse runs, with no honest fault -- the same
# unbounded-wait the subprocess backends already guard. Bound it on a daemon
# thread so the worker is freed and the caller gets a structured timeout. The
# parse cannot be cancelled (pure C/Python, no yield point), so a runaway one
# keeps running in the background until it finishes, but it no longer holds the
# pool hostage. Generous, since a legitimate large multidex app is still seconds
# to tens of seconds; only a stuck or absurd parse reaches this.
_PARSE_TIMEOUT_S = 300.0
# Ceiling on the total *uncompressed* size of the members androguard decompresses
# into memory (the dex files, resources.arsc and the manifest). A decompression
# bomb -- a member with a tiny compressed size but a huge uncompressed one --
# would OOM the whole process the instant zipfile inflates it, which the
# wall-clock deadline cannot prevent because the allocation happens long before
# the timeout. 512 MiB is far above any legitimate app (a large multidex app's
# dex + arsc totals a couple hundred MiB), so only a bomb reaches it.
_MAX_ANALYZE_UNCOMPRESSED_BYTES = 512 * 1024 * 1024
_ANALYSED_MEMBERS = ("AndroidManifest.xml", "resources.arsc")


class ApkError(RuntimeError):
    def __init__(self, code: str, message: str, **details: object) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details


def _run_deadline(work: Callable[[], T], *, timeout: float) -> T:
    """Run a blocking androguard call under a wall-clock deadline.

    Mirrors the Frida backend's ``_run_deadline``: the work runs on a daemon
    thread and the caller waits with ``Future.result(timeout=)``. On timeout the
    caller is freed with an ``ApkError`` while the daemon unwinds on its own.
    """
    done: Future[T] = Future()

    def run() -> None:
        try:
            done.set_result(work())
        except BaseException as exc:  # noqa: BLE001 - handed back to the caller
            if not done.done():
                done.set_exception(exc)

    thread = threading.Thread(target=run, name="androguard-parse", daemon=True)
    thread.start()
    try:
        return done.result(timeout=timeout)
    except FutureTimeout as exc:
        raise ApkError(
            "timeout",
            f"androguard did not finish within {timeout:g}s; the APK may be "
            "pathologically large or malformed",
        ) from exc


def _refuse_decompression_bomb(path: Path) -> None:
    """Refuse an APK whose analysed members would inflate past the memory cap.

    androguard decompresses classes*.dex, resources.arsc and the manifest into
    memory (via zipfile) before parsing them, so a member crafted to inflate to
    gigabytes would OOM the process at that read. The declared uncompressed size
    in the central directory is a reliable upper bound on what zipfile will
    produce -- CPython stops at it and raises on a mismatch rather than
    overrunning it (verified) -- so sum it for just those members, from metadata
    alone, and refuse before handing the file to androguard. A malformed archive
    is left for androguard to report as backend_error rather than guessed at.
    """
    total = 0
    try:
        with zipfile.ZipFile(path) as archive:
            for info in archive.infolist():
                name = info.filename
                if name in _ANALYSED_MEMBERS or (
                    name.startswith("classes") and name.endswith(".dex")
                ):
                    total += int(info.file_size)
    except (OSError, zipfile.BadZipFile):
        return
    if total > _MAX_ANALYZE_UNCOMPRESSED_BYTES:
        raise ApkError(
            "too_large",
            "APK analysed members would decompress past the in-process limit; "
            "decode it with apk.decode/apk.decompile (bounded subprocesses) instead",
            uncompressed_bytes=total,
            cap=_MAX_ANALYZE_UNCOMPRESSED_BYTES,
        )


def _page_bounds(offset: int, limit: int, *, cap: int) -> tuple[int, int]:
    """Clamp caller pagination the way the web/proxy/frida backends do.

    A negative offset turns ``values[offset:offset+limit]`` into a tail slice
    that silently returns the end of the list as page zero, and an oversized
    limit ignores the page cap. The MCP schema refuses both (offset>=0,
    limit<=cap), but the agent transport calls handlers directly without that
    validation, so bound them here as well. Returns ``(start, capped_limit)``.
    """
    start = max(0, int(offset))
    capped = max(1, min(int(limit), cap))
    return start, capped


def _sig_flag(apk: Any, name: str) -> bool:
    """Whether an androguard APK signing predicate is true, guarded.

    ``is_signed_v2``/``is_signed_v3`` may be absent on an older androguard or
    raise on a malformed signing block; either way the scheme is reported absent
    rather than breaking the whole certificates answer.
    """
    fn = getattr(apk, name, None)
    if not callable(fn):
        return False
    try:
        return bool(fn())
    except Exception:  # noqa: BLE001
        return False


def _cert_str(cert: Any, name: str) -> str:
    """A stringified certificate attribute, or "" when absent/odd-shaped.

    asn1crypto certificate objects vary across androguard versions, so each
    field is read defensively -- a datetime is rendered ISO 8601, everything
    else via str -- so one missing attribute never drops the whole certificate.
    """
    try:
        value = getattr(cert, name)
    except Exception:  # noqa: BLE001
        return ""
    if value is None:
        return ""
    iso = getattr(value, "isoformat", None)
    if callable(iso):
        try:
            return str(iso())
        except Exception:  # noqa: BLE001
            return ""
    return str(value)


def _cert_public_key(cert: Any) -> tuple[str, int | None]:
    """The signer key's algorithm and bit size, read defensively.

    A weak signer key -- 1024-bit RSA, or a legacy DSA key -- is a classic
    repackaged-malware / old-toolchain tell, so it belongs beside the hash and
    validity window in the triage answer. asn1crypto exposes these on the
    certificate's ``public_key`` (``algorithm``/``bit_size``); a version whose
    shape differs degrades to ``("", None)`` rather than dropping the whole
    certificate.
    """
    try:
        pub = cert.public_key
    except Exception:  # noqa: BLE001
        return "", None
    try:
        algo = str(pub.algorithm)
    except Exception:  # noqa: BLE001
        algo = ""
    try:
        raw = pub.bit_size
        size = int(raw) if isinstance(raw, int) else None
    except Exception:  # noqa: BLE001
        size = None
    return algo, size


def _intent_filter_names(element: Any) -> tuple[list[str], list[str]]:
    """The distinct action and category names across a component's intent-filters.

    Walks the ``<intent-filter>`` children of a component element and collects
    each ``<action>``/``<category>`` ``android:name``. Duplicates are dropped and
    each list is bounded so a filter-heavy component cannot bloat the answer;
    both lists are sorted for a stable result. An odd node shape is skipped
    rather than raising, so it never breaks the components answer.
    """
    actions: list[str] = []
    categories: list[str] = []
    for child in element:
        if getattr(child, "tag", None) != "intent-filter":
            continue
        for node in child:
            tag = getattr(node, "tag", None)
            if tag == "action":
                target = actions
            elif tag == "category":
                target = categories
            else:
                continue
            name = node.get(_ANDROID_NS + "name")
            if name is None:
                continue
            value = str(name)
            if value not in target and len(target) < _MAX_INTENT_NAMES:
                target.append(value)
    actions.sort()
    categories.sort()
    return actions, categories


def _cap_names(values: Any, limit: int) -> tuple[list[str], bool]:
    items: list[str] = []
    has_more = False
    for item in values or []:
        if len(items) >= limit:
            has_more = True
            break
        items.append(str(item))
    items.sort()
    return items, has_more


class _ParsedApk:
    __slots__ = ("apk", "analysis", "_dex")

    def __init__(self, apk: Any, analysis: Any, dex: Any) -> None:
        self.apk = apk
        self.analysis = analysis
        self._dex = dex


class ApkClient:
    """Bounded androguard operations over one APK path."""

    # Process-wide, and reached from several threads at once: tool calls run on
    # a worker pool while session close calls release() on the same dicts.
    # Reproduced with the switch interval forced low -- release() iterating the
    # cache while another thread inserted raised "OrderedDict mutated during
    # iteration", and move_to_end raced eviction into a KeyError, which the
    # result mapper then reports as session_not_found. One lock over every
    # mutation; the parse itself stays outside it so two different APKs still
    # analyse in parallel.
    _cache_lock: ClassVar[threading.RLock] = threading.RLock()
    _light_cache: OrderedDict[tuple[str, int], Any] = OrderedDict()
    _full_cache: OrderedDict[tuple[str, int], _ParsedApk] = OrderedDict()

    def __init__(self) -> None:
        self._androguard: Any = None
        self._available = False
        try:
            import androguard  # noqa: F401

            self._androguard = androguard
            self._available = True
        except Exception:
            self._androguard = None
            self._available = False

    @property
    def available(self) -> bool:
        return self._available

    @classmethod
    def release(cls, path: Path) -> bool:
        """Drop cached parses for one APK.

        The cache is capped, but a full DEX analysis is tens to hundreds of
        megabytes and the cap alone means that memory stays resident long after
        the session that needed it closed. Releasing on session close keeps an
        idle unattended process from sitting on an APK it will never look at
        again.
        """
        try:
            resolved = str(path.expanduser().resolve())
        except OSError:
            return False
        dropped = False
        with cls._cache_lock:
            for cache in (cls._light_cache, cls._full_cache):
                for key in [key for key in cache if key[0] == resolved]:
                    cache.pop(key, None)
                    dropped = True
        return dropped

    def _require(self, path: Path) -> Path:
        if not self._available:
            raise ApkError("capability_unavailable", "androguard is not installed")
        resolved = path.expanduser().resolve()
        if not resolved.is_file():
            raise ApkError("not_found", "apk not found", path=str(resolved))
        return resolved

    def _key(self, path: Path) -> tuple[str, int]:
        return (str(path), int(path.stat().st_mtime_ns))

    def _apk(self, path: Path) -> Any:
        """Parse manifest-level facts only (cheap; no DEX analysis)."""
        resolved = self._require(path)
        key = self._key(resolved)
        with self._cache_lock:
            cached = self._light_cache.get(key)
            if cached is not None:
                self._light_cache.move_to_end(key)
                return cached
        _refuse_decompression_bomb(resolved)
        from androguard.core.apk import APK

        try:
            apk = _run_deadline(lambda: APK(str(resolved)), timeout=_PARSE_TIMEOUT_S)
        except ApkError:
            raise
        except Exception as exc:  # noqa: BLE001 - androguard raises many types
            raise ApkError("backend_error", f"failed to parse APK: {exc}") from exc
        with self._cache_lock:
            self._light_cache[key] = apk
            while len(self._light_cache) > _CACHE_LIMIT:
                self._light_cache.popitem(last=False)
        return apk

    def _parsed(self, path: Path) -> _ParsedApk:
        """Parse APK plus full DEX analysis (expensive; cached)."""
        resolved = self._require(path)
        key = self._key(resolved)
        with self._cache_lock:
            cached = self._full_cache.get(key)
            if cached is not None:
                self._full_cache.move_to_end(key)
                return cached
        _refuse_decompression_bomb(resolved)
        from androguard.misc import AnalyzeAPK

        try:
            apk, dex, analysis = _run_deadline(
                lambda: AnalyzeAPK(str(resolved)), timeout=_PARSE_TIMEOUT_S
            )
        except ApkError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise ApkError("backend_error", f"failed to analyze APK: {exc}") from exc
        parsed = _ParsedApk(apk, analysis, dex)
        with self._cache_lock:
            self._full_cache[key] = parsed
            while len(self._full_cache) > _CACHE_LIMIT:
                self._full_cache.popitem(last=False)
        return parsed

    def open(self, path: Path) -> JsonObject:
        apk = self._apk(path)
        return {
            "opened": True,
            "package": apk.get_package(),
            "version_name": apk.get_androidversion_name(),
            "version_code": apk.get_androidversion_code(),
            "min_sdk": apk.get_min_sdk_version(),
            "target_sdk": apk.get_target_sdk_version(),
            "main_activity": apk.get_main_activity(),
            "permission_count": len(apk.get_permissions()),
            "native_abis": sorted(
                {
                    name.split("/")[1]
                    for name in apk.get_files()
                    if name.startswith("lib/") and len(name.split("/")) >= 3
                }
            ),
            "security": self._security_flags(apk),
        }

    def _security_flags(self, apk: Any) -> JsonObject:
        """Application-level manifest flags that drive first-pass triage.

        These live on the single ``<application>`` tag, so unlike per-component
        lookups they read reliably by attribute name (no relative-name mismatch).
        Absent attributes fall back to the platform default, which is the value
        the app actually runs with: debuggable defaults off, allowBackup on, and
        cleartext traffic is allowed below API 28 and denied at or above it. Each
        is read defensively so a missing accessor never breaks apk.open.
        """
        def attr(name: str) -> str | None:
            getter = getattr(apk, "get_attribute_value", None)
            if not callable(getter):
                return None
            try:
                value = getter("application", name)
            except Exception:  # noqa: BLE001
                return None
            return None if value is None else str(value)

        def as_bool(raw: str | None, default: bool) -> bool:
            if raw is None:
                return default
            return str(raw).strip().lower() == "true"

        try:
            target = int(apk.get_target_sdk_version() or 0)
        except (TypeError, ValueError):
            target = 0
        # Google flipped the cleartext default to off at API 28; below that (or
        # when the target is unknown) plaintext HTTP is allowed by default.
        cleartext_default = target < 28
        return {
            "debuggable": as_bool(attr("debuggable"), False),
            "allow_backup": as_bool(attr("allowBackup"), True),
            "uses_cleartext_traffic": as_bool(attr("usesCleartextTraffic"), cleartext_default),
            # Whether the app ships a custom Network Security Config (which can
            # re-enable cleartext or pin/trust CAs); presence alone is the signal.
            "network_security_config": bool(attr("networkSecurityConfig")),
            # A declared sharedUserId puts the app in a shared Linux sandbox with
            # every app of the same id and signer; the value itself is the signal
            # (android.uid.system is a major red flag). It lives on the root
            # <manifest> tag, not <application>, so it is read from the tree.
            # Deprecated since API 29 but still honored, hence still triage-worthy.
            "shared_user_id": self._manifest_root_attr(apk, "sharedUserId"),
        }

    def _manifest_root_attr(self, apk: Any, name: str) -> str | None:
        """A namespaced attribute of the root ``<manifest>`` tag, or None.

        Read from the parsed manifest tree so a root-level attribute (which the
        ``<application>``-scoped ``get_attribute_value`` cannot reach) is
        available; degrades to None when the manifest cannot be parsed.
        """
        getter = getattr(apk, "get_android_manifest_xml", None)
        if not callable(getter):
            return None
        try:
            root = getter()
        except Exception:  # noqa: BLE001
            return None
        if root is None:
            return None
        value = root.get(_ANDROID_NS + name)
        return None if value is None else str(value)

    def manifest(self, path: Path, *, spill_dir: Path | None = None) -> JsonObject:
        apk = self._apk(path)
        try:
            xml = apk.get_android_manifest_axml().get_xml().decode("utf-8", "replace")
        except Exception as exc:  # noqa: BLE001
            raise ApkError("backend_error", f"failed to decode manifest: {exc}") from exc
        truncated = len(xml) > _MAX_MANIFEST_CHARS
        result: JsonObject = {
            "package": apk.get_package(),
            "manifest_xml": xml[:_MAX_MANIFEST_CHARS],
            "truncated": truncated,
        }
        # A manifest cut at the char cap is not even well-formed XML, and the
        # tool had no way to hand back the rest. When it is cut, write the whole
        # document beside the preview so the caller can parse the real thing;
        # the caller keys it under a session artifact dir that retention prunes.
        if truncated and spill_dir is not None:
            spilled = self._spill_manifest(spill_dir, xml)
            if spilled is not None:
                result["manifest_path"] = str(spilled)
        return result

    @staticmethod
    def _spill_manifest(spill_dir: Path, xml: str) -> Path | None:
        try:
            spill_dir.mkdir(parents=True, exist_ok=True)
            out = spill_dir / f"manifest-{uuid4().hex}.xml"
            out.write_bytes(xml.encode("utf-8", errors="replace"))
        except OSError:
            return None
        # An absurdly large manifest (a bomb, not a real app) is deleted rather
        # than left on disk; the caller still has the bounded inline preview.
        _size, over = capped_file_size(out, cap=UNREGISTERED_CAPTURE_MAX_BYTES)
        if over:
            return None
        return out

    def permissions(self, path: Path) -> JsonObject:
        apk = self._apk(path)
        declared, declared_more = _cap_names(apk.get_permissions(), _MAX_PERMISSIONS)
        try:
            requested, requested_more = _cap_names(
                apk.get_requested_permissions(), _MAX_PERMISSIONS
            )
        except Exception:  # noqa: BLE001 - older androguard lacks this
            requested, requested_more = declared, declared_more
        custom, custom_more = self._declared_permissions(apk)
        return {
            "permissions": declared,
            "requested_permissions": requested,
            # The custom permissions the app itself defines, with their
            # protection level. A normal/dangerous level on a permission that
            # guards an exported component is a privilege-escalation surface, so
            # it belongs beside the requested list, not folded into it.
            "declared_permissions": custom,
            "count": len(declared),
            "has_more": declared_more or requested_more or custom_more,
        }

    def _declared_permissions(self, apk: Any) -> tuple[list[JsonObject], bool]:
        """The app's own ``<permission>`` declarations with protection levels.

        androguard exposes these separately from uses-permission; older builds
        lack the accessor, and the detail dict's shape varies, so read both
        defensively and degrade to an empty list rather than break the answer.
        """
        getter = getattr(apk, "get_declared_permissions_details", None)
        if not callable(getter):
            return [], False
        try:
            details = getter() or {}
        except Exception:  # noqa: BLE001
            return [], False
        if not isinstance(details, dict):
            return [], False
        out: list[JsonObject] = []
        has_more = False
        for name in sorted(details):
            if len(out) >= _MAX_PERMISSIONS:
                has_more = True
                break
            detail = details.get(name)
            level = ""
            if isinstance(detail, dict):
                level = str(detail.get("protectionLevel", "") or "")
            out.append({"name": str(name), "protection_level": level})
        return out, has_more

    def certificates(self, path: Path) -> JsonObject:
        apk = self._apk(path)
        items: list[JsonObject] = []
        try:
            names = apk.get_signature_names()
        except Exception:  # noqa: BLE001
            names = []
        sig_files: list[str] = []
        files_more = False
        for name in names or []:
            if len(sig_files) >= _MAX_CERTIFICATES:
                files_more = True
                break
            sig_files.append(str(name))
        certs_more = False
        for cert in apk.get_certificates():
            if len(items) >= _MAX_CERTIFICATES:
                certs_more = True
                break
            try:
                key_algo, key_size = _cert_public_key(cert)
                items.append(
                    {
                        "subject": str(getattr(cert, "subject", "")),
                        "issuer": str(getattr(cert, "issuer", "")),
                        "serial": str(getattr(cert, "serial_number", "")),
                        "sha1": _cert_str(cert, "sha1_fingerprint"),
                        "sha256": _cert_str(cert, "sha256_fingerprint"),
                        "hash_algo": _cert_str(cert, "hash_algo"),
                        # The signature scheme and signer-key strength: an MD5/SHA1
                        # signature or a 1024-bit RSA key is a weak-signing tell
                        # common in old or repackaged apps.
                        "signature_algo": _cert_str(cert, "signature_algo"),
                        "key_algo": key_algo,
                        "key_size": key_size,
                        # The validity window is a strong triage signal: a
                        # freshly minted or absurdly long-lived signer is a
                        # malware tell, and it pins which cert to trust.
                        "not_before": _cert_str(cert, "not_valid_before"),
                        "not_after": _cert_str(cert, "not_valid_after"),
                    }
                )
            except Exception:  # noqa: BLE001 - certificate objects vary by version
                continue
        # v1 is JAR/META-INF signing; v2/v3 are the APK Signature Scheme blocks a
        # modern app actually relies on. Reporting only v1 (from the presence of
        # signature files) hid that a v2/v3-only app was signed at all, and hid
        # the v1-only signing that flags a Janus-style tampering risk.
        v1_signed = _sig_flag(apk, "is_signed_v1") or bool(names)
        v2_signed = _sig_flag(apk, "is_signed_v2")
        v3_signed = _sig_flag(apk, "is_signed_v3")
        return {
            "signature_files": sig_files,
            "certificates": items,
            "v1_signed": v1_signed,
            "v2_signed": v2_signed,
            "v3_signed": v3_signed,
            "signed": v1_signed or v2_signed or v3_signed or _sig_flag(apk, "is_signed"),
            "has_more": certs_more or files_more,
        }

    def components(self, path: Path) -> JsonObject:
        apk = self._apk(path)
        activities, a_more = _cap_names(apk.get_activities(), _MAX_COMPONENT_NAMES)
        services, s_more = _cap_names(apk.get_services(), _MAX_COMPONENT_NAMES)
        receivers, r_more = _cap_names(apk.get_receivers(), _MAX_COMPONENT_NAMES)
        providers, p_more = _cap_names(apk.get_providers(), _MAX_COMPONENT_NAMES)
        exported, e_more = self._exported_components(apk)
        return {
            "activities": activities,
            "services": services,
            "receivers": receivers,
            "providers": providers,
            "main_activity": apk.get_main_activity(),
            # The components other apps can reach -- the app's external attack
            # surface -- with the permission that guards each (null when
            # unguarded). Additive to the name lists above, not a replacement.
            "exported": exported,
            "exported_count": len(exported),
            "has_more": a_more or s_more or r_more or p_more or e_more,
        }

    def _exported_components(self, apk: Any) -> tuple[list[JsonObject], bool]:
        """Components reachable from other apps -- the app's external attack surface.

        A component is exported when ``android:exported="true"``, or -- when the
        attribute is absent -- by the platform's implicit rule: an activity,
        activity-alias, service or receiver with at least one ``<intent-filter>``
        is exported, and a provider is exported only when the target SDK predates
        API 17 (where providers still defaulted to exported). An exported
        component with no ``android:permission`` guard is directly invokable by
        any installed app, so each entry carries its permission (null when
        unguarded). Read straight from the manifest tree so the flag is
        authoritative rather than inferred from a name list, and degrades to an
        empty list if the manifest cannot be parsed rather than failing the call.
        """
        getter = getattr(apk, "get_android_manifest_xml", None)
        if not callable(getter):
            return [], False
        try:
            root = getter()
        except Exception:  # noqa: BLE001
            return [], False
        if root is None:
            return [], False
        try:
            target = int(apk.get_target_sdk_version() or 0)
        except (TypeError, ValueError):
            target = 0
        out: list[JsonObject] = []
        has_more = False
        for element in root.iter():
            tag = getattr(element, "tag", None)
            if not isinstance(tag, str) or tag not in _COMPONENT_TAGS:
                continue
            exported_attr = element.get(_ANDROID_NS + "exported")
            if exported_attr is not None:
                exported = str(exported_attr).strip().lower() == "true"
            elif tag == "provider":
                # Providers defaulted to exported only before API 17; unknown
                # target (0) stays conservative rather than raising a false alarm.
                exported = 0 < target < 17
            else:
                exported = any(
                    isinstance(getattr(child, "tag", None), str)
                    and child.tag == "intent-filter"
                    for child in element
                )
            if not exported:
                continue
            if len(out) >= _MAX_COMPONENT_NAMES:
                has_more = True
                break
            name = element.get(_ANDROID_NS + "name")
            permission = element.get(_ANDROID_NS + "permission")
            actions, categories = _intent_filter_names(element)
            out.append(
                {
                    "type": tag,
                    "name": str(name) if name is not None else "",
                    "permission": None if permission is None else str(permission),
                    # The intent-filter actions/categories that reach this
                    # component are its concrete invocation surface: an action
                    # like BOOT_COMPLETED (persistence) or SMS_RECEIVED
                    # (interception), or a BROWSABLE category (deep-link entry),
                    # is what an analyst triages an exported component for.
                    "actions": actions,
                    "categories": categories,
                }
            )
        out.sort(key=lambda c: (str(c["type"]), str(c["name"])))
        return out, has_more

    @staticmethod
    def _member_sizes(path: Path) -> dict[str, int]:
        """Uncompressed size per archive member, read from the central directory.

        The zip metadata carries file_size without decompressing anything, so a
        packed multi-megabyte payload can be flagged by size without reading it.
        A malformed/absent archive degrades to no sizes rather than an error.
        """
        sizes: dict[str, int] = {}
        try:
            with zipfile.ZipFile(path) as archive:
                for info in archive.infolist():
                    if not info.is_dir():
                        sizes[info.filename] = int(info.file_size)
        except (OSError, zipfile.BadZipFile):
            return {}
        return sizes

    def native_libs(self, path: Path) -> JsonObject:
        apk = self._apk(path)
        sizes = self._member_sizes(path)
        entries: list[JsonObject] = []
        abis: set[str] = set()
        has_more = False
        for name in apk.get_files() or []:
            text = str(name)
            if not text.startswith("lib/"):
                continue
            parts = text.split("/")
            abi = parts[1] if len(parts) >= 3 else ""
            if abi:
                abis.add(abi)
            if len(entries) >= _MAX_NATIVE_LIBS:
                has_more = True
                continue
            # Each .so is now an object (path, abi, and size when the archive
            # metadata had it) rather than a bare path, matching the rest of the
            # apk surface and letting the packed payload be spotted by size.
            entry: JsonObject = {"path": text, "abi": abi}
            size = sizes.get(text)
            if isinstance(size, int):
                entry["size"] = size
            entries.append(entry)
        entries.sort(key=lambda item: str(item["path"]))
        return {
            "native_libs": entries,
            "abis": sorted(abis),
            "count": len(entries),
            "has_more": has_more,
        }

    def classes(
        self, path: Path, *, offset: int = 0, limit: int = 100, name_filter: str = ""
    ) -> JsonObject:
        parsed = self._parsed(path)
        needle = name_filter.strip() if isinstance(name_filter, str) else ""
        names: list[str] = []
        scan_more = False
        for klass in parsed.analysis.get_classes():
            if klass.is_external():
                continue
            # Filter during the scan, before the collect cap: without it the
            # collected set is an arbitrary prefix of get_classes() and offset
            # paging can never reach a class past the cap (has_more only pages
            # within what was collected). A substring filter makes a specific
            # class in a >10k-class app findable regardless of scan order.
            if needle and needle not in klass.name:
                continue
            if len(names) >= _MAX_CLASSES_COLLECT:
                scan_more = True
                break
            names.append(klass.name)
        names.sort()
        start, capped = _page_bounds(offset, limit, cap=_MAX_CLASSES_PAGE)
        window = names[start : start + capped]
        return {
            "classes": window,
            "count": len(window),
            "total": len(names),
            "offset": start,
            "has_more": start + len(window) < len(names),
            "scan_capped": scan_more,
        }

    def methods(
        self,
        path: Path,
        class_name: str,
        *,
        offset: int = 0,
        limit: int = 100,
        name_filter: str = "",
    ) -> JsonObject:
        parsed = self._parsed(path)
        target = class_name.strip()
        if not target:
            raise ApkError("invalid_params", "class_name is required")
        needle = name_filter.strip() if isinstance(name_filter, str) else ""
        found = [
            klass
            for klass in parsed.analysis.get_classes()
            if klass.name == target or klass.name == _dotted_to_smali(target)
        ]
        if not found:
            raise ApkError("not_found", "class not found", class_name=class_name)
        methods: list[JsonObject] = []
        scan_more = False
        for klass in found:
            for method in klass.get_methods():
                # Filter before the collect cap, like classes/strings, so a
                # target method on a class that declares more than the cap is
                # reachable by name rather than stranded past it.
                if needle and needle not in method.name:
                    continue
                if len(methods) >= _MAX_METHODS_COLLECT:
                    scan_more = True
                    break
                methods.append(
                    {
                        "name": method.name,
                        "descriptor": str(getattr(method, "descriptor", "")),
                        "access": str(getattr(method, "access", "")),
                    }
                )
            if scan_more:
                break
        start, capped = _page_bounds(offset, limit, cap=_MAX_METHODS_PAGE)
        window = methods[start : start + capped]
        return {
            "class_name": found[0].name,
            "methods": window,
            "count": len(window),
            "total": len(methods),
            "offset": start,
            "has_more": start + len(window) < len(methods),
            "scan_capped": scan_more,
        }

    def strings(
        self,
        path: Path,
        *,
        offset: int = 0,
        limit: int = 200,
        name_filter: str = "",
        min_len: int = 0,
    ) -> JsonObject:
        parsed = self._parsed(path)
        needle = name_filter.strip() if isinstance(name_filter, str) else ""
        floor = min_len if isinstance(min_len, int) and min_len > 0 else 0
        seen: set[str] = set()
        scan_more = False
        for item in parsed.analysis.get_strings():
            value = str(item.get_value())[:_MAX_STRING_LEN]
            # Both narrowings run during the scan, before the collect cap, for
            # the same reason: the collected set is a prefix of get_strings(),
            # so anything they would have dropped that sits past _MAX_STRINGS_
            # COLLECT is unreachable by any offset. min_len is the strings(1)
            # idiom -- a DEX pool is dominated by short noise (type descriptors
            # like I/V/Ljava/lang/Object;, single letters, obfuscated a/b/c), so
            # a length floor is what makes a URL/key/command sitting past 5000
            # noise entries actually reachable, not just tidier. name_filter then
            # matches a known fragment.
            if floor and len(value) < floor:
                continue
            if needle and needle not in value:
                continue
            if len(seen) >= _MAX_STRINGS_COLLECT:
                scan_more = True
                break
            seen.add(value)
        values = sorted(seen)
        start, capped = _page_bounds(offset, limit, cap=_MAX_STRINGS_PAGE)
        window = values[start : start + capped]
        return {
            "strings": window,
            "count": len(window),
            "total": len(values),
            "offset": start,
            "has_more": start + len(window) < len(values),
            "scan_capped": scan_more,
        }

    def xrefs(
        self,
        path: Path,
        method_name: str,
        *,
        offset: int = 0,
        limit: int = 100,
        class_name: str = "",
    ) -> JsonObject:
        parsed = self._parsed(path)
        target = method_name.strip()
        if not target:
            raise ApkError("invalid_params", "method_name is required")
        # Optional declaring-class scope. Matching by method name alone conflates
        # unrelated methods that share it: in an obfuscated app (everything named
        # a/b/c) or with a common name (decrypt, run, <init>) the callers of many
        # different methods pile into one list and blow the collect cap, so the
        # answer is neither precise nor complete for any single method. Scoping to
        # the declaring class (dotted or Lsmali/ form, like apk.methods) makes it
        # the callers of exactly one method.
        scope = class_name.strip() if isinstance(class_name, str) else ""
        scope_smali = _dotted_to_smali(scope) if scope else ""
        # Same shape as classes/methods/strings: collect into a bounded list,
        # then page it. The old version had only a limit and no offset, so the
        # callers of a hot method past the first page were unreachable -- and it
        # reported no total, leaving "are these all the callers" unanswerable
        # beyond the has_more bit. Cap the collection so a method with a
        # pathological number of call sites cannot build an unbounded list, and
        # disclose that ceiling with scan_capped the way the siblings do.
        callers: list[JsonObject] = []
        scan_more = False
        for method in parsed.analysis.get_methods():
            if method.is_external() or method.name != target:
                continue
            if scope:
                owner = str(getattr(method, "class_name", ""))
                if owner != scope and owner != scope_smali:
                    continue
            for _, call, _ in method.get_xref_from():
                if len(callers) >= _MAX_XREFS_COLLECT:
                    scan_more = True
                    break
                callers.append(
                    {
                        "class": str(call.class_name),
                        "method": str(call.name),
                    }
                )
            if scan_more:
                break
        start, capped = _page_bounds(offset, limit, cap=_MAX_XREFS_PAGE)
        window = callers[start : start + capped]
        return {
            "method_name": target,
            "class_name": scope or None,
            "callers": window,
            "count": len(window),
            "total": len(callers),
            "offset": start,
            # A caller deciding "these are all the callers" has to know whether
            # the page ended the list or merely filled the limit.
            "has_more": start + len(window) < len(callers),
            "scan_capped": scan_more,
        }

    def string_xrefs(
        self, path: Path, value: str, *, offset: int = 0, limit: int = 100
    ) -> JsonObject:
        """Methods that reference a DEX string constant.

        The companion to apk.strings: an analyst copies an interesting string
        (a C2 URL, a suspect log line, a crypto label) and asks where it is
        used. androguard's StringAnalysis.get_xref_from() gives the referencing
        (class, method) pairs; each caller row echoes the matched string so a
        fragment that hit several constants stays disambiguable.
        """
        parsed = self._parsed(path)
        needle = value.strip() if isinstance(value, str) else ""
        if not needle:
            raise ApkError("invalid_params", "value is required")
        callers: list[JsonObject] = []
        matched = 0
        scan_more = False
        for item in parsed.analysis.get_strings():
            text = str(item.get_value())
            # Substring match, like apk.strings' name_filter, so a URL/key
            # fragment works and the caller need not reproduce a 300-char string
            # verbatim. Case-sensitive to match the sibling tools.
            if needle not in text:
                continue
            matched += 1
            echo = text[:_MAX_XREF_STRING_ECHO]
            for caller in item.get_xref_from():
                # androguard hands back (ClassAnalysis, MethodAnalysis); older
                # shapes tack on an offset, so unpack defensively.
                if not isinstance(caller, (tuple, list)) or len(caller) < 2:
                    continue
                method = caller[1]
                if method is None:
                    continue
                if len(callers) >= _MAX_XREFS_COLLECT:
                    scan_more = True
                    break
                callers.append(
                    {
                        "class": str(getattr(method, "class_name", "")),
                        "method": str(getattr(method, "name", "")),
                        "string": echo,
                    }
                )
            if scan_more:
                break
        start, capped = _page_bounds(offset, limit, cap=_MAX_XREFS_PAGE)
        window = callers[start : start + capped]
        return {
            "value": needle,
            "matched_strings": matched,
            "callers": window,
            "count": len(window),
            "total": len(callers),
            "offset": start,
            "has_more": start + len(window) < len(callers),
            "scan_capped": scan_more,
        }


def _dotted_to_smali(name: str) -> str:
    """com.example.Foo -> Lcom/example/Foo; so either form resolves a class."""
    if name.startswith("L") and name.endswith(";"):
        return name
    return "L" + name.replace(".", "/") + ";"
