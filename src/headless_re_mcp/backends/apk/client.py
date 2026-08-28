"""In-process APK static analysis via androguard.

androguard is an optional dependency: importing it lazily keeps the whole
Android surface usable-but-degraded when it is absent, exactly like the Frida
backend. DEX analysis is expensive, so a small process-wide cache keyed by path
and mtime keeps repeated tool calls within one session from re-parsing.
"""

from __future__ import annotations

import functools
import hashlib
import threading
from collections import OrderedDict
from collections.abc import Callable
from pathlib import Path
from typing import Any, ClassVar, TypeVar

JsonObject = dict[str, Any]

# DEX analysis of a large app can take seconds and tens of MB; keep only a few
# parsed apps resident and evict the oldest.
_CACHE_LIMIT = 4
_MAX_STRING_LEN = 2000
_MAX_STRINGS_COLLECT = 5000
_MAX_CLASSES_COLLECT = 10_000
_MAX_METHODS_COLLECT = 2000
# A class's field list. Most classes have a handful; an obfuscated or generated
# one can carry hundreds, so the list is bounded and the overflow is flagged.
_MAX_FIELDS = 1000
_MAX_NATIVE_LIBS = 256
# A single .so pulled out for r2/Ghidra. 64 MiB matches the unregistered-capture
# budget the service enforces on trees, so a pathological lib is refused here
# rather than after it has already landed on disk.
_MAX_EXTRACT_BYTES = 64 * 1024 * 1024
_MAX_COMPONENT_NAMES = 256
_MAX_PERMISSIONS = 256
_MAX_CERTIFICATES = 32
_MAX_MANIFEST_CHARS = 200_000
# A page of the archive's file listing. An APK can hold thousands of resource
# entries, so the listing is paginated and each entry name is bounded.
_MAX_FILES_PAGE = 5000
_MAX_ENTRY_NAME = 1024

# Dalvik method access flags (dex format), most-to-least significant bits of
# interest. Decoded into explicit booleans by apk.method_info so a caller reads
# "native" / "static" without parsing the flag string androguard renders.
_ACCESS_PUBLIC = 0x1
_ACCESS_PRIVATE = 0x2
_ACCESS_PROTECTED = 0x4
_ACCESS_STATIC = 0x8
_ACCESS_FINAL = 0x10
_ACCESS_NATIVE = 0x100
_ACCESS_ABSTRACT = 0x400
_ACCESS_SYNTHETIC = 0x1000
_ACCESS_CONSTRUCTOR = 0x10000


def _split_type_list(params: str) -> list[str]:
    """Split a Dalvik parameter run into individual type descriptors.

    ``Ljava/lang/String;[BI`` -> ``['Ljava/lang/String;', '[B', 'I']``. Array
    prefixes (``[``) bind to the type that follows; ``L...;`` runs to its
    semicolon; every other letter is a one-char primitive. A malformed tail
    (an ``L`` with no ``;``) is emitted whole rather than dropped, so a parse
    slip degrades to a visible descriptor instead of a silent omission.
    """
    out: list[str] = []
    i = 0
    n = len(params)
    while i < n:
        start = i
        while i < n and params[i] == "[":
            i += 1
        if i >= n:
            out.append(params[start:])
            break
        if params[i] == "L":
            end = params.find(";", i)
            if end == -1:
                out.append(params[start:])
                break
            i = end + 1
        else:
            i += 1
        out.append(params[start:i])
    return out


def _parse_method_descriptor(descriptor: str) -> tuple[list[str], str]:
    """``(Ljava/lang/String;[BI)V`` -> ``(['Ljava/lang/String;','[B','I'], 'V')``.

    Returns ``([], "")`` for a descriptor that is not the ``(params)return``
    shape, so a caller always gets a list and a string rather than an error.
    """
    text = descriptor.replace(" ", "")
    if not text.startswith("(") or ")" not in text:
        return ([], "")
    close = text.index(")")
    return (_split_type_list(text[1:close]), text[close + 1 :])


def _apk_entry_category(name: str) -> str:
    """Bucket an APK zip entry by what it is, for triage.

    Order matters: META-INF signatures and the manifest are matched before the
    generic resource/asset buckets so a signer file under META-INF is not read
    as an ordinary "other" entry.
    """
    lower = name.lower()
    if name == "AndroidManifest.xml":
        return "manifest"
    if name.startswith("META-INF/"):
        return "signature"
    if lower.endswith(".dex"):
        return "dex"
    if name.startswith("lib/") and lower.endswith(".so"):
        return "native_lib"
    if name == "resources.arsc" or name.startswith("res/"):
        return "resource"
    if name.startswith("assets/"):
        return "asset"
    return "other"


def _safe_entry_filename(entry: str) -> str:
    """Flatten an archive path into a single safe output filename.

    The entry is already constrained to something androguard lists, but the
    output name is still flattened: separators become underscores so a nested
    entry cannot climb out of the artifact dir, and leading dots are dropped so
    no ``..`` fragment survives as a traversal. The length is capped so a
    pathological name cannot blow past the filesystem limit.
    """
    cleaned = entry.replace("\\", "/").strip("/")
    flat = cleaned.replace("/", "_").lstrip(".")
    return (flat or "entry")[:200]

# Manifest attributes live in the Android resource namespace; the AXML decoder
# androguard hands back keeps that URI, so component attributes read as
# ``{http://schemas.android.com/apk/res/android}exported`` etc.
_ANDROID_NS = "http://schemas.android.com/apk/res/android"
_COMPONENT_TAGS: tuple[tuple[str, str], ...] = (
    ("activities", "activity"),
    ("services", "service"),
    ("receivers", "receiver"),
    ("providers", "provider"),
)
# Intent-filters define implicit-intent and deep-link entry points; a benign
# app has a handful per component, so these caps only ever bite pathological
# or obfuscated manifests.
_MAX_INTENT_FILTERS = 32
_MAX_FILTER_ENTRIES = 64
# The data-element attributes that shape a deep link, in URI order.
_FILTER_DATA_ATTRS: tuple[str, ...] = (
    "scheme",
    "host",
    "port",
    "path",
    "pathPrefix",
    "pathPattern",
    "mimeType",
)


def _android_attr(element: Any, name: str) -> str | None:
    """Read an ``android:``-namespaced attribute off a manifest element."""
    value = element.get(f"{{{_ANDROID_NS}}}{name}")
    return None if value is None else str(value)


def _android_bool(value: str | None) -> bool | None:
    """Parse an AXML boolean attribute; ``None`` means the attribute is absent."""
    if value is None:
        return None
    return value.strip().lower() == "true"


def _to_int_or_none(value: Any) -> int | None:
    """Coerce an androguard SDK getter's return (often a decimal string) to int."""
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _effective_target_sdk(apk: Any) -> int | None:
    """The app's effective targetSdk, falling back to minSdk, as an int.

    The provider export default depends on it, so a best-effort read is worth
    more than nothing; anything unparseable yields ``None`` and callers keep
    the conservative modern default.
    """
    for method in ("get_effective_target_sdk_version", "get_target_sdk_version"):
        getter = getattr(apk, method, None)
        if getter is None:
            continue
        try:
            value = getter()
        except Exception:  # noqa: BLE001 - androguard raises raw types
            value = None
        if value is not None:
            try:
                return int(value)
            except (TypeError, ValueError):
                pass
    getter = getattr(apk, "get_min_sdk_version", None)
    if getter is not None:
        try:
            value = getter()
            if value is not None:
                return int(value)
        except Exception:  # noqa: BLE001
            pass
    return None


def _collect_named(parent: Any, tag: str) -> list[str]:
    """Collect the ``android:name`` of each ``tag`` child, bounded and de-duped."""
    names: list[str] = []
    seen: set[str] = set()
    for node in parent.findall(tag):
        if len(names) >= _MAX_FILTER_ENTRIES:
            break
        value = _android_attr(node, "name")
        if value and value not in seen:
            seen.add(value)
            names.append(value)
    return names


class ApkError(RuntimeError):
    def __init__(self, code: str, message: str, **details: object) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details


_F = TypeVar("_F", bound=Callable[..., Any])


def _guard_androguard(func: _F) -> _F:
    """Turn any androguard failure into a structured ``backend_error``.

    ``APK()`` / ``AnalyzeAPK()`` do not raise on a malformed manifest -- they
    log the parse error and return an object whose *getters* then raise raw
    exceptions (a bare ``KeyError('Name')`` from walking the unparsed manifest,
    for one). ``_apk`` / ``_parsed`` only guard construction, so those escaped
    unwrapped, reached the service envelope as ``internal_error`` and minted a
    logged incident -- casting a property of the input file as a server defect,
    the same miscasting the r2/jadx/apktool adapters were fixed to avoid.

    ``ApkError`` (the deliberate codes: not_found, capability_unavailable,
    invalid_params, too_large, backend_error) passes straight through.
    """

    @functools.wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        try:
            return func(*args, **kwargs)
        except ApkError:
            raise
        except Exception as exc:  # noqa: BLE001 - androguard raises many raw types
            raise ApkError(
                "backend_error",
                f"androguard could not read the APK (manifest or dex may be malformed): {exc}",
            ) from exc

    return wrapper  # type: ignore[return-value]


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
        from androguard.core.apk import APK

        try:
            apk = APK(str(resolved))
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
        from androguard.misc import AnalyzeAPK

        try:
            apk, dex, analysis = AnalyzeAPK(str(resolved))
        except Exception as exc:  # noqa: BLE001
            raise ApkError("backend_error", f"failed to analyze APK: {exc}") from exc
        parsed = _ParsedApk(apk, analysis, dex)
        with self._cache_lock:
            self._full_cache[key] = parsed
            while len(self._full_cache) > _CACHE_LIMIT:
                self._full_cache.popitem(last=False)
        return parsed

    @_guard_androguard
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
        }

    @_guard_androguard
    def manifest(self, path: Path) -> JsonObject:
        apk = self._apk(path)
        try:
            xml = apk.get_android_manifest_axml().get_xml().decode("utf-8", "replace")
        except Exception as exc:  # noqa: BLE001
            raise ApkError("backend_error", f"failed to decode manifest: {exc}") from exc
        return {
            "package": apk.get_package(),
            "manifest_xml": xml[:_MAX_MANIFEST_CHARS],
            "truncated": len(xml) > _MAX_MANIFEST_CHARS,
        }

    @_guard_androguard
    def permissions(self, path: Path) -> JsonObject:
        apk = self._apk(path)
        declared, declared_more = _cap_names(apk.get_permissions(), _MAX_PERMISSIONS)
        try:
            requested, requested_more = _cap_names(
                apk.get_requested_permissions(), _MAX_PERMISSIONS
            )
        except Exception:  # noqa: BLE001 - older androguard lacks this
            requested, requested_more = declared, declared_more
        return {
            "permissions": declared,
            "requested_permissions": requested,
            "count": len(declared),
            "has_more": declared_more or requested_more,
        }

    @_guard_androguard
    def certificates(self, path: Path) -> JsonObject:
        apk = self._apk(path)
        items: list[JsonObject] = []
        try:
            names = apk.get_signature_names()
        except Exception:  # noqa: BLE001
            names = []

        def _scheme(method: str) -> bool:
            getter = getattr(apk, method, None)
            if getter is None:
                return False
            try:
                return bool(getter())
            except Exception:  # noqa: BLE001 - varies by androguard version / apk
                return False
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
                items.append(
                    {
                        "subject": str(getattr(cert, "subject", "")),
                        "issuer": str(getattr(cert, "issuer", "")),
                        "serial": str(getattr(cert, "serial_number", "")),
                        "sha256": cert.sha256_fingerprint
                        if hasattr(cert, "sha256_fingerprint")
                        else "",
                    }
                )
            except Exception:  # noqa: BLE001 - certificate objects vary by version
                continue
        v1_signed = _scheme("is_signed_v1") or bool(names)
        v2_signed = _scheme("is_signed_v2")
        v3_signed = _scheme("is_signed_v3")
        return {
            "signature_files": sig_files,
            "certificates": items,
            "v1_signed": v1_signed,
            "v2_signed": v2_signed,
            "v3_signed": v3_signed,
            "signed": v1_signed or v2_signed or v3_signed,
            "has_more": certs_more or files_more,
        }

    @staticmethod
    def _application_element(apk: Any) -> Any | None:
        """The single ``<application>`` element from the parsed manifest tree.

        Best-effort, exactly like ``_component_elements``: a manifest androguard
        cannot re-parse into an lxml tree (malformed, or an old build lacking the
        getter) yields ``None`` and the caller reports every flag as unknown
        rather than failing the call.
        """
        getter = getattr(apk, "get_android_manifest_xml", None)
        if getter is None:
            return None
        try:
            root = getter()
        except Exception:  # noqa: BLE001 - androguard raises raw types on bad AXML
            return None
        if root is None:
            return None
        try:
            for element in root.iter("application"):
                return element
        except Exception:  # noqa: BLE001 - defensive against non-lxml stand-ins
            return None
        return None

    @_guard_androguard
    def security(self, path: Path) -> JsonObject:
        """The ``<application>`` element's security posture -- the triage flags.

        components() maps the exported attack surface, but the first things an
        analyst checks live on the ``<application>`` element itself and were only
        reachable by hand-parsing the apk.manifest XML: whether the app ships
        debuggable (a live debugger can attach and dump memory), whether
        android:allowBackup lets ``adb backup`` pull the private data dir off an
        unrooted device, whether cleartext HTTP is permitted, whether a custom
        network-security-config is present (it can pin certs -- or, the reverse,
        trust user-added CAs and open the app to interception), and the custom
        Application subclass (android:name) where startup, licensing and
        anti-tamper hooks usually sit.

        Each boolean is Android's tri-state: true/false when the manifest sets
        the attribute, null when it is unset -- so a caller can tell "declared
        secure" from "left at the platform default". The platform defaults an
        unset value falls back to are documented on the tool, not baked in here,
        because they turn on the target SDK (allowBackup historically defaults on;
        usesCleartextTraffic defaults on below target 28 and off at/above it), so
        min_sdk and target_sdk are returned alongside for that judgement.
        """
        apk = self._apk(path)
        app = self._application_element(apk)
        if app is not None:
            debuggable = _android_bool(_android_attr(app, "debuggable"))
            allow_backup = _android_bool(_android_attr(app, "allowBackup"))
            uses_cleartext = _android_bool(_android_attr(app, "usesCleartextTraffic"))
            network_security_config = _android_attr(app, "networkSecurityConfig")
            application_class = _android_attr(app, "name")
        else:
            debuggable = allow_backup = uses_cleartext = None
            network_security_config = application_class = None
        return {
            "debuggable": debuggable,
            "allow_backup": allow_backup,
            "uses_cleartext_traffic": uses_cleartext,
            "network_security_config": network_security_config,
            "application_class": application_class,
            "min_sdk": _to_int_or_none(apk.get_min_sdk_version()),
            "target_sdk": _to_int_or_none(apk.get_target_sdk_version()),
        }

    @staticmethod
    def _component_elements(apk: Any, tag: str) -> dict[str, Any]:
        """Map each ``android:name`` under ``tag`` to its manifest element.

        Best-effort: a manifest that androguard cannot re-parse into an lxml
        tree (malformed, or an old build predating the getter) leaves the map
        empty, and callers fall back to the flat name list with unknown
        export state rather than failing the whole call.
        """
        getter = getattr(apk, "get_android_manifest_xml", None)
        if getter is None:
            return {}
        try:
            root = getter()
        except Exception:  # noqa: BLE001 - androguard raises raw types on bad AXML
            return {}
        if root is None:
            return {}
        elements: dict[str, Any] = {}
        try:
            for element in root.iter(tag):
                name = _android_attr(element, "name")
                if name is not None:
                    elements[name] = element
        except Exception:  # noqa: BLE001 - defensive against non-lxml stand-ins
            return {}
        return elements

    @staticmethod
    def _intent_filters(element: Any) -> list[JsonObject]:
        """Extract each ``<intent-filter>``'s actions, categories, and data.

        These are the implicit-intent and deep-link entry points an attacker
        can reach: the action strings, the categories that gate them, and the
        data specs (custom URL schemes, hosts, path patterns, MIME types).
        Empty groups are dropped so a filter that only declares actions does
        not carry three empty arrays.
        """
        filters: list[JsonObject] = []
        try:
            raw_filters = element.findall("intent-filter")
        except Exception:  # noqa: BLE001 - defensive against non-lxml stand-ins
            return filters
        for raw in raw_filters[:_MAX_INTENT_FILTERS]:
            actions = _collect_named(raw, "action")
            categories = _collect_named(raw, "category")
            data: list[JsonObject] = []
            for node in raw.findall("data")[:_MAX_FILTER_ENTRIES]:
                spec = {
                    attr: _android_attr(node, attr)
                    for attr in _FILTER_DATA_ATTRS
                    if _android_attr(node, attr)
                }
                if spec:
                    data.append(spec)
            entry: JsonObject = {}
            if actions:
                entry["actions"] = actions
            if categories:
                entry["categories"] = categories
            if data:
                entry["data"] = data
            filters.append(entry)
        return filters

    def _component_details(
        self, apk: Any, plural: str, tag: str, names: list[str], target_sdk: int | None
    ) -> tuple[list[JsonObject], list[str]]:
        """Annotate each named component with its export state.

        ``exported`` is Android's effective value: the explicit
        ``android:exported`` when the manifest sets it. When it is unset,
        activities/services/receivers default to exported iff they declare an
        ``<intent-filter>``; a ``<provider>`` instead follows the platform
        default that flipped at API 17 -- exported below a targetSdk of 17,
        private at or above it (an intent-filter still forces it exported).
        ``exported_explicit`` preserves the raw attribute (``None`` when unset)
        so a caller can tell a declared value from an inferred one.
        """
        elements = self._component_elements(apk, tag)
        details: list[JsonObject] = []
        exported: list[str] = []
        for name in names:
            element = elements.get(name)
            if element is not None:
                explicit = _android_bool(_android_attr(element, "exported"))
                filters = self._intent_filters(element)
                permission = _android_attr(element, "permission")
            else:
                explicit = None
                filters = []
                permission = None
            has_filter = bool(filters)
            if explicit is not None:
                effective = explicit
            elif tag == "provider":
                legacy_default = target_sdk is not None and target_sdk < 17
                effective = has_filter or legacy_default
            else:
                effective = has_filter
            entry: JsonObject = {
                "name": name,
                "exported": effective,
                "exported_explicit": explicit,
                "has_intent_filter": has_filter,
            }
            if filters:
                entry["intent_filters"] = filters
            if permission:
                entry["permission"] = permission
            details.append(entry)
            if effective:
                exported.append(name)
        return details, exported

    @_guard_androguard
    def components(self, path: Path) -> JsonObject:
        apk = self._apk(path)
        activities, a_more = _cap_names(apk.get_activities(), _MAX_COMPONENT_NAMES)
        services, s_more = _cap_names(apk.get_services(), _MAX_COMPONENT_NAMES)
        receivers, r_more = _cap_names(apk.get_receivers(), _MAX_COMPONENT_NAMES)
        providers, p_more = _cap_names(apk.get_providers(), _MAX_COMPONENT_NAMES)
        name_lists = {
            "activities": activities,
            "services": services,
            "receivers": receivers,
            "providers": providers,
        }
        target_sdk = _effective_target_sdk(apk)
        details: JsonObject = {}
        exported: JsonObject = {}
        for plural, tag in _COMPONENT_TAGS:
            comp_details, comp_exported = self._component_details(
                apk, plural, tag, name_lists[plural], target_sdk
            )
            details[plural] = comp_details
            exported[plural] = comp_exported
        return {
            "activities": activities,
            "services": services,
            "receivers": receivers,
            "providers": providers,
            "main_activity": apk.get_main_activity(),
            "details": details,
            "exported": exported,
            "has_more": a_more or s_more or r_more or p_more,
        }

    @_guard_androguard
    def native_libs(self, path: Path) -> JsonObject:
        apk = self._apk(path)
        libs: list[str] = []
        abis: set[str] = set()
        has_more = False
        for name in apk.get_files() or []:
            text = str(name)
            if not text.startswith("lib/"):
                continue
            parts = text.split("/")
            if len(parts) >= 3:
                abis.add(parts[1])
            if len(libs) >= _MAX_NATIVE_LIBS:
                has_more = True
                continue
            libs.append(text)
        libs.sort()
        return {
            "native_libs": libs,
            "abis": sorted(abis),
            "count": len(libs),
            "has_more": has_more,
        }

    @_guard_androguard
    def files(self, path: Path, *, offset: int = 0, limit: int = 1000) -> JsonObject:
        """List the archive's entries with size and a triage category.

        ``native_libs`` only sees ``lib/*.so``; nothing showed the rest of the
        archive -- how many dex, whether there is an ``assets/`` tree (a common
        place to hide a bundled dex/JS payload or config), the resource table,
        the signer files. Enumerating it meant a full ``apktool`` decode.

        Sizes come from the zip central directory (no decompression), so this
        is cheap even on a large app. The APK is parsed through androguard first
        so the call is gated and validated like the rest of the line, but the
        listing is the real zip contents, which is what triage needs.
        """
        import zipfile

        # Parse through androguard so this is gated (capability_unavailable when
        # absent, not_found for a missing file) and only a real, parseable APK
        # is listed -- not any zip. _apk resolves and validates the path.
        self._apk(path)
        resolved = path.expanduser().resolve()
        try:
            with zipfile.ZipFile(resolved) as archive:
                infos = [info for info in archive.infolist() if not info.is_dir()]
        except zipfile.BadZipFile as exc:
            raise ApkError("backend_error", f"apk is not a readable zip: {exc}") from exc

        # Category tallies span the whole archive, not just the page, so "how
        # many dex" and "is there an assets tree" are answerable in one call.
        categories: dict[str, int] = {}
        total_bytes = 0
        for info in infos:
            categories[_apk_entry_category(info.filename)] = (
                categories.get(_apk_entry_category(info.filename), 0) + 1
            )
            total_bytes += int(info.file_size)

        start = max(0, int(offset))
        cap = max(1, min(int(limit), _MAX_FILES_PAGE))
        window = infos[start : start + cap]
        items: list[JsonObject] = []
        for info in window:
            name = info.filename
            name_truncated = len(name) > _MAX_ENTRY_NAME
            entry: JsonObject = {
                "name": name[:_MAX_ENTRY_NAME],
                "size": int(info.file_size),
                "compressed": int(info.compress_size),
                "category": _apk_entry_category(name),
            }
            if name_truncated:
                entry["name_truncated"] = True
            items.append(entry)
        return {
            "files": items,
            "count": len(items),
            "total": len(infos),
            "offset": start,
            "has_more": start + len(window) < len(infos),
            "categories": categories,
            "total_bytes": total_bytes,
        }

    @_guard_androguard
    def extract_native_lib(self, path: Path, entry: str, out_dir: Path) -> JsonObject:
        """Pull one bundled ``.so`` out of the APK, ready for r2/Ghidra.

        ``native_libs`` names the libraries, but the interesting logic in a
        modern Android app (crypto, licensing, anti-tamper) lives in that native
        code, and getting the bytes out meant a full ``apktool`` decode of the
        whole archive. This reads a single library straight from the zip and
        writes it to ``out_dir`` so the binary-analysis line can open it.

        Only a real loadable library is allowed, and only by its exact archive
        path (``lib/<abi>/<name>.so``): the entry must be one androguard already
        lists, so a caller cannot climb out of ``lib/`` or read an arbitrary
        zip member. The ABI is flattened into the output name so the same
        library for two ABIs does not collide on disk.
        """
        apk = self._apk(path)
        target = (entry or "").strip()
        if not target:
            raise ApkError("invalid_params", "entry is required")
        files = {str(name) for name in (apk.get_files() or [])}
        if target not in files:
            raise ApkError("not_found", "native library not in apk", entry=target)
        parts = target.split("/")
        if len(parts) != 3 or parts[0] != "lib" or not parts[2].endswith(".so"):
            raise ApkError(
                "invalid_params",
                "entry must be a bundled native library path lib/<abi>/<name>.so",
                entry=target,
            )
        abi, name = parts[1], parts[2]
        try:
            blob = apk.get_file(target)
        except Exception as exc:  # noqa: BLE001 - androguard raises FileNotPresent etc.
            raise ApkError(
                "not_found", f"could not read {target}: {exc}", entry=target
            ) from exc
        if not isinstance(blob, bytes | bytearray):
            raise ApkError("backend_error", "apk entry was not raw bytes", entry=target)
        data = bytes(blob)
        size = len(data)
        if size > _MAX_EXTRACT_BYTES:
            raise ApkError(
                "too_large",
                "native library exceeds capture cap",
                entry=target,
                size=size,
                cap=_MAX_EXTRACT_BYTES,
            )
        out_dir.mkdir(parents=True, exist_ok=True)
        out = out_dir / f"{abi}-{name}"
        out.write_bytes(data)
        return {
            "entry": target,
            "abi": abi,
            "name": name,
            "path": str(out),
            "size": size,
            "sha256": hashlib.sha256(data).hexdigest(),
        }

    @_guard_androguard
    def extract_file(self, path: Path, entry: str, out_dir: Path) -> JsonObject:
        """Pull any one archive entry out of the APK to a file.

        ``apk.files`` lists what is inside; this fetches a single member -- a
        bundled asset (config, JS, a hidden dex/APK), a resource, the manifest,
        a signer file -- which otherwise needed a full ``apktool`` decode of the
        whole package. ``extract_native_lib`` is the .so-only specialisation;
        this is the general reader.

        The entry must be one androguard already lists, so a caller cannot name
        an arbitrary zip member or a path outside the archive; the output name
        is flattened so a nested entry cannot climb out of ``out_dir``. A member
        over the capture cap is refused before anything lands on disk.
        """
        apk = self._apk(path)
        target = (entry or "").strip()
        if not target:
            raise ApkError("invalid_params", "entry is required")
        files = {str(name) for name in (apk.get_files() or [])}
        if target not in files:
            raise ApkError("not_found", "entry not in apk", entry=target)
        try:
            blob = apk.get_file(target)
        except Exception as exc:  # noqa: BLE001 - androguard raises FileNotPresent etc.
            raise ApkError(
                "not_found", f"could not read {target}: {exc}", entry=target
            ) from exc
        if not isinstance(blob, bytes | bytearray):
            raise ApkError("backend_error", "apk entry was not raw bytes", entry=target)
        data = bytes(blob)
        size = len(data)
        if size > _MAX_EXTRACT_BYTES:
            raise ApkError(
                "too_large",
                "apk entry exceeds capture cap",
                entry=target,
                size=size,
                cap=_MAX_EXTRACT_BYTES,
            )
        out_dir.mkdir(parents=True, exist_ok=True)
        out = out_dir / _safe_entry_filename(target)
        out.write_bytes(data)
        return {
            "entry": target,
            "name": target.rsplit("/", 1)[-1],
            "category": _apk_entry_category(target),
            "path": str(out),
            "size": size,
            "sha256": hashlib.sha256(data).hexdigest(),
        }

    @_guard_androguard
    def classes(
        self, path: Path, *, offset: int = 0, limit: int = 100, contains: str | None = None
    ) -> JsonObject:
        parsed = self._parsed(path)
        # A substring filter is applied during the scan, not after, so the
        # collection cap bounds *matches*: hunting one class (a crypto package,
        # an Activity, an obfuscated name) in an app with far more than
        # _MAX_CLASSES_COLLECT classes would otherwise never reach it, because
        # the unfiltered scan stops at the cap first.
        needle = contains.casefold() if contains else None
        names: list[str] = []
        scan_more = False
        for klass in parsed.analysis.get_classes():
            if klass.is_external():
                continue
            if len(names) >= _MAX_CLASSES_COLLECT:
                scan_more = True
                break
            name = klass.name
            if needle is not None and needle not in name.casefold():
                continue
            names.append(name)
        names.sort()
        window = names[offset : offset + limit]
        result: JsonObject = {
            "classes": window,
            "count": len(window),
            "total": len(names),
            "offset": offset,
            "has_more": offset + len(window) < len(names),
            "scan_capped": scan_more,
        }
        if needle is not None:
            # total already counts only matches; name the filter so a small
            # result is read as "few matches", not "few classes in the DEX".
            result["filtered"] = True
            result["query"] = contains
        return result

    @_guard_androguard
    def methods(
        self,
        path: Path,
        class_name: str,
        *,
        offset: int = 0,
        limit: int = 100,
    ) -> JsonObject:
        parsed = self._parsed(path)
        target = class_name.strip()
        if not target:
            raise ApkError("invalid_params", "class_name is required")
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
        window = methods[offset : offset + limit]
        return {
            "class_name": found[0].name,
            "methods": window,
            "count": len(window),
            "total": len(methods),
            "offset": offset,
            "has_more": offset + len(window) < len(methods),
            "scan_capped": scan_more,
        }

    @_guard_androguard
    def method_info(
        self,
        path: Path,
        class_name: str,
        method_name: str,
        *,
        descriptor: str | None = None,
    ) -> JsonObject:
        """One method's shape: parsed signature and decoded access flags.

        apk.methods lists a class's methods as raw ``{name, descriptor, access}``;
        this resolves a single method and hands back the parts a caller otherwise
        parses by hand -- the ``(params)return`` descriptor split into a params
        list and a return_type, and the Dalvik access flags decoded into explicit
        booleans. The load-bearing one is is_native: a native method has no
        Dalvik body and hands control to a ``.so`` (pair it with apk.native_libs
        and r2/Ghidra on the extracted lib), which has_code false confirms.
        """
        parsed = self._parsed(path)
        cls = class_name.strip()
        if not cls:
            raise ApkError("invalid_params", "class_name is required")
        name = method_name.strip()
        if not name:
            raise ApkError("invalid_params", "method_name is required")
        smali = _dotted_to_smali(cls)
        klass = next(
            (
                k
                for k in parsed.analysis.get_classes()
                if k.name == cls or k.name == smali
            ),
            None,
        )
        if klass is None:
            raise ApkError("not_found", "class not found", class_name=class_name)
        wanted = descriptor.strip() if descriptor else None
        matches = [
            m
            for m in klass.get_methods()
            if m.name == name
            and (wanted is None or str(getattr(m, "descriptor", "") or "") == wanted)
        ]
        if not matches:
            details: JsonObject = {"class_name": class_name, "method_name": method_name}
            if wanted is not None:
                details["descriptor"] = wanted
            raise ApkError("not_found", "method not found", **details)
        if len(matches) > 1:
            # An overloaded name (same name, different signatures). Rather than
            # silently pick one, name the candidates so the caller re-queries
            # with descriptor -- the same disambiguation apk.methods surfaces.
            raise ApkError(
                "invalid_params",
                "method name is overloaded; pass descriptor to disambiguate",
                class_name=class_name,
                method_name=method_name,
                candidates=[str(getattr(m, "descriptor", "") or "") for m in matches],
            )
        method = matches[0]
        method_desc = str(getattr(method, "descriptor", "") or "")
        params, return_type = _parse_method_descriptor(method_desc)

        # Prefer the underlying EncodedMethod's integer flags for the booleans
        # and for whether a Dalvik body exists; an external method (one only
        # seen referenced) has neither, so the flags stay zero and is_external
        # carries the story.
        flags = 0
        has_code = False
        access_str = str(getattr(method, "access", "") or "")
        enc = method.get_method() if hasattr(method, "get_method") else None
        if enc is not None:
            try:
                flags = int(enc.get_access_flags())
            except Exception:  # noqa: BLE001 - flag getter varies by androguard build
                flags = 0
            try:
                has_code = enc.get_code() is not None
            except Exception:  # noqa: BLE001 - defensive against exotic method stand-ins
                has_code = False
            if not access_str:
                try:
                    access_str = str(enc.get_access_flags_string())
                except Exception:  # noqa: BLE001 - as above
                    access_str = ""
        return {
            "class_name": klass.name,
            "name": method.name,
            "descriptor": method_desc,
            "params": params,
            "return_type": return_type,
            "access": access_str,
            "is_public": bool(flags & _ACCESS_PUBLIC),
            "is_private": bool(flags & _ACCESS_PRIVATE),
            "is_protected": bool(flags & _ACCESS_PROTECTED),
            "is_static": bool(flags & _ACCESS_STATIC),
            "is_final": bool(flags & _ACCESS_FINAL),
            "is_native": bool(flags & _ACCESS_NATIVE),
            "is_abstract": bool(flags & _ACCESS_ABSTRACT),
            "is_synthetic": bool(flags & _ACCESS_SYNTHETIC),
            "is_constructor": bool(flags & _ACCESS_CONSTRUCTOR),
            "is_external": method.is_external(),
            "has_code": has_code,
        }

    @_guard_androguard
    def class_info(self, path: Path, class_name: str) -> JsonObject:
        """One class's shape: superclass, interfaces, access, fields, method count.

        apk.classes lists class names and apk.methods lists a class's methods,
        but nothing told you what a single class *is*: what it extends (its
        role -- Activity/Service, or a crypto/obfuscation base), what it
        implements (``X509TrustManager`` is a cert-pinning-bypass smell,
        ``Runnable`` a background task), its access modifiers, and its declared
        fields (static keys and config live here). This is the "tell me about
        this one class" view that otherwise needed a full jadx/apktool decode.
        """
        parsed = self._parsed(path)
        target = class_name.strip()
        if not target:
            raise ApkError("invalid_params", "class_name is required")
        smali = _dotted_to_smali(target)
        found = next(
            (
                klass
                for klass in parsed.analysis.get_classes()
                if klass.name == target or klass.name == smali
            ),
            None,
        )
        if found is None:
            raise ApkError("not_found", "class not found", class_name=class_name)

        # extends/implements come from the high-level ClassAnalysis and are
        # always present; access flags and fields need the underlying class-def,
        # which is absent for a class androguard only saw referenced (external).
        interfaces = [str(iface) for iface in (getattr(found, "implements", None) or [])]
        vm_class = found.get_vm_class() if hasattr(found, "get_vm_class") else None
        access = ""
        fields: list[JsonObject] = []
        fields_more = False
        if vm_class is not None:
            try:
                access = str(vm_class.get_access_flags_string())
            except Exception:  # noqa: BLE001 - access string varies by androguard build
                access = ""
            for field in vm_class.get_fields():
                if len(fields) >= _MAX_FIELDS:
                    fields_more = True
                    break
                fields.append(
                    {
                        "name": str(field.get_name()),
                        "type": str(field.get_descriptor()),
                        "access": str(field.get_access_flags_string()),
                    }
                )
        method_count = sum(1 for _ in found.get_methods())
        return {
            "class_name": found.name,
            "superclass": str(getattr(found, "extends", "") or ""),
            "interfaces": interfaces,
            "access": access,
            "fields": fields,
            "field_count": len(fields),
            "method_count": method_count,
            "is_external": found.is_external(),
            "has_more": fields_more,
        }

    @_guard_androguard
    def strings(
        self, path: Path, *, offset: int = 0, limit: int = 200, contains: str | None = None
    ) -> JsonObject:
        parsed = self._parsed(path)
        # A substring filter is applied during the scan, not after, so the
        # collection cap bounds *matches*: hunting one URL or key in an app with
        # far more than _MAX_STRINGS_COLLECT distinct strings would otherwise
        # never reach it, because the unfiltered scan stops at the cap first.
        needle = contains.casefold() if contains else None
        seen: set[str] = set()
        scan_more = False
        for item in parsed.analysis.get_strings():
            if len(seen) >= _MAX_STRINGS_COLLECT:
                scan_more = True
                break
            value = str(item.get_value())[:_MAX_STRING_LEN]
            if needle is not None and needle not in value.casefold():
                continue
            seen.add(value)
        values = sorted(seen)
        window = values[offset : offset + limit]
        result: JsonObject = {
            "strings": window,
            "count": len(window),
            "total": len(values),
            "offset": offset,
            "has_more": offset + len(window) < len(values),
            "scan_capped": scan_more,
        }
        if needle is not None:
            # total already counts only matches; name the filter so a small
            # result is read as "few matches", not "few strings in the DEX".
            result["filtered"] = True
            result["query"] = contains
        return result

    @_guard_androguard
    def xrefs(self, path: Path, method_name: str, *, limit: int = 100) -> JsonObject:
        parsed = self._parsed(path)
        target = method_name.strip()
        if not target:
            raise ApkError("invalid_params", "method_name is required")
        cap = max(1, int(limit))
        callers: list[JsonObject] = []
        has_more = False
        for method in parsed.analysis.get_methods():
            if method.is_external() or method.name != target:
                continue
            for _, call, _ in method.get_xref_from():
                if len(callers) >= cap:
                    # Only set once something was actually left out, so a result
                    # that happens to fill the page is not reported as partial.
                    has_more = True
                    break
                callers.append(
                    {
                        "class": str(call.class_name),
                        "method": str(call.name),
                    }
                )
            if has_more:
                break
        return {
            "method_name": target,
            "callers": callers,
            "count": len(callers),
            # A caller deciding "these are all the callers" has to know whether
            # the enumeration ended or merely stopped.
            "has_more": has_more,
        }


def _dotted_to_smali(name: str) -> str:
    """com.example.Foo -> Lcom/example/Foo; so either form resolves a class."""
    if name.startswith("L") and name.endswith(";"):
        return name
    return "L" + name.replace(".", "/") + ";"
