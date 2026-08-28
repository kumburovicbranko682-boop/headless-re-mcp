"""In-process APK static analysis via androguard.

androguard is an optional dependency: importing it lazily keeps the whole
Android surface usable-but-degraded when it is absent, exactly like the Frida
backend. DEX analysis is expensive, so a small process-wide cache keyed by path
and mtime keeps repeated tool calls within one session from re-parsing.
"""

from __future__ import annotations

import re
import threading
from collections import OrderedDict
from pathlib import Path
from typing import Any, ClassVar
from xml.etree import ElementTree as ET

JsonObject = dict[str, Any]

# The manifest namespace every android:* attribute lives under; ElementTree
# surfaces those attributes as "{uri}name", so exported-component parsing reads
# them through this URI rather than the "android:" prefix.
_ANDROID_NS = "http://schemas.android.com/apk/res/android"
# Android made providers private by default in API 17; below it an unset
# android:exported still meant exported, which is why the derivation needs the
# target SDK to resolve a provider that never declared the attribute.
_PROVIDER_DEFAULT_EXPORT_SDK = 17
# The four component tags plus activity-alias (an activity entry point in its
# own right), mapped to the type each row reports.
_COMPONENT_TAGS = {
    "activity": "activity",
    "activity-alias": "activity",
    "service": "service",
    "receiver": "receiver",
    "provider": "provider",
}

# DEX analysis of a large app can take seconds and tens of MB; keep only a few
# parsed apps resident and evict the oldest.
_CACHE_LIMIT = 4
_MAX_STRING_LEN = 2000
_MAX_STRINGS_COLLECT = 5000
_MAX_CLASSES_COLLECT = 10_000
_MAX_METHODS_COLLECT = 2000
_MAX_NATIVE_LIBS = 256
# A classic zip caps entries near 65535; a safety valve keeps a pathological
# archive from building an unbounded row list while staying well above real APKs.
_MAX_FILES_COLLECT = 50_000
_MAX_FILES_PAGE = 1000
# The coarse buckets apk.files sorts every zip entry into; kept fixed so the
# counts dict has a stable shape rather than varying with the archive.
_APK_FILE_TYPES = (
    "dex",
    "native_lib",
    "resource",
    "asset",
    "arsc",
    "manifest",
    "signature",
    "other",
)
# apk.capabilities caps the distinct calling methods sampled per capability; the
# call_sites total is still exact, only the caller list is clipped.
_MAX_CAP_CALLERS = 25
# apk.native_methods collect/page ceilings (JNI declarations are usually few, but
# a generated binding layer can produce thousands).
_MAX_NATIVE_COLLECT = 5000
_MAX_NATIVE_PAGE = 1000
# apk.urls: how many DEX strings to run the URL match over, how many distinct URLs
# to hold, and the page ceiling. The scan bound is generous (most strings are not
# URLs) but finite so a pathological string pool cannot run unbounded.
_MAX_URL_STRINGS_SCAN = 50000
_MAX_URLS_COLLECT = 5000
_MAX_URLS_PAGE = 1000
# A scheme://rest token: a scheme (letter then letters/digits/+.-), "://", then a
# run of non-delimiter characters. Mirrors js.endpoints so the two backends agree
# on what counts as a URL.
_APK_URL_RE = re.compile(r"[a-zA-Z][a-zA-Z0-9+.\-]{0,31}://[^\s\"'`<>\\)\]}]{1,2048}")
# Punctuation that commonly trails a URL rather than belonging to it.
_APK_URL_TRAILING = ".,;:!?)]}'\""
# The security-relevant platform APIs apk.capabilities fingerprints: each row is
# (category, label, class-name regex, method-name regex). The regexes are matched
# with re.match (start-anchored) exactly as androguard's find_methods does, so a
# class pattern ends with ";$" for an exact class and a method pattern ends with
# "$" to avoid a prefix matching a longer name. This is an occurrence fingerprint
# -- "what can this app reach" -- never a maliciousness verdict.
_APK_CAPABILITY_CATALOG: tuple[tuple[str, str, str, str], ...] = (
    ("dynamic_code", "DexClassLoader", r"Ldalvik/system/DexClassLoader;$", r"<init>$"),
    ("dynamic_code", "PathClassLoader", r"Ldalvik/system/PathClassLoader;$", r"<init>$"),
    (
        "dynamic_code",
        "InMemoryDexClassLoader",
        r"Ldalvik/system/InMemoryDexClassLoader;$",
        r"<init>$",
    ),
    ("dynamic_code", "BaseDexClassLoader", r"Ldalvik/system/BaseDexClassLoader;$", r"<init>$"),
    ("dynamic_code", "System.load", r"Ljava/lang/System;$", r"(?:load|loadLibrary)$"),
    ("dynamic_code", "Runtime.load", r"Ljava/lang/Runtime;$", r"(?:load|loadLibrary)$"),
    ("process_exec", "Runtime.exec", r"Ljava/lang/Runtime;$", r"exec$"),
    ("process_exec", "ProcessBuilder", r"Ljava/lang/ProcessBuilder;$", r"(?:<init>|start)$"),
    ("reflection", "Class.forName", r"Ljava/lang/Class;$", r"forName$"),
    ("reflection", "Class.getMethod", r"Ljava/lang/Class;$", r"(?:getMethod|getDeclaredMethod)$"),
    ("reflection", "Method.invoke", r"Ljava/lang/reflect/Method;$", r"invoke$"),
    ("crypto", "Cipher", r"Ljavax/crypto/Cipher;$", r"getInstance$"),
    ("crypto", "Mac", r"Ljavax/crypto/Mac;$", r"getInstance$"),
    ("crypto", "MessageDigest", r"Ljava/security/MessageDigest;$", r"getInstance$"),
    ("crypto", "SecretKeySpec", r"Ljavax/crypto/spec/SecretKeySpec;$", r"<init>$"),
    ("network", "URL.openConnection", r"Ljava/net/URL;$", r"openConnection$"),
    ("network", "Socket", r"Ljava/net/Socket;$", r"<init>$"),
    ("network", "OkHttpClient", r"Lokhttp3/OkHttpClient;$", r"(?:<init>|newCall)$"),
    (
        "webview",
        "WebView.loadUrl",
        r"Landroid/webkit/WebView;$",
        r"(?:loadUrl|postUrl|loadData|loadDataWithBaseURL)$",
    ),
    (
        "webview",
        "WebView.addJavascriptInterface",
        r"Landroid/webkit/WebView;$",
        r"addJavascriptInterface$",
    ),
    (
        "webview",
        "WebSettings.setJavaScriptEnabled",
        r"Landroid/webkit/WebSettings;$",
        r"setJavaScriptEnabled$",
    ),
    (
        "telephony_sms",
        "SmsManager.send",
        r"Landroid/telephony/SmsManager;$",
        r"(?:sendTextMessage|sendMultipartTextMessage|sendDataMessage)$",
    ),
    (
        "device_identifiers",
        "TelephonyManager.identifiers",
        r"Landroid/telephony/TelephonyManager;$",
        r"(?:getDeviceId|getImei|getMeid|getSubscriberId|getSimSerialNumber|getLine1Number)$",
    ),
    (
        "device_identifiers",
        "Settings.Secure.getString",
        r"Landroid/provider/Settings\$Secure;$",
        r"getString$",
    ),
    (
        "location",
        "LocationManager",
        r"Landroid/location/LocationManager;$",
        r"(?:getLastKnownLocation|requestLocationUpdates|requestSingleUpdate)$",
    ),
    (
        "installed_apps",
        "PackageManager.getInstalled",
        r"Landroid/content/pm/PackageManager;$",
        r"(?:getInstalledPackages|getInstalledApplications)$",
    ),
    (
        "clipboard",
        "ClipboardManager",
        r"Landroid/content/ClipboardManager;$",
        r"(?:getPrimaryClip|getText|setPrimaryClip|setText)$",
    ),
    (
        "storage",
        "Environment.getExternalStorage",
        r"Landroid/os/Environment;$",
        r"(?:getExternalStorageDirectory|getExternalStoragePublicDirectory)$",
    ),
)
_MAX_COMPONENT_NAMES = 256
_MAX_PERMISSIONS = 256
_MAX_CERTIFICATES = 32
_MAX_MANIFEST_CHARS = 200_000
# Page ceilings, kept equal to the apk.* tool schema maxima so the MCP path
# (schema-validated) and the agent/OpenAI paths (clamped here) agree on the
# largest page. test_apk_offset_schema.py pins them against the schema.
_MAX_CLASSES_PAGE = 1000
_MAX_METHODS_PAGE = 1000
_MAX_STRINGS_PAGE = 2000
_MAX_XREFS_PAGE = 1000
_MAX_COMPONENTS_PAGE = 1000
_MAX_EXPORTED_COLLECT = 2000
_MAX_FILTERS_COLLECT = 2000
# Per intent-filter, the ceiling on each of the action/category/data lists so a
# pathological manifest cannot blow one filter row up unbounded.
_MAX_FILTER_ITEMS = 256
# The <data> attributes worth surfacing for a deep link / MIME route; each row
# carries this fixed set (null when the element omits one) so the shape is
# predictable rather than varying with whatever the manifest happened to set.
_DATA_ATTRS = ("scheme", "host", "port", "path", "pathPrefix", "pathPattern", "mimeType")
# A deep link is a VIEW filter carrying a URI scheme; BROWSABLE additionally
# marks it reachable from a web browser / other app. The three path attributes
# map to the kind each row reports.
_VIEW_ACTION = "android.intent.action.VIEW"
_BROWSABLE_CATEGORY = "android.intent.category.BROWSABLE"
_PATH_ATTRS = (("path", "literal"), ("pathPrefix", "prefix"), ("pathPattern", "pattern"))
# The <uses-permission*> tag variants a manifest requests permissions through;
# permission_details reads maxSdkVersion off whichever one carries the name.
_USES_PERMISSION_TAGS = ("uses-permission", "uses-permission-sdk-23", "uses-permission-sdk-m")
# android:usesCleartextTraffic defaulted to true until Android 9 (API 28) flipped
# it to false, so security_flags resolves an unset attribute against this line.
_CLEARTEXT_DEFAULT_FALSE_SDK = 28
# network_security_config bounds: a real policy has a handful of domain-configs,
# but a hostile or generated one could nest thousands, so cap the collection and
# each config's domain/pin lists (reusing the per-filter ceiling).
_MAX_NSC_DOMAIN_CONFIGS = 1000
# Compiled AXML resource files open with the RES_XML_TYPE chunk header (0x0003),
# so a file that does not start with these two bytes is treated as plain XML.
_AXML_MAGIC = b"\x03\x00"
# The low nibble of an android:protectionLevel flags int is the base level; the
# upper bits are modifiers (privileged, appop, ...). Declared permissions store
# the raw AXML int, so this maps the base to the same word get_details_permissions
# resolves AOSP permissions to. The categories permission_details buckets into.
_BASE_PROTECTION = {0: "normal", 1: "dangerous", 2: "signature", 3: "signatureOrSystem"}
_PERMISSION_CATEGORIES = ("dangerous", "normal", "signature", "other", "unknown")


class ApkError(RuntimeError):
    def __init__(self, code: str, message: str, **details: object) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details


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


def _clamp_page(offset: int, limit: int, *, max_limit: int) -> tuple[int, int]:
    """Clamp a page window at the source, not only at the tool schema.

    The apk.* schemas bound ``offset >= 0`` and ``limit`` within range, but the
    agent and OpenAI-bridge transports call the handler directly and never run
    that pydantic validation -- only the MCP path does. A negative offset then
    becomes a tail slice (``names[-1:-1+limit]`` returned an empty page that
    still reported ``has_more``), and a negative limit an all-but-the-tail slice
    (``names[0:-5]``), so page zero silently misread the DEX. Clamp here so the
    contract holds on every path, the way the web, proxy and jsre list backends
    already do; ``xrefs`` already clamped its limit and now shares the ceiling.
    """
    start = max(0, int(offset))
    cap = max(1, min(int(limit), max_limit))
    return start, cap


def _jni_mangle(text: str) -> str:
    """Mangle one component of a JNI short symbol name (JNI spec, table 2-1).

    Alphanumerics pass through; the package separators ``/`` and ``.`` become
    ``_``; the reserved characters escape to ``_1`` (underscore), ``_2`` (``;``)
    and ``_3`` (``[``); everything else (``$`` in an inner class, any non-ASCII
    identifier char) becomes ``_0xxxx`` with the lowercase 4-digit code point.
    """
    out: list[str] = []
    for ch in text:
        if ("a" <= ch <= "z") or ("A" <= ch <= "Z") or ("0" <= ch <= "9"):
            out.append(ch)
        elif ch in "/.":
            out.append("_")
        elif ch == "_":
            out.append("_1")
        elif ch == ";":
            out.append("_2")
        elif ch == "[":
            out.append("_3")
        else:
            out.append(f"_0{ord(ch):04x}")
    return "".join(out)


def _jni_short_symbol(class_smali: str, method: str) -> str:
    """Build the short JNI export name a native method resolves to by default.

    Turns a smali class (``Lcom/example/Foo;``) and method name into
    ``Java_com_example_Foo_method`` -- the exact symbol to grep for in the .so.
    The short form applies unless the native name is overloaded (then the JVM
    also looks for a long form with the argument signature appended), so this is
    the primary lookup, not the only possible one.
    """
    inner = class_smali
    if inner.startswith("L"):
        inner = inner[1:]
    if inner.endswith(";"):
        inner = inner[:-1]
    return f"Java_{_jni_mangle(inner)}_{_jni_mangle(method)}"


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

    def open(self, path: Path) -> JsonObject:
        apk = self._apk(path)
        package = apk.get_package()
        # Measured: get_package() returning None still answered
        # {opened: True, package: None}, so an unattended agent treated a zip
        # that is not an APK as an opened package.
        if not package:
            raise ApkError(
                "backend_error",
                "failed to read package name",
                opened=False,
                package=None,
            )
        return {
            "opened": True,
            "package": package,
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
        return {
            "signature_files": sig_files,
            "certificates": items,
            "v1_signed": bool(names),
            "has_more": certs_more or files_more,
        }

    def components(self, path: Path) -> JsonObject:
        apk = self._apk(path)
        activities, a_more = _cap_names(apk.get_activities(), _MAX_COMPONENT_NAMES)
        services, s_more = _cap_names(apk.get_services(), _MAX_COMPONENT_NAMES)
        receivers, r_more = _cap_names(apk.get_receivers(), _MAX_COMPONENT_NAMES)
        providers, p_more = _cap_names(apk.get_providers(), _MAX_COMPONENT_NAMES)
        return {
            "activities": activities,
            "services": services,
            "receivers": receivers,
            "providers": providers,
            "main_activity": apk.get_main_activity(),
            "has_more": a_more or s_more or r_more or p_more,
        }

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

    def files(self, path: Path, *, offset: int = 0, limit: int = 100) -> JsonObject:
        """List every entry in the APK zip with its size and coarse type.

        The whole-archive inventory apk.native_libs (lib/ only) does not give:
        it walks the zip and reports each file's uncompressed and compressed
        size and a path-based type -- dex (extra classesN.dex flags multidex or
        dynamically loaded code), native_lib, resource, asset (where embedded
        configs, JS bundles and models hide), the arsc/manifest singletons, the
        v1 signature files, and other. Sizes come from the central directory, so
        it never reads a file's contents. Answers with files (each name, type,
        size and compressed_size, sorted by name), counts (the per-type tally
        over the whole archive), total_size and total_compressed_size (byte sums
        over the archive), count, total, offset and has_more so a filled page is
        not read as every entry; total is capped at 50000 with scan_capped when
        an archive somehow holds more. size/compressed_size are null for an entry
        whose central-directory record could not be read.
        """
        apk = self._apk(path)
        names = apk.get_files() or []
        try:
            info = apk.zip.infolist()
        except Exception:  # noqa: BLE001 - androguard/apkInspector internal
            info = {}

        rows: list[JsonObject] = []
        counts = {file_type: 0 for file_type in _APK_FILE_TYPES}
        total_size = 0
        total_compressed = 0
        scan_capped = False
        for name in sorted(str(entry) for entry in names):
            if len(rows) >= _MAX_FILES_COLLECT:
                scan_capped = True
                break
            file_type = _classify_apk_file(name)
            counts[file_type] += 1
            entry = info.get(name) if isinstance(info, dict) else None
            size = getattr(entry, "uncompressed_size", None)
            compressed = getattr(entry, "compressed_size", None)
            size = size if isinstance(size, int) else None
            compressed = compressed if isinstance(compressed, int) else None
            if size is not None:
                total_size += size
            if compressed is not None:
                total_compressed += compressed
            rows.append(
                {
                    "name": name,
                    "type": file_type,
                    "size": size,
                    "compressed_size": compressed,
                }
            )
        start, cap = _clamp_page(offset, limit, max_limit=_MAX_FILES_PAGE)
        window = rows[start : start + cap]
        return {
            "files": window,
            "counts": counts,
            "total_size": total_size,
            "total_compressed_size": total_compressed,
            "count": len(window),
            "total": len(rows),
            "offset": start,
            "has_more": start + len(window) < len(rows),
            "scan_capped": scan_capped,
        }

    def summary(self, path: Path) -> JsonObject:
        """Roll the manifest-level facts into one triage profile (no DEX analysis).

        Uses the cheap _apk (manifest-only) parse the identity and listing tools
        share, so it rolls up apk.open, apk.components, apk.permissions,
        apk.certificates and apk.native_libs -- five calls -- into one without
        the expensive full DEX analysis apk.classes/strings/xrefs need.
        """
        apk = self._apk(path)
        package = apk.get_package()
        if not package:
            raise ApkError(
                "backend_error",
                "failed to read package name",
                opened=False,
                package=None,
            )
        native_libs = [
            text for name in apk.get_files() or [] if (text := str(name)).startswith("lib/")
        ]
        abis = sorted({parts[1] for lib in native_libs if len(parts := lib.split("/")) >= 3})
        try:
            signature_files = apk.get_signature_names() or []
        except Exception:  # noqa: BLE001 - older androguard variants
            signature_files = []
        try:
            certificate_count = len(apk.get_certificates())
        except Exception:  # noqa: BLE001 - certificate objects vary by version
            certificate_count = 0
        return {
            "opened": True,
            "package": package,
            "version_name": apk.get_androidversion_name(),
            "version_code": apk.get_androidversion_code(),
            "min_sdk": apk.get_min_sdk_version(),
            "target_sdk": apk.get_target_sdk_version(),
            "main_activity": apk.get_main_activity(),
            "permission_count": len(apk.get_permissions()),
            "components": {
                "activities": len(apk.get_activities() or []),
                "services": len(apk.get_services() or []),
                "receivers": len(apk.get_receivers() or []),
                "providers": len(apk.get_providers() or []),
            },
            "native_abis": abis,
            "native_lib_count": len(native_libs),
            "certificate_count": certificate_count,
            "v1_signed": bool(signature_files),
        }

    def exported_components(self, path: Path, *, offset: int = 0, limit: int = 100) -> JsonObject:
        """List the components reachable by other apps (the Android attack surface).

        Manifest-level (uses the cheap _apk parse, no DEX analysis): it walks
        AndroidManifest.xml and reports each activity, activity-alias, service,
        receiver or provider that resolves to exported, the way another app or
        the shell can reach it. See _effective_exported for the rule; every row
        also carries the raw evidence so the derivation is auditable.
        """
        apk = self._apk(path)
        package = apk.get_package() or ""
        target_sdk = _int_or_none(apk.get_target_sdk_version())
        try:
            xml_bytes = apk.get_android_manifest_axml().get_xml()
        except Exception as exc:  # noqa: BLE001 - androguard raises many types
            raise ApkError("backend_error", f"failed to decode manifest: {exc}") from exc

        rows: list[JsonObject] = []
        counts = {"activity": 0, "service": 0, "receiver": 0, "provider": 0}
        scan_more = False
        truncated = False
        try:
            root = ET.fromstring(xml_bytes)
        except ET.ParseError:
            root = None
            truncated = True
        application = root.find("application") if root is not None else None
        if application is not None:
            for element in application:
                tag = element.tag if isinstance(element.tag, str) else ""
                comp_type = _COMPONENT_TAGS.get(tag)
                if comp_type is None:
                    continue
                if len(rows) >= _MAX_EXPORTED_COLLECT:
                    scan_more = True
                    break
                declared = _android_attr(element, "exported")
                has_intent_filter = element.find("intent-filter") is not None
                if not _effective_exported(comp_type, declared, has_intent_filter, target_sdk):
                    continue
                name = _android_attr(element, "name") or ""
                counts[comp_type] += 1
                rows.append(
                    {
                        "name": _resolve_component_name(package, name),
                        "type": comp_type,
                        "exported_declared": declared,
                        "has_intent_filter": has_intent_filter,
                        "permission": _android_attr(element, "permission"),
                    }
                )
        start, cap = _clamp_page(offset, limit, max_limit=_MAX_COMPONENTS_PAGE)
        window = rows[start : start + cap]
        return {
            "exported": window,
            "counts": counts,
            "count": len(window),
            "total": len(rows),
            "offset": start,
            "has_more": start + len(window) < len(rows),
            "scan_capped": scan_more,
            "truncated": truncated,
        }

    def intent_filters(self, path: Path, *, offset: int = 0, limit: int = 100) -> JsonObject:
        """List the intent filters each component advertises (deep links, actions).

        Manifest-level (uses the cheap _apk parse, no DEX analysis): it walks
        AndroidManifest.xml and reports every <intent-filter> on an activity,
        activity-alias, service, receiver or provider -- the actions a component
        answers to, the categories it carries and the data (scheme/host/port/
        path.../mimeType) it routes, i.e. the deep-link URIs and MIME types an
        implicit intent can reach. Each row also carries the owning component's
        name, type and resolved exported status (see _effective_exported), so a
        VIEW filter on an exported activity -- a classic deep-link entry point
        -- stands out from an internal one.
        """
        apk = self._apk(path)
        package = apk.get_package() or ""
        target_sdk = _int_or_none(apk.get_target_sdk_version())
        try:
            xml_bytes = apk.get_android_manifest_axml().get_xml()
        except Exception as exc:  # noqa: BLE001 - androguard raises many types
            raise ApkError("backend_error", f"failed to decode manifest: {exc}") from exc

        rows: list[JsonObject] = []
        scan_more = False
        truncated = False
        try:
            root = ET.fromstring(xml_bytes)
        except ET.ParseError:
            root = None
            truncated = True
        application = root.find("application") if root is not None else None
        if application is not None:
            for element in application:
                tag = element.tag if isinstance(element.tag, str) else ""
                comp_type = _COMPONENT_TAGS.get(tag)
                if comp_type is None:
                    continue
                filters = element.findall("intent-filter")
                if not filters:
                    continue
                declared = _android_attr(element, "exported")
                exported = _effective_exported(comp_type, declared, True, target_sdk)
                name = _resolve_component_name(package, _android_attr(element, "name") or "")
                for intent_filter in filters:
                    if len(rows) >= _MAX_FILTERS_COLLECT:
                        scan_more = True
                        break
                    actions, a_more = _filter_names(intent_filter, "action")
                    categories, c_more = _filter_names(intent_filter, "category")
                    data, d_more = _filter_data(intent_filter)
                    scan_more = scan_more or a_more or c_more or d_more
                    rows.append(
                        {
                            "component": name,
                            "type": comp_type,
                            "exported": exported,
                            "actions": actions,
                            "categories": categories,
                            "data": data,
                        }
                    )
                if scan_more and len(rows) >= _MAX_FILTERS_COLLECT:
                    break
        start, cap = _clamp_page(offset, limit, max_limit=_MAX_COMPONENTS_PAGE)
        window = rows[start : start + cap]
        return {
            "filters": window,
            "count": len(window),
            "total": len(rows),
            "offset": start,
            "has_more": start + len(window) < len(rows),
            "scan_capped": scan_more,
            "truncated": truncated,
        }

    def deep_links(self, path: Path, *, offset: int = 0, limit: int = 100) -> JsonObject:
        """Distill the manifest's deep links into testable URI templates.

        Manifest-level (uses the cheap _apk parse, no DEX analysis): it keeps
        only the VIEW intent filters that carry a URI scheme -- the deep links
        another app or a browser can drive the app with -- and crosses each
        filter's merged scheme/host/path sets into concrete scheme://host/path
        templates ready to paste into `adb shell am start -a
        android.intent.action.VIEW -d <uri>`. See _deep_link_rows for the
        cross-product rule; browsable, auto_verify and the owning component's
        exported status are carried so a web-reachable, unverified link on an
        exported activity -- the hijack/injection risk -- stands out.
        """
        apk = self._apk(path)
        package = apk.get_package() or ""
        target_sdk = _int_or_none(apk.get_target_sdk_version())
        try:
            xml_bytes = apk.get_android_manifest_axml().get_xml()
        except Exception as exc:  # noqa: BLE001 - androguard raises many types
            raise ApkError("backend_error", f"failed to decode manifest: {exc}") from exc

        rows: list[JsonObject] = []
        scan_more = False
        truncated = False
        try:
            root = ET.fromstring(xml_bytes)
        except ET.ParseError:
            root = None
            truncated = True
        application = root.find("application") if root is not None else None
        if application is not None:
            for element in application:
                tag = element.tag if isinstance(element.tag, str) else ""
                comp_type = _COMPONENT_TAGS.get(tag)
                if comp_type is None:
                    continue
                declared = _android_attr(element, "exported")
                name = _resolve_component_name(package, _android_attr(element, "name") or "")
                for intent_filter in element.findall("intent-filter"):
                    actions = {_android_attr(a, "name") for a in intent_filter.findall("action")}
                    if _VIEW_ACTION not in actions:
                        continue
                    links, capped = _deep_link_rows(intent_filter)
                    if not links:
                        continue
                    scan_more = scan_more or capped
                    categories = {
                        _android_attr(c, "name") for c in intent_filter.findall("category")
                    }
                    exported = _effective_exported(comp_type, declared, True, target_sdk)
                    browsable = _BROWSABLE_CATEGORY in categories
                    auto_verify = _android_attr(intent_filter, "autoVerify") == "true"
                    for link in links:
                        if len(rows) >= _MAX_FILTERS_COLLECT:
                            scan_more = True
                            break
                        rows.append(
                            {
                                "component": name,
                                "type": comp_type,
                                "exported": exported,
                                "browsable": browsable,
                                "auto_verify": auto_verify,
                                **link,
                            }
                        )
                    if len(rows) >= _MAX_FILTERS_COLLECT:
                        break
                if len(rows) >= _MAX_FILTERS_COLLECT:
                    break
        start, cap = _clamp_page(offset, limit, max_limit=_MAX_COMPONENTS_PAGE)
        window = rows[start : start + cap]
        return {
            "deep_links": window,
            "count": len(window),
            "total": len(rows),
            "offset": start,
            "has_more": start + len(window) < len(rows),
            "scan_capped": scan_more,
            "truncated": truncated,
        }

    def permission_details(self, path: Path) -> JsonObject:
        """Classify the app's permissions by protection level (triage roll-up).

        Manifest-level (uses the cheap _apk parse, no DEX analysis): where
        apk.permissions just lists names, this resolves each requested
        <uses-permission> to its protection level via androguard's AOSP
        permission database and buckets it -- dangerous (gates runtime consent
        and sensitive data: location, contacts, SMS, camera...), signature (held
        only by same-signer apps), normal (auto-granted) or unknown (a
        third-party permission androguard cannot resolve). It also lists the
        <permission> entries the app itself declares -- the custom permissions
        another app could hold to reach this one, a surface worth auditing when
        their protection level is weak. Requested rows carry name,
        protection_level (the raw resolved word, e.g. "signature|privileged", so
        the bucket is auditable), category, max_sdk (the maxSdkVersion cap when
        the request is version-scoped, else null) and app_defined (true when the
        app declares this permission itself). Declared rows carry name,
        protection_level, category and group (the android:permissionGroup, or
        null). Answers with requested, declared, counts (the per-category tally
        over every requested permission, not just the returned page), package,
        target_sdk, requested_count, declared_count and has_more so a list capped
        at 256 is not read as complete; truncated is true when the manifest XML
        could not be parsed for the maxSdkVersion enrichment.
        """
        apk = self._apk(path)
        package = apk.get_package() or ""
        target_sdk = _int_or_none(apk.get_target_sdk_version())

        try:
            details = apk.get_details_permissions() or {}
        except Exception:  # noqa: BLE001 - androguard raises many types
            details = {}
        try:
            declared_details = apk.get_declared_permissions_details() or {}
        except Exception:  # noqa: BLE001 - older androguard variants
            declared_details = {}
        declared_names = set(declared_details)

        # maxSdkVersion is only in the manifest, not in androguard's permission
        # list, so read it from the AXML the way the sibling manifest tools do; a
        # parse failure only costs the enrichment, not the classification.
        maxsdk: dict[str, int] = {}
        truncated = False
        try:
            root: Any = ET.fromstring(apk.get_android_manifest_axml().get_xml())
        except Exception:  # noqa: BLE001 - decode or XML parse can both fail
            root = None
            truncated = True
        if root is not None:
            for tag in _USES_PERMISSION_TAGS:
                for elem in root.iter(tag):
                    name = _android_attr(elem, "name")
                    if name is None:
                        continue
                    value = _int_or_none(_android_attr(elem, "maxSdkVersion"))
                    if value is not None:
                        maxsdk[name] = value

        try:
            raw_requested = apk.get_permissions() or []
        except Exception:  # noqa: BLE001
            raw_requested = []
        requested_rows: list[JsonObject] = []
        counts = {category: 0 for category in _PERMISSION_CATEGORIES}
        requested_total = 0
        req_more = False
        seen: set[str] = set()
        for value in raw_requested:
            name = str(value)
            if name in seen:
                continue
            seen.add(name)
            requested_total += 1
            level = (details.get(name) or [None])[0]
            category = _permission_category(level)
            counts[category] += 1
            if len(requested_rows) >= _MAX_PERMISSIONS:
                req_more = True
                continue
            requested_rows.append(
                {
                    "name": name,
                    "protection_level": _protection_level_label(level),
                    "category": category,
                    "max_sdk": maxsdk.get(name),
                    "app_defined": name in declared_names,
                }
            )

        declared_rows: list[JsonObject] = []
        dec_more = False
        for name, info in declared_details.items():
            if len(declared_rows) >= _MAX_PERMISSIONS:
                dec_more = True
                break
            raw_level = info.get("protectionLevel") if isinstance(info, dict) else None
            group = info.get("permissionGroup") if isinstance(info, dict) else None
            if group in (None, "None", ""):
                group = None
            declared_rows.append(
                {
                    "name": str(name),
                    "protection_level": _protection_level_label(raw_level),
                    "category": _permission_category(raw_level),
                    "group": group,
                }
            )

        return {
            "package": package,
            "target_sdk": target_sdk,
            "requested": requested_rows,
            "declared": declared_rows,
            "counts": counts,
            "requested_count": requested_total,
            "declared_count": len(declared_details),
            "has_more": req_more or dec_more,
            "truncated": truncated,
        }

    def security_flags(self, path: Path) -> JsonObject:
        """Read the security-relevant <application> flags in one call (triage).

        Manifest-level (uses the cheap _apk parse, no DEX analysis): it resolves
        the <application> and <manifest> attributes a review checks first --
        debuggable (a shipped debuggable build lets anyone attach a debugger and
        read process memory), allow_backup (adb backup can pull private data off
        the device when true, the default), uses_cleartext_traffic (plaintext
        HTTP/WebSocket allowed), the network_security_config reference (a custom
        trust/pinning/cleartext policy worth pulling), the backup rule files and
        sharedUserId (a shared Linux UID widening the trust boundary). Booleans
        fall back to Android's documented default when unset; uses_cleartext_
        traffic additionally follows the API-28 default flip (true below 28, false
        at or above), and its raw declared value is carried so the resolution is
        auditable. When a networkSecurityConfig is present it, not this attribute,
        governs cleartext on API 24+, so treat the flag as the manifest default
        and pull the referenced config to be sure. Answers with package, min_sdk,
        target_sdk, debuggable, allow_backup, test_only, has_code, large_heap,
        uses_cleartext_traffic, uses_cleartext_traffic_declared,
        network_security_config, backup_agent, full_backup_content,
        data_extraction_rules, shared_user_id and install_location; truncated is
        true when the manifest XML could not be parsed.
        """
        apk = self._apk(path)
        package = apk.get_package() or ""
        min_sdk = _int_or_none(apk.get_min_sdk_version())
        target_sdk = _int_or_none(apk.get_target_sdk_version())
        try:
            xml_bytes = apk.get_android_manifest_axml().get_xml()
        except Exception as exc:  # noqa: BLE001 - androguard raises many types
            raise ApkError("backend_error", f"failed to decode manifest: {exc}") from exc

        truncated = False
        try:
            root: Any = ET.fromstring(xml_bytes)
        except ET.ParseError:
            root = None
            truncated = True

        if root is not None:
            shared_user_id = _str_or_none(_android_attr(root, "sharedUserId"))
            install_location = _str_or_none(_android_attr(root, "installLocation"))
            application = root.find("application")
        else:
            shared_user_id = None
            install_location = None
            application = None
        cleartext_declared = (
            _android_attr(application, "usesCleartextTraffic") if application is not None else None
        )
        if cleartext_declared is not None:
            uses_cleartext = _manifest_bool(cleartext_declared, True)
        else:
            uses_cleartext = target_sdk is None or target_sdk < _CLEARTEXT_DEFAULT_FALSE_SDK

        def app_attr(name: str) -> str | None:
            return _android_attr(application, name) if application is not None else None

        return {
            "package": package,
            "min_sdk": min_sdk,
            "target_sdk": target_sdk,
            "debuggable": _manifest_bool(app_attr("debuggable"), False),
            "allow_backup": _manifest_bool(app_attr("allowBackup"), True),
            "test_only": _manifest_bool(app_attr("testOnly"), False),
            "has_code": _manifest_bool(app_attr("hasCode"), True),
            "large_heap": _manifest_bool(app_attr("largeHeap"), False),
            "uses_cleartext_traffic": uses_cleartext,
            "uses_cleartext_traffic_declared": _str_or_none(cleartext_declared),
            "network_security_config": _str_or_none(app_attr("networkSecurityConfig")),
            "backup_agent": _str_or_none(app_attr("backupAgent")),
            "full_backup_content": _str_or_none(app_attr("fullBackupContent")),
            "data_extraction_rules": _str_or_none(app_attr("dataExtractionRules")),
            "shared_user_id": shared_user_id,
            "install_location": install_location,
            "truncated": truncated,
        }

    def network_security_config(self, path: Path) -> JsonObject:
        """Pull and distill the app's network security config (the policy itself).

        The payload apk.security_flags only points at: where that reports whether
        a networkSecurityConfig is declared, this resolves the reference through
        the resource table, reads the backing res/xml file, decodes its compiled
        AXML and distills the policy that actually governs TLS -- the part a
        review needs to judge interception exposure. It surfaces cleartext_
        permitted_domains (the hosts explicitly opened to plaintext), trusts_user_
        ca (true when a base or domain trust-anchor trusts the user certificate
        store -- the setting that makes traffic interceptable with a user-
        installed CA, the classic MITM enabler; debug-overrides are excluded since
        they only apply to debuggable builds) and has_pinning (whether any
        pin-set is present). Manifest/resource-level, so it needs no DEX analysis.
        Answers with configured (the manifest declares one), reference (the raw
        @id), resource_path (the resolved file), xml_available (the file was read
        and decoded), base_config (cleartext_permitted plus trust_anchors),
        domain_configs (each with its domains, cleartext_permitted, trust_anchors
        and pin_set), debug_overrides, cleartext_permitted_domains, trusts_user_ca,
        has_pinning, domain_config_count and package; scan_capped is true when the
        policy was clipped (domain-configs at 1000, a config's domain/pin lists at
        256) and truncated when the config XML could not be parsed. When no config
        is declared, configured is false and the policy fields are empty -- absence
        means the platform default (cleartext allowed below a target SDK of 28)
        governs, so read this together with apk.security_flags.
        """
        apk = self._apk(path)
        package = apk.get_package() or ""
        try:
            xml_bytes = apk.get_android_manifest_axml().get_xml()
        except Exception as exc:  # noqa: BLE001 - androguard raises many types
            raise ApkError("backend_error", f"failed to decode manifest: {exc}") from exc
        try:
            root: Any = ET.fromstring(xml_bytes)
        except ET.ParseError:
            root = None
        application = root.find("application") if root is not None else None
        reference = (
            _str_or_none(_android_attr(application, "networkSecurityConfig"))
            if application is not None
            else None
        )

        if reference is None:
            return {
                "package": package,
                "configured": False,
                "reference": None,
                "resource_path": None,
                "xml_available": False,
                **_empty_nsc_policy(),
                "scan_capped": False,
                "truncated": False,
            }

        resource_path, xml_text = _load_network_security_config(apk, reference)
        if xml_text is None:
            return {
                "package": package,
                "configured": True,
                "reference": reference,
                "resource_path": resource_path,
                "xml_available": False,
                **_empty_nsc_policy(),
                "scan_capped": False,
                "truncated": False,
            }

        policy, scan_capped, truncated = _parse_network_security_config(xml_text)
        return {
            "package": package,
            "configured": True,
            "reference": reference,
            "resource_path": resource_path,
            "xml_available": True,
            **policy,
            "scan_capped": scan_capped,
            "truncated": truncated,
        }

    def classes(self, path: Path, *, offset: int = 0, limit: int = 100) -> JsonObject:
        parsed = self._parsed(path)
        names: list[str] = []
        scan_more = False
        for klass in parsed.analysis.get_classes():
            if klass.is_external():
                continue
            if len(names) >= _MAX_CLASSES_COLLECT:
                scan_more = True
                break
            names.append(klass.name)
        names.sort()
        start, cap = _clamp_page(offset, limit, max_limit=_MAX_CLASSES_PAGE)
        window = names[start : start + cap]
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
        start, cap = _clamp_page(offset, limit, max_limit=_MAX_METHODS_PAGE)
        window = methods[start : start + cap]
        return {
            "class_name": found[0].name,
            "methods": window,
            "count": len(window),
            "total": len(methods),
            "offset": start,
            "has_more": start + len(window) < len(methods),
            "scan_capped": scan_more,
        }

    def strings(self, path: Path, *, offset: int = 0, limit: int = 200) -> JsonObject:
        parsed = self._parsed(path)
        seen: set[str] = set()
        scan_more = False
        for item in parsed.analysis.get_strings():
            if len(seen) >= _MAX_STRINGS_COLLECT:
                scan_more = True
                break
            seen.add(str(item.get_value())[:_MAX_STRING_LEN])
        values = sorted(seen)
        start, cap = _clamp_page(offset, limit, max_limit=_MAX_STRINGS_PAGE)
        window = values[start : start + cap]
        return {
            "strings": window,
            "count": len(window),
            "total": len(values),
            "offset": start,
            "has_more": start + len(window) < len(values),
            "scan_capped": scan_more,
        }

    def xrefs(self, path: Path, method_name: str, *, limit: int = 100) -> JsonObject:
        parsed = self._parsed(path)
        target = method_name.strip()
        if not target:
            raise ApkError("invalid_params", "method_name is required")
        _, cap = _clamp_page(0, limit, max_limit=_MAX_XREFS_PAGE)
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

    def callees(self, path: Path, method_name: str, *, limit: int = 100) -> JsonObject:
        parsed = self._parsed(path)
        target = method_name.strip()
        if not target:
            raise ApkError("invalid_params", "method_name is required")
        _, cap = _clamp_page(0, limit, max_limit=_MAX_XREFS_PAGE)
        callees: list[JsonObject] = []
        has_more = False
        for method in parsed.analysis.get_methods():
            if method.is_external() or method.name != target:
                continue
            # get_xref_to is the mirror of xrefs' get_xref_from: the methods this
            # one invokes rather than the methods that invoke it. Same 3-tuple
            # shape (class, callee-method, offset), so the middle element carries
            # the callee's class_name and name.
            for _, callee, _ in method.get_xref_to():
                if len(callees) >= cap:
                    has_more = True
                    break
                callees.append(
                    {
                        "class": str(callee.class_name),
                        "method": str(callee.name),
                    }
                )
            if has_more:
                break
        return {
            "method_name": target,
            "callees": callees,
            "count": len(callees),
            "has_more": has_more,
        }

    def string_xrefs(self, path: Path, value: str, *, limit: int = 100) -> JsonObject:
        parsed = self._parsed(path)
        # Do NOT strip: unlike a method name, a string constant can carry
        # meaningful leading/trailing whitespace, so the query is matched byte
        # for byte. Only a truly empty query is rejected.
        if value == "":
            raise ApkError("invalid_params", "value is required")
        _, cap = _clamp_page(0, limit, max_limit=_MAX_XREFS_PAGE)
        referrers: list[JsonObject] = []
        found = False
        has_more = False
        for string in parsed.analysis.get_strings():
            if string.get_value() != value:
                continue
            found = True
            # StringAnalysis.get_xref_from yields (class, method) pairs; the
            # method is a MethodAnalysis with the same class_name/name the
            # xrefs/callees rows read.
            for _, method in string.get_xref_from():
                if len(referrers) >= cap:
                    has_more = True
                    break
                referrers.append(
                    {
                        "class": str(method.class_name),
                        "method": str(method.name),
                    }
                )
            # The string pool is keyed by value, so one match is the whole set.
            break
        return {
            "value": value,
            "found": found,
            "referrers": referrers,
            "count": len(referrers),
            "has_more": has_more,
        }

    def field_xrefs(self, path: Path, field_name: str, *, limit: int = 100) -> JsonObject:
        parsed = self._parsed(path)
        # A field name is an identifier, so -- like a method name and unlike a
        # string constant -- it is stripped and a blank query rejected.
        target = field_name.strip()
        if not target:
            raise ApkError("invalid_params", "field_name is required")
        _, cap = _clamp_page(0, limit, max_limit=_MAX_XREFS_PAGE)
        accesses: list[JsonObject] = []
        matched_fields = 0
        has_more = False
        for field in parsed.analysis.get_fields():
            if field.name != target:
                continue
            matched_fields += 1
            # Field names are not unique across classes (TAG, mContext, ...), so
            # each row carries the declaring class to disambiguate which field an
            # access touched; class/method stay the accessing code, as in the
            # sibling xref tools.
            field_class = str(field.get_field().get_class_name())
            # get_xref_read/get_xref_write yield (class, method) pairs; the
            # method is a MethodAnalysis with the same class_name/name.
            for kind, edges in (
                ("read", field.get_xref_read()),
                ("write", field.get_xref_write()),
            ):
                for _, method in edges:
                    if len(accesses) >= cap:
                        has_more = True
                        break
                    accesses.append(
                        {
                            "class": str(method.class_name),
                            "method": str(method.name),
                            "kind": kind,
                            "field_class": field_class,
                        }
                    )
                if has_more:
                    break
            if has_more:
                break
        return {
            "field_name": target,
            "found": matched_fields > 0,
            "matched_fields": matched_fields,
            "accesses": accesses,
            "count": len(accesses),
            "has_more": has_more,
        }

    def capabilities(self, path: Path) -> JsonObject:
        """Fingerprint the DEX's use of security-relevant platform APIs.

        The Android counterpart to js.capabilities: it matches the app's methods
        against a fixed table of platform APIs a triage cares about and reports
        which are reached and from where. Categories include dynamic_code (a
        DexClassLoader / System.load pulling code at runtime -- the payload-drop
        surface), process_exec (Runtime.exec / ProcessBuilder, often a su probe),
        reflection (Class.forName / Method.invoke hiding real call targets),
        crypto (Cipher / MessageDigest), network (URL / Socket / OkHttp), webview
        (a WebView.loadUrl, or the far riskier addJavascriptInterface JS bridge
        and setJavaScriptEnabled), telephony_sms, device_identifiers (IMEI /
        subscriber id / ANDROID_ID reads used for tracking), location,
        installed_apps enumeration, clipboard and storage. This needs the full
        DEX analysis (like apk.classes/xrefs), so it is heavier than the
        manifest tools. Each detected row is api (the label), category,
        call_sites (the total number of call sites) and callers (a sample of the
        distinct calling class/method, capped at 25). Answers with capabilities
        (rows sorted by call_sites then api), categories (the sorted distinct
        categories detected), count and scan_capped (a caller sample was
        clipped). This is an occurrence fingerprint -- what the app can reach --
        never a maliciousness verdict; a name reached only by reflection is
        invisible to it.
        """
        parsed = self._parsed(path)
        analysis = parsed.analysis
        rows: list[JsonObject] = []
        scan_capped = False
        for category, label, class_re, method_re in _APK_CAPABILITY_CATALOG:
            call_sites = 0
            callers: list[JsonObject] = []
            seen: set[tuple[str, str]] = set()
            clipped = False
            try:
                matches = analysis.find_methods(classname=class_re, methodname=method_re)
            except Exception:  # noqa: BLE001 - analysis internals vary by version
                continue
            for method in matches:
                try:
                    edges = method.get_xref_from()
                except Exception:  # noqa: BLE001
                    continue
                for _, caller, _ in edges:
                    call_sites += 1
                    key = (str(caller.class_name), str(caller.name))
                    if key in seen:
                        continue
                    seen.add(key)
                    if len(callers) >= _MAX_CAP_CALLERS:
                        clipped = True
                        continue
                    callers.append({"class": key[0], "method": key[1]})
            if call_sites == 0:
                continue
            scan_capped = scan_capped or clipped
            rows.append(
                {
                    "api": label,
                    "category": category,
                    "call_sites": call_sites,
                    "callers": callers,
                }
            )
        rows.sort(key=lambda row: (-int(row["call_sites"]), str(row["api"])))
        categories = sorted({str(row["category"]) for row in rows})
        return {
            "capabilities": rows,
            "categories": categories,
            "count": len(rows),
            "scan_capped": scan_capped,
        }

    def native_methods(self, path: Path, *, offset: int = 0, limit: int = 100) -> JsonObject:
        """List the JNI entry points -- the app's methods declared ``native``.

        The DEX-to-native bridge apk.native_libs (which .so files ship) and
        apk.capabilities (where System.loadLibrary is called) only point at: this
        names the Java side of the boundary, the methods with no bytecode whose
        body lives in a native library. For each it computes jni_symbol, the
        default ``Java_<class>_<method>`` export the runtime binds to (mangled per
        the JNI spec: package dots/slashes to ``_``, ``_``/``;``/``[`` escaped, an
        inner-class ``$`` to ``_00024``), so the exact symbol to grep for in the
        .so is in hand -- the natural pivot into apk.native_libs and a native
        disassembler. Overloaded natives also resolve through a longer signature-
        qualified form, so treat jni_symbol as the primary name, not the only one.
        Needs the full DEX analysis (like apk.classes/methods). Answers with
        native_methods rows (class, method, descriptor, access and jni_symbol)
        sorted by class then method, count, total (all native methods found),
        offset, has_more, and scan_capped when the 5000 collect ceiling was hit.
        """
        parsed = self._parsed(path)
        collected: list[JsonObject] = []
        scan_more = False
        for klass in parsed.analysis.get_classes():
            if scan_more:
                break
            if klass.is_external():
                continue
            for method in klass.get_methods():
                access = str(getattr(method, "access", ""))
                if "native" not in access.split():
                    continue
                if len(collected) >= _MAX_NATIVE_COLLECT:
                    scan_more = True
                    break
                cls = str(getattr(method, "class_name", klass.name))
                name = str(method.name)
                collected.append(
                    {
                        "class": cls,
                        "method": name,
                        "descriptor": str(getattr(method, "descriptor", "")),
                        "access": access,
                        "jni_symbol": _jni_short_symbol(cls, name),
                    }
                )
        collected.sort(
            key=lambda row: (str(row["class"]), str(row["method"]), str(row["descriptor"]))
        )
        start, cap = _clamp_page(offset, limit, max_limit=_MAX_NATIVE_PAGE)
        window = collected[start : start + cap]
        return {
            "native_methods": window,
            "count": len(window),
            "total": len(collected),
            "offset": start,
            "has_more": start + len(window) < len(collected),
            "scan_capped": scan_more,
        }

    def urls(self, path: Path, *, offset: int = 0, limit: int = 100) -> JsonObject:
        """Extract the schemed URLs hard-coded in the DEX string pool.

        The Android counterpart to js.endpoints and the "what does this app
        contact" pivot over apk.strings: it runs a URL match across the same DEX
        string constants apk.strings lists and keeps only tokens that carry a
        scheme -- http, https, ws, wss, ftp and the like -- the API/CDN/C2 hosts
        that are the first network IOCs of a triage. Schemeless paths (``/api/x``)
        stay with apk.strings; a URL split across concatenated strings or built at
        runtime is invisible here (the string pool holds only literal fragments).
        Each row is url, host (the authority after ``://`` up to the first /?#,
        userinfo stripped) and scheme (lowercased). Rows are de-duplicated by url
        and sorted. Needs the full DEX analysis (like apk.strings). Answers with
        urls rows, count, total, offset, has_more so a filled page is not read as
        every URL, and scan_capped when the string-scan or URL-collect ceiling was
        hit.
        """
        parsed = self._parsed(path)
        seen: dict[str, str] = {}
        scan_more = False
        scanned = 0
        for item in parsed.analysis.get_strings():
            if len(seen) >= _MAX_URLS_COLLECT or scanned >= _MAX_URL_STRINGS_SCAN:
                scan_more = True
                break
            scanned += 1
            value = str(item.get_value())[:_MAX_STRING_LEN]
            for match in _APK_URL_RE.finditer(value):
                url = match.group().rstrip(_APK_URL_TRAILING)
                if not url or url in seen:
                    continue
                if len(seen) >= _MAX_URLS_COLLECT:
                    scan_more = True
                    break
                authority = url.split("://", 1)[1]
                for sep in ("/", "?", "#"):
                    authority = authority.split(sep, 1)[0]
                seen[url] = authority.rsplit("@", 1)[-1]
        rows = [
            {"url": url, "host": host, "scheme": url.split("://", 1)[0].lower()}
            for url, host in sorted(seen.items())
        ]
        start, cap = _clamp_page(offset, limit, max_limit=_MAX_URLS_PAGE)
        window = rows[start : start + cap]
        return {
            "urls": window,
            "count": len(window),
            "total": len(rows),
            "offset": start,
            "has_more": start + len(window) < len(rows),
            "scan_capped": scan_more,
        }


def _android_attr(elem: Any, name: str) -> str | None:
    """Read an android:* manifest attribute through its namespace URI."""
    value: str | None = elem.get(f"{{{_ANDROID_NS}}}{name}")
    return value


def _resolve_component_name(package: str, name: str) -> str:
    """Expand a manifest android:name to a fully qualified class name.

    Android reads a name that begins with a dot as relative to the package
    (".Main" under "com.x" is "com.x.Main"); anything else is taken as already
    qualified. A bare single segment (no dot at all) is also package-relative.
    """
    if not name:
        return name
    if name.startswith("."):
        return package + name
    if "." not in name:
        return f"{package}.{name}"
    return name


def _int_or_none(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _manifest_bool(value: Any, default: bool) -> bool:
    """Read a manifest boolean attribute, falling back to Android's default.

    androguard's decoded AXML renders boolean attributes as "true"/"false", but a
    hand-decompiled or odd manifest can leave the raw int (-1/0xffffffff for true,
    0 for false); parse both and fall back to the attribute's documented default
    when it is absent or unreadable.
    """
    if value is None:
        return default
    text = str(value).strip().lower()
    if text == "true":
        return True
    if text in ("false", ""):
        return False
    try:
        return int(text, 0) != 0
    except ValueError:
        return default


def _str_or_none(value: Any) -> str | None:
    """Normalise a manifest attribute to a non-empty string, else None."""
    if value is None:
        return None
    text = str(value).strip()
    if not text or text.lower() == "none":
        return None
    return text


def _classify_apk_file(name: str) -> str:
    """Bucket a zip entry by its path/extension (no content sniffing).

    Deliberately path-based so it needs neither python-magic nor a read of the
    file: the buckets a triage pass cares about are code (dex), native_lib,
    resource, asset, the arsc/manifest singletons, the v1 signature files under
    META-INF, and everything else.
    """
    lower = name.lower()
    if name == "AndroidManifest.xml":
        return "manifest"
    if name == "resources.arsc":
        return "arsc"
    if lower.endswith(".dex"):
        return "dex"
    if name.startswith("lib/"):
        return "native_lib"
    if name.startswith("res/"):
        return "resource"
    if name.startswith("assets/"):
        return "asset"
    if name.startswith("META-INF/") and lower.endswith((".rsa", ".dsa", ".ec", ".sf", ".mf")):
        return "signature"
    return "other"


def _protection_level_label(raw: Any) -> str | None:
    """Normalise an android:protectionLevel to a human word (best-effort).

    AOSP permissions arrive already resolved by androguard ("dangerous",
    "signature|privileged"); declared custom permissions carry the raw AXML value,
    which for a compiled APK is a flags int (2 -> signature, 3 -> signature or
    system). Pass strings through untouched and map an int's base nibble; anything
    unrecognised falls back to a hex rendering so it is never silently dropped.
    """
    if raw is None:
        return None
    text = str(raw).strip()
    if not text or text.lower() == "none":
        return None
    try:
        num = int(text, 0)
    except ValueError:
        return text
    return _BASE_PROTECTION.get(num & 0xF, f"0x{num:x}")


def _permission_category(raw: Any) -> str:
    """Bucket a protection level into dangerous/normal/signature/other/unknown.

    The base level (before the "|" modifiers, or the low nibble of a flags int)
    is what governs triage: dangerous permissions gate runtime consent, signature
    ones are held only by same-signer apps, normal ones are auto-granted. Anything
    resolvable but off that axis (internal, role, ...) is "other"; anything
    missing or unparseable is "unknown".
    """
    if raw is None:
        return "unknown"
    text = str(raw).strip()
    if not text or text.lower() == "none":
        return "unknown"
    try:
        num = int(text, 0)
    except ValueError:
        base = text.split("|", 1)[0].strip().lower()
    else:
        base = _BASE_PROTECTION.get(num & 0xF, "").lower()
    if base == "dangerous":
        return "dangerous"
    if base == "normal":
        return "normal"
    if base.startswith("signature"):
        return "signature"
    if base.startswith("unknown"):
        return "unknown"
    return "other" if base else "unknown"


def _effective_exported(
    comp_type: str, declared: str | None, has_intent_filter: bool, target_sdk: int | None
) -> bool:
    """Resolve whether a component is reachable by other apps (best-effort).

    An explicit android:exported wins. With it unset, an activity, service or
    receiver is exported exactly when it declares an intent filter, while a
    provider falls back to the API-17 default: exported below 17, private at or
    above it (and, when the target SDK is unknown, treated as private).
    """
    if declared is not None:
        return declared.strip().lower() == "true"
    if comp_type == "provider":
        return target_sdk is not None and target_sdk < _PROVIDER_DEFAULT_EXPORT_SDK
    return has_intent_filter


def _filter_names(intent_filter: Any, tag: str) -> tuple[list[str], bool]:
    """Collect the android:name of an intent-filter's <action>/<category> children."""
    names: list[str] = []
    more = False
    for child in intent_filter.findall(tag):
        if len(names) >= _MAX_FILTER_ITEMS:
            more = True
            break
        value = _android_attr(child, "name")
        if value is not None:
            names.append(value)
    return names, more


def _filter_data(intent_filter: Any) -> tuple[list[JsonObject], bool]:
    """Collect an intent-filter's <data> elements as fixed-shape spec dicts."""
    specs: list[JsonObject] = []
    more = False
    for child in intent_filter.findall("data"):
        if len(specs) >= _MAX_FILTER_ITEMS:
            more = True
            break
        spec = {attr: _android_attr(child, attr) for attr in _DATA_ATTRS}
        if any(value is not None for value in spec.values()):
            specs.append(spec)
    return specs, more


def _ordered_distinct(values: Any) -> list[str]:
    """Distinct non-null values in first-appearance order."""
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        if value is None or value in seen:
            continue
        seen.add(value)
        out.append(value)
    return out


def _build_deep_link_uri(scheme: str, host: str | None, port: str | None, path: str | None) -> str:
    """Assemble a testable scheme://host[:port][path] template (best-effort)."""
    uri = f"{scheme}://"
    if host:
        uri += host
        if port:
            uri += f":{port}"
    if path:
        uri += path
    return uri


def _deep_link_rows(intent_filter: Any) -> tuple[list[JsonObject], bool]:
    """Cross the filter's merged scheme/host/port/path sets into link templates.

    Android matches a URI when its scheme, host and path each satisfy one of the
    filter's declared values (attributes merge across every <data> tag), so the
    testable links are that cross product rather than one row per <data>. Returns
    (rows, capped); rows carry only the URI parts, the caller attaches the owning
    component. A filter with no scheme is not a deep link and yields nothing.
    """
    datas = intent_filter.findall("data")
    schemes = _ordered_distinct(_android_attr(d, "scheme") for d in datas)
    if not schemes:
        return [], False
    hosts = _ordered_distinct(_android_attr(d, "host") for d in datas)
    ports = _ordered_distinct(_android_attr(d, "port") for d in datas)
    # Pairing hosts with ports across separate <data> tags is ambiguous, so a
    # port is only applied when the filter declares exactly one.
    port = ports[0] if len(ports) == 1 else None
    paths: list[tuple[str | None, str | None]] = []
    seen_paths: set[tuple[str, str]] = set()
    for data in datas:
        for attr, kind in _PATH_ATTRS:
            value = _android_attr(data, attr)
            if value is not None and (value, kind) not in seen_paths:
                seen_paths.add((value, kind))
                paths.append((value, kind))
    no_path: tuple[str | None, str | None] = (None, None)
    hosts_or_none: list[str | None] = list(hosts) or [None]
    rows: list[JsonObject] = []
    for scheme in schemes:
        for host in hosts_or_none:
            for path_value, path_kind in paths or [no_path]:
                if len(rows) >= _MAX_FILTER_ITEMS:
                    return rows, True
                rows.append(
                    {
                        "scheme": scheme,
                        "host": host,
                        "port": port,
                        "path": path_value,
                        "path_kind": path_kind,
                        "uri": _build_deep_link_uri(scheme, host, port, path_value),
                    }
                )
    return rows, False


def _bool_or_none(value: Any) -> bool | None:
    """Tri-state boolean: True/False for an explicit value, None when unset.

    A network-security-config attribute left unset inherits a default the parser
    cannot know without the target SDK, so None is reported rather than guessing.
    """
    if value is None:
        return None
    text = str(value).strip().lower()
    if text == "true":
        return True
    if text == "false":
        return False
    try:
        return int(text, 0) != 0
    except ValueError:
        return None


def _nsc_reference_to_id(reference: str | None) -> int | None:
    """Parse a manifest resource reference (@[pkg:]7F0F0000) to its numeric id.

    androguard renders a resolved reference as an 8-hex-digit id, optionally
    package-qualified (@android:01080000). A named reference (@xml/name) has no
    numeric id and returns None so the caller falls back to the path convention.
    """
    if not reference:
        return None
    text = reference.strip()
    if not text.startswith("@"):
        return None
    text = text[1:]
    if ":" in text:
        text = text.split(":", 1)[1]
    if "/" in text:
        return None
    try:
        return int(text, 16)
    except ValueError:
        return None


def _nsc_named_ref_path(reference: str | None) -> str | None:
    """Map a named reference (@[pkg:]xml/name) to its conventional res path."""
    if not reference:
        return None
    text = reference.strip()
    if not text.startswith("@") or "/" not in text:
        return None
    body = text[1:]
    if ":" in body:
        body = body.split(":", 1)[1]
    rtype, _, rname = body.partition("/")
    if not rtype or not rname:
        return None
    return f"res/{rtype}/{rname}.xml"


def _decode_axml_or_text(raw: bytes | None) -> str | None:
    """Decode a resource file: compiled AXML via androguard, else UTF-8 text."""
    if not raw:
        return None
    if raw[:2] == _AXML_MAGIC:
        try:
            from androguard.core.axml import AXMLPrinter

            decoded: bytes = AXMLPrinter(raw).get_xml()
            return decoded.decode("utf-8", "replace")
        except Exception:  # noqa: BLE001 - a malformed chunk should degrade, not raise
            return None
    return raw.decode("utf-8", "replace")


def _load_network_security_config(apk: Any, reference: str) -> tuple[str | None, str | None]:
    """Resolve a networkSecurityConfig reference to its file path and decoded XML.

    Numeric references resolve through the ARSC table to the backing res path;
    named ones fall back to the res/<type>/<name>.xml convention. Returns
    (resource_path, xml_text); either may be None when the reference cannot be
    resolved or the file cannot be read/decoded -- a graceful gap, not an error.
    """
    resource_path: str | None = None
    rid = _nsc_reference_to_id(reference)
    if rid is not None:
        try:
            resources = apk.get_android_resources()
        except Exception:  # noqa: BLE001
            resources = None
        if resources is not None:
            try:
                for _config, value in resources.get_resolved_res_configs(rid):
                    if isinstance(value, str) and value.startswith("res/"):
                        resource_path = value
                        break
            except Exception:  # noqa: BLE001 - ARSC resolution varies by build
                resource_path = None
    if resource_path is None:
        named = _nsc_named_ref_path(reference)
        if named is not None:
            try:
                files = set(apk.get_files() or [])
            except Exception:  # noqa: BLE001
                files = set()
            if named in files:
                resource_path = named
    if resource_path is None:
        return None, None
    try:
        raw = apk.get_file(resource_path)
    except Exception:  # noqa: BLE001 - FileNotPresent and friends
        return resource_path, None
    return resource_path, _decode_axml_or_text(raw)


def _nsc_trust_anchors(element: Any) -> list[JsonObject]:
    """Collect a <trust-anchors>'s <certificates> as {src, override_pins} rows."""
    anchors: list[JsonObject] = []
    trust = element.find("trust-anchors")
    if trust is None:
        return anchors
    for cert in trust.findall("certificates"):
        if len(anchors) >= _MAX_FILTER_ITEMS:
            break
        anchors.append(
            {
                "src": _str_or_none(cert.get("src")),
                "override_pins": _manifest_bool(cert.get("overridePins"), False),
            }
        )
    return anchors


def _empty_nsc_policy() -> JsonObject:
    return {
        "base_config": None,
        "domain_configs": [],
        "debug_overrides": None,
        "cleartext_permitted_domains": [],
        "trusts_user_ca": False,
        "has_pinning": False,
        "domain_config_count": 0,
    }


def _parse_network_security_config(xml_text: str) -> tuple[JsonObject, bool, bool]:
    """Distill a network-security-config XML into a structured policy.

    Returns (policy, scan_capped, truncated). Domain-configs are flattened (each
    reports its own <domain> children, so a nested config is its own row);
    trusts_user_ca aggregates the base and domain trust anchors -- not the
    debug-overrides, which only apply to debuggable builds and normally trust the
    user store -- and cleartext_permitted_domains lists the domains a config
    explicitly opens to plaintext.
    """
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return _empty_nsc_policy(), False, True

    scan_capped = False
    trusts_user = False
    has_pins = False
    cleartext_domains: list[str] = []

    base_config: JsonObject | None = None
    base_el = root.find("base-config")
    if base_el is not None:
        base_anchors = _nsc_trust_anchors(base_el)
        trusts_user = trusts_user or any(a["src"] == "user" for a in base_anchors)
        base_config = {
            "cleartext_permitted": _bool_or_none(base_el.get("cleartextTrafficPermitted")),
            "trust_anchors": base_anchors,
        }

    domain_configs: list[JsonObject] = []
    for dc in root.iter("domain-config"):
        if len(domain_configs) >= _MAX_NSC_DOMAIN_CONFIGS:
            scan_capped = True
            break
        domains: list[JsonObject] = []
        for dom in dc.findall("domain"):
            if len(domains) >= _MAX_FILTER_ITEMS:
                scan_capped = True
                break
            name = (dom.text or "").strip()
            domains.append(
                {
                    "name": name,
                    "include_subdomains": _manifest_bool(dom.get("includeSubdomains"), False),
                }
            )
        anchors = _nsc_trust_anchors(dc)
        trusts_user = trusts_user or any(a["src"] == "user" for a in anchors)
        cleartext = _bool_or_none(dc.get("cleartextTrafficPermitted"))
        if cleartext is True:
            cleartext_domains.extend(d["name"] for d in domains if d["name"])
        pin_set: JsonObject | None = None
        pins_el = dc.find("pin-set")
        if pins_el is not None:
            has_pins = True
            pins: list[JsonObject] = []
            for pin in pins_el.findall("pin"):
                if len(pins) >= _MAX_FILTER_ITEMS:
                    scan_capped = True
                    break
                pins.append(
                    {"digest": _str_or_none(pin.get("digest")), "value": (pin.text or "").strip()}
                )
            pin_set = {"expiration": _str_or_none(pins_el.get("expiration")), "pins": pins}
        domain_configs.append(
            {
                "domains": domains,
                "cleartext_permitted": cleartext,
                "trust_anchors": anchors,
                "pin_set": pin_set,
            }
        )

    debug_overrides: JsonObject | None = None
    debug_el = root.find("debug-overrides")
    if debug_el is not None:
        debug_overrides = {"trust_anchors": _nsc_trust_anchors(debug_el)}

    policy = {
        "base_config": base_config,
        "domain_configs": domain_configs,
        "debug_overrides": debug_overrides,
        "cleartext_permitted_domains": _ordered_distinct(cleartext_domains),
        "trusts_user_ca": trusts_user,
        "has_pinning": has_pins,
        "domain_config_count": len(domain_configs),
    }
    return policy, scan_capped, False


def _dotted_to_smali(name: str) -> str:
    """com.example.Foo -> Lcom/example/Foo; so either form resolves a class."""
    if name.startswith("L") and name.endswith(";"):
        return name
    return "L" + name.replace(".", "/") + ";"
