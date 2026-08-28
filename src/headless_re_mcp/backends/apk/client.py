"""In-process APK static analysis via androguard.

androguard is an optional dependency: importing it lazily keeps the whole
Android surface usable-but-degraded when it is absent, exactly like the Frida
backend. DEX analysis is expensive, so a small process-wide cache keyed by path
and mtime keeps repeated tool calls within one session from re-parsing.
"""

from __future__ import annotations

import re
import struct
import threading
from collections import Counter, OrderedDict
from collections.abc import Iterable
from pathlib import Path
from typing import Any, ClassVar
from urllib.parse import urlsplit

from headless_re_mcp.backends.common.secrets import classify_secrets

JsonObject = dict[str, Any]

# DEX analysis of a large app can take seconds and tens of MB; keep only a few
# parsed apps resident and evict the oldest.
_CACHE_LIMIT = 4
_MAX_STRING_LEN = 2000
_MAX_STRINGS_COLLECT = 5000
_MAX_CLASSES_COLLECT = 10_000
_MAX_METHODS_COLLECT = 2000
_MAX_NATIVE_LIBS = 256
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
_MAX_FILES_PAGE = 2000
_MAX_FILES_COLLECT = 50_000
_MAX_META_DATA = 500
_MAX_META_VALUE_CHARS = 4096
_ANDROID_NS = "{http://schemas.android.com/apk/res/android}"
_MAX_INTENT_COMPONENTS = 500
_MAX_INTENT_ITEMS = 100
_MAX_METHOD_OVERLOADS = 200
_MAX_CLASS_FIELDS = 500
_MAX_INTERFACES = 100
_MAX_USES_FEATURES = 300
_MAX_USES_LIBRARIES = 300
# apk.declared_permissions: bound the app's own <permission> / <permission-tree>
# / <permission-group> declarations. protectionLevel is a bitfield -- the low
# nibble is the base and the high bits are flags -- so it is decoded here from
# either the source-XML name form or the compiled AXML integer form.
_MAX_DECLARED_PERMISSIONS = 500
_PROTECTION_BASE = {
    0: "normal",
    1: "dangerous",
    2: "signature",
    3: "signatureOrSystem",
}
_PROTECTION_FLAGS = {
    0x10: "privileged",
    0x20: "development",
    0x40: "appop",
    0x80: "pre23",
    0x100: "installer",
    0x200: "verifier",
    0x400: "preinstalled",
    0x800: "setup",
    0x1000: "instant",
    0x2000: "runtime",
    0x4000: "oem",
    0x8000: "vendorPrivileged",
    0x10000: "systemTextClassifier",
    0x20000: "configurator",
    0x40000: "incidentReportApprover",
    0x80000: "appPredictor",
    0x100000: "companion",
    0x200000: "retailDemo",
    0x400000: "recents",
    0x800000: "role",
    0x1000000: "knownSigner",
}
# A base any third-party app can hold: normal is auto-granted and dangerous is
# grantable with user consent, so either one guarding an exported component is a
# privilege-escalation door. signature and above are not.
_WEAK_PROTECTION_BASES = frozenset({"normal", "dangerous"})
# apk.providers caps: bound the provider list, each provider's authorities, and
# its child <path-permission>/<grant-uri-permission> elements.
_MAX_PROVIDERS = 500
_MAX_PROVIDER_AUTHORITIES = 100
_MAX_PATH_PERMISSIONS = 200
_MAX_GRANT_URIS = 200
# apk.native_methods caps: an app can declare many JNI stubs; bound the scan and
# the returned page.
_MAX_NATIVE_METHODS_COLLECT = 5000
_MAX_NATIVE_METHODS_PAGE = 2000
# apk.disassemble caps: a single Dalvik method is small, but a crafted/obfuscated
# one could carry a very long instruction stream; bound the decode and the page,
# and clip each rendered operand string and raw-hex snippet.
_MAX_DALVIK_INSNS_COLLECT = 20_000
_MAX_DALVIK_INSNS_PAGE = 2000
_MAX_OPERAND_LEN = 512
_MAX_INSN_HEX_LEN = 64
# apk.dex_headers cap: even a heavily multidex app rarely ships more than a few
# dozen classesN.dex; bound the listing so a crafted archive cannot make it grow.
_MAX_DEX_FILES = 200
_DEX_MAGIC = b"dex\n"
_DEX_HEADER_SIZE = 112
# apk.api_usage caps: a big app has hundreds of thousands of analysis method
# nodes; bound the scan, the callers counted per API, and the APIs shown per
# category so a hostile app cannot make the scan unbounded.
_MAX_API_METHODS_SCAN = 400_000
_MAX_API_CALLERS = 5000
_MAX_API_ROWS = 60
# apk.urls caps: a big app carries thousands of string constants; bound the
# distinct-URL set, the per-host and IP roll-ups, and each captured URL length.
_MAX_URLS_COLLECT = 5000
_MAX_URL_VALUE_LEN = 2000
_MAX_HOST_ROLLUP = 500
_MAX_IP_ROLLUP = 500
_MAX_URLS_PAGE = 2000
# Trailing punctuation to strip off a URL matched inside prose or a quoted string.
_URL_TRAILING = ".,;:!?'\")]}>"
_URL_RE = re.compile(r"(?:https?|wss?|ftp)://[^\s\"'<>\\)\]}(]+", re.IGNORECASE)
_IPV4_RE = re.compile(
    r"(?<![\w.])"
    r"(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)"
    r"(?![\w.])"
)


_DEX_LOADERS = frozenset(
    {
        "Ldalvik/system/DexClassLoader;",
        "Ldalvik/system/PathClassLoader;",
        "Ldalvik/system/InMemoryDexClassLoader;",
        "Ldalvik/system/BaseDexClassLoader;",
        "Ldalvik/system/DexFile;",
    }
)


def _classify_api(cls: str, name: str) -> str | None:
    """Bucket a called API (smali class descriptor + method) into a threat category.

    Pure over the two strings so a fake analysis can drive it in a unit test.
    Only high-signal APIs that malware triage looks for are matched; anything
    else returns None and is ignored. Categories are the words a reviewer would
    grep an app for: reflection, dynamic code loading, process exec, native
    loads, crypto, SMS, device identifiers, and so on.
    """
    if cls.startswith("Ljava/lang/reflect/"):
        return "reflection"
    if cls == "Ljava/lang/Class;" and name in {
        "forName",
        "getMethod",
        "getDeclaredMethod",
        "getMethods",
        "getDeclaredMethods",
        "getDeclaredField",
        "getField",
    }:
        return "reflection"
    if cls in _DEX_LOADERS:
        return "dynamic_code"
    if cls == "Ljava/lang/Runtime;" and name == "exec":
        return "process_exec"
    if cls == "Ljava/lang/ProcessBuilder;":
        return "process_exec"
    if cls in {"Ljava/lang/System;", "Ljava/lang/Runtime;"} and name in {
        "load",
        "loadLibrary",
    }:
        return "native_load"
    if cls.startswith("Ljavax/crypto/"):
        return "crypto"
    if cls in {
        "Ljava/security/MessageDigest;",
        "Ljava/security/KeyStore;",
        "Ljava/security/Signature;",
        "Ljava/security/KeyPairGenerator;",
    }:
        return "crypto"
    if cls == "Landroid/telephony/SmsManager;":
        return "sms"
    if cls == "Landroid/telephony/TelephonyManager;" and name in {
        "getDeviceId",
        "getSubscriberId",
        "getSimSerialNumber",
        "getLine1Number",
        "getImei",
        "getMeid",
    }:
        return "device_id"
    if cls == "Landroid/location/LocationManager;":
        return "location"
    if cls == "Landroid/app/admin/DevicePolicyManager;":
        return "device_admin"
    if cls.startswith("Landroid/accessibilityservice/"):
        return "accessibility"
    if cls in {
        "Landroid/content/ClipboardManager;",
        "Landroid/text/ClipboardManager;",
    }:
        return "clipboard"
    if cls == "Landroid/content/pm/PackageManager;" and name in {
        "getInstalledApplications",
        "getInstalledPackages",
    }:
        return "installed_apps"
    if cls in {"Landroid/media/MediaRecorder;", "Landroid/media/AudioRecord;"}:
        return "record_audio"
    if cls == "Ljava/net/URL;" and name == "openConnection":
        return "network"
    if (
        cls.startswith("Lokhttp3/")
        or cls.startswith("Lorg/apache/http/")
        or cls == "Ljava/net/Socket;"
    ):
        return "network"
    return None


def _extract_url_indicators(
    values: Iterable[Any],
) -> tuple[dict[str, JsonObject], Counter[str], set[str], bool]:
    """Pull network indicators out of a stream of string constants.

    Pure over the raw string values so it can be unit-tested without androguard.
    Collects distinct absolute URLs (http/https/ws/wss/ftp) with their scheme and
    host, a per-host tally, and bare IPv4 literals. Bounded on every axis so a
    hostile app packed with generated strings cannot blow memory.
    """
    urls: dict[str, JsonObject] = {}
    hosts: Counter[str] = Counter()
    ips: set[str] = set()
    scanned = 0
    scan_capped = False
    for raw in values:
        if scanned >= _MAX_STRINGS_COLLECT:
            scan_capped = True
            break
        scanned += 1
        text = str(raw)
        for match in _URL_RE.finditer(text):
            url = match.group(0).rstrip(_URL_TRAILING)[:_MAX_URL_VALUE_LEN]
            if not url:
                continue
            if url not in urls:
                if len(urls) >= _MAX_URLS_COLLECT:
                    scan_capped = True
                    continue
                parts = urlsplit(url)
                host = (parts.hostname or "").lower()
                urls[url] = {"url": url, "scheme": parts.scheme.lower(), "host": host}
                if host:
                    hosts[host] += 1
        for match in _IPV4_RE.finditer(text):
            if len(ips) < _MAX_IP_ROLLUP:
                ips.add(match.group(0))
            else:
                scan_capped = True
    return urls, hosts, ips, scan_capped


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


def _decode_protection_level(raw: str | None) -> tuple[str, list[str]]:
    """Decode android:protectionLevel into its base level and flag names.

    Two forms reach us: source manifests write names ("signature|privileged"),
    while a compiled AndroidManifest.xml carries the integer bitfield androguard
    surfaces ("0x12"). The low nibble is the base level; higher bits are flags.
    When the attribute is absent the platform default is ``normal`` -- the loose
    end this tool exists to catch -- so an absent level decodes to ``normal``.
    """
    text = (raw or "").strip()
    if not text:
        return "normal", []
    try:
        value = int(text, 0)
    except ValueError:
        value = None
    if value is not None:
        base = _PROTECTION_BASE.get(value & 0xF, "unknown")
        flags = [name for bit, name in _PROTECTION_FLAGS.items() if value & bit]
        return base, flags
    base = "normal"
    base_set = False
    flags = []
    aliases = {
        "normal": "normal",
        "dangerous": "dangerous",
        "signature": "signature",
        "signatureorsystem": "signatureOrSystem",
    }
    for token in (part.strip() for part in text.split("|")):
        if not token:
            continue
        canonical = aliases.get(token.lower())
        if canonical is not None and not base_set:
            base = canonical
            base_set = True
        else:
            flags.append(token)
    return base, flags


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

    def security(self, path: Path) -> JsonObject:
        """Report the <application> element's security posture.

        The first thing a reviewer checks: is the app debuggable, does it allow
        cloud backup of its data, does it permit cleartext HTTP, does it pin a
        network security config, and does it install a custom Application class
        (a common place for packers/loaders to run first). A boolean flag that
        the manifest never declared is reported as null -- "not set", which is
        not the same as false -- so the caller can apply the right platform
        default for the target SDK.
        """
        apk = self._apk(path)

        def _attr(name: str) -> str | None:
            try:
                value = apk.get_attribute_value("application", name)
            except Exception:  # noqa: BLE001 - androguard manifest access varies
                return None
            if value is None or str(value) == "":
                return None
            return str(value)

        def _bool_attr(name: str) -> bool | None:
            raw = _attr(name)
            if raw is None:
                return None
            return raw.strip().lower() == "true"

        try:
            debuggable: bool | None = bool(apk.is_debuggable())
        except Exception:  # noqa: BLE001
            debuggable = _bool_attr("debuggable")

        return {
            "package": apk.get_package(),
            "debuggable": debuggable,
            "allow_backup": _bool_attr("allowBackup"),
            "uses_cleartext_traffic": _bool_attr("usesCleartextTraffic"),
            "network_security_config": _attr("networkSecurityConfig"),
            "application_class": _attr("name"),
            "min_sdk": _as_int(apk.get_min_sdk_version()),
            "target_sdk": _as_int(apk.get_target_sdk_version()),
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

    def declared_permissions(self, path: Path) -> JsonObject:
        """List the app's own <permission> declarations and their protection.

        permissions lists what the app *uses*; this lists what it *defines* --
        the custom permissions that gate its own components. The decisive field
        is protectionLevel: a permission left at the default, or set to normal or
        dangerous, can be held by any third-party app, so if it guards an
        exported activity/service/receiver/provider it is a privilege-escalation
        door (permission squatting). signature and above are safe. Each entry is
        reported with its decoded protection_level, any protection_flags, its
        permission_group, and weak_protection (true when the base is normal or
        dangerous). weak_count folds those up; permission_groups and
        permission_trees list the app's <permission-group>/<permission-tree>
        declarations. Only the app's declarations are returned -- for the
        permissions it requests, use apk.permissions.
        """
        apk = self._apk(path)
        root = apk.get_android_manifest_xml()
        empty: JsonObject = {
            "permissions": [],
            "permission_groups": [],
            "permission_trees": [],
            "count": 0,
            "total": 0,
            "weak_count": 0,
            "has_more": False,
        }
        if root is None:
            return empty

        def _attr(element: Any, name: str) -> str | None:
            value = element.get(_ANDROID_NS + name)
            if value is None or str(value) == "":
                return None
            return str(value)[:_MAX_META_VALUE_CHARS]

        permissions: list[JsonObject] = []
        total = 0
        weak_count = 0
        has_more = False
        for element in root.iter("permission"):
            total += 1
            if len(permissions) >= _MAX_DECLARED_PERMISSIONS:
                has_more = True
                continue
            raw_level = _attr(element, "protectionLevel")
            base, flags = _decode_protection_level(raw_level)
            weak = base in _WEAK_PROTECTION_BASES
            if weak:
                weak_count += 1
            permissions.append(
                {
                    "name": _attr(element, "name"),
                    "protection_level": base,
                    "protection_flags": flags,
                    "protection_level_raw": raw_level,
                    "permission_group": _attr(element, "permissionGroup"),
                    "label": _attr(element, "label"),
                    "weak_protection": weak,
                }
            )

        def _named(tag: str) -> tuple[list[JsonObject], bool]:
            rows: list[JsonObject] = []
            cut = False
            for element in root.iter(tag):
                if len(rows) >= _MAX_DECLARED_PERMISSIONS:
                    cut = True
                    break
                rows.append(
                    {"name": _attr(element, "name"), "label": _attr(element, "label")}
                )
            return rows, cut

        groups, groups_more = _named("permission-group")
        trees, trees_more = _named("permission-tree")
        return {
            "permissions": permissions,
            "permission_groups": groups,
            "permission_trees": trees,
            "count": len(permissions),
            "total": total,
            "weak_count": weak_count,
            "has_more": has_more or groups_more or trees_more,
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

    def meta_data(self, path: Path) -> JsonObject:
        """Lift every <meta-data> element out of the manifest.

        meta-data is where an app parks its keys and switches for the framework
        to read at runtime: Maps/Firebase API keys, the WorkManager/GCM markers,
        a custom SDK's app id, feature toggles. Each entry is reported with the
        component it sits inside (application, activity, service, receiver or
        provider) and that component's name, so a key scoped to one exported
        activity is not mistaken for an app-wide one. value carries the literal
        android:value; resource carries android:resource (a @resource id) when
        the entry points at a resource instead of a literal.
        """
        apk = self._apk(path)
        root = apk.get_android_manifest_xml()
        if root is None:
            return {"meta_data": [], "count": 0, "total": 0, "has_more": False}

        def _attr(element: Any, name: str) -> str | None:
            value = element.get(_ANDROID_NS + name)
            if value is None or str(value) == "":
                return None
            return str(value)[:_MAX_META_VALUE_CHARS]

        items: list[JsonObject] = []
        total = 0
        has_more = False
        for element in root.iter("meta-data"):
            total += 1
            if len(items) >= _MAX_META_DATA:
                has_more = True
                continue
            parent = element.getparent()
            scope = None
            scope_name = None
            if parent is not None:
                scope = str(getattr(parent, "tag", "")) or None
                scope_name = _attr(parent, "name")
            items.append(
                {
                    "name": _attr(element, "name"),
                    "value": _attr(element, "value"),
                    "resource": _attr(element, "resource"),
                    "scope": scope,
                    "scope_name": scope_name,
                }
            )
        return {
            "meta_data": items,
            "count": len(items),
            "total": total,
            "has_more": has_more,
        }

    def uses_features(self, path: Path) -> JsonObject:
        """Report the hardware/software features and libraries the app declares.

        The capability profile a reviewer reads before the code: <uses-feature>
        says what the app expects the device to have (camera, telephony, GPS,
        fingerprint, GL ES level), and <uses-library>/<uses-native-library> name
        the platform and vendor libraries it links against. required=false marks
        a feature the app can run without (it degrades rather than refuses to
        install), which is exactly how an app broadens its install base while
        still using a sensitive capability when present.
        """
        apk = self._apk(path)
        root = apk.get_android_manifest_xml()
        empty = {
            "features": [],
            "feature_count": 0,
            "feature_total": 0,
            "libraries": [],
            "library_count": 0,
            "library_total": 0,
            "has_more": False,
        }
        if root is None:
            return empty

        def _attr(element: Any, name: str) -> str | None:
            value = element.get(_ANDROID_NS + name)
            if value is None or str(value) == "":
                return None
            return str(value)[:_MAX_META_VALUE_CHARS]

        def _required(element: Any) -> bool:
            raw = _attr(element, "required")
            if raw is None:
                return True  # the platform default when android:required is absent
            return raw.strip().lower() == "true"

        features: list[JsonObject] = []
        feature_total = 0
        has_more = False
        for element in root.iter("uses-feature"):
            feature_total += 1
            if len(features) >= _MAX_USES_FEATURES:
                has_more = True
                continue
            features.append(
                {
                    "name": _attr(element, "name"),
                    "required": _required(element),
                    "gl_es_version": _attr(element, "glEsVersion"),
                }
            )

        libraries: list[JsonObject] = []
        library_total = 0
        for tag, native in (("uses-library", False), ("uses-native-library", True)):
            for element in root.iter(tag):
                library_total += 1
                if len(libraries) >= _MAX_USES_LIBRARIES:
                    has_more = True
                    continue
                libraries.append(
                    {
                        "name": _attr(element, "name"),
                        "required": _required(element),
                        "native": native,
                    }
                )

        return {
            "features": features,
            "feature_count": len(features),
            "feature_total": feature_total,
            "libraries": libraries,
            "library_count": len(libraries),
            "library_total": library_total,
            "has_more": has_more,
        }

    def providers(self, path: Path) -> JsonObject:
        """Report content providers as an attack surface: authorities and guards.

        A content provider is the widest data door an app can leave open, and
        the facts that decide whether it is safe live in attributes the other
        component tools do not surface: the authorities that address it, whether
        it is exported, the read/write permissions guarding it, whether it hands
        out temporary URI grants (grantUriPermissions plus any
        <grant-uri-permission> paths), and any <path-permission> children that
        guard a sub-path differently from the provider as a whole. An exported
        provider with no permission is the classic leak (arbitrary read/write,
        SQL-injection or path-traversal into the app's data), so this folds each
        provider with those fields and flags the unguarded-and-exported ones.
        """
        apk = self._apk(path)
        root = apk.get_android_manifest_xml()
        empty: JsonObject = {
            "providers": [],
            "count": 0,
            "total": 0,
            "exported_unguarded": 0,
            "has_more": False,
        }
        if root is None:
            return empty

        def _attr(element: Any, name: str) -> str | None:
            value = element.get(_ANDROID_NS + name)
            if value is None or str(value) == "":
                return None
            return str(value)[:_MAX_META_VALUE_CHARS]

        def _bool_attr(element: Any, name: str) -> bool | None:
            raw = _attr(element, name)
            if raw is None:
                return None
            return raw.strip().lower() == "true"

        def _path_spec(element: Any) -> JsonObject:
            return {
                "path": _attr(element, "path"),
                "path_prefix": _attr(element, "pathPrefix"),
                "path_pattern": _attr(element, "pathPattern"),
            }

        target_sdk = _as_int(apk.get_target_sdk_version()) or _as_int(
            apk.get_min_sdk_version()
        )
        # Providers are exported by default only when targetSdk < 17; from 17 on
        # the default is false. With no SDK to read, do not guess a default.
        default_exported = target_sdk is not None and target_sdk < 17

        providers: list[JsonObject] = []
        total = 0
        exported_unguarded = 0
        has_more = False
        for element in root.iter("provider"):
            total += 1
            if len(providers) >= _MAX_PROVIDERS:
                has_more = True
                continue
            authorities_raw = _attr(element, "authorities") or ""
            authorities = [a for a in authorities_raw.split(";") if a][
                :_MAX_PROVIDER_AUTHORITIES
            ]
            explicit = _bool_attr(element, "exported")
            permission = _attr(element, "permission")
            read_permission = _attr(element, "readPermission")
            write_permission = _attr(element, "writePermission")
            guarded = (
                permission is not None
                or read_permission is not None
                or write_permission is not None
            )
            effective = (
                explicit
                if explicit is not None
                else default_exported and bool(authorities)
            )
            grant_all = _bool_attr(element, "grantUriPermissions")
            grant_uris = [
                _path_spec(child)
                for child in list(element.iter("grant-uri-permission"))[:_MAX_GRANT_URIS]
            ]
            path_permissions = [
                {
                    **_path_spec(child),
                    "permission": _attr(child, "permission"),
                    "read_permission": _attr(child, "readPermission"),
                    "write_permission": _attr(child, "writePermission"),
                }
                for child in list(element.iter("path-permission"))[:_MAX_PATH_PERMISSIONS]
            ]
            if effective and not guarded:
                exported_unguarded += 1
            providers.append(
                {
                    "name": _attr(element, "name"),
                    "authorities": authorities,
                    "exported": explicit,
                    "effective_exported": effective,
                    "enabled": _bool_attr(element, "enabled"),
                    "permission": permission,
                    "read_permission": read_permission,
                    "write_permission": write_permission,
                    "grant_uri_permissions": bool(grant_all) or bool(grant_uris),
                    "grant_uris": grant_uris,
                    "path_permissions": path_permissions,
                    "guarded": guarded,
                }
            )
        return {
            "providers": providers,
            "count": len(providers),
            "total": total,
            "exported_unguarded": exported_unguarded,
            "has_more": has_more,
        }

    def intent_filters(self, path: Path) -> JsonObject:
        """Map each component's <intent-filter>: the app's declared entry points.

        components lists names; this lists how the outside world reaches them --
        the actions and categories a component answers to, and any data filters
        (scheme/host/path/mimeType) that make it a deep-link or custom-scheme
        handler. Only components that actually declare a filter are returned.
        exported is read from the manifest (true/false, or null when the
        attribute is absent and the platform default applies); an exported
        component with a MAIN/LAUNCHER or a custom-scheme filter is the attack
        surface a reviewer looks for first.
        """
        apk = self._apk(path)

        def _exported(itemtype: str, name: str) -> bool | None:
            try:
                raw = apk.get_attribute_value(itemtype, "exported", name=name)
            except Exception:  # noqa: BLE001 - androguard manifest access varies
                return None
            if raw is None or str(raw) == "":
                return None
            return str(raw).strip().lower() == "true"

        components: list[JsonObject] = []
        total = 0
        has_more = False
        for itemtype, getter in (
            ("activity", apk.get_activities),
            ("service", apk.get_services),
            ("receiver", apk.get_receivers),
        ):
            for raw_name in getter() or []:
                name = str(raw_name)
                try:
                    filt = apk.get_intent_filters(itemtype, name)
                except Exception:  # noqa: BLE001
                    filt = {}
                if not filt:
                    continue
                total += 1
                if len(components) >= _MAX_INTENT_COMPONENTS:
                    has_more = True
                    continue
                actions, actions_more = _cap_names(filt.get("action"), _MAX_INTENT_ITEMS)
                categories, cats_more = _cap_names(filt.get("category"), _MAX_INTENT_ITEMS)
                data_entries = filt.get("data") or []
                data = [d for d in data_entries[:_MAX_INTENT_ITEMS] if isinstance(d, dict)]
                schemes = sorted(
                    {str(d["scheme"]) for d in data if d.get("scheme")}
                )
                components.append(
                    {
                        "type": itemtype,
                        "name": name,
                        "exported": _exported(itemtype, name),
                        "actions": actions,
                        "categories": categories,
                        "data": data,
                        "schemes": schemes,
                        "deep_link": bool(schemes),
                        "has_more": actions_more or cats_more,
                    }
                )
        return {
            "components": components,
            "count": len(components),
            "total": total,
            "has_more": has_more,
        }

    def exported_components(self, path: Path) -> JsonObject:
        """Fold the four component types into the externally-reachable surface.

        components lists names and intent_filters lists filters; this answers the
        security question they only imply: which activities, services, receivers
        and providers can another app invoke, and which of those are not guarded
        by a permission. A component is treated as exported when android:exported
        says so, or -- when the attribute is absent -- when it declares an
        intent-filter (the platform default), which is flagged exported_implied.
        """
        apk = self._apk(path)

        def _attr(itemtype: str, name: str, attr: str) -> str | None:
            try:
                raw = apk.get_attribute_value(itemtype, attr, name=name)
            except Exception:  # noqa: BLE001 - androguard manifest access varies
                return None
            if raw is None or str(raw) == "":
                return None
            return str(raw).strip()

        def _exported_flag(itemtype: str, name: str) -> bool | None:
            raw = _attr(itemtype, name, "exported")
            if raw is None:
                return None
            return raw.lower() == "true"

        components: list[JsonObject] = []
        exported_total = 0
        total_components = 0
        unguarded = 0
        has_more = False
        getters: tuple[tuple[str, Any], ...] = (
            ("activity", apk.get_activities),
            ("service", apk.get_services),
            ("receiver", apk.get_receivers),
            ("provider", getattr(apk, "get_providers", lambda: [])),
        )
        for itemtype, getter in getters:
            try:
                names = getter() or []
            except Exception:  # noqa: BLE001
                names = []
            for raw_name in names:
                name = str(raw_name)
                total_components += 1
                try:
                    filt = apk.get_intent_filters(itemtype, name)
                except Exception:  # noqa: BLE001
                    filt = {}
                has_filter = bool(filt)
                explicit = _exported_flag(itemtype, name)
                if explicit is None:
                    effective = has_filter
                    implied = has_filter
                else:
                    effective = explicit
                    implied = False
                if not effective:
                    continue
                exported_total += 1
                permission = _attr(itemtype, name, "permission")
                read_permission = _attr(itemtype, name, "readPermission")
                write_permission = _attr(itemtype, name, "writePermission")
                guarded = (
                    permission is not None
                    or read_permission is not None
                    or write_permission is not None
                )
                if not guarded:
                    unguarded += 1
                if len(components) >= _MAX_INTENT_COMPONENTS:
                    has_more = True
                    continue
                actions = {str(a) for a in (filt.get("action") or [])}
                categories = {str(c) for c in (filt.get("category") or [])}
                data_entries = [d for d in (filt.get("data") or []) if isinstance(d, dict)]
                schemes = sorted({str(d["scheme"]) for d in data_entries if d.get("scheme")})
                components.append(
                    {
                        "type": itemtype,
                        "name": name,
                        "exported": explicit,
                        "effective_exported": True,
                        "exported_implied": implied,
                        "has_intent_filter": has_filter,
                        "permission": permission,
                        "read_permission": read_permission,
                        "write_permission": write_permission,
                        "guarded": guarded,
                        "launcher": (
                            "android.intent.action.MAIN" in actions
                            and "android.intent.category.LAUNCHER" in categories
                        ),
                        "deep_link": bool(schemes),
                        "schemes": schemes[:_MAX_INTENT_ITEMS],
                    }
                )
        return {
            "components": components,
            "count": len(components),
            "exported_total": exported_total,
            "total_components": total_components,
            "unguarded_count": unguarded,
            "has_more": has_more,
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

    def files(self, path: Path, *, offset: int = 0, limit: int = 200) -> JsonObject:
        """List every archive entry, bucketed, with best-effort sizes.

        native_libs only sees lib/; this is the whole zip -- how many DEX files
        (a multidex or a packed loader stub shows up here), embedded jars/apks
        under assets/, the arsc, the signature block. Sizes come from the
        central directory when androguard exposes it, and are null otherwise
        rather than read by inflating each entry.
        """
        apk = self._apk(path)
        sizes: dict[str, int] = {}
        try:
            info = apk.zip.infolist()
            items_view = info.items() if hasattr(info, "items") else []
            for entry_name, entry in items_view:
                size = getattr(entry, "uncompressed_size", None)
                if size is not None:
                    sizes[str(entry_name)] = int(size)
        except Exception:  # noqa: BLE001 - zip internals vary across versions
            sizes = {}

        names: list[str] = []
        scan_more = False
        for raw in apk.get_files() or []:
            if len(names) >= _MAX_FILES_COLLECT:
                scan_more = True
                break
            names.append(str(raw))
        names.sort()

        categories: dict[str, int] = {}
        total_uncompressed = 0
        entries: list[JsonObject] = []
        for name in names:
            category = _categorize_apk_entry(name)
            categories[category] = categories.get(category, 0) + 1
            size = sizes.get(name)
            if size is not None:
                total_uncompressed += size
            entries.append({"name": name, "category": category, "size": size})

        start, cap = _clamp_page(offset, limit, max_limit=_MAX_FILES_PAGE)
        window = entries[start : start + cap]
        return {
            "files": window,
            "count": len(window),
            "total": len(entries),
            "offset": start,
            "has_more": start + len(window) < len(entries),
            "categories": categories,
            "total_uncompressed": total_uncompressed,
            "scan_capped": scan_more,
        }

    def dex_headers(self, path: Path) -> JsonObject:
        """Report each classesN.dex header: version, id counts, multidex shape.

        The structural fingerprint a packer or an unusual build leaves before any
        code is read. Each DEX file carries a fixed header with its format
        version (035/037/038/039 -- a newer version than the app's minSdk
        implies is a tell) and the sizes of its id pools (strings, types,
        methods, classes). A single classes.dex with almost no classes beside a
        large encrypted asset is the classic dropper shape; an unexpected count
        of .dex files is the multidex/packer shape. Read straight from the DEX
        headers, so it stays cheap and needs no full analysis.

        Answers with dex_files (one per classesN.dex, in archive order),
        dex_count, multidex, total_classes / total_methods / total_strings
        (summed over valid headers) and has_more. Each entry carries name,
        version, valid (false when the blob is not a parseable DEX), checksum,
        declared_file_size, actual_size, and the id counts string_count /
        type_count / proto_count / field_count / method_count / class_def_count
        plus data_size.
        """
        apk = self._apk(path)
        try:
            names = list(apk.get_dex_names() or [])
        except Exception:  # noqa: BLE001 - androguard access varies by version
            names = []
        try:
            raws = list(apk.get_all_dex() or [])
        except Exception:  # noqa: BLE001
            raws = []

        entries: list[JsonObject] = []
        total_classes = 0
        total_methods = 0
        total_strings = 0
        has_more = False
        for index, raw in enumerate(raws):
            if len(entries) >= _MAX_DEX_FILES:
                has_more = True
                break
            name = str(names[index]) if index < len(names) else f"dex[{index}]"
            header = _parse_dex_header(bytes(raw))
            header["name"] = name
            if header["valid"]:
                total_classes += int(header["class_def_count"] or 0)
                total_methods += int(header["method_count"] or 0)
                total_strings += int(header["string_count"] or 0)
            entries.append(header)

        return {
            "dex_files": entries,
            "dex_count": len(raws),
            "multidex": len(raws) > 1,
            "total_classes": total_classes,
            "total_methods": total_methods,
            "total_strings": total_strings,
            "has_more": has_more,
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

    def method_info(
        self, path: Path, class_name: str, method_name: str
    ) -> JsonObject:
        """Parse a method's proto (params, return) and decode its access flags.

        methods lists a class's methods with raw descriptor and access strings;
        this resolves one method (all overloads of a name) into typed parameters,
        a return type and boolean flags (is_native, has_code, is_static...). Native
        methods with no bytecode are the JNI bridge worth chasing next.
        """
        parsed = self._parsed(path)
        klass_target = class_name.strip()
        method_target = method_name.strip()
        if not klass_target:
            raise ApkError("invalid_params", "class_name is required")
        if not method_target:
            raise ApkError("invalid_params", "method_name is required")

        smali = _dotted_to_smali(klass_target)
        found = [
            klass
            for klass in parsed.analysis.get_classes()
            if klass.name == klass_target or klass.name == smali
        ]
        if not found:
            raise ApkError("not_found", "class not found", class_name=class_name)

        overloads: list[JsonObject] = []
        scan_more = False
        for klass in found:
            for method in klass.get_methods():
                if str(method.name) != method_target:
                    continue
                if len(overloads) >= _MAX_METHOD_OVERLOADS:
                    scan_more = True
                    break
                descriptor = str(getattr(method, "descriptor", ""))
                access = str(getattr(method, "access", ""))
                proto = _parse_dalvik_proto(descriptor)
                entry: JsonObject = {
                    "descriptor": descriptor,
                    "params": proto["params"],
                    "return_type": proto["return_type"],
                    "signature_parsed": proto["parsed"],
                    "access": access,
                }
                entry.update(_decode_method_access(access))
                overloads.append(entry)
            if scan_more:
                break

        if not overloads:
            raise ApkError(
                "not_found",
                "method not found",
                class_name=class_name,
                method_name=method_name,
            )

        return {
            "class_name": found[0].name,
            "method_name": method_target,
            "methods": overloads,
            "count": len(overloads),
            "scan_capped": scan_more,
        }

    def class_info(self, path: Path, class_name: str) -> JsonObject:
        """Report a class's superclass, interfaces, access flags and fields.

        methods/method_info cover the behaviour; this covers the shape: what the
        class extends and implements (a class extending a known base or
        implementing a Parcelable/Serializable is a fast structural tell), its
        declared fields with types, and its method count.
        """
        parsed = self._parsed(path)
        target = class_name.strip()
        if not target:
            raise ApkError("invalid_params", "class_name is required")

        smali = _dotted_to_smali(target)
        found = None
        for klass in parsed.analysis.get_classes():
            if klass.name == target or klass.name == smali:
                found = klass
                break
        if found is None:
            raise ApkError("not_found", "class not found", class_name=class_name)

        superclass = getattr(found, "extends", None)
        interfaces_raw = getattr(found, "implements", None) or []
        interfaces: list[str] = []
        interfaces_truncated = False
        for iface in interfaces_raw:
            if len(interfaces) >= _MAX_INTERFACES:
                interfaces_truncated = True
                break
            interfaces.append(_dalvik_type_human(str(iface)))

        access = ""
        try:
            vm_class = found.get_vm_class()
            access = str(vm_class.get_access_flags_string()) if vm_class is not None else ""
        except Exception:  # noqa: BLE001 - external/synthetic classes lack a vm class
            access = ""

        fields: list[JsonObject] = []
        fields_truncated = False
        try:
            field_iter = list(found.get_fields())
        except Exception:  # noqa: BLE001
            field_iter = []
        for fld in field_iter:
            if len(fields) >= _MAX_CLASS_FIELDS:
                fields_truncated = True
                break
            try:
                encoded = fld.get_field()
                fname = str(encoded.get_name())
                descriptor = str(encoded.get_descriptor())
                faccess = str(encoded.get_access_flags_string())
            except Exception:  # noqa: BLE001
                continue
            field_entry: JsonObject = {
                "name": fname,
                "type": _dalvik_type_human(descriptor),
                "descriptor": descriptor,
                "access": faccess,
            }
            field_entry.update(_decode_field_access(faccess))
            fields.append(field_entry)

        try:
            method_count = int(found.get_nb_methods())
        except Exception:  # noqa: BLE001
            method_count = 0

        result: JsonObject = {
            "class_name": found.name,
            "superclass": _dalvik_type_human(str(superclass)) if superclass else None,
            "interfaces": interfaces,
            "interfaces_truncated": interfaces_truncated,
            "access": access,
            "fields": fields,
            "field_count": len(fields),
            "fields_truncated": fields_truncated,
            "method_count": method_count,
            "external": bool(found.is_external()),
        }
        result.update(_decode_class_access(access))
        return result

    def disassemble(
        self,
        path: Path,
        class_name: str,
        method_name: str,
        *,
        descriptor: str | None = None,
        offset: int = 0,
        limit: int = 200,
    ) -> JsonObject:
        """Decode one method's Dalvik (smali) instruction stream.

        apk.method_info gives the signature and flags; this gives the body --
        the actual bytecode the method runs, straight from androguard with no
        decompiler in the loop, so it answers even where apk.decompile has no
        jadx. Resolves the class (dotted or Lsmali/form) and the method by name,
        optionally narrowed by descriptor when the name is overloaded, then walks
        the code item's instructions.
        """
        parsed = self._parsed(path)
        klass_target = class_name.strip()
        method_target = method_name.strip()
        if not klass_target:
            raise ApkError("invalid_params", "class_name is required")
        if not method_target:
            raise ApkError("invalid_params", "method_name is required")
        desc_target = (descriptor or "").strip() or None

        smali = _dotted_to_smali(klass_target)
        found = [
            klass
            for klass in parsed.analysis.get_classes()
            if klass.name == klass_target or klass.name == smali
        ]
        if not found:
            raise ApkError("not_found", "class not found", class_name=class_name)

        matches: list[tuple[Any, str]] = []
        available: list[str] = []
        for klass in found:
            for method in klass.get_methods():
                if str(method.name) != method_target:
                    continue
                descriptor_str = str(getattr(method, "descriptor", ""))
                available.append(descriptor_str)
                if desc_target is None or _descriptor_matches(descriptor_str, desc_target):
                    matches.append((method, descriptor_str))

        if not matches:
            raise ApkError(
                "not_found",
                "method not found",
                class_name=class_name,
                method_name=method_name,
            )

        ambiguous = desc_target is None and len(matches) > 1
        # Prefer an overload that actually has a code item so a name that also
        # has a native/abstract declaration still disassembles the real body.
        chosen, chosen_desc = matches[0]
        for method, descriptor_str in matches:
            if _encoded_code(method.get_method()) is not None:
                chosen, chosen_desc = method, descriptor_str
                break

        encoded = chosen.get_method()
        is_external = bool(chosen.is_external()) if hasattr(chosen, "is_external") else False
        access = str(getattr(chosen, "access", ""))
        proto = _parse_dalvik_proto(chosen_desc)
        header: JsonObject = {
            "class_name": found[0].name,
            "method_name": method_target,
            "descriptor": chosen_desc,
            "params": proto["params"],
            "return_type": proto["return_type"],
            "access": access,
            "ambiguous": ambiguous,
            "overloads": len(available),
        }

        if encoded is None or is_external or _encoded_code(encoded) is None:
            # Native, abstract or referenced-only: no bytecode to walk.
            return {
                **header,
                "has_code": False,
                "instructions": [],
                "count": 0,
                "total": 0,
                "offset": 0,
                "has_more": False,
                "scan_capped": False,
            }

        rows: list[JsonObject] = []
        scan_capped = False
        code_offset = 0
        for ins in encoded.get_instructions():
            if len(rows) >= _MAX_DALVIK_INSNS_COLLECT:
                scan_capped = True
                break
            size = _insn_length(ins)
            row: JsonObject = {
                "offset": code_offset,
                "mnemonic": _insn_name(ins),
                "operands": _insn_operands(ins, code_offset),
                "size": size,
            }
            opcode = _insn_opcode(ins)
            if opcode is not None:
                row["opcode"] = opcode
            hex_bytes = _insn_hex(ins)
            if hex_bytes:
                row["hex"] = hex_bytes
            rows.append(row)
            code_offset += size

        total = len(rows)
        start, cap = _clamp_page(offset, limit, max_limit=_MAX_DALVIK_INSNS_PAGE)
        window = rows[start : start + cap]
        return {
            **header,
            "has_code": True,
            "instructions": window,
            "count": len(window),
            "total": total,
            "offset": start,
            "has_more": start + len(window) < total,
            "scan_capped": scan_capped,
        }

    def native_methods(
        self, path: Path, *, offset: int = 0, limit: int = 100
    ) -> JsonObject:
        """Enumerate the app's JNI native methods -- the boundary into the .so files.

        A method declared ``native`` has no bytecode: its body lives in a shared
        library, reached over JNI. apk.method_info decodes that flag for one
        method at a time; this sweeps the whole DEX and lists every native
        method with its class, signature and the C symbol JNI would resolve it
        to, so an analyst who found nothing in the bytecode knows exactly which
        exports to chase in apk.native_libs. The jni_symbol is the short
        (non-overloaded) mangling -- for an overloaded native method the real
        export carries an argument-type suffix this does not add.
        """
        parsed = self._parsed(path)
        rows: list[JsonObject] = []
        scan_more = False
        for klass in parsed.analysis.get_classes():
            if klass.is_external():
                continue
            for method in klass.get_methods():
                access = str(getattr(method, "access", ""))
                if "native" not in access.split():
                    continue
                if len(rows) >= _MAX_NATIVE_METHODS_COLLECT:
                    scan_more = True
                    break
                descriptor = str(getattr(method, "descriptor", ""))
                proto = _parse_dalvik_proto(descriptor)
                cls = str(klass.name)
                name = str(method.name)
                rows.append(
                    {
                        "class": _dalvik_type_human(cls),
                        "method": name,
                        "descriptor": descriptor,
                        "params": proto["params"],
                        "return_type": proto["return_type"],
                        "jni_symbol": _jni_short_name(cls, name),
                    }
                )
            if scan_more:
                break
        rows.sort(key=lambda r: (str(r["class"]), str(r["method"])))
        start, cap = _clamp_page(offset, limit, max_limit=_MAX_NATIVE_METHODS_PAGE)
        window = rows[start : start + cap]
        return {
            "native_methods": window,
            "count": len(window),
            "total": len(rows),
            "offset": start,
            "has_more": start + len(window) < len(rows),
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

    def urls(self, path: Path, *, offset: int = 0, limit: int = 200) -> JsonObject:
        """Extract network indicators (URLs, hosts, IPs) from DEX string constants.

        apk.strings lists every constant; this distils the network-relevant ones
        -- the C2 endpoints, API bases, tracking beacons and hard-coded IPs a
        triage wants first -- into a deduped, classified inventory.
        """
        parsed = self._parsed(path)
        url_map, hosts, ips, scan_capped = _extract_url_indicators(
            item.get_value() for item in parsed.analysis.get_strings()
        )
        url_list = sorted(url_map.values(), key=lambda row: str(row["url"]))
        start, cap = _clamp_page(offset, limit, max_limit=_MAX_URLS_PAGE)
        window = url_list[start : start + cap]
        host_rollup = [
            {"host": host, "count": count}
            for host, count in hosts.most_common(_MAX_HOST_ROLLUP)
        ]
        ip_list = sorted(ips)
        return {
            "urls": window,
            "count": len(window),
            "total": len(url_list),
            "offset": start,
            "has_more": start + len(window) < len(url_list),
            "hosts": host_rollup,
            "host_count": len(host_rollup),
            "hosts_truncated": len(hosts) > len(host_rollup),
            "ips": ip_list,
            "ip_count": len(ip_list),
            "scan_capped": scan_capped,
        }

    def secrets(self, path: Path, *, offset: int = 0, limit: int = 200) -> JsonObject:
        """Classify DEX string constants against known credential patterns.

        apk.strings lists every constant; this classifies each against the
        shared credential table (AWS/Google/GitHub/Slack/Stripe keys, Firebase
        URLs, JWTs, PEM private keys, ...) -- the hard-coded-key triage that is
        one of the top findings in a mobile audit. Matches are deduped and
        redacted; the string pool has no line numbers, so each finding's lines
        list stays empty.
        """
        parsed = self._parsed(path)
        values: list[tuple[str, int | None]] = []
        scan_capped = False
        for item in parsed.analysis.get_strings():
            if len(values) >= _MAX_STRINGS_COLLECT:
                scan_capped = True
                break
            values.append((str(item.get_value())[:_MAX_STRING_LEN], None))
        return classify_secrets(
            values, offset=offset, limit=limit, scan_capped=scan_capped
        )

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

    def api_usage(self, path: Path) -> JsonObject:
        """Scan for calls into sensitive platform APIs, grouped by threat category.

        Where apk.permissions and apk.urls read the manifest and string pool,
        this reads the call graph: for every external API the app invokes it
        matches the method against a curated table (reflection, dynamic code
        loading, process exec, native loads, crypto, SMS, device identifiers,
        ...) and counts the call sites via each method's xref_from. The result
        is the "what does this app actually *do*" view a malware triage reaches
        for after the manifest -- a permission only says an app *may* send SMS,
        a call site into SmsManager.sendTextMessage says it *does*.
        """
        parsed = self._parsed(path)
        # category -> {"hits": int, "apis": {(human_class, method): callers}}
        cats: OrderedDict[str, dict[str, Any]] = OrderedDict()
        scanned = 0
        scan_capped = False
        for method in parsed.analysis.get_methods():
            if scanned >= _MAX_API_METHODS_SCAN:
                scan_capped = True
                break
            scanned += 1
            cls = str(method.class_name)
            name = str(method.name)
            category = _classify_api(cls, name)
            if category is None:
                continue
            callers = 0
            for _ in method.get_xref_from():
                callers += 1
                if callers >= _MAX_API_CALLERS:
                    break
            # An API node with no caller is dead metadata (androguard still
            # models the external ref); only a real call site counts as usage.
            if callers == 0:
                continue
            bucket = cats.setdefault(category, {"hits": 0, "apis": {}})
            bucket["hits"] += callers
            key = (_dalvik_type_human(cls), name)
            apis: dict[tuple[str, str], int] = bucket["apis"]
            apis[key] = apis.get(key, 0) + callers

        categories: list[JsonObject] = []
        for category, bucket in cats.items():
            ranked = sorted(bucket["apis"].items(), key=lambda kv: (-kv[1], kv[0]))
            rows = [
                {"class": cls_h, "method": mname, "callers": n}
                for (cls_h, mname), n in ranked[:_MAX_API_ROWS]
            ]
            categories.append(
                {
                    "category": category,
                    "hits": bucket["hits"],
                    "apis": rows,
                    "api_count": len(rows),
                    "apis_truncated": len(ranked) > len(rows),
                }
            )
        categories.sort(key=lambda c: (-int(c["hits"]), str(c["category"])))
        return {
            "categories": categories,
            "category_count": len(categories),
            "total_call_sites": sum(int(c["hits"]) for c in categories),
            "scan_capped": scan_capped,
        }


def _parse_dex_header(raw: bytes) -> JsonObject:
    """Parse a DEX file's fixed 112-byte header into its version and count table.

    The DEX header layout is fixed little-endian, so this reads it directly
    rather than through androguard: magic + version, then the ids-size counts
    (strings/types/protos/fields/methods/class_defs) and the header's own
    file_size/data_size. A blob that is not a DEX or is too short to hold the
    header comes back with valid False and whatever could be read.
    """
    out: JsonObject = {
        "valid": False,
        "version": None,
        "checksum": None,
        "declared_file_size": None,
        "actual_size": len(raw),
        "string_count": None,
        "type_count": None,
        "proto_count": None,
        "field_count": None,
        "method_count": None,
        "class_def_count": None,
        "data_size": None,
    }
    if len(raw) < 8 or raw[:4] != _DEX_MAGIC:
        return out
    out["version"] = raw[4:7].decode("ascii", errors="replace")
    if len(raw) < _DEX_HEADER_SIZE:
        return out
    checksum = struct.unpack_from("<I", raw, 8)[0]
    out["checksum"] = f"{checksum:08x}"
    out["declared_file_size"] = struct.unpack_from("<I", raw, 32)[0]
    out["string_count"] = struct.unpack_from("<I", raw, 56)[0]
    out["type_count"] = struct.unpack_from("<I", raw, 64)[0]
    out["proto_count"] = struct.unpack_from("<I", raw, 72)[0]
    out["field_count"] = struct.unpack_from("<I", raw, 80)[0]
    out["method_count"] = struct.unpack_from("<I", raw, 88)[0]
    out["class_def_count"] = struct.unpack_from("<I", raw, 96)[0]
    out["data_size"] = struct.unpack_from("<I", raw, 104)[0]
    out["valid"] = True
    return out


def _categorize_apk_entry(name: str) -> str:
    """Bucket an archive entry the way an APK reviewer reads a zip listing."""
    if name == "AndroidManifest.xml":
        return "manifest"
    if name == "resources.arsc":
        return "arsc"
    if name.startswith("META-INF/"):
        return "signature"
    if name.endswith(".dex"):
        return "dex"
    if name.startswith("lib/"):
        return "native_lib"
    if name.startswith("res/"):
        return "resource"
    if name.startswith("assets/"):
        return "asset"
    if name.startswith("kotlin/"):
        return "kotlin"
    return "other"


def _as_int(value: Any) -> int | None:
    """Coerce androguard's SDK-version value (str/int/None) to an int, or None."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _dotted_to_smali(name: str) -> str:
    """com.example.Foo -> Lcom/example/Foo; so either form resolves a class."""
    if name.startswith("L") and name.endswith(";"):
        return name
    return "L" + name.replace(".", "/") + ";"


def _descriptor_matches(descriptor: str, target: str) -> bool:
    """Whether a method descriptor matches the caller's, ignoring stray spaces.

    androguard renders a proto with incidental spaces (``(Ljava/lang/String; I)V``),
    so an exact string compare is too strict; compare with whitespace removed.
    """
    return descriptor == target or descriptor.replace(" ", "") == target.replace(" ", "")


def _encoded_code(encoded: object) -> Any:
    """The method's DalvikCode item, or None for native/abstract/unavailable."""
    getter = getattr(encoded, "get_code", None)
    if getter is None:
        return None
    try:
        return getter()
    except Exception:  # noqa: BLE001 - external/synthetic methods have no code
        return None


def _insn_length(ins: object) -> int:
    getter = getattr(ins, "get_length", None)
    if getter is None:
        return 0
    try:
        return int(getter() or 0)
    except Exception:  # noqa: BLE001
        return 0


def _insn_name(ins: object) -> str:
    getter = getattr(ins, "get_name", None)
    if getter is None:
        return ""
    try:
        return str(getter())
    except Exception:  # noqa: BLE001
        return ""


def _insn_operands(ins: object, code_offset: int) -> str:
    """The rendered operand string, passing the offset so branch targets resolve."""
    getter = getattr(ins, "get_output", None)
    if getter is None:
        return ""
    try:
        try:
            out = getter(code_offset)
        except TypeError:
            out = getter()
    except Exception:  # noqa: BLE001 - some instructions fault rendering operands
        return ""
    return str(out)[:_MAX_OPERAND_LEN]


def _insn_opcode(ins: object) -> int | None:
    getter = getattr(ins, "get_op_value", None)
    if getter is None:
        return None
    try:
        value = getter()
    except Exception:  # noqa: BLE001
        return None
    return int(value) if isinstance(value, int) else None


def _insn_hex(ins: object) -> str:
    getter = getattr(ins, "get_hex", None)
    if getter is None:
        return ""
    try:
        return str(getter())[:_MAX_INSN_HEX_LEN]
    except Exception:  # noqa: BLE001
        return ""


_DALVIK_PRIMS = {
    "V": "void",
    "Z": "boolean",
    "B": "byte",
    "S": "short",
    "C": "char",
    "I": "int",
    "J": "long",
    "F": "float",
    "D": "double",
}


def _read_dalvik_type(text: str, pos: int) -> tuple[str | None, int]:
    """Read one Dalvik type descriptor at ``pos``; return (human, next_pos)."""
    arr = 0
    while pos < len(text) and text[pos] == "[":
        arr += 1
        pos += 1
    if pos >= len(text):
        return None, pos
    ch = text[pos]
    if ch in _DALVIK_PRIMS:
        base = _DALVIK_PRIMS[ch]
        pos += 1
    elif ch == "L":
        end = text.find(";", pos)
        if end == -1:
            return None, len(text)
        base = text[pos + 1 : end].replace("/", ".")
        pos = end + 1
    else:
        # Unknown token: cannot know its length; stop to avoid desync.
        return None, pos + 1
    return base + "[]" * arr, pos


def _parse_dalvik_proto(proto: str) -> JsonObject:
    """Split a Dalvik method proto ``(params)ret`` into human-readable types.

    androguard formats the proto with stray spaces (e.g. ``(Ljava/lang/String; I)V``)
    so whitespace is stripped before scanning. ``parsed`` is false when the shape
    is not a proto we can walk, leaving the raw descriptor as the source of truth.
    """
    result: JsonObject = {"params": [], "return_type": None, "parsed": False}
    text = (proto or "").strip()
    if not text.startswith("("):
        return result
    close = text.find(")")
    if close == -1:
        return result
    param_str = text[1:close].replace(" ", "")
    ret_str = text[close + 1 :].replace(" ", "")

    params: list[str] = []
    pos = 0
    while pos < len(param_str):
        human, nxt = _read_dalvik_type(param_str, pos)
        if human is None or nxt <= pos:
            return result
        params.append(human)
        pos = nxt

    return_type: str | None = None
    if ret_str:
        return_type, _ = _read_dalvik_type(ret_str, 0)

    result["params"] = params
    result["return_type"] = return_type
    result["parsed"] = True
    return result


def _dalvik_type_human(descriptor: str) -> str:
    """Render one Dalvik type descriptor as a human type, or echo it on failure."""
    human, _ = _read_dalvik_type(descriptor or "", 0)
    return human if human is not None else (descriptor or "")


def _jni_short_name(smali_class: str, method_name: str) -> str:
    """The C symbol JNI resolves a native method to, in its short (non-overloaded) form.

    JNI mangles ``Ljava/lang/Foo;`` + ``do_it`` to
    ``Java_java_lang_Foo_do_1it``: package separators become ``_`` and a literal
    ``_`` becomes ``_1``. The short form (no argument-type suffix) is what a
    single, non-overloaded native method exports, so it is the string to grep
    for in the .so.
    """
    internal = smali_class
    if internal.startswith("L") and internal.endswith(";"):
        internal = internal[1:-1]
    mangled_class = internal.replace("_", "_1").replace("/", "_")
    mangled_method = method_name.replace("_", "_1")
    return f"Java_{mangled_class}_{mangled_method}"


def _decode_class_access(access: str) -> JsonObject:
    """Decode a class's androguard access-flag string into booleans."""
    tokens = (access or "").split()
    flags = set(tokens)

    def has(token: str) -> bool:
        return token in flags

    return {
        "flags": tokens,
        "is_public": has("public"),
        "is_final": has("final"),
        "is_abstract": has("abstract"),
        "is_interface": has("interface"),
        "is_enum": has("enum"),
        "is_annotation": has("annotation"),
        "is_synthetic": has("synthetic"),
    }


def _decode_field_access(access: str) -> JsonObject:
    """Decode a field's androguard access-flag string into booleans."""
    tokens = (access or "").split()
    flags = set(tokens)

    def has(token: str) -> bool:
        return token in flags

    return {
        "is_public": has("public"),
        "is_private": has("private"),
        "is_protected": has("protected"),
        "is_static": has("static"),
        "is_final": has("final"),
        "is_volatile": has("volatile"),
        "is_transient": has("transient"),
        "is_enum": has("enum"),
        "is_synthetic": has("synthetic"),
    }


def _decode_method_access(access: str) -> JsonObject:
    """Decode an androguard access-flag string into booleans (order-free)."""
    tokens = (access or "").split()
    flags = set(tokens)

    def has(token: str) -> bool:
        return token in flags

    return {
        "flags": tokens,
        "is_public": has("public"),
        "is_private": has("private"),
        "is_protected": has("protected"),
        "is_static": has("static"),
        "is_final": has("final"),
        "is_synchronized": has("synchronized") or has("declared_synchronized"),
        "is_native": has("native"),
        "is_abstract": has("abstract"),
        "is_synthetic": has("synthetic"),
        "is_varargs": has("varargs"),
        "is_constructor": has("constructor"),
        # A method carries bytecode unless it is native or abstract.
        "has_code": not (has("native") or has("abstract")),
    }
