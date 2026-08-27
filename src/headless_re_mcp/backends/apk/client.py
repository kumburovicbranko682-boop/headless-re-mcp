"""In-process APK static analysis via androguard.

androguard is an optional dependency: importing it lazily keeps the whole
Android surface usable-but-degraded when it is absent, exactly like the Frida
backend. DEX analysis is expensive, so a small process-wide cache keyed by path
and mtime keeps repeated tool calls within one session from re-parsing.
"""

from __future__ import annotations

import contextlib
import threading
from collections import OrderedDict
from pathlib import Path
from typing import Any, ClassVar

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


class ApkError(RuntimeError):
    def __init__(self, code: str, message: str, **details: object) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details


_LOGGING_QUIETED = False


def _quiet_androguard_logging() -> None:
    """Drop androguard's loguru output so apk.* calls do not flood the server.

    androguard logs through loguru at DEBUG by default -- ~150 lines for even a
    one-class APK, one per basic block, on every AnalyzeAPK. In an unattended
    MCP server that buries the server's own logs on every
    apk.classes/methods/strings/xrefs call. Analysis problems already surface as
    structured results, so silence androguard's stream specifically.
    ``loguru.disable(name)`` is the embedder-safe way: it filters out records
    from the androguard package without removing handlers or touching the host
    app's own logging, unlike ``androguard.util.set_log`` which removes loguru's
    default handler and adds a global stderr one (reconfiguring the whole logger,
    not just androguard). Runs once; the flag makes repeat construction cheap.
    """
    global _LOGGING_QUIETED
    if _LOGGING_QUIETED:
        return
    _LOGGING_QUIETED = True
    with contextlib.suppress(Exception):
        from loguru import logger

        logger.disable("androguard")


def _safe_attr(getter: Any) -> Any:
    """Read one androguard manifest getter, tolerating the ones that raise.

    androguard is inconsistent on a ZIP-valid APK whose AndroidManifest.xml is
    not decodable (obfuscated, truncated, or deliberately corrupted, which is
    common in the wild): most getters swallow the parse failure and return
    ``None``/``[]``, but ``get_androidversion_name``/``get_androidversion_code``
    raise ``KeyError('Name')`` / ``KeyError('Code')``. Left unwrapped in
    ``open()`` that bare KeyError escaped the backend, and the service's
    catch-all filed it as ``internal_error`` with a logged incident -- telling
    the caller our code broke when the APK is merely malformed, and burying the
    fields that did parse. Smoothing it to ``None`` matches what androguard
    already does for the sibling getters on the same input.
    """
    try:
        return getter()
    except Exception:  # noqa: BLE001 - androguard raises many types
        return None


def _readable_name(value: Any) -> str:
    """Render a certificate subject/issuer as a readable distinguished name.

    androguard 4.x hands back asn1crypto ``x509`` certificates, whose ``subject``
    and ``issuer`` are ``x509.Name`` objects. ``str(name)`` on those is an object
    repr -- ``<asn1crypto.x509.Name 0x.. b'0<1\\x0b0\\t..'>`` -- so the previous
    ``str(getattr(cert, "subject"))`` shipped that raw repr to any caller asking
    who signed an APK, i.e. the one thing a certificate read exists to answer came
    back unreadable. ``Name.human_friendly`` renders the DN ("Common Name: .. ,
    Organization: .."). Fall back to ``str`` for any cert shape (older androguard,
    a plain string) that has no such attribute, and treat a raising property as
    absent so one odd cert cannot blank the field.
    """
    try:
        human = value.human_friendly
    except Exception:  # noqa: BLE001 - property access varies by object
        human = None
    if isinstance(human, str) and human:
        return human
    return str(value)


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
            _quiet_androguard_logging()
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
        # The version getters raise on an unparseable manifest; read them
        # through _safe_attr so one bad attribute cannot turn an otherwise
        # readable open() into a bare KeyError. The outer guard is a backstop:
        # any other androguard surprise still answers with a structured
        # envelope, the contract every sibling apk.* method already honours.
        try:
            return {
                "opened": True,
                "package": _safe_attr(apk.get_package),
                "version_name": _safe_attr(apk.get_androidversion_name),
                "version_code": _safe_attr(apk.get_androidversion_code),
                "min_sdk": _safe_attr(apk.get_min_sdk_version),
                "target_sdk": _safe_attr(apk.get_target_sdk_version),
                "main_activity": _safe_attr(apk.get_main_activity),
                "permission_count": len(apk.get_permissions()),
                "native_abis": sorted(
                    {
                        name.split("/")[1]
                        for name in apk.get_files()
                        if name.startswith("lib/") and len(name.split("/")) >= 3
                    }
                ),
            }
        except ApkError:
            raise
        except Exception as exc:  # noqa: BLE001 - androguard raises many types
            raise ApkError("backend_error", f"failed to read APK metadata: {exc}") from exc

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
                        "subject": _readable_name(getattr(cert, "subject", "")),
                        "issuer": _readable_name(getattr(cert, "issuer", "")),
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
        window = names[offset : offset + limit]
        return {
            "classes": window,
            "count": len(window),
            "total": len(names),
            "offset": offset,
            "has_more": offset + len(window) < len(names),
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
        window = values[offset : offset + limit]
        return {
            "strings": window,
            "count": len(window),
            "total": len(values),
            "offset": offset,
            "has_more": offset + len(window) < len(values),
            "scan_capped": scan_more,
        }

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
