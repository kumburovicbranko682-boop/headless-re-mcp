"""In-process APK static analysis via androguard.

androguard is an optional dependency: importing it lazily keeps the whole
Android surface usable-but-degraded when it is absent, exactly like the Frida
backend. DEX analysis is expensive, so a small process-wide cache keyed by path
and mtime keeps repeated tool calls within one session from re-parsing.
"""

from __future__ import annotations

import threading
from collections import OrderedDict
from pathlib import Path
from typing import Any, ClassVar

JsonObject = dict[str, Any]

# DEX analysis of a large app can take seconds and tens of MB; keep only a few
# parsed apps resident and evict the oldest.
_CACHE_LIMIT = 4
_MAX_STRING_LEN = 2000
_MAX_MANIFEST_CHARS = 200_000


class ApkError(RuntimeError):
    def __init__(self, code: str, message: str, **details: object) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details


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

    def manifest(self, path: Path) -> JsonObject:
        apk = self._apk(path)
        try:
            xml = apk.get_android_manifest_axml().get_xml().decode("utf-8", "replace")
        except Exception as exc:  # noqa: BLE001
            raise ApkError("backend_error", f"failed to decode manifest: {exc}") from exc
        # The tool text says this is the decoded manifest. Cutting it without
        # saying so is how an agent concludes a permission or component is
        # absent. Measured: a 250020-character manifest came back as 200000
        # characters, no truncated field, and the XML no longer closed.
        return {
            "package": apk.get_package(),
            "manifest_xml": xml[:_MAX_MANIFEST_CHARS],
            "truncated": len(xml) > _MAX_MANIFEST_CHARS,
            "bytes": len(xml),
        }

    def permissions(self, path: Path, *, limit: int = 500) -> JsonObject:
        apk = self._apk(path)
        declared = sorted(apk.get_permissions())
        try:
            requested = sorted(apk.get_requested_permissions())
        except Exception:  # noqa: BLE001 - older androguard lacks this
            requested = declared
        cap = max(1, int(limit))
        # Measured: 3000 declared and 2500 requested came back in full with
        # only count=3000. Nothing said the lists were complete, so an
        # overnight agent ships every permission into context every time.
        return {
            "permissions": declared[:cap],
            "requested_permissions": requested[:cap],
            "count": min(len(declared), cap),
            "total": len(declared),
            "requested_total": len(requested),
            "has_more": len(declared) > cap or len(requested) > cap,
        }

    def certificates(self, path: Path) -> JsonObject:
        apk = self._apk(path)
        items: list[JsonObject] = []
        skipped = 0
        names_ok = True
        try:
            names = apk.get_signature_names()
        except Exception:  # noqa: BLE001
            # Measured: a raising get_signature_names next to one readable
            # certificate came back as signature_files=[], v1_signed=False,
            # skipped=0. The agent then treats a signed APK as unsigned.
            names = []
            names_ok = False
        for cert in apk.get_certificates():
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
                # Swallowing here used to drop a signer with no trace. Measured:
                # one unreadable cert next to one good one came back as a single
                # certificate and v1_signed=True, so an agent treats the APK as
                # having exactly one signer.
                skipped += 1
                continue
        if not names_ok:
            skipped += 1
            if not items and skipped == 1:
                raise ApkError("backend_error", "failed to read signature names")
        return {
            "signature_files": list(names),
            "certificates": items,
            "v1_signed": bool(names) if names_ok else True,
            "skipped": skipped,
            "truncated": skipped > 0,
        }

    def components(self, path: Path, *, limit: int = 500) -> JsonObject:
        apk = self._apk(path)
        activities = sorted(apk.get_activities())
        services = sorted(apk.get_services())
        receivers = sorted(apk.get_receivers())
        providers = sorted(apk.get_providers())
        cap = max(1, int(limit))
        # Measured: 2000 activities, 800 services, 400 receivers and 100
        # providers came back in full with no total or has_more.
        return {
            "activities": activities[:cap],
            "services": services[:cap],
            "receivers": receivers[:cap],
            "providers": providers[:cap],
            "main_activity": apk.get_main_activity(),
            "totals": {
                "activities": len(activities),
                "services": len(services),
                "receivers": len(receivers),
                "providers": len(providers),
            },
            "has_more": (
                len(activities) > cap
                or len(services) > cap
                or len(receivers) > cap
                or len(providers) > cap
            ),
        }

    def native_libs(self, path: Path, *, limit: int = 500) -> JsonObject:
        apk = self._apk(path)
        libs = sorted(name for name in apk.get_files() if name.startswith("lib/"))
        abis = sorted(
            {name.split("/")[1] for name in libs if len(name.split("/")) >= 3}
        )
        cap = max(1, int(limit))
        # Measured: 2500 lib/ paths came back as count=2500 with no has_more.
        return {
            "native_libs": libs[:cap],
            "abis": abis,
            "count": min(len(libs), cap),
            "total": len(libs),
            "has_more": len(libs) > cap,
        }

    def classes(self, path: Path, *, offset: int = 0, limit: int = 100) -> JsonObject:
        parsed = self._parsed(path)
        names = sorted(
            klass.name
            for klass in parsed.analysis.get_classes()
            if not klass.is_external()
        )
        window = names[offset : offset + limit]
        # Measured: 250 classes came back as count=100, total=250, offset=0
        # and no has_more. An agent that only reads count treats the page
        # as the whole DEX.
        return {
            "classes": window,
            "count": len(window),
            "total": len(names),
            "offset": offset,
            "has_more": offset + len(window) < len(names),
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
        for klass in found:
            for method in klass.get_methods():
                methods.append(
                    {
                        "name": method.name,
                        "descriptor": str(getattr(method, "descriptor", "")),
                        "access": str(getattr(method, "access", "")),
                    }
                )
        window = methods[offset : offset + limit]
        return {
            "class_name": found[0].name,
            "methods": window,
            "count": len(window),
            "total": len(methods),
            "offset": offset,
        }

    def strings(self, path: Path, *, offset: int = 0, limit: int = 200) -> JsonObject:
        parsed = self._parsed(path)
        values = sorted(
            {
                str(item.get_value())[:_MAX_STRING_LEN]
                for item in parsed.analysis.get_strings()
            }
        )
        window = values[offset : offset + limit]
        return {
            "strings": window,
            "count": len(window),
            "total": len(values),
            "offset": offset,
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
