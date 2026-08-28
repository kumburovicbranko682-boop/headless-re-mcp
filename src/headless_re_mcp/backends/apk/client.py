"""In-process APK static analysis via androguard.

androguard is an optional dependency: importing it lazily keeps the whole
Android surface usable-but-degraded when it is absent, exactly like the Frida
backend. DEX analysis is expensive, so a small process-wide cache keyed by path
and mtime keeps repeated tool calls within one session from re-parsing.
"""

from __future__ import annotations

import hashlib
import threading
from collections import OrderedDict
from collections.abc import Callable
from pathlib import Path
from typing import Any, ClassVar

JsonObject = dict[str, Any]

# DEX analysis of a large app can take seconds and tens of MB; keep only a few
# parsed apps resident and evict the oldest.
_CACHE_LIMIT = 4
_MAX_STRING_LEN = 2000
_MAX_STRINGS_COLLECT = 5000
_MAX_FIELDS_COLLECT = 20_000
_MAX_CLASSES_COLLECT = 10_000
_MAX_METHODS_COLLECT = 2000
_MAX_NATIVE_LIBS = 256
# A single native library is at most tens of MB; refuse anything absurd so a
# crafted APK cannot make extraction write a huge file.
_MAX_NATIVE_LIB_BYTES = 128 * 1024 * 1024
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

    def _read_manifest(self, path: Path, build: Callable[[Any], JsonObject]) -> JsonObject:
        """Run a manifest-level accessor block, mapping androguard faults cleanly.

        ``APK(path)`` logs and swallows a broken AndroidManifest.xml rather than
        raising, so the object exists but its accessors then raise raw KeyError /
        AttributeError from deep in androguard. Left unwrapped those escape the
        service's ApkError branch and surface as ``internal_error`` -- the
        leaked-exception bucket -- for what is really an unparseable input. Wrap
        them as ``backend_error`` so a corrupt APK degrades the same way across
        open/permissions/components/certificates/native_libs.
        """
        apk = self._apk(path)
        try:
            return build(apk)
        except ApkError:
            raise
        except Exception as exc:  # noqa: BLE001 - androguard raises many types
            raise ApkError("backend_error", f"failed to read APK metadata: {exc}") from exc

    def open(self, path: Path) -> JsonObject:
        def build(apk: Any) -> JsonObject:
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

        return self._read_manifest(path, build)

    def manifest(self, path: Path) -> JsonObject:
        def build(apk: Any) -> JsonObject:
            try:
                xml = apk.get_android_manifest_axml().get_xml().decode("utf-8", "replace")
            except Exception as exc:  # noqa: BLE001
                raise ApkError("backend_error", f"failed to decode manifest: {exc}") from exc
            return {
                "package": apk.get_package(),
                "manifest_xml": xml[:_MAX_MANIFEST_CHARS],
                "truncated": len(xml) > _MAX_MANIFEST_CHARS,
            }

        return self._read_manifest(path, build)

    def permissions(self, path: Path) -> JsonObject:
        def build(apk: Any) -> JsonObject:
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

        return self._read_manifest(path, build)

    def certificates(self, path: Path) -> JsonObject:
        def build(apk: Any) -> JsonObject:
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
            # Which APK Signature Schemes actually signed the APK. v1 is the old
            # JAR signature (per-entry, so a repacked APK can keep valid-looking
            # v1 certs while its DEX changed); v2/v3 hash the whole archive and
            # are what make a build tamper-evident. An analyst deciding whether an
            # APK is safely modifiable, or which cert chain to trust, needs the
            # scheme -- not just that *some* certificate exists. Reported via
            # androguard's authoritative predicates rather than inferred from the
            # presence of META-INF signature files (v2/v3 leave none).
            v1 = _signing_predicate(apk, "is_signed_v1", fallback=bool(names))
            v2 = _signing_predicate(apk, "is_signed_v2")
            v3 = _signing_predicate(apk, "is_signed_v3")
            schemes = [tag for tag, present in (("v1", v1), ("v2", v2), ("v3", v3)) if present]
            return {
                "signature_files": sig_files,
                "certificates": items,
                "v1_signed": v1,
                "v2_signed": v2,
                "v3_signed": v3,
                "signing_schemes": schemes,
                "has_more": certs_more or files_more,
            }

        return self._read_manifest(path, build)

    def components(self, path: Path) -> JsonObject:
        def build(apk: Any) -> JsonObject:
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

        return self._read_manifest(path, build)

    def native_libs(self, path: Path) -> JsonObject:
        def build(apk: Any) -> JsonObject:
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

        return self._read_manifest(path, build)

    def extract_native_lib(self, path: Path, name: str, dest_dir: Path) -> JsonObject:
        """Pull one embedded native library out of the APK to a file on disk.

        ``apk.native_libs`` can list the ``.so`` files an app ships, but nothing
        could hand one to the native RE backends -- jadx and apktool only touch
        Java/smali, so an app's crypto, DRM or anti-tamper logic (which lives in
        native code) was a dead end. This reads the exact bytes of a
        ``lib/<abi>/<name>.so`` entry and writes them to ``dest_dir``, so a
        follow-up native session can open the file with radare2 or Ghidra. The
        entry must be a real ``.so`` present in the archive; anything else is
        refused so this cannot be turned into an arbitrary zip extractor.
        """
        resolved = self._require(path)
        entry = str(name).strip()
        if not entry:
            raise ApkError("invalid_params", "name is required")
        apk = self._apk(resolved)
        try:
            files = {str(item) for item in (apk.get_files() or [])}
        except Exception as exc:  # noqa: BLE001 - androguard raises many types
            raise ApkError("backend_error", f"failed to list APK files: {exc}") from exc
        if entry not in files:
            raise ApkError("not_found", "no such file in the APK", name=entry)
        parts = entry.split("/")
        if not (entry.startswith("lib/") and len(parts) >= 3 and entry.endswith(".so")):
            raise ApkError(
                "invalid_params",
                "not a native library entry (expected lib/<abi>/<name>.so)",
                name=entry,
            )
        try:
            blob = apk.get_file(entry)
        except Exception as exc:  # noqa: BLE001 - androguard raises FileNotPresent etc.
            raise ApkError(
                "backend_error", f"failed to read native library: {exc}", name=entry
            ) from exc
        if not isinstance(blob, (bytes, bytearray)) or len(blob) == 0:
            raise ApkError("backend_error", "native library entry was empty", name=entry)
        if len(blob) > _MAX_NATIVE_LIB_BYTES:
            raise ApkError(
                "too_large",
                "native library exceeds extraction cap",
                name=entry,
                size=len(blob),
                cap=_MAX_NATIVE_LIB_BYTES,
            )
        blob = bytes(blob)
        abi = parts[1]
        # The zip path is attacker-influenced; keep only the basename and prefix
        # the ABI so two same-named libs from different ABIs cannot collide, and
        # nothing can escape dest_dir.
        safe = Path(entry).name
        dest_dir.mkdir(parents=True, exist_ok=True)
        out = dest_dir / f"{abi}-{safe}"
        out.write_bytes(blob)
        return {
            "name": entry,
            "abi": abi,
            "path": str(out),
            "size": len(blob),
            "sha256": hashlib.sha256(blob).hexdigest(),
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

    def string_xrefs(
        self, path: Path, value: str, *, offset: int = 0, limit: int = 100
    ) -> JsonObject:
        """Methods that reference an exact string constant.

        Pivoting from an interesting constant (a URL, an API key, an error
        message) to the code that uses it is a core triage move the string list
        alone cannot answer. ``found`` separates "the string is not in the DEX"
        (found False, total 0) from "it is present but nothing references it"
        (found True, total 0); ``scan_capped`` says the search stopped before
        examining every string. Edges share ``apk.xrefs``'s {class, method}
        shape.
        """
        if not isinstance(value, str) or value == "":
            raise ApkError("invalid_params", "value is required")
        parsed = self._parsed(path)
        cap = max(1, int(limit))
        start = max(0, int(offset))
        edges: set[tuple[str, str]] = set()
        scanned = 0
        scan_capped = False
        found = False
        for sa in parsed.analysis.get_strings():
            if scanned >= _MAX_STRINGS_COLLECT:
                scan_capped = True
                break
            scanned += 1
            if str(sa.get_value()) != value:
                continue
            found = True
            for _klass, method in sa.get_xref_from():
                edges.add(
                    (
                        str(getattr(method, "class_name", "")),
                        str(getattr(method, "name", "")),
                    )
                )
            # androguard keys its string table by value, so one exact match is
            # the whole story -- no need to scan the rest.
            break
        ordered = sorted(edges)
        window = ordered[start : start + cap]
        return {
            "value": value,
            "found": found,
            "xrefs": [{"class": cls, "method": name} for cls, name in window],
            "count": len(window),
            "total": len(ordered),
            "offset": start,
            "has_more": start + len(window) < len(ordered),
            "scan_capped": scan_capped,
        }

    def field_xrefs(
        self,
        path: Path,
        field_name: str,
        *,
        direction: str = "read",
        offset: int = 0,
        limit: int = 100,
    ) -> JsonObject:
        """Methods that read or write a field, matched by exact name.

        Fields are where keys, tokens and config live, so "who sets this" and
        "who uses this" are distinct triage questions -- ``direction="read"``
        (default) walks androguard's read xrefs and ``direction="write"`` its
        write xrefs. Names are not unique across classes, so every field with
        the name is considered and the edges are merged (the same aggregate-by-
        name rule ``apk.xrefs`` uses). ``found`` separates an absent field from
        one present but untouched in the chosen direction; ``scan_capped`` says
        the field scan stopped early. Edges share the {class, method} shape.
        """
        if direction not in ("read", "write"):
            raise ApkError(
                "invalid_params",
                "direction must be read or write",
                direction=direction,
            )
        if not isinstance(field_name, str) or field_name.strip() == "":
            raise ApkError("invalid_params", "field_name is required")
        parsed = self._parsed(path)
        target = field_name.strip()
        cap = max(1, int(limit))
        start = max(0, int(offset))
        edges: set[tuple[str, str]] = set()
        scanned = 0
        scan_capped = False
        found = False
        for fa in parsed.analysis.get_fields():
            if scanned >= _MAX_FIELDS_COLLECT:
                scan_capped = True
                break
            scanned += 1
            if str(fa.name) != target:
                continue
            # A field name can repeat across classes, so unlike a string value
            # this cannot stop at the first hit -- every match contributes.
            found = True
            walk = fa.get_xref_read() if direction == "read" else fa.get_xref_write()
            for _klass, method in walk:
                edges.add(
                    (
                        str(getattr(method, "class_name", "")),
                        str(getattr(method, "name", "")),
                    )
                )
        ordered = sorted(edges)
        window = ordered[start : start + cap]
        return {
            "field_name": target,
            "direction": direction,
            "found": found,
            "xrefs": [{"class": cls, "method": name} for cls, name in window],
            "count": len(window),
            "total": len(ordered),
            "offset": start,
            "has_more": start + len(window) < len(ordered),
            "scan_capped": scan_capped,
        }

    def xrefs(
        self,
        path: Path,
        method_name: str,
        *,
        direction: str = "callers",
        limit: int = 100,
    ) -> JsonObject:
        """Walk one direction of the call graph for methods named method_name.

        ``direction="callers"`` (the default) answers who calls the method
        (androguard's xref_from); ``direction="callees"`` answers what the method
        calls (xref_to), including framework APIs, which is how an agent traces a
        call forward rather than only backward. The edges are the same
        ``{class, method}`` shape either way, and the ``callers``/``callees`` key
        names the direction so a reply cannot be misread.
        """
        if direction not in ("callers", "callees"):
            raise ApkError(
                "invalid_params",
                "direction must be callers or callees",
                direction=direction,
            )
        parsed = self._parsed(path)
        target = method_name.strip()
        if not target:
            raise ApkError("invalid_params", "method_name is required")
        cap = max(1, int(limit))
        refs: list[JsonObject] = []
        has_more = False
        for method in parsed.analysis.get_methods():
            if method.is_external() or method.name != target:
                continue
            walk = method.get_xref_from() if direction == "callers" else method.get_xref_to()
            for _, other, _ in walk:
                if len(refs) >= cap:
                    # Only set once something was actually left out, so a result
                    # that happens to fill the page is not reported as partial.
                    has_more = True
                    break
                refs.append(
                    {
                        "class": str(other.class_name),
                        "method": str(other.name),
                    }
                )
            if has_more:
                break
        return {
            "method_name": target,
            "direction": direction,
            direction: refs,
            "count": len(refs),
            # A caller deciding "these are all the refs" has to know whether the
            # enumeration ended or merely stopped.
            "has_more": has_more,
        }


def _signing_predicate(apk: Any, method: str, *, fallback: bool = False) -> bool:
    """Call an androguard is_signed_vN predicate, degrading to ``fallback``.

    Older androguard builds may not expose every scheme predicate, and a
    malformed signing block can make one raise; neither should fail the whole
    certificates read, so an absent or throwing predicate reports ``fallback``
    (for v1, the presence of META-INF signature files; otherwise False).
    """
    probe = getattr(apk, method, None)
    if not callable(probe):
        return fallback
    try:
        return bool(probe())
    except Exception:  # noqa: BLE001 - androguard raises many types on bad sig blocks
        return fallback


def _dotted_to_smali(name: str) -> str:
    """com.example.Foo -> Lcom/example/Foo; so either form resolves a class."""
    if name.startswith("L") and name.endswith(";"):
        return name
    return "L" + name.replace(".", "/") + ";"
