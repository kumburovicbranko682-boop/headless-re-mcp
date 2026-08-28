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
# A Dalvik method's instruction count is bounded by the DEX code format, but cap
# how many rows apk.method_bytecode materialises so a crafted method cannot make
# one call build an unbounded list.
_MAX_METHOD_INSNS = 100_000
# apk.method_refs dedups a method's called targets / touched fields / loaded
# strings; cap each unique list so a crafted method cannot make one summary
# build an unbounded envelope.
_MAX_METHOD_REFS = 4096
_MAX_NATIVE_LIBS = 256
# A single native library is at most tens of MB; refuse anything absurd so a
# crafted APK cannot make extraction write a huge file.
_MAX_NATIVE_LIB_BYTES = 128 * 1024 * 1024
_MAX_COMPONENT_NAMES = 256
_MAX_PERMISSIONS = 256
_MAX_CERTIFICATES = 32
_MAX_MANIFEST_CHARS = 200_000
# apk.subclasses pages its merged subtype list; keep the ceiling equal to the
# tool schema maximum so the MCP and agent paths agree on the largest page.
_MAX_SUBTYPES_PAGE = 1000
# apk.class_xrefs dedups usage edges into a set before paging; cap the set so a
# heavily-referenced class (a framework type used everywhere) cannot make one
# reply hold an unbounded edge list, and page at the tool-schema maximum.
_MAX_CLASS_XREFS_COLLECT = 20_000
_MAX_CLASS_XREFS_PAGE = 1000
# apk.method_xrefs dedups precise call-site edges (class, method, descriptor,
# offset) into a set before paging; cap the set so a hot method (a logger, a
# framework API) cannot make one reply hold an unbounded edge list, and page at
# the tool-schema maximum.
_MAX_METHOD_XREFS_COLLECT = 20_000
_MAX_METHOD_XREFS_PAGE = 1000
# apk.method_cfg returns a whole method's basic-block graph in one reply (a CFG
# paginated block-by-block is unreadable), so it caps the block count and
# discloses truncation rather than paging; an obfuscated method with a huge
# block count is trimmed, edges built only from the kept blocks.
_MAX_CFG_BLOCKS = 4096


def _bb_start(block: Any) -> int:
    """A basic block's start byte offset, tolerant of androguard accessor drift."""
    getter = getattr(block, "get_start", None)
    if callable(getter):
        return int(getter())
    return int(getattr(block, "start", 0))


def _bb_end(block: Any) -> int:
    """A basic block's end byte offset (exclusive), tolerant of accessor drift."""
    getter = getattr(block, "get_end", None)
    if callable(getter):
        return int(getter())
    return int(getattr(block, "end", 0))


def _bb_children(block: Any) -> list[Any]:
    """The successor blocks of a basic block.

    androguard models an edge as ``(pos, child_start, child_block)`` in
    ``childs``; the child block is the third element. Guard the shape so a
    version that stored bare blocks (or an unexpected tuple) does not raise.
    """
    out: list[Any] = []
    for child in getattr(block, "childs", None) or []:
        if isinstance(child, (tuple, list)):
            if len(child) >= 3:
                out.append(child[2])
        else:
            out.append(child)
    return out


def _bb_instr_summary(block: Any) -> tuple[int, str]:
    """(instruction count, last mnemonic) for a basic block.

    The terminator names the block's role -- a conditional (``if-*``), an
    unconditional ``goto``, a ``return``/``throw`` sink, a ``*-switch`` -- without
    the caller pivoting to apk.method_bytecode. Iteration is bounded by the DEX
    code format and the method-instruction cap.
    """
    count = 0
    last = ""
    getter = getattr(block, "get_instructions", None)
    if callable(getter):
        for ins in getter():
            count += 1
            last = str(ins.get_name())
            if count >= _MAX_METHOD_INSNS:
                break
    return count, last


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


def _member_filter(name_contains: str, access: str) -> JsonObject:
    """The active, normalised class-member filter -- empty when nothing was asked.

    Shared by apk.methods and apk.fields so listing a class's members reads the
    same way whether they are methods or fields: name_contains is a
    case-insensitive substring of the member name, access a case-insensitive
    substring of its access-flag string (so ``native``, ``public``, ``static`` or
    ``abstract`` all work). The fields are folded to the case the match uses, so
    the echoed ``filter`` in the reply is exactly what was compared.
    """
    active: JsonObject = {}
    if isinstance(name_contains, str) and name_contains.strip():
        active["name_contains"] = name_contains.strip().lower()
    if isinstance(access, str) and access.strip():
        active["access"] = access.strip().lower()
    return active


def _member_matches(name: str, access: str, active: JsonObject) -> bool:
    """True when a member's name and access satisfy every field of an active filter."""
    if "name_contains" in active and active["name_contains"] not in name.lower():
        return False
    return not ("access" in active and active["access"] not in access.lower())


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

    def class_summary(self, path: Path, class_name: str) -> JsonObject:
        """A class header at a glance: superclass, interfaces, access and counts.

        ``apk.classes`` lists names and ``apk.methods`` / ``apk.fields`` enumerate
        members, but placing a class in the app -- what it extends, which
        interfaces it implements, whether it is public/abstract/final, and how big
        it is -- meant paging both member lists just to count them. This resolves
        one class (dotted or ``Lsmali/`` form) and answers with ``superclass``,
        ``interfaces`` (both smali descriptors), the ``access`` flag string,
        ``method_count`` and ``field_count``, plus ``is_external`` for a class only
        referenced, not defined, in the DEX. It is the Android analogue of reading
        a type's header before diving into its members.
        """
        target = class_name.strip()
        if not target:
            raise ApkError("invalid_params", "class_name is required")
        parsed = self._parsed(path)
        smali = _dotted_to_smali(target)
        found = [
            klass
            for klass in parsed.analysis.get_classes()
            if klass.name == target or klass.name == smali
        ]
        if not found:
            raise ApkError("not_found", "class not found", class_name=class_name)
        # A name can resolve to both a defined class and an external stub; prefer
        # the defined one so the summary describes the real body, not the shadow.
        klass = next((k for k in found if not k.is_external()), found[0])
        try:
            superclass = str(getattr(klass, "extends", "") or "")
            interfaces = [str(i) for i in (getattr(klass, "implements", None) or [])]
            access = ""
            vm = klass.get_vm_class() if hasattr(klass, "get_vm_class") else None
            if vm is not None and hasattr(vm, "get_access_flags_string"):
                access = str(vm.get_access_flags_string() or "")
            if not superclass and vm is not None and hasattr(vm, "get_superclassname"):
                superclass = str(vm.get_superclassname() or "")
            method_count = sum(1 for _ in klass.get_methods())
            field_count = sum(1 for _ in klass.get_fields())
        except ApkError:
            raise
        except Exception as exc:  # noqa: BLE001 - androguard raises many types
            raise ApkError(
                "backend_error", f"failed to read class summary: {exc}", class_name=class_name
            ) from exc
        return {
            "class_name": klass.name,
            "superclass": superclass,
            "interfaces": interfaces,
            "access": access,
            "method_count": method_count,
            "field_count": field_count,
            "is_external": bool(klass.is_external()),
        }

    def subclasses(
        self, path: Path, class_name: str, *, offset: int = 0, limit: int = 100
    ) -> JsonObject:
        """The inverse of class_summary: who extends a class or implements an interface.

        class_summary reads one class's own superclass and interfaces -- the
        "up" edges. This is the "down" direction the call/type graph needs:
        given a class or interface (dotted or ``Lsmali/`` form), it scans the DEX
        for every defined class that names the target as its superclass or in its
        interface list. That answers the questions an Android triage starts with
        -- every Activity/Service subclass, every implementer of a callback or
        crypto interface, every subclass of an obfuscated base -- which the
        forward view cannot. The target need not be defined in the DEX (a
        framework class such as ``android/app/Activity`` is the common case), so
        this never raises not_found; ``target_defined`` reports whether the DEX
        itself carries it.

        Answers with subtypes -- a merged list of {class_name, relation} where
        relation is ``extends`` (a direct subclass) or ``implements`` (an
        interface implementer), sorted by class name -- plus count, total, offset
        and has_more for paging, subclass_count and implementer_count (the totals
        before paging), target (the resolved smali form) and scan_capped (set once
        the class scan hit its 10000 ceiling). Only *direct* subtypes are
        reported, not the full transitive tree.
        """
        target = class_name.strip()
        if not target:
            raise ApkError("invalid_params", "class_name is required")
        parsed = self._parsed(path)
        smali = _dotted_to_smali(target)
        matches: list[JsonObject] = []
        subclass_count = 0
        implementer_count = 0
        target_defined = False
        scanned = 0
        scan_more = False
        for klass in parsed.analysis.get_classes():
            name = str(klass.name)
            external = bool(klass.is_external())
            if not external and name in (smali, target):
                target_defined = True
            if external:
                continue
            if scanned >= _MAX_CLASSES_COLLECT:
                scan_more = True
                break
            scanned += 1
            superclass, interfaces = _supertypes(klass)
            if superclass == smali:
                matches.append({"class_name": name, "relation": "extends"})
                subclass_count += 1
            elif smali in interfaces:
                matches.append({"class_name": name, "relation": "implements"})
                implementer_count += 1
        matches.sort(key=lambda item: str(item["class_name"]))
        start = max(0, int(offset))
        cap = min(max(1, int(limit)), _MAX_SUBTYPES_PAGE)
        window = matches[start : start + cap]
        return {
            "target": smali,
            "target_defined": target_defined,
            "subtypes": window,
            "count": len(window),
            "total": len(matches),
            "offset": start,
            "has_more": start + len(window) < len(matches),
            "subclass_count": subclass_count,
            "implementer_count": implementer_count,
            "scan_capped": scan_more,
        }

    def methods(
        self,
        path: Path,
        class_name: str,
        *,
        offset: int = 0,
        limit: int = 100,
        name_contains: str = "",
        access: str = "",
    ) -> JsonObject:
        """List a class's methods (name, descriptor, access), optionally filtered.

        name_contains is a case-insensitive substring of the method name and
        access a case-insensitive substring of the access-flag string, so
        ``access="native"`` isolates the JNI bridges into a ``.so`` and
        ``public``/``static``/``abstract`` slice by modifier. Dotted or Lsmali/
        class form; the paginated, scan-capped shape ``apk.fields`` shares.
        """
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
        active = _member_filter(name_contains, access)
        methods: list[JsonObject] = []
        scanned = 0
        scan_more = False
        for klass in found:
            for method in klass.get_methods():
                # Cap the scan, not the matches: a filter narrow enough to keep
                # nothing must still stop after a bounded number of methods rather
                # than walking an enormous class end to end.
                if scanned >= _MAX_METHODS_COLLECT:
                    scan_more = True
                    break
                scanned += 1
                name = str(method.name)
                access_str = str(getattr(method, "access", ""))
                if active and not _member_matches(name, access_str, active):
                    continue
                methods.append(
                    {
                        "name": name,
                        "descriptor": str(getattr(method, "descriptor", "")),
                        "access": access_str,
                    }
                )
            if scan_more:
                break
        window = methods[offset : offset + limit]
        result: JsonObject = {
            "class_name": found[0].name,
            "methods": window,
            "count": len(window),
            # total is the size of the set being paged: the matches when a filter
            # is active, so offset/has_more stay honest over the filtered view.
            "total": len(methods),
            "offset": offset,
            "has_more": offset + len(window) < len(methods),
            "scan_capped": scan_more,
        }
        if active:
            result["filter"] = active
        return result

    def fields(
        self,
        path: Path,
        class_name: str,
        *,
        offset: int = 0,
        limit: int = 100,
        name_contains: str = "",
        access: str = "",
    ) -> JsonObject:
        """List a class's declared fields (name, type, access).

        The read surface had a lister for a class's methods (``apk.methods``) but
        not its fields, yet a field is where a key, token, URL or feature flag
        usually lives, and ``apk.field_xrefs`` needs an exact name to pivot on.
        This gives the field inventory of one class -- each entry's name, ``type``
        (the raw Dalvik type descriptor, e.g. ``I`` for int or
        ``Ljava/lang/String;``) and access -- so a caller can spot the interesting
        field then hand its name to ``apk.field_xrefs``. Mirrors ``apk.methods``:
        dotted or Lsmali/ class form, the same name_contains/access filter, and
        the same paginated, scan-capped shape.
        """
        parsed = self._parsed(path)
        target = class_name.strip()
        if not target:
            raise ApkError("invalid_params", "class_name is required")
        smali = _dotted_to_smali(target)
        found = [
            klass
            for klass in parsed.analysis.get_classes()
            if klass.name == target or klass.name == smali
        ]
        if not found:
            raise ApkError("not_found", "class not found", class_name=class_name)
        active = _member_filter(name_contains, access)
        fields: list[JsonObject] = []
        scanned = 0
        scan_more = False
        for klass in found:
            for fa in klass.get_fields():
                if scanned >= _MAX_FIELDS_COLLECT:
                    scan_more = True
                    break
                scanned += 1
                # The FieldClassAnalysis wraps an EncodedField for an internal
                # field; go through it for type and access. An external field
                # reference would lack these accessors, so degrade to the name.
                ef = fa.get_field()
                name = ef.get_name() if hasattr(ef, "get_name") else getattr(fa, "name", "")
                type_desc = ef.get_descriptor() if hasattr(ef, "get_descriptor") else ""
                access_str = (
                    ef.get_access_flags_string()
                    if hasattr(ef, "get_access_flags_string")
                    else ""
                )
                if active and not _member_matches(str(name), str(access_str), active):
                    continue
                fields.append(
                    {"name": str(name), "type": str(type_desc), "access": str(access_str)}
                )
            if scan_more:
                break
        window = fields[offset : offset + limit]
        result: JsonObject = {
            "class_name": found[0].name,
            "fields": window,
            "count": len(window),
            "total": len(fields),
            "offset": offset,
            "has_more": offset + len(window) < len(fields),
            "scan_capped": scan_more,
        }
        if active:
            result["filter"] = active
        return result

    def _resolve_method(
        self, path: Path, class_name: str, method_name: str, descriptor: str | None
    ) -> tuple[str, Any, list[Any]]:
        """Resolve class + name (+ optional descriptor) to one method analysis.

        Returns the class's display name, the chosen ``MethodClassAnalysis`` and
        every same-named overload, raising the shared invalid_params/not_found
        contract. Both apk.method_bytecode and apk.method_refs pivot on this, so
        a method resolves identically whichever reader an agent reaches for.
        """
        cls = class_name.strip()
        mname = method_name.strip()
        if not cls:
            raise ApkError("invalid_params", "class_name is required")
        if not mname:
            raise ApkError("invalid_params", "method_name is required")
        parsed = self._parsed(path)
        smali = _dotted_to_smali(cls)
        found = [
            klass
            for klass in parsed.analysis.get_classes()
            if klass.name == cls or klass.name == smali
        ]
        if not found:
            raise ApkError("not_found", "class not found", class_name=class_name)
        matches = [
            mca
            for klass in found
            for mca in klass.get_methods()
            if not mca.is_external() and str(getattr(mca, "name", "")) == mname
        ]
        if not matches:
            raise ApkError(
                "not_found", "method not found", class_name=found[0].name, method_name=mname
            )
        want = descriptor.strip() if isinstance(descriptor, str) and descriptor.strip() else None
        if want is None:
            return found[0].name, matches[0], matches
        chosen = next((m for m in matches if str(getattr(m, "descriptor", "")) == want), None)
        if chosen is None:
            # Present class, present name, but no such signature: name the
            # overloads the caller could have meant rather than a bare miss.
            raise ApkError(
                "not_found",
                "no method overload with that descriptor",
                method_name=mname,
                descriptor=want,
                available=[str(getattr(m, "descriptor", "")) for m in matches][:32],
            )
        return found[0].name, chosen, matches

    def method_bytecode(
        self,
        path: Path,
        class_name: str,
        method_name: str,
        *,
        descriptor: str | None = None,
        offset: int = 0,
        limit: int = 200,
    ) -> JsonObject:
        """Disassemble one method's Dalvik bytecode.

        ``apk.methods`` lists a class's methods but could not show what any of
        them does; jadx/apktool decompile the whole app (and need those tools
        installed), where an agent chasing one routine -- a license check, a
        crypto call, an anti-tamper guard -- wants just its instructions. This
        resolves a single method by class + name (plus an optional ``descriptor``
        to pick one overload) and returns its instruction listing: the Android
        analogue of ``r2.disasm_function`` for a native binary. Each instruction
        carries its offset (bytes into the method code), mnemonic, operands (with
        the invoked method or referenced field/string named, not an index), raw
        bytes and size, so a call or field access reads as a target rather than
        an opcode number. When several methods share the name, ``overloads``
        reports how many and the first is used unless a ``descriptor`` pins one;
        the listing paginates with ``offset``/``limit`` and ``has_more``. An
        abstract/native method resolves with ``has_code`` False and no
        instructions.
        """
        mname = method_name.strip()
        class_display, chosen, matches = self._resolve_method(
            path, class_name, method_name, descriptor
        )
        has_code = False
        try:
            encoded = chosen.get_method()
            code = encoded.get_code()
            has_code = code is not None
            raw: list[tuple[int, Any]] = []
            if has_code:
                pos = 0
                for ins in encoded.get_instructions():
                    raw.append((pos, ins))
                    pos += int(ins.get_length())
                    if len(raw) >= _MAX_METHOD_INSNS:
                        break
            rows = [
                {
                    "addr": pos,
                    "mnemonic": str(ins.get_name()),
                    # get_output resolves the operand: an invoked method, a
                    # referenced field/string, or the registers -- the whole
                    # reason to read bytecode over a raw opcode dump.
                    "operands": str(ins.get_output()),
                    "bytes": str(ins.get_hex()).replace(" ", ""),
                    "size": int(ins.get_length()),
                }
                for pos, ins in raw
            ]
        except ApkError:
            raise
        except Exception as exc:  # noqa: BLE001 - androguard raises many types
            raise ApkError(
                "backend_error", f"failed to read method bytecode: {exc}", method_name=mname
            ) from exc
        total = len(rows)
        start = max(0, int(offset))
        cap = max(1, int(limit))
        window = rows[start : start + cap]
        return {
            "class_name": class_display,
            "method": mname,
            "descriptor": str(getattr(chosen, "descriptor", "")),
            "access": str(getattr(chosen, "access", "")),
            "has_code": has_code,
            "instructions": window,
            "count": len(window),
            "total": total,
            "offset": start,
            "has_more": start + len(window) < total,
            # More than one method shares this name; when the caller did not pin a
            # descriptor, this says the first overload was chosen so they know to
            # disambiguate if they meant another.
            "overloads": len(matches),
            "insns_capped": total >= _MAX_METHOD_INSNS,
        }

    def method_cfg(
        self,
        path: Path,
        class_name: str,
        method_name: str,
        *,
        descriptor: str | None = None,
    ) -> JsonObject:
        """The control-flow graph of one Dalvik method: basic blocks and edges.

        Where apk.method_bytecode lists a method's instructions in address order,
        this reads its shape -- the basic blocks and the branch edges between them
        -- so loops, conditionals and fall-through are legible without tracing
        every goto by hand. It is the Android twin of r2.cfg (native) and
        static.cfg (PE), the seam from apk.method_bytecode to "how does control
        move through this routine", which is exactly what an obfuscated guard or a
        licence check hides in its branching.

        Resolves one method by class + name (plus an optional ``descriptor`` to
        pin an overload; ``overloads`` reports how many share the name). Each node
        carries addr (byte offset of the block start, the same offset space
        apk.method_bytecode uses so a node pivots straight to its instructions),
        end, size, ninstr, name (androguard's block label) and terminator (the
        block's last mnemonic -- if-eqz, goto, return-void, throw, ...). Each edge
        carries src, dst and kind: "fall_through" when the successor is the next
        sequential block (a not-taken conditional or straight-line flow) and
        "branch" for an explicit jump target (a taken conditional, a goto, a
        switch arm). Edges are deduplicated and sorted; entry is the start offset
        of the entry block, node_count/edge_count summarise the graph, and
        blocks_truncated/blocks_total disclose a method past the 4096-block cap
        (edges are built only from the kept blocks). An abstract or native method
        resolves with has_code False and an empty graph, not an error.
        """
        mname = method_name.strip()
        class_display, chosen, matches = self._resolve_method(
            path, class_name, method_name, descriptor
        )
        has_code = False
        nodes: list[JsonObject] = []
        edge_set: set[tuple[int, int, str]] = set()
        blocks_total = 0
        try:
            encoded = chosen.get_method()
            has_code = encoded.get_code() is not None
            if has_code:
                bbs = chosen.basic_blocks
                try:
                    raw_blocks = list(bbs.get())
                except AttributeError:
                    raw_blocks = list(bbs)
                blocks_total = len(raw_blocks)
                # Sort by start offset so the node list is deterministic and the
                # entry (offset 0) leads; androguard does not promise an order.
                raw_blocks.sort(key=_bb_start)
                for block in raw_blocks[:_MAX_CFG_BLOCKS]:
                    start = _bb_start(block)
                    end = _bb_end(block)
                    ninstr, terminator = _bb_instr_summary(block)
                    node: JsonObject = {
                        "addr": start,
                        "end": end,
                        "size": max(0, end - start),
                        "ninstr": ninstr,
                        "name": str(block.get_name()),
                    }
                    if terminator:
                        node["terminator"] = terminator
                    nodes.append(node)
                    for child in _bb_children(block):
                        child_start = _bb_start(child)
                        # The sequential successor (start == this block's end) is
                        # the fall-through; anything else is an explicit target.
                        kind = "fall_through" if child_start == end else "branch"
                        edge_set.add((start, child_start, kind))
        except ApkError:
            raise
        except Exception as exc:  # noqa: BLE001 - androguard raises many types
            raise ApkError(
                "backend_error", f"failed to read method cfg: {exc}", method_name=mname
            ) from exc
        edges = [{"src": s, "dst": d, "kind": k} for s, d, k in sorted(edge_set)]
        return {
            "class_name": class_display,
            "method": mname,
            "descriptor": str(getattr(chosen, "descriptor", "")),
            "access": str(getattr(chosen, "access", "")),
            "has_code": has_code,
            "entry": nodes[0]["addr"] if nodes else None,
            "nodes": nodes,
            "edges": edges,
            "node_count": len(nodes),
            "edge_count": len(edges),
            "overloads": len(matches),
            "blocks_truncated": blocks_total > _MAX_CFG_BLOCKS,
            "blocks_total": blocks_total,
        }

    def method_refs(
        self,
        path: Path,
        class_name: str,
        method_name: str,
        *,
        descriptor: str | None = None,
    ) -> JsonObject:
        """Summarise what one method touches: its calls, fields and strings.

        Where ``apk.method_bytecode`` returns every instruction, this abstracts the
        triage question an agent actually asks of a routine -- what does it call,
        which fields does it read or write, which string constants does it load --
        into three deduplicated lists. It is the static-Dalvik analogue of reading
        a native function's call and data references at a glance. ``calls`` names
        each invoked target (``Lpkg/Cls;->m(...)ret``) with how many call sites
        reach it; ``fields`` names each accessed field with its ``reads`` and
        ``writes`` counts, so a config flag flipped once stands out from one merely
        read; ``strings`` names each loaded constant with its occurrence ``count``
        (an embedded URL, key or error message). Every list is sorted for stable
        output. The method resolves by class + name, with an optional
        ``descriptor`` to pin one overload (``overloads`` reports how many share
        the name); an abstract/native method resolves with ``has_code`` False and
        empty lists. ``calls_truncated`` / ``fields_truncated`` /
        ``strings_truncated`` mark a method whose unique set exceeded the 4096 cap.
        """
        mname = method_name.strip()
        class_display, chosen, matches = self._resolve_method(
            path, class_name, method_name, descriptor
        )
        calls: dict[str, int] = {}
        fields: dict[str, dict[str, int]] = {}
        strings: dict[str, int] = {}
        has_code = False
        capped = {"calls": False, "fields": False, "strings": False}

        def _bump(bucket: dict[str, int], key: str, which: str) -> None:
            if key in bucket or len(bucket) < _MAX_METHOD_REFS:
                bucket[key] = bucket.get(key, 0) + 1
            else:
                capped[which] = True

        def _bump_field(key: str, *, is_write: bool) -> None:
            if key in fields or len(fields) < _MAX_METHOD_REFS:
                entry = fields.setdefault(key, {"reads": 0, "writes": 0})
                entry["writes" if is_write else "reads"] += 1
            else:
                capped["fields"] = True

        try:
            encoded = chosen.get_method()
            has_code = encoded.get_code() is not None
            if has_code:
                seen = 0
                for ins in encoded.get_instructions():
                    seen += 1
                    if seen > _MAX_METHOD_INSNS:
                        break
                    name = str(ins.get_name())
                    # The resolved reference (a method/field descriptor, or the
                    # literal for const-string). Instructions without a c-operand
                    # raise here, so guard rather than classify on kind ids that
                    # drift between androguard releases.
                    try:
                        ref = str(ins.get_translated_kind())
                    except Exception:  # noqa: BLE001 - androguard raises many types
                        continue
                    if not ref:
                        continue
                    if name.startswith("invoke"):
                        _bump(calls, ref, "calls")
                    elif name.startswith(("iget", "sget")):
                        _bump_field(ref, is_write=False)
                    elif name.startswith(("iput", "sput")):
                        _bump_field(ref, is_write=True)
                    elif name.startswith("const-string"):
                        _bump(strings, ref, "strings")
        except ApkError:
            raise
        except Exception as exc:  # noqa: BLE001 - androguard raises many types
            raise ApkError(
                "backend_error", f"failed to read method refs: {exc}", method_name=mname
            ) from exc

        call_rows = [
            {"target": target, "count": count} for target, count in sorted(calls.items())
        ]
        field_rows = [
            {"field": field, "reads": counts["reads"], "writes": counts["writes"]}
            for field, counts in sorted(fields.items())
        ]
        string_rows = [{"value": value, "count": count} for value, count in sorted(strings.items())]
        return {
            "class_name": class_display,
            "method": mname,
            "descriptor": str(getattr(chosen, "descriptor", "")),
            "access": str(getattr(chosen, "access", "")),
            "has_code": has_code,
            "calls": call_rows,
            "fields": field_rows,
            "strings": string_rows,
            "call_count": len(call_rows),
            "field_count": len(field_rows),
            "string_count": len(string_rows),
            "overloads": len(matches),
            "calls_truncated": capped["calls"],
            "fields_truncated": capped["fields"],
            "strings_truncated": capped["strings"],
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

    def method_xrefs(
        self,
        path: Path,
        class_name: str,
        method_name: str,
        *,
        descriptor: str | None = None,
        direction: str = "callers",
        offset: int = 0,
        limit: int = 100,
    ) -> JsonObject:
        """Precise per-method cross references with call-site offsets.

        apk.xrefs sweeps by bare method name and returns only ``{class, method}``;
        this pins one exact method (class + name + optional ``descriptor``) and
        walks its call graph one hop, keeping androguard's descriptor and
        call-site offset for each edge. ``direction="callers"`` (the default,
        xref_from) answers who invokes this method -- each edge is the calling
        method and the bytecode offset within it where the invoke sits, so a
        caller can jump straight there with apk.method_bytecode.
        ``direction="callees"`` (xref_to) answers what this method invokes,
        framework APIs included, the offset being the site inside this method. It
        is the Android analogue of a native xref-to with call sites, and the
        precise, offset-bearing counterpart to apk.xrefs' name-wide sweep.
        """
        if direction not in ("callers", "callees"):
            raise ApkError(
                "invalid_params",
                "direction must be callers or callees",
                direction=direction,
            )
        class_display, chosen, matches = self._resolve_method(
            path, class_name, method_name, descriptor
        )
        walk = chosen.get_xref_from() if direction == "callers" else chosen.get_xref_to()
        edges: set[tuple[str, str, str, int]] = set()
        scan_capped = False
        for ref in walk:
            if not isinstance(ref, tuple) or len(ref) < 3:
                continue
            other_class, other_method, ref_offset = ref[0], ref[1], ref[2]
            edge_class = str(
                getattr(other_method, "class_name", "") or getattr(other_class, "name", "")
            )
            edge_method = str(getattr(other_method, "name", ""))
            edge_desc = str(getattr(other_method, "descriptor", ""))
            try:
                off = int(ref_offset)
            except (TypeError, ValueError):
                off = -1
            if len(edges) >= _MAX_METHOD_XREFS_COLLECT:
                scan_capped = True
                break
            edges.add((edge_class, edge_method, edge_desc, off))
        ordered = sorted(edges)
        start = max(0, int(offset))
        cap = min(max(1, int(limit)), _MAX_METHOD_XREFS_PAGE)
        window = ordered[start : start + cap]
        return {
            "class_name": class_display,
            "method": method_name.strip(),
            "descriptor": str(getattr(chosen, "descriptor", "")),
            "direction": direction,
            # More than one method shares this name; when no descriptor was pinned
            # the first overload was resolved, so the caller knows to disambiguate.
            "overloads": len(matches),
            "xrefs": [
                {"class": cls, "method": m, "descriptor": d, "offset": off}
                for cls, m, d, off in window
            ],
            "count": len(window),
            "total": len(ordered),
            "offset": start,
            "has_more": start + len(window) < len(ordered),
            "scan_capped": scan_capped,
        }

    def class_xrefs(
        self,
        path: Path,
        class_name: str,
        *,
        direction: str = "from",
        offset: int = 0,
        limit: int = 100,
    ) -> JsonObject:
        """Class-level cross references: who uses a class, or what a class uses.

        apk.xrefs walks the call graph by method name and apk.subclasses walks
        the inheritance tree; this is the type *usage* edge neither shows.
        ``direction="from"`` (the default) answers who references the class --
        every site that instantiates it (REF_NEW_INSTANCE), names it
        (REF_CLASS_USAGE) or invokes one of its methods -- which is how you find
        where an obfuscated or crypto class is actually put to work.
        ``direction="to"`` answers what classes this class depends on. The target
        need not be defined in the DEX: a framework type such as
        ``javax/crypto/Cipher`` still carries inbound edges, so "who uses Cipher"
        resolves. Resolve by class_name (dotted or ``Lsmali/`` form); a name the
        DEX neither defines nor references anywhere is a clean not_found.

        Answers with xrefs -- edges of {class, method, kind, offset}, where class
        is the class at the other end of the edge, method the method that carries
        the reference, kind the androguard REF_TYPE name (REF_NEW_INSTANCE,
        REF_CLASS_USAGE, INVOKE_VIRTUAL, ...) and offset the bytecode offset --
        deduplicated and sorted, plus count, total, offset and has_more for
        paging, target (the resolved smali form), direction, and scan_capped once
        the 20000-edge collection ceiling was hit. The list field is xrefs.
        """
        if direction not in ("from", "to"):
            raise ApkError(
                "invalid_params", "direction must be from or to", direction=direction
            )
        target = class_name.strip()
        if not target:
            raise ApkError("invalid_params", "class_name is required")
        parsed = self._parsed(path)
        smali = _dotted_to_smali(target)
        found = [
            klass
            for klass in parsed.analysis.get_classes()
            if klass.name == target or klass.name == smali
        ]
        if not found:
            raise ApkError("not_found", "class not found", class_name=class_name)
        edges: set[tuple[str, str, str, int]] = set()
        scan_capped = False
        for klass in found:
            mapping = klass.get_xref_from() if direction == "from" else klass.get_xref_to()
            try:
                items = list(mapping.items())
            except AttributeError:
                items = []
            for other, refs in items:
                other_name = str(getattr(other, "name", ""))
                for ref in refs:
                    if not isinstance(ref, tuple) or len(ref) < 3:
                        continue
                    ref_kind, ref_method, ref_offset = ref[0], ref[1], ref[2]
                    kind = str(getattr(ref_kind, "name", "") or ref_kind)
                    method = str(getattr(ref_method, "name", ""))
                    try:
                        off = int(ref_offset)
                    except (TypeError, ValueError):
                        off = -1
                    if len(edges) >= _MAX_CLASS_XREFS_COLLECT:
                        scan_capped = True
                        break
                    edges.add((other_name, method, kind, off))
                if scan_capped:
                    break
            if scan_capped:
                break
        ordered = sorted(edges)
        start = max(0, int(offset))
        cap = min(max(1, int(limit)), _MAX_CLASS_XREFS_PAGE)
        window = ordered[start : start + cap]
        return {
            "class_name": found[0].name,
            "target": smali,
            "direction": direction,
            "xrefs": [
                {"class": cls, "method": method, "kind": kind, "offset": off}
                for cls, method, kind, off in window
            ],
            "count": len(window),
            "total": len(ordered),
            "offset": start,
            "has_more": start + len(window) < len(ordered),
            "scan_capped": scan_capped,
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


def _supertypes(klass: Any) -> tuple[str, list[str]]:
    """(superclass, interfaces) as smali descriptors, tolerant of androguard drift.

    Mirrors class_summary: read ``extends``/``implements`` first, and only fall
    back to the underlying vm class when the superclass is missing, so scanning
    the whole class table does not pay a get_vm_class() call per class.
    """
    superclass = str(getattr(klass, "extends", "") or "")
    interfaces = [str(i) for i in (getattr(klass, "implements", None) or [])]
    if not superclass:
        vm = klass.get_vm_class() if hasattr(klass, "get_vm_class") else None
        if vm is not None and hasattr(vm, "get_superclassname"):
            superclass = str(vm.get_superclassname() or "")
        if not interfaces and vm is not None and hasattr(vm, "get_interfaces"):
            try:
                raw = vm.get_interfaces() or []
            except Exception:  # noqa: BLE001 - androguard raises many types
                raw = []
            interfaces = [str(i) for i in raw]
    return superclass, interfaces
