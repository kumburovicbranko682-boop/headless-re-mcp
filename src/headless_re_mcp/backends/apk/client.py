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

from headless_re_mcp.backends.common.json_budget import fit_json_list, fit_json_text

JsonObject = dict[str, Any]

# DEX analysis of a large app can take seconds and tens of MB; keep only a few
# parsed apps resident and evict the oldest.
_CACHE_LIMIT = 4
# Headroom for a list result's small scalar siblings (count/total/offset/
# has_more/scan_capped and a class or method name) so the whole encoded reply
# stays under the budget; the paged list itself gets the rest.
_LIST_FIELD_RESERVE = 16 * 1024
_MAX_STRING_LEN = 2000
_MAX_STRINGS_COLLECT = 5000
_MAX_CLASSES_COLLECT = 10_000
_MAX_METHODS_COLLECT = 2000
# A DEX method tops out around 65535 instructions; collect well under that so a
# single disassembly cannot pin unbounded memory, and page the collected rows.
_MAX_INSTRUCTIONS_COLLECT = 20_000
_MAX_NATIVE_LIBS = 256
_MAX_COMPONENT_NAMES = 256
# Intent-filter extraction bounds: a hostile manifest can declare a great many
# components, filters, and action/category/data children, so cap each dimension.
_MAX_INTENT_COMPONENTS = 256
_MAX_FILTERS_PER_COMPONENT = 64
_MAX_FILTER_ITEMS = 64
_MAX_INTENT_STR = 512
_MAX_PERMISSIONS = 256
_MAX_CERTIFICATES = 32
_MAX_MANIFEST_CHARS = 200_000
# Headroom for manifest()'s other fields (package name, truncated flag) when the
# XML is bounded by encoded size; both are tiny, so a small reserve leaves nearly
# the whole budget for the manifest itself.
_MANIFEST_FIELD_RESERVE = 8 * 1024
# android: attribute namespace, and the manifest tags that declare an exportable
# component -- read straight off the decoded manifest tree since androguard has no
# per-component exported getter.
_ANDROID_NS = "{http://schemas.android.com/apk/res/android}"
_COMPONENT_TAGS: tuple[tuple[str, str], ...] = (
    ("activity", "activities"),
    ("activity-alias", "activities"),
    ("service", "services"),
    ("receiver", "receivers"),
    ("provider", "providers"),
)


class ApkError(RuntimeError):
    def __init__(self, code: str, message: str, **details: object) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details


def _norm_contains(value: str | None) -> str | None:
    """A case-folded substring needle, or None when the filter is absent/blank.

    Returns the needle already case-folded so the match site is a plain ``in``.
    A whitespace-only value is treated as "no filter" rather than a match-all
    (the empty substring is in every string) so an accidentally-blank argument
    does not silently widen the list to everything. Mirrors the proxy.flows /
    web.network.list filter normalization so the list surfaces behave the same.
    """
    if value is None:
        return None
    text = value.strip()
    return text.casefold() if text else None


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


def _sig_scheme(apk: Any, method: str) -> bool | None:
    """Best-effort read of an androguard APK signature-scheme predicate.

    androguard exposes ``is_signed`` / ``is_signed_v1`` / ``is_signed_v2`` /
    ``is_signed_v3``, but which of these exist -- and whether they parse a given
    APK's signing block without raising -- varies across versions and malformed
    inputs. Returning ``True``/``False`` only when the predicate answers cleanly,
    and ``None`` when the method is missing or raises, lets a caller tell "this
    APK is not signed with that scheme" apart from "this build could not
    determine it" -- a distinction that matters when v1-only signing on a modern
    target is the CVE-2017-13156 (Janus) risk pattern the field exists to flag.
    """
    func = getattr(apk, method, None)
    if not callable(func):
        return None
    try:
        return bool(func())
    except Exception:  # noqa: BLE001 - signing-block parsing varies by version
        return None


def _cert_datetime(cert: Any, attr: str) -> str | None:
    """ISO-8601 validity bound from an asn1crypto x509 cert, or ``None``.

    androguard 4.x certs are asn1crypto ``x509.Certificate`` objects whose
    ``not_valid_before`` / ``not_valid_after`` are timezone-aware ``datetime``
    objects -- which the MCP JSON serializer cannot encode, so they must be
    rendered to ISO-8601 strings here at the source. An expired signer, or an
    absurd multi-decade validity window, is a real signal a certificate read
    should surface; but a cert shape without these attributes (older androguard,
    a plain string) or a raising property must degrade to ``None`` rather than
    blank the surrounding fields or crash serialization with a raw datetime.
    """
    try:
        value = getattr(cert, attr)
    except Exception:  # noqa: BLE001 - property access varies by object
        return None
    iso = getattr(value, "isoformat", None)
    if callable(iso):
        try:
            return str(iso())
        except Exception:  # noqa: BLE001 - odd datetime-likes may raise
            return None
    if value is None:
        return None
    return str(value)


def _manifest_flag(apk: Any, attribute: str) -> bool | None:
    """Read a boolean ``<application>`` manifest attribute, or ``None``.

    androguard's ``get_attribute_value('application', attr)`` returns the
    declared string ("true"/"false") or ``None`` when the attribute is absent.
    Map it to a real bool so a caller need not re-parse AXML string casing, but
    keep ``None`` for "not declared" rather than collapsing it to ``False``:
    that distinction is the whole point of the field. An unset ``allowBackup``
    still defaults to backups enabled on pre-Android-12 targets, so reporting a
    fabricated ``False`` would read as an explicit deny the manifest never made;
    the honest answer is "never pinned". A missing method or raising accessor
    (older androguard, an unparseable manifest) likewise degrades to ``None``.
    """
    try:
        raw = apk.get_attribute_value("application", attribute)
    except Exception:  # noqa: BLE001 - manifest access varies by version
        return None
    if raw is None:
        return None
    text = str(raw).strip().lower()
    if text == "true":
        return True
    if text == "false":
        return False
    return None


def _manifest_attr(apk: Any, attribute: str, *, limit: int = 512) -> str | None:
    """Read a string-valued ``<application>`` manifest attribute, or ``None``.

    Unlike :func:`_manifest_flag`, this keeps the declared string rather than
    coercing to bool -- for attributes like ``networkSecurityConfig`` whose value
    is a resource reference ("@xml/network_security_config"), not a truth value.
    Its mere presence is the signal a review wants: a Network Security Config can
    re-permit cleartext or pin/trust user CAs, so knowing one governs the app (and
    which resource) qualifies the ``uses_cleartext_traffic`` reading. ``None`` for
    "not declared", degrading the same way on a missing/raising accessor; bounded
    to ``limit`` so a hostile value cannot bloat the reply.
    """
    try:
        raw = apk.get_attribute_value("application", attribute)
    except Exception:  # noqa: BLE001 - manifest access varies by version
        return None
    if raw is None:
        return None
    return str(raw)[:limit]


def _resolve_component_name(package: str, name: str) -> str:
    """Fully-qualify a manifest ``android:name`` the way Android resolves it.

    A name beginning with ``.`` is relative to the package, a bare name with no
    dot at all is likewise package-relative, and an already-dotted name is
    absolute. Matching this to androguard's ``get_activities()``/etc. output is
    what lets the exported subset names line up with the flat component lists --
    a manifest that writes ``.MainActivity`` must read back as the same FQN the
    flat list reports, or an analyst cross-referencing the two sees a phantom
    mismatch.
    """
    if not name:
        return name
    if name.startswith("."):
        return package + name
    if "." not in name:
        return package + "." + name
    return name


def _component_is_exported(exported_attr: str | None, has_intent_filter: bool) -> bool:
    """Decide whether a manifest component is exported (its attack surface).

    An explicit ``android:exported`` wins outright ("true"/"false"). When it is
    absent, a component counts as exported iff it declares an intent-filter --
    the pre-Android-12 implicit-export default, and the same rule MobSF/drozer
    apply. The unset+filter case is deliberately biased toward *exported*: for a
    security read, flagging a possible entry point an analyst can dismiss beats
    hiding one. The rare legacy provider default (an unset provider is exported
    when ``targetSdk < 17``) is intentionally not inferred here; such a provider
    reads as not exported unless it says otherwise, which the caller doc notes.
    """
    if exported_attr is not None:
        return exported_attr.strip().lower() == "true"
    return has_intent_filter


def _exported_components(apk: Any) -> dict[str, list[str]]:
    """Names of exported components, grouped by kind, from the manifest tree.

    androguard has no per-component exported getter, so the decoded manifest XML
    (``get_android_manifest_xml``) is the source of truth: for each component tag
    read ``android:exported`` and whether it declares an intent-filter, then apply
    :func:`_component_is_exported`. Guarded end to end -- a manifest that will not
    parse (older androguard, a malformed tree) yields empty groups rather than
    failing ``components()``. Names are resolved to FQNs to line up with the flat
    lists, de-duplicated, sorted for a stable reply, and capped like them.
    """
    groups: dict[str, list[str]] = {
        "activities": [],
        "services": [],
        "receivers": [],
        "providers": [],
    }
    try:
        root = apk.get_android_manifest_xml()
        package = str(apk.get_package() or "")
    except Exception:  # noqa: BLE001 - manifest access varies by version
        return groups
    if root is None:
        return groups
    for tag, key in _COMPONENT_TAGS:
        try:
            elements = list(root.iter(tag))
        except Exception:  # noqa: BLE001 - odd tree shapes iterate poorly
            continue
        for el in elements:
            name = el.get(_ANDROID_NS + "name")
            if not name:
                continue
            exported_attr = el.get(_ANDROID_NS + "exported")
            try:
                has_filter = len(el.findall("intent-filter")) > 0
            except Exception:  # noqa: BLE001 - findall varies by tree impl
                has_filter = False
            if _component_is_exported(exported_attr, has_filter):
                groups[key].append(_resolve_component_name(package, str(name)))
    for key, names in groups.items():
        groups[key] = sorted(set(names))[:_MAX_COMPONENT_NAMES]
    return groups


def _intent_names(filter_el: Any, tag: str) -> list[str]:
    """The android:name values of a filter's ``action``/``category`` children.

    De-duplicated, sorted, capped, each string bounded, so a manifest that spams
    a filter with thousands of actions cannot bloat the reply. A child with no
    android:name is skipped rather than emitted as an empty string.
    """
    names: set[str] = set()
    try:
        children = filter_el.findall(tag)
    except Exception:  # noqa: BLE001 - findall varies by tree impl
        return []
    for child in children:
        if len(names) >= _MAX_FILTER_ITEMS:
            break
        value = child.get(_ANDROID_NS + "name")
        if value:
            names.add(str(value)[:_MAX_INTENT_STR])
    return sorted(names)


def _intent_data(filter_el: Any) -> list[JsonObject]:
    """The declared android:* attributes of each ``<data>`` in an intent-filter.

    Android merges data attributes (scheme, host, port, path*, mimeType, ssp ...)
    across all ``<data>`` elements of a filter, but reporting them per element as
    declared stays faithful to the manifest without guessing the merge -- the
    caller sees exactly which schemes/hosts/paths the filter names, which is the
    deep-link attack surface. Only android-namespaced attributes are kept (the
    namespace prefix stripped), each value bounded, empties skipped.
    """
    entries: list[JsonObject] = []
    try:
        data_els = filter_el.findall("data")
    except Exception:  # noqa: BLE001 - findall varies by tree impl
        return []
    for data_el in data_els:
        if len(entries) >= _MAX_FILTER_ITEMS:
            break
        attrs: JsonObject = {}
        try:
            items = list(data_el.attrib.items())
        except Exception:  # noqa: BLE001 - odd element shapes
            items = []
        for raw_key, raw_value in items:
            key = str(raw_key)
            if not key.startswith(_ANDROID_NS):
                continue
            short = key[len(_ANDROID_NS) :]
            if short and raw_value:
                attrs[short] = str(raw_value)[:_MAX_INTENT_STR]
        if attrs:
            entries.append(attrs)
    return entries


def _intent_filters(apk: Any) -> tuple[list[JsonObject], bool]:
    """Per-component intent-filters from the manifest tree, and a scan-capped flag.

    androguard has no structured intent-filter getter, so the decoded manifest
    XML (``get_android_manifest_xml``) is the source of truth: for each component
    tag that declares at least one ``<intent-filter>``, record the component FQN,
    kind, whether it is exported, and each filter's actions, categories and data.
    A filter is flagged ``deep_link`` when it is the classic browsable web entry
    (VIEW action + BROWSABLE category + a data scheme) -- the hijack surface a
    review looks for first. Guarded end to end like :func:`_exported_components`:
    a manifest that will not parse yields an empty list rather than raising. The
    bool is True when the component cap was hit before the walk finished.
    """
    components: list[JsonObject] = []
    try:
        root = apk.get_android_manifest_xml()
        package = str(apk.get_package() or "")
    except Exception:  # noqa: BLE001 - manifest access varies by version
        return [], False
    if root is None:
        return [], False
    scan_capped = False
    for tag, key in _COMPONENT_TAGS:
        try:
            elements = list(root.iter(tag))
        except Exception:  # noqa: BLE001 - odd tree shapes iterate poorly
            continue
        for el in elements:
            name = el.get(_ANDROID_NS + "name")
            if not name:
                continue
            try:
                filter_els = el.findall("intent-filter")
            except Exception:  # noqa: BLE001 - findall varies by tree impl
                filter_els = []
            if not filter_els:
                continue
            if len(components) >= _MAX_INTENT_COMPONENTS:
                scan_capped = True
                break
            exported_attr = el.get(_ANDROID_NS + "exported")
            filters: list[JsonObject] = []
            for filter_el in filter_els[:_MAX_FILTERS_PER_COMPONENT]:
                actions = _intent_names(filter_el, "action")
                categories = _intent_names(filter_el, "category")
                data = _intent_data(filter_el)
                deep_link = (
                    "android.intent.action.VIEW" in actions
                    and "android.intent.category.BROWSABLE" in categories
                    and any(entry.get("scheme") for entry in data)
                )
                filters.append(
                    {
                        "actions": actions,
                        "categories": categories,
                        "data": data,
                        "deep_link": deep_link,
                    }
                )
            components.append(
                {
                    "component": _resolve_component_name(package, str(name)),
                    "type": key,
                    # A component with a filter is exported unless it says
                    # exported="false"; the explicit attribute still wins.
                    "exported": _component_is_exported(exported_attr, True),
                    "filters": filters,
                }
            )
        if scan_capped:
            break
    components.sort(key=lambda c: (str(c["type"]), str(c["component"])))
    return components, scan_capped


def _permission_protection(apk: Any, names: set[str]) -> tuple[dict[str, str], list[str]]:
    """Base protection level per requested permission, and the dangerous subset.

    androguard's ``get_details_permissions`` maps a requested permission to
    ``[protectionLevel, label, description]``, but only for permissions it can
    resolve: AOSP platform permissions, plus custom ones the APK itself declares
    with a numeric protectionLevel. The protection level answers what a bare name
    list cannot -- an app requesting a *dangerous* permission (contacts, location,
    SMS, mic ...) is the runtime-consent attack surface a review looks at first.
    Only the base token is kept ("normal|instant" -> "normal"), and a permission
    is flagged dangerous when any ``|``-separated token is exactly "dangerous".
    Restricted to ``names`` (the already-capped requested set) so an unbounded
    details dict cannot outgrow the reply, and guarded so a build without the
    bundled AOSP DB degrades to no levels rather than failing ``permissions()``.
    """
    try:
        details = apk.get_details_permissions()
    except Exception:  # noqa: BLE001 - AOSP permission DB varies by version
        return {}, []
    if not isinstance(details, dict):
        return {}, []
    levels: dict[str, str] = {}
    dangerous: list[str] = []
    for perm, info in details.items():
        perm = str(perm)
        if perm not in names:
            continue
        raw_level = ""
        if isinstance(info, (list, tuple)) and info:
            raw_level = str(info[0])
        elif isinstance(info, str):
            raw_level = info
        tokens = [tok.strip().lower() for tok in raw_level.split("|") if tok.strip()]
        if not tokens:
            continue
        levels[perm] = tokens[0]
        if "dangerous" in tokens:
            dangerous.append(perm)
    return levels, sorted(dangerous)


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
        capped = xml[:_MAX_MANIFEST_CHARS]
        # Bound by the JSON-encoded size, not just the raw char count: a
        # 200k-char manifest is full of attribute quotes that each become \" when
        # encoded, so the char cap alone can still push the result past the
        # transport budget and get the whole thing -- manifest, package, and all
        # -- discarded for a ~16 KiB summary. fit_json_text trims the encoded
        # form under the budget; truncated stays honest whether the char cap or
        # the encoded bound did the cutting.
        inline, _bytes, encoded_cut = fit_json_text(capped, reserve=_MANIFEST_FIELD_RESERVE)
        return {
            "package": apk.get_package(),
            "manifest_xml": inline,
            "truncated": encoded_cut or len(xml) > _MAX_MANIFEST_CHARS,
            "debuggable": _manifest_flag(apk, "debuggable"),
            "allow_backup": _manifest_flag(apk, "allowBackup"),
            "uses_cleartext_traffic": _manifest_flag(apk, "usesCleartextTraffic"),
            "network_security_config": _manifest_attr(apk, "networkSecurityConfig"),
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
        try:
            custom, custom_more = _cap_names(
                apk.get_declared_permissions(), _MAX_PERMISSIONS
            )
        except Exception:  # noqa: BLE001 - older androguard lacks this
            custom, custom_more = [], False
        protection_levels, dangerous = _permission_protection(
            apk, set(declared) | set(requested)
        )
        return {
            "permissions": declared,
            "requested_permissions": requested,
            "custom_permissions": custom,
            "protection_levels": protection_levels,
            "dangerous": dangerous,
            "count": len(declared),
            "has_more": declared_more or requested_more or custom_more,
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
                        # str()-coerced like the fields above: this whole payload
                        # is JSON-serialized across the MCP boundary, and
                        # asn1crypto's sibling ``sha256`` is raw bytes -- one cert
                        # object exposing bytes here (or any non-scalar) would not
                        # fail this loop but would crash the serializer later, so
                        # every cert field is pinned to a string at the source.
                        "sha256": str(cert.sha256_fingerprint)
                        if hasattr(cert, "sha256_fingerprint")
                        else "",
                        "not_before": _cert_datetime(cert, "not_valid_before"),
                        "not_after": _cert_datetime(cert, "not_valid_after"),
                    }
                )
            except Exception:  # noqa: BLE001 - certificate objects vary by version
                continue
        return {
            "signature_files": sig_files,
            "certificates": items,
            "v1_signed": bool(names),
            "v2_signed": _sig_scheme(apk, "is_signed_v2"),
            "v3_signed": _sig_scheme(apk, "is_signed_v3"),
            "signed": _sig_scheme(apk, "is_signed"),
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
            "exported": _exported_components(apk),
            "has_more": a_more or s_more or r_more or p_more,
        }

    def intent_filters(self, path: Path, *, offset: int = 0, limit: int = 100) -> JsonObject:
        apk = self._apk(path)
        all_components, scan_capped = _intent_filters(apk)
        start = max(0, int(offset))
        window = all_components[start : start + max(1, int(limit))]
        # Bound the page by encoded size too: a component can carry many filters
        # with long data URIs, so a window can outgrow the budget. See classes().
        window = fit_json_list(window, reserve=_LIST_FIELD_RESERVE)[0]
        return {
            "components": window,
            "count": len(window),
            "total": len(all_components),
            "offset": start,
            "has_more": start + len(window) < len(all_components),
            # True when the component cap was hit before the manifest walk ended.
            "scan_capped": scan_capped,
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

    def classes(
        self, path: Path, *, offset: int = 0, limit: int = 100, contains: str | None = None
    ) -> JsonObject:
        parsed = self._parsed(path)
        needle = _norm_contains(contains)
        names: list[str] = []
        scan_more = False
        # Cap on internal classes examined, not on matches stored: a filtered
        # scan still walks (and bounds work at) the same _MAX_CLASSES_COLLECT
        # classes as the unfiltered list, keeping the two identical when no
        # filter is set. A case-insensitive substring decides storage, so the
        # whole examined window is searched even when few classes match.
        examined = 0
        for klass in parsed.analysis.get_classes():
            if klass.is_external():
                continue
            if examined >= _MAX_CLASSES_COLLECT:
                scan_more = True
                break
            examined += 1
            name = klass.name
            if needle is not None and needle not in name.casefold():
                continue
            names.append(name)
        names.sort()
        window = names[offset : offset + limit]
        # Bound the page by its JSON-encoded size, not just the row count: a
        # class-name list of 1000 deeply-nested/obfuscated names can encode past
        # the result budget and be discarded whole for a ~16 KiB summary.
        # Trimming before has_more is computed keeps it honest -- a budget-cut
        # page still reports more to fetch, so the caller can page past it.
        window = fit_json_list(window, reserve=_LIST_FIELD_RESERVE)[0]
        result: JsonObject = {
            "classes": window,
            "count": len(window),
            "total": len(names),
            "offset": offset,
            "has_more": offset + len(window) < len(names),
            # True when the examined cap was hit before the class walk ended, so a
            # filtered miss is not read as "no such class" when more went unseen.
            "scan_capped": scan_more,
        }
        if needle is not None:
            # total now counts only matches; flag the narrowing so a filtered page
            # is not mistaken for the whole class list. Mirrors network_list.
            result["filtered"] = True
        return result

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
        # Bound the page by encoded size too: 1000 {name, descriptor, access}
        # rows with long signatures can outgrow the budget. See classes().
        window = fit_json_list(window, reserve=_LIST_FIELD_RESERVE)[0]
        return {
            "class_name": found[0].name,
            "methods": window,
            "count": len(window),
            "total": len(methods),
            "offset": offset,
            "has_more": offset + len(window) < len(methods),
            "scan_capped": scan_more,
        }

    def strings(
        self, path: Path, *, offset: int = 0, limit: int = 200, contains: str | None = None
    ) -> JsonObject:
        parsed = self._parsed(path)
        needle = _norm_contains(contains)
        seen: set[str] = set()
        scan_more = False
        # Cap on strings examined, not on matches stored, so a filtered scan
        # walks the same _MAX_STRINGS_COLLECT window as the unfiltered list. The
        # substring is tested against the full constant, then the truncated form
        # is stored -- the same match/display split apk.string_xrefs uses, so a
        # contains query agrees across the two tools.
        examined = 0
        for item in parsed.analysis.get_strings():
            if examined >= _MAX_STRINGS_COLLECT:
                scan_more = True
                break
            examined += 1
            raw = str(item.get_value())
            if needle is not None and needle not in raw.casefold():
                continue
            seen.add(raw[:_MAX_STRING_LEN])
        values = sorted(seen)
        window = values[offset : offset + limit]
        # Bound the page by encoded size too, and this one bites the soonest:
        # each string is capped at 2000 chars, so a default 200-row page can be
        # ~400 KB -- well past the budget -- before the row count ever caps. See
        # classes().
        window = fit_json_list(window, reserve=_LIST_FIELD_RESERVE)[0]
        result: JsonObject = {
            "strings": window,
            "count": len(window),
            "total": len(values),
            "offset": offset,
            "has_more": offset + len(window) < len(values),
            "scan_capped": scan_more,
        }
        if needle is not None:
            # total now counts only matching strings; flag the narrowing so a
            # filtered page is not read as the whole string pool. See classes().
            result["filtered"] = True
        return result

    def xrefs(
        self,
        path: Path,
        method_name: str,
        *,
        limit: int = 100,
        direction: str = "callers",
    ) -> JsonObject:
        parsed = self._parsed(path)
        target = method_name.strip()
        if not target:
            raise ApkError("invalid_params", "method_name is required")
        # Callers (xref-from) is only half of xref analysis; tracing what a method
        # does needs its callees (xref-to) too. androguard exposes both on a
        # MethodAnalysis with the same (class, ref, offset) tuple shape, so one
        # direction switch drives both; keep "callers" the default so the existing
        # contract is unchanged. Reject anything else rather than silently defaulting.
        mode = direction.strip().lower()
        if mode not in ("callers", "callees"):
            raise ApkError(
                "invalid_params",
                "direction must be 'callers' or 'callees'",
                direction=direction,
            )
        cap = max(1, int(limit))
        rows: list[JsonObject] = []
        has_more = False
        for method in parsed.analysis.get_methods():
            if method.is_external() or method.name != target:
                continue
            edges = method.get_xref_from() if mode == "callers" else method.get_xref_to()
            for _, ref, _ in edges:
                if len(rows) >= cap:
                    # Only set once something was actually left out, so a result
                    # that happens to fill the page is not reported as partial.
                    has_more = True
                    break
                rows.append(
                    {
                        "class": str(ref.class_name),
                        "method": str(ref.name),
                    }
                )
            if has_more:
                break
        # Bound the list by encoded size too: xrefs has no offset to page with,
        # so a budget cut just means some rows are omitted -- fold it into
        # has_more so a caller does not read a trimmed list as the whole set.
        rows, _dropped, budget_cut = fit_json_list(rows, reserve=_LIST_FIELD_RESERVE)
        # The list field names the direction so a callees reply is never mistaken
        # for callers: callers (xref-from) or callees (xref-to), never both.
        list_key = "callers" if mode == "callers" else "callees"
        return {
            "method_name": target,
            "direction": mode,
            list_key: rows,
            "count": len(rows),
            # A caller deciding "these are all the rows" has to know whether the
            # enumeration ended or merely stopped.
            "has_more": has_more or budget_cut,
        }

    def string_xrefs(
        self,
        path: Path,
        value: str,
        *,
        limit: int = 100,
        contains: bool = False,
    ) -> JsonObject:
        parsed = self._parsed(path)
        # A string is not stripped the way a method name is: leading/trailing
        # whitespace can be part of a real constant, and an empty needle in
        # contains mode would match every string, so reject only the empty one.
        if not value:
            raise ApkError("invalid_params", "value is required")
        cap = max(1, int(limit))
        rows: list[JsonObject] = []
        has_more = False
        scan_capped = False
        strings_matched = 0
        # androguard's StringAnalysis carries the same xref-from edges as a
        # method, so "which methods reference this string" answers the question
        # apk.strings cannot: where a hardcoded URL/key/command is actually used.
        # get_xref_from() on a StringAnalysis yields (ClassAnalysis,
        # MethodAnalysis) pairs -- take the method (element 1), tolerating a
        # longer tuple shape from another androguard version.
        for scanned, sa in enumerate(parsed.analysis.get_strings()):
            if scanned >= _MAX_STRINGS_COLLECT:
                scan_capped = True
                break
            text = str(sa.get_value())
            if (value in text) if contains else (text == value):
                strings_matched += 1
                matched_value = text[:_MAX_STRING_LEN]
                for edge in sa.get_xref_from():
                    ref = edge[1]
                    if len(rows) >= cap:
                        # Set only once a row was actually left out, so a page
                        # that exactly fills the cap is not flagged partial.
                        has_more = True
                        break
                    rows.append(
                        {
                            "class": str(getattr(ref, "class_name", "")),
                            "method": str(getattr(ref, "name", "")),
                            # Which matched string this edge belongs to: redundant
                            # in exact mode, load-bearing in contains mode where
                            # several distinct strings can match one query.
                            "string": matched_value,
                        }
                    )
                if has_more:
                    break
        # Bound the list by encoded size too: like method xrefs there is no
        # offset to page with, so a budget cut just omits rows -- fold it into
        # has_more so a trimmed list is never read as the whole set.
        rows, _dropped, budget_cut = fit_json_list(rows, reserve=_LIST_FIELD_RESERVE)
        return {
            "value": value,
            # exact needs the whole constant; contains finds any string holding
            # the needle. Echoed so a contains reply is never read as exact.
            "match": "contains" if contains else "exact",
            "strings_matched": strings_matched,
            "xrefs": rows,
            "count": len(rows),
            "has_more": has_more or budget_cut,
            # True when the string scan hit its own cap before the whole DEX was
            # walked, so an empty/short result is not read as "nowhere else".
            "scan_capped": scan_capped,
        }

    def disassemble(
        self,
        path: Path,
        class_name: str,
        method_name: str,
        *,
        descriptor: str = "",
        offset: int = 0,
        limit: int = 200,
    ) -> JsonObject:
        parsed = self._parsed(path)
        target_class = class_name.strip()
        if not target_class:
            raise ApkError("invalid_params", "class_name is required")
        target_method = method_name.strip()
        if not target_method:
            raise ApkError("invalid_params", "method_name is required")
        want_desc = descriptor.strip()
        smali_class = _dotted_to_smali(target_class)
        # Reading a method's DEX bytecode straight from androguard needs no jadx
        # (Java, a JRE) or apktool (baksmali) -- so this works on a host where
        # those are absent, and answers what the xref tools only point at: what a
        # method actually does. Collect every non-external method in the class
        # with this name so overloads are visible, then pick the one to show.
        overloads: list[str] = []
        matches: list[Any] = []
        for method in parsed.analysis.get_methods():
            if method.is_external():
                continue
            if method.class_name not in (target_class, smali_class):
                continue
            if method.name != target_method:
                continue
            desc = str(method.descriptor)
            overloads.append(desc)
            if not want_desc or desc == want_desc:
                matches.append(method)
        if not matches:
            raise ApkError(
                "not_found",
                "method not found",
                class_name=class_name,
                method_name=method_name,
                descriptor=descriptor,
            )
        # Deterministic choice when a name has overloads and none was pinned:
        # sort by descriptor and take the first. overloads still lists them all so
        # the caller can re-ask with a specific descriptor.
        chosen = sorted(matches, key=lambda m: str(m.descriptor))[0]
        rows: list[JsonObject] = []
        scan_more = False
        addr = 0
        try:
            instructions = chosen.get_method().get_instructions()
        except Exception:  # noqa: BLE001 - abstract/native methods have no code
            instructions = []
        for ins in instructions:
            if len(rows) >= _MAX_INSTRUCTIONS_COLLECT:
                scan_more = True
                break
            try:
                mnemonic = str(ins.get_name())
                operands = str(ins.get_output())[:_MAX_STRING_LEN]
                length = int(ins.get_length())
            except Exception:  # noqa: BLE001 - odd instruction shapes vary
                continue
            rows.append(
                {
                    "idx": len(rows),
                    # DEX addresses are 16-bit code units; report the code-unit
                    # offset (bytes // 2) so branch targets line up with it.
                    "addr": addr // 2,
                    "mnemonic": mnemonic,
                    "operands": operands,
                }
            )
            addr += length
        start = max(0, int(offset))
        window = rows[start : start + max(1, int(limit))]
        # Bound the page by encoded size too: a const-string operand can be 2000
        # chars, so a long window can outgrow the budget. See classes().
        window = fit_json_list(window, reserve=_LIST_FIELD_RESERVE)[0]
        return {
            "class_name": chosen.class_name,
            "method_name": target_method,
            "descriptor": str(chosen.descriptor),
            "access": str(chosen.access),
            "instructions": window,
            "count": len(window),
            "total": len(rows),
            "offset": start,
            "has_more": start + len(window) < len(rows),
            # True when the instruction scan hit its cap before the method ended,
            # so a truncated listing is not read as the whole method.
            "scan_capped": scan_more,
            # Every descriptor for this method name in the class, sorted, so a
            # caller can disambiguate an overload with the descriptor parameter.
            "overloads": sorted(set(overloads)),
        }


def _dotted_to_smali(name: str) -> str:
    """com.example.Foo -> Lcom/example/Foo; so either form resolves a class."""
    if name.startswith("L") and name.endswith(";"):
        return name
    return "L" + name.replace(".", "/") + ";"
