"""Every non-PE reader that reports ``has_more`` must page, or be a documented
exception.

Four readers shipped, one after another, with the same honest-but-unreachable
gap: they collected a full set into memory, sorted it, returned an alphabetical
*prefix* with ``has_more`` -- and no ``offset``. ``device.packages``,
``device.properties``, ``apk.native_libs`` and ``adb`` ``list_devices`` each told
the agent "a name that sorts within this page but is absent is genuinely not
there", yet without an offset that reasoning held for the first page alone: a
real item sorting past the cap was flagged by ``has_more`` but could never be
fetched to confirm. Each fix was the same -- add ``offset`` -- and each slipped
past every existing guard, because the schema/clamp guards check that a *declared*
offset is bounded, not that a capped full-set reader declares one at all.

This is that missing invariant as a drift guard. It scans the non-PE backend
readers, finds every method that reports ``has_more``, and fails if one takes no
``offset`` unless it is in ``_UNPAGED_HAS_MORE_OK`` -- a fail-closed allowlist,
keyed by ``(backend, method)``, whose value is the reason the tail is not
stranded. The allowlist is pinned to be *exactly* the offset-less set: a new
capped reader that forgets to page trips here until it either gains an offset or
is added with a reason (the deliberate decision), and a listed reader that later
gains an offset must be removed, so the allowlist cannot rot into a rubber stamp.
"""

from __future__ import annotations

import ast
from pathlib import Path

import headless_re_mcp

_NON_PE_BACKENDS = frozenset(
    {"web", "proxy", "adb", "frida", "apk", "jsre", "jadx", "apktool"}
)

# (backend, method) readers that report has_more yet legitimately take no offset,
# each with the reason paging is unnecessary or unsound. Fail-closed: this set is
# asserted to equal the offset-less has_more readers found by the scan, so it
# cannot silently gain a real gap or keep a stale entry.
_UNPAGED_HAS_MORE_OK: dict[tuple[str, str], str] = {
    ("frida", "modules"): (
        "live runtime enumeration; the module set changes between calls, so a "
        "cross-call offset would page a moving target rather than a stable list"
    ),
    ("frida", "exports"): (
        "live runtime enumeration; same moving-target reason as frida.modules"
    ),
    ("frida", "java_enumerate"): (
        "live JVM enumeration; same moving-target reason as frida.modules"
    ),
    ("web", "console"): (
        "bounded ring buffer whose max limit spans the whole ring, so the "
        "newest-N page already reaches every retained message -- there is no "
        "tail past the cap to offset to"
    ),
    ("jadx", "export_sources"): (
        "has_more / listing_truncated flag a capped PREVIEW of files that are all "
        "written to output_dir; the full set is the on-disk tree, reachable "
        "there, not a truncated in-memory list"
    ),
    ("apk", "permissions"): (
        "multi-list overview (declared + requested permissions) in one envelope; "
        "a single offset cannot address independent lists, and the per-list caps "
        "are generous versus real manifests"
    ),
    ("apk", "certificates"): (
        "multi-list overview (signature_files + certificates); a single offset "
        "cannot address independent lists, and real APKs carry a handful"
    ),
    ("apk", "components"): (
        "multi-list overview (activities / services / receivers / providers); "
        "four independent capped lists, not one pageable sequence"
    ),
}


def _backends_dir() -> Path:
    return Path(headless_re_mcp.__file__).parent / "backends"


def _arg_names(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    args = fn.args
    names: set[str] = set()
    for group in (args.posonlyargs, args.args, args.kwonlyargs):
        names.update(arg.arg for arg in group)
    return names


def _reports_has_more(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """True when ``"has_more"`` appears as a string literal in the body.

    Catches it as a returned dict key (``{"has_more": ...}``) and as a subscript
    assignment (``result["has_more"] = ...``) alike, and descends into the inner
    ``work`` / ``use`` closures the frida readers build their envelope in.
    """
    return any(
        isinstance(node, ast.Constant) and node.value == "has_more"
        for node in ast.walk(fn)
    )


def _scan() -> dict[tuple[str, str], bool]:
    """(backend, method) -> whether a has_more-reporting reader takes an offset."""
    result: dict[tuple[str, str], bool] = {}
    for path in sorted(_backends_dir().glob("*/client.py")):
        backend = path.parent.name
        if backend not in _NON_PE_BACKENDS:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for cls in ast.walk(tree):
            if not isinstance(cls, ast.ClassDef):
                continue
            for node in cls.body:
                if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                if _reports_has_more(node):
                    result[(backend, node.name)] = "offset" in _arg_names(node)
    return result


def test_scan_reaches_and_recognises_the_known_has_more_readers() -> None:
    """Non-vacuity: the scan finds has_more readers of both kinds -- paged (with
    offset) and the documented offset-less ones -- so the violation check below
    cannot pass by finding nothing, and the offset detector is not stuck on/off.
    """
    scanned = _scan()
    paged = {
        ("apk", "classes"),
        ("apk", "native_libs"),
        ("adb", "packages"),
        ("adb", "properties"),
        ("adb", "list_devices"),
        ("web", "network_list"),
    }
    unpaged = {("frida", "modules"), ("web", "console")}
    assert paged <= set(scanned), f"the has_more scan looks broken, saw {sorted(scanned)}"
    assert unpaged <= set(scanned), f"the has_more scan looks broken, saw {sorted(scanned)}"
    assert all(scanned[key] for key in paged), {key: scanned[key] for key in paged}
    assert not any(scanned[key] for key in unpaged), {
        key: scanned[key] for key in unpaged
    }


def test_every_has_more_reader_pages_or_is_a_documented_exception() -> None:
    scanned = _scan()
    offset_less = {key for key, has_offset in scanned.items() if not has_offset}

    undocumented = sorted(offset_less - set(_UNPAGED_HAS_MORE_OK))
    assert undocumented == [], (
        "these non-PE readers report has_more but take no offset, so an item "
        "sorting past the cap is flagged as existing yet can never be fetched -- "
        "give them an offset (like device.packages / apk.native_libs) or add "
        f"them to _UNPAGED_HAS_MORE_OK with a reason: {undocumented}"
    )

    # Fail-closed the other way: an allowlist entry that has since gained an
    # offset (or was renamed away) must be removed, so the list stays a live
    # record of real exceptions rather than a rubber stamp.
    stale = sorted(set(_UNPAGED_HAS_MORE_OK) - offset_less)
    assert stale == [], (
        "these _UNPAGED_HAS_MORE_OK entries no longer name an offset-less "
        f"has_more reader (they gained an offset or moved); drop them: {stale}"
    )
