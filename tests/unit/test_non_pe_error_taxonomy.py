"""The non-PE backends speak one small, shared error-code vocabulary.

Every non-PE backend (web, proxy, adb, apk static, apktool, frida, jsre, jadx)
raises a typed error whose first argument is a machine-routable ``code`` that
rides through ``_as_rpc`` into the ``RpcError.code`` the caller sees. Agents and
the OpenAI bridge branch on that code -- retry a ``timeout``, degrade around a
``capability_unavailable``, abort on ``permission_denied``, re-page after
``too_large`` -- so the code is a contract, not a log string. The contract only
works if the vocabulary stays small and shared:

* a typo (``capabilty_unavailable``, ``invalid_param``) mints a code no caller
  has a branch for, so it silently falls through to the generic-failure path;
* the PE line speaks a *different* vocabulary (``invalid_argument``,
  ``process_failed``, ``input_too_large``, ``executable_not_found`` ...), so a
  non-PE backend that copies a PE pattern -- or a shared helper that leaks one --
  hands the caller a code from the wrong dialect that its non-PE routing misses.

Nothing pinned the vocabulary: the codes are bare string literals scattered
across eight backends with no enum, so either drift ships unnoticed. This scans
the raised literals and asserts they are exactly ``_NON_PE_ERROR_CODES`` -- no
code outside it (the typo / PE-contamination guard) and none inside it that no
backend emits (so the vocabulary cannot rot into a permissive superset that
waves everything through). A genuinely new code has to be added here with a
reason, which is the deliberate decision this forces.
"""

from __future__ import annotations

import re
from pathlib import Path

import headless_re_mcp

# The eight non-PE backend clients and the error class each raises. A client
# only ever raises its own class, so matching all eight names against every file
# is harmless and keeps the scanner a single regex.
_NON_PE_BACKENDS = ("web", "proxy", "adb", "apk", "apktool", "frida", "jsre", "jadx")
_ERROR_CLASSES = (
    "WebError",
    "ProxyError",
    "AdbError",
    "ApkError",
    "FridaError",
    "JsReError",
    "JadxError",
    "ApktoolError",
)

# The canonical machine-routable vocabulary the non-PE backends speak. Kept
# deliberately small: each entry is a distinct thing a caller routes on.
_NON_PE_ERROR_CODES = frozenset(
    {
        "backend_error",  # the backend or the tool it drives failed
        "capability_unavailable",  # an optional dependency/tool is not installed
        "invalid_params",  # a caller argument is malformed or out of range
        "invalid_state",  # the session/resource is not in a usable state
        "not_found",  # a named device/flow/path/class/file is absent
        "permission_denied",  # the pid/target is outside the session's allow-set
        "timeout",  # a bounded operation outran its deadline
        "too_large",  # input or output exceeded a capture/expansion cap
    }
)

# ``\s*`` after ``(`` also matches newlines, so a code on the line below the
# class name (the common multi-line raise) is still captured. The class
# definition ``class WebError(RuntimeError):`` and uses like ``except WebError``
# never put a quoted lowercase token right after ``(``, so they do not match.
_CODE_RE = re.compile(r"(?:" + "|".join(_ERROR_CLASSES) + r")\(\s*[\"']([a-z_]+)[\"']")


def _emitted_codes() -> dict[str, set[str]]:
    """Map each non-PE backend to the set of error-code literals its client raises."""
    backends_dir = Path(headless_re_mcp.__file__).parent / "backends"
    found: dict[str, set[str]] = {}
    for name in _NON_PE_BACKENDS:
        source = (backends_dir / name / "client.py").read_text(encoding="utf-8")
        found[name] = set(_CODE_RE.findall(source))
    return found


def test_non_pe_backends_speak_exactly_the_canonical_error_vocabulary() -> None:
    codes = _emitted_codes()
    union: set[str] = set().union(*codes.values()) if codes else set()

    # Non-vacuous: the scan must actually reach several backends and find the
    # codes every one of them raises, or a broken regex/enumeration would let
    # this pass by finding nothing to check.
    backends_with_codes = {name for name, found in codes.items() if found}
    assert {"web", "adb", "frida", "apk"} <= backends_with_codes, (
        f"the error-code scan looks broken, saw codes only in {sorted(backends_with_codes)}"
    )
    assert {"capability_unavailable", "invalid_params", "backend_error", "too_large"} <= union, (
        f"the scan missed well-known non-PE codes, saw {sorted(union)}"
    )

    # Drift guard: a code outside the vocabulary is a typo or a code borrowed
    # from the PE line's different dialect -- either way the caller has no branch
    # for it, so it silently degrades to the generic-failure path.
    unknown = union - _NON_PE_ERROR_CODES
    assert unknown == set(), (
        "non-PE backends raise error codes outside the canonical vocabulary "
        "(a typo, or a code borrowed from the PE line?); add it to "
        f"_NON_PE_ERROR_CODES with a reason or fix the raise: {sorted(unknown)}"
    )

    # Rot guard: a canonical code that no backend emits is aspirational; drop it
    # so the vocabulary cannot quietly grow into a superset that waves anything
    # through. (Each mapping is by exact code, so this stays honest.)
    dead = _NON_PE_ERROR_CODES - union
    assert dead == set(), (
        f"canonical codes no longer emitted by any non-PE backend, remove them: {sorted(dead)}"
    )
