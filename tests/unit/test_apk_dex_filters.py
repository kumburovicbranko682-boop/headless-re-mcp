"""apk DEX-analysis filters, cache reuse, and native-lib ABI parsing, with fakes.

The page-clamp tests drive classes/methods/xrefs by monkeypatching _parsed, and
their fake classes/methods always report is_external() == False -- so the
"exclude the external symbol" filters those methods exist to apply never ran.
An external class is one androguard synthesises for a referenced-but-not-defined
type (a framework class the app calls); listing it as one of the app's own
classes, or counting a framework method's callers as the app's, is exactly the
wrong-conclusion an unattended agent would draw. These seed a real _ParsedApk
into the process cache instead of stubbing _parsed, so the cache-hit path and
the _ParsedApk container are exercised too, and pin: classes() drops external
classes, xrefs() skips both external methods and methods whose name is not the
target, native_libs() extracts ABIs only from properly nested lib paths while
still listing a top-level lib entry, and a client without androguard is
unavailable and refuses rather than pretending.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from headless_re_mcp.backends.apk.client import ApkClient, ApkError, _ParsedApk


@pytest.fixture(autouse=True)
def _clear_apk_caches() -> Iterator[None]:
    yield
    with ApkClient._cache_lock:
        ApkClient._light_cache.clear()
        ApkClient._full_cache.clear()


def _client() -> ApkClient:
    client = ApkClient()
    client._available = True
    return client


def _apk_file(tmp_path: Path) -> Path:
    path = tmp_path / "app.apk"
    path.write_bytes(b"PK\x03\x04 stand-in; never parsed because the cache is seeded")
    return path


def _key(path: Path) -> tuple[str, int]:
    resolved = path.expanduser().resolve()
    return (str(resolved), int(resolved.stat().st_mtime_ns))


def _seed_full(path: Path, analysis: Any) -> None:
    """Seed a real _ParsedApk so _parsed returns it on a cache hit (no androguard
    import) and the container's own assignment runs."""
    parsed = _ParsedApk(apk=None, analysis=analysis, dex=None)
    with ApkClient._cache_lock:
        ApkClient._full_cache[_key(path)] = parsed


def _seed_light(path: Path, apk: Any) -> None:
    with ApkClient._cache_lock:
        ApkClient._light_cache[_key(path)] = apk


class _Klass:
    def __init__(self, name: str, *, external: bool = False) -> None:
        self.name = name
        self._external = external

    def is_external(self) -> bool:
        return self._external


class _Analysis:
    def __init__(self, *, classes: Any = (), methods: Any = ()) -> None:
        self._classes = list(classes)
        self._methods = list(methods)

    def get_classes(self) -> list[Any]:
        return self._classes

    def get_methods(self) -> list[Any]:
        return self._methods


class _XrefCall:
    def __init__(self, index: int) -> None:
        self.class_name = f"Lcom/example/Caller{index};"
        self.name = "invoke"


class _Method:
    def __init__(self, name: str, *, external: bool = False, callers: int = 0) -> None:
        self.name = name
        self._external = external
        self._callers = callers

    def is_external(self) -> bool:
        return self._external

    def get_xref_from(self) -> list[tuple[object, _XrefCall, int]]:
        return [(None, _XrefCall(index), index) for index in range(self._callers)]


def test_classes_excludes_androguard_synthesised_external_classes(tmp_path: Path) -> None:
    path = _apk_file(tmp_path)
    analysis = _Analysis(
        classes=[
            _Klass("Lcom/app/A;"),
            _Klass("Landroid/os/Bundle;", external=True),
            _Klass("Lcom/app/B;"),
        ]
    )
    _seed_full(path, analysis)
    payload = _client().classes(path, offset=0, limit=100)
    assert payload["classes"] == ["Lcom/app/A;", "Lcom/app/B;"]
    assert payload["total"] == 2
    assert payload["count"] == 2
    assert payload["has_more"] is False


def test_xrefs_skips_external_methods_and_name_mismatches(tmp_path: Path) -> None:
    path = _apk_file(tmp_path)
    analysis = _Analysis(
        methods=[
            _Method("decrypt", external=False, callers=2),
            _Method("decrypt", external=True, callers=5),
            _Method("encrypt", external=False, callers=3),
        ]
    )
    _seed_full(path, analysis)
    payload = _client().xrefs(path, "decrypt", limit=100)
    assert payload["method_name"] == "decrypt"
    # Only the non-external method actually named "decrypt" contributes callers;
    # the external homonym and the differently-named method are skipped.
    assert payload["count"] == 2
    assert payload["has_more"] is False


def test_xrefs_for_a_name_with_no_internal_definition_is_empty(tmp_path: Path) -> None:
    """When every method of that name is external, the result is empty, not the
    external callers -- the honest 'this name has no in-app definition' answer."""
    path = _apk_file(tmp_path)
    analysis = _Analysis(methods=[_Method("decrypt", external=True, callers=9)])
    _seed_full(path, analysis)
    payload = _client().xrefs(path, "decrypt", limit=100)
    assert payload["count"] == 0
    assert payload["has_more"] is False


def test_native_libs_extracts_abis_only_from_nested_paths(tmp_path: Path) -> None:
    """A lib/<abi>/<file> path yields an ABI; a top-level lib/<file> path has no
    ABI segment and must not synthesise one, yet still counts as a lib entry.
    Non-lib entries are ignored entirely."""
    path = _apk_file(tmp_path)
    apk = SimpleNamespace(
        get_files=lambda: [
            "lib/arm64-v8a/libfoo.so",
            "lib/x86/libbar.so",
            "lib/toplevel.so",
            "res/layout/main.xml",
        ]
    )
    _seed_light(path, apk)
    payload = _client().native_libs(path)
    assert payload["abis"] == ["arm64-v8a", "x86"]
    assert "lib/toplevel.so" in payload["native_libs"]
    assert "res/layout/main.xml" not in payload["native_libs"]
    assert payload["has_more"] is False


def test_a_client_without_androguard_is_unavailable_and_refuses(tmp_path: Path) -> None:
    """The capability flag and the gate must agree: no androguard means available
    is False and a DEX read is refused as capability_unavailable, not attempted."""
    client = ApkClient()
    client._available = False
    client._androguard = None
    assert client.available is False
    with pytest.raises(ApkError) as caught:
        client.classes(tmp_path / "app.apk")
    assert caught.value.code == "capability_unavailable"
