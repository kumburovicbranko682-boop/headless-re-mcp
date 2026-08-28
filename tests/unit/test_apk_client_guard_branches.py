"""Guard, cache and error branches of the APK (androguard) backend.

The apk field tests fake ``_apk`` / ``_parsed`` outright and assert payload
shapes. That leaves the seams those fakes stand in for untested: the lazy
availability probe, the ``_require`` path checks, the mtime-keyed cache with its
eviction, and the per-method fallbacks that keep one androguard version quirk
from turning a whole read into an exception. Each test here pins one of those.

androguard is optional and may be absent here (CI installs only the core
extras), so the parse seam is exercised by planting a stub ``androguard`` module
tree in ``sys.modules`` and monkeypatching ``APK`` / ``AnalyzeAPK`` on it rather
than shipping a real APK fixture; the client's lazy per-call import picks the
stub up either way, and monkeypatch restores the previous state afterwards. The
shared class-level caches are cleared around every test so a parse here cannot
leak into another module's run.
"""

from __future__ import annotations

import sys
import types
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.apk.client import (
    ApkClient,
    ApkError,
    _dotted_to_smali,
    _ParsedApk,
)


@pytest.fixture(autouse=True)
def _clear_caches() -> Any:
    ApkClient._light_cache.clear()
    ApkClient._full_cache.clear()
    yield
    ApkClient._light_cache.clear()
    ApkClient._full_cache.clear()


def _available_client() -> ApkClient:
    client = ApkClient()
    client._available = True
    return client


def _stub_androguard(monkeypatch: Any) -> None:
    """Make the lazy androguard import sites patchable even when it is absent.

    The client imports ``androguard.core.apk`` / ``androguard.misc`` inside each
    call, so a stub module tree in ``sys.modules`` satisfies those imports
    without the real package. ``monkeypatch.setitem`` restores whatever was
    there before (including nothing), so an installed androguard is untouched
    for other tests.
    """
    root = types.ModuleType("androguard")
    core = types.ModuleType("androguard.core")
    apk_mod = types.ModuleType("androguard.core.apk")
    misc = types.ModuleType("androguard.misc")
    apk_mod.APK = None  # type: ignore[attr-defined]
    misc.AnalyzeAPK = None  # type: ignore[attr-defined]
    core.apk = apk_mod  # type: ignore[attr-defined]
    root.core = core  # type: ignore[attr-defined]
    root.misc = misc  # type: ignore[attr-defined]
    for name, module in (
        ("androguard", root),
        ("androguard.core", core),
        ("androguard.core.apk", apk_mod),
        ("androguard.misc", misc),
    ):
        monkeypatch.setitem(sys.modules, name, module)


# ---------------------------------------------------------------------------
# Availability and the parsed-apk holder.
# ---------------------------------------------------------------------------
def test_parsed_apk_holds_the_three_androguard_objects() -> None:
    parsed = _ParsedApk("apk", "analysis", "dex")
    assert parsed.apk == "apk"
    assert parsed.analysis == "analysis"
    assert parsed._dex == "dex"


def test_client_without_androguard_reports_unavailable(monkeypatch: Any) -> None:
    """A missing androguard degrades to capability_unavailable, not ImportError.

    The import is lazy so the whole Android surface stays usable-but-degraded
    when the extra is absent; _require is the choke point that must say so.
    """
    import builtins

    real_import = builtins.__import__

    def deny(name: str, *args: Any, **kwargs: Any) -> Any:
        if name == "androguard" or name.startswith("androguard."):
            raise ImportError("no androguard")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", deny)
    client = ApkClient()
    assert client.available is False
    with pytest.raises(ApkError) as caught:
        client._require(Path("whatever.apk"))
    assert caught.value.code == "capability_unavailable"


# ---------------------------------------------------------------------------
# release().
# ---------------------------------------------------------------------------
def test_release_returns_false_when_the_path_cannot_be_resolved() -> None:
    class _BadPath:
        def expanduser(self) -> _BadPath:
            return self

        def resolve(self) -> Path:
            raise OSError("cannot resolve")

    assert ApkClient.release(_BadPath()) is False  # type: ignore[arg-type]


def test_release_drops_cached_parses_for_the_path(tmp_path: Path) -> None:
    apk = tmp_path / "app.apk"
    apk.write_bytes(b"PK\x03\x04")
    resolved = str(apk.expanduser().resolve())
    ApkClient._light_cache[(resolved, 1)] = object()
    ApkClient._full_cache[(resolved, 1)] = _ParsedApk("a", "b", "c")

    assert ApkClient.release(apk) is True
    assert not ApkClient._light_cache
    assert not ApkClient._full_cache
    # A second release finds nothing left and says so.
    assert ApkClient.release(apk) is False


# ---------------------------------------------------------------------------
# _require path checks.
# ---------------------------------------------------------------------------
def test_require_reports_a_missing_file_as_not_found(tmp_path: Path) -> None:
    client = _available_client()
    with pytest.raises(ApkError) as caught:
        client._require(tmp_path / "absent.apk")
    assert caught.value.code == "not_found"


# ---------------------------------------------------------------------------
# _apk: parse, cache hit, eviction, backend_error.
# ---------------------------------------------------------------------------
def test_apk_parse_caches_by_path_and_mtime(tmp_path: Path, monkeypatch: Any) -> None:
    """A second read of the same file reuses the parse instead of re-parsing.

    DEX/manifest parsing is expensive, so the mtime-keyed cache must return the
    same object on a repeat call within a session rather than rebuild it.
    """
    apk = tmp_path / "app.apk"
    apk.write_bytes(b"PK\x03\x04")
    parses: list[str] = []

    class _FakeAPK:
        def __init__(self, path: str) -> None:
            parses.append(path)

    _stub_androguard(monkeypatch)
    monkeypatch.setattr("androguard.core.apk.APK", _FakeAPK)
    client = _available_client()
    first = client._apk(apk)
    second = client._apk(apk)
    assert first is second
    assert len(parses) == 1


def test_apk_parse_evicts_the_oldest_when_the_cache_is_full(
    tmp_path: Path, monkeypatch: Any
) -> None:
    monkeypatch.setattr("headless_re_mcp.backends.apk.client._CACHE_LIMIT", 1)

    class _FakeAPK:
        def __init__(self, path: str) -> None:
            self.path = path

    _stub_androguard(monkeypatch)
    monkeypatch.setattr("androguard.core.apk.APK", _FakeAPK)
    client = _available_client()
    first = tmp_path / "a.apk"
    second = tmp_path / "b.apk"
    first.write_bytes(b"PK")
    second.write_bytes(b"PK")
    client._apk(first)
    client._apk(second)
    assert len(ApkClient._light_cache) == 1


def test_apk_parse_failure_becomes_backend_error(tmp_path: Path, monkeypatch: Any) -> None:
    apk = tmp_path / "app.apk"
    apk.write_bytes(b"not a zip")

    def _raise(path: str) -> None:
        raise ValueError("bad zip")

    _stub_androguard(monkeypatch)
    monkeypatch.setattr("androguard.core.apk.APK", _raise)
    client = _available_client()
    with pytest.raises(ApkError) as caught:
        client._apk(apk)
    assert caught.value.code == "backend_error"


def test_full_analysis_caches_and_translates_failure(
    tmp_path: Path, monkeypatch: Any
) -> None:
    apk = tmp_path / "app.apk"
    apk.write_bytes(b"PK\x03\x04")
    calls: list[str] = []

    def _analyze(path: str) -> tuple[str, str, str]:
        calls.append(path)
        return ("apk", "dex", "analysis")

    _stub_androguard(monkeypatch)
    monkeypatch.setattr("androguard.misc.AnalyzeAPK", _analyze)
    client = _available_client()
    first = client._parsed(apk)
    second = client._parsed(apk)
    assert first is second
    assert len(calls) == 1
    assert first.apk == "apk"
    assert first.analysis == "analysis"

    def _boom(path: str) -> tuple[str, str, str]:
        raise RuntimeError("dex decode failed")

    monkeypatch.setattr("androguard.misc.AnalyzeAPK", _boom)
    other = tmp_path / "b.apk"
    other.write_bytes(b"PK\x03\x04")
    with pytest.raises(ApkError) as caught:
        client._parsed(other)
    assert caught.value.code == "backend_error"


def test_full_analysis_evicts_the_oldest_when_full(
    tmp_path: Path, monkeypatch: Any
) -> None:
    monkeypatch.setattr("headless_re_mcp.backends.apk.client._CACHE_LIMIT", 1)
    _stub_androguard(monkeypatch)
    monkeypatch.setattr(
        "androguard.misc.AnalyzeAPK", lambda path: ("apk", "dex", "analysis")
    )
    client = _available_client()
    first = tmp_path / "a.apk"
    second = tmp_path / "b.apk"
    first.write_bytes(b"PK")
    second.write_bytes(b"PK")
    client._parsed(first)
    client._parsed(second)
    assert len(ApkClient._full_cache) == 1


# ---------------------------------------------------------------------------
# manifest / permissions / certificates fallbacks.
# ---------------------------------------------------------------------------
def test_manifest_decode_failure_becomes_backend_error(
    tmp_path: Path, monkeypatch: Any
) -> None:
    class _Apk:
        def get_android_manifest_axml(self) -> Any:
            raise RuntimeError("axml corrupt")

    client = _available_client()
    monkeypatch.setattr(ApkClient, "_apk", lambda self, path: _Apk())
    with pytest.raises(ApkError) as caught:
        client.manifest(tmp_path / "app.apk")
    assert caught.value.code == "backend_error"


def test_permissions_falls_back_when_requested_permissions_is_unavailable(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """An older androguard lacks get_requested_permissions.

    Rather than fail the whole read, the requested list falls back to the
    declared one so the tool still answers, and has_more reflects the fallback.
    """

    class _Apk:
        def get_permissions(self) -> list[str]:
            return ["android.permission.INTERNET"]

        def get_requested_permissions(self) -> list[str]:
            raise AttributeError("not on this version")

    client = _available_client()
    monkeypatch.setattr(ApkClient, "_apk", lambda self, path: _Apk())
    payload = client.permissions(tmp_path / "app.apk")
    assert payload["permissions"] == ["android.permission.INTERNET"]
    assert payload["requested_permissions"] == ["android.permission.INTERNET"]


def test_certificates_tolerate_missing_signature_names_and_bad_certs(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A cert object that raises while being read is skipped, not fatal.

    Certificate objects vary by androguard version, so get_signature_names may
    be absent and a single unreadable cert must not sink the whole listing.
    """

    class _BadCert:
        @property
        def subject(self) -> str:
            raise RuntimeError("unreadable cert")

    class _Apk:
        def get_signature_names(self) -> list[str]:
            raise AttributeError("older androguard")

        def get_certificates(self) -> list[Any]:
            return [_BadCert()]

    client = _available_client()
    monkeypatch.setattr(ApkClient, "_apk", lambda self, path: _Apk())
    payload = client.certificates(tmp_path / "app.apk")
    assert payload["signature_files"] == []
    assert payload["certificates"] == []
    assert payload["v1_signed"] is False


# ---------------------------------------------------------------------------
# classes / methods / xrefs guard branches.
# ---------------------------------------------------------------------------
class _Klass:
    def __init__(self, name: str, *, external: bool = False, methods: int = 0) -> None:
        self.name = name
        self._external = external
        self._methods = [
            type("_M", (), {"name": f"m{i}", "descriptor": "()V", "access": "public"})()
            for i in range(methods)
        ]

    def is_external(self) -> bool:
        return self._external

    def get_methods(self) -> list[Any]:
        return self._methods


class _Parsed:
    def __init__(
        self,
        classes: list[_Klass] | None = None,
        methods: list[Any] | None = None,
        strings: list[str] | None = None,
    ) -> None:
        self.analysis = self
        self._classes = classes or []
        self._methods = methods or []
        self._strings = strings or []

    def get_classes(self) -> list[_Klass]:
        return self._classes

    def get_methods(self) -> list[Any]:
        return self._methods

    def get_strings(self) -> list[Any]:
        return [type("_S", (), {"get_value": staticmethod(lambda v=s: v)})() for s in self._strings]


def test_classes_skips_external_classes(tmp_path: Path, monkeypatch: Any) -> None:
    """External classes are references, not code in this APK, so they are dropped."""
    parsed = _Parsed(
        classes=[_Klass("Lcom/app/Real;"), _Klass("Landroid/Framework;", external=True)]
    )
    client = _available_client()
    monkeypatch.setattr(ApkClient, "_parsed", lambda self, path: parsed)
    payload = client.classes(tmp_path / "app.apk")
    assert payload["classes"] == ["Lcom/app/Real;"]
    assert payload["total"] == 1


def test_methods_requires_a_class_name(tmp_path: Path, monkeypatch: Any) -> None:
    client = _available_client()
    monkeypatch.setattr(ApkClient, "_parsed", lambda self, path: _Parsed())
    with pytest.raises(ApkError) as caught:
        client.methods(tmp_path / "app.apk", "   ")
    assert caught.value.code == "invalid_params"


def test_methods_reports_an_unknown_class_as_not_found(
    tmp_path: Path, monkeypatch: Any
) -> None:
    parsed = _Parsed(classes=[_Klass("Lcom/app/Other;", methods=1)])
    client = _available_client()
    monkeypatch.setattr(ApkClient, "_parsed", lambda self, path: parsed)
    with pytest.raises(ApkError) as caught:
        client.methods(tmp_path / "app.apk", "com.app.Missing")
    assert caught.value.code == "not_found"


def test_methods_resolves_a_dotted_class_name(tmp_path: Path, monkeypatch: Any) -> None:
    parsed = _Parsed(classes=[_Klass("Lcom/app/Foo;", methods=2)])
    client = _available_client()
    monkeypatch.setattr(ApkClient, "_parsed", lambda self, path: parsed)
    payload = client.methods(tmp_path / "app.apk", "com.app.Foo")
    assert payload["class_name"] == "Lcom/app/Foo;"
    assert payload["total"] == 2


def test_xrefs_requires_a_method_name(tmp_path: Path, monkeypatch: Any) -> None:
    client = _available_client()
    monkeypatch.setattr(ApkClient, "_parsed", lambda self, path: _Parsed())
    with pytest.raises(ApkError) as caught:
        client.xrefs(tmp_path / "app.apk", "")
    assert caught.value.code == "invalid_params"


def test_xrefs_skips_external_methods_and_name_mismatches(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """Only the named, in-APK method contributes callers.

    An external stub or a same-named-but-different method must not add spurious
    callers, so both are skipped before the xref walk.
    """

    class _Call:
        class_name = "Lcom/app/Caller;"
        name = "invoke"

    class _Method:
        def __init__(self, name: str, *, external: bool, callers: int) -> None:
            self.name = name
            self._external = external
            self._callers = callers

        def is_external(self) -> bool:
            return self._external

        def get_xref_from(self) -> list[tuple[Any, Any, int]]:
            return [(None, _Call(), i) for i in range(self._callers)]

    parsed = _Parsed(
        methods=[
            _Method("decrypt", external=True, callers=5),  # external: skipped
            _Method("other", external=False, callers=5),  # wrong name: skipped
            _Method("decrypt", external=False, callers=2),  # the real one
        ]
    )
    client = _available_client()
    monkeypatch.setattr(ApkClient, "_parsed", lambda self, path: parsed)
    payload = client.xrefs(tmp_path / "app.apk", "decrypt")
    assert payload["count"] == 2
    assert payload["has_more"] is False


# ---------------------------------------------------------------------------
# scan-cap honesty: "we stopped collecting before the end".
# ---------------------------------------------------------------------------
def test_classes_reports_when_the_scan_was_capped(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """scan_capped tells a reader the total is a floor, not the full count.

    The collect loop stops at an internal ceiling well below the page size so a
    pathological DEX cannot be walked forever; when it stops early the flag must
    say so, or a caller reads total as the whole class list.
    """
    monkeypatch.setattr("headless_re_mcp.backends.apk.client._MAX_CLASSES_COLLECT", 1)
    parsed = _Parsed(classes=[_Klass("Lcom/app/A;"), _Klass("Lcom/app/B;")])
    client = _available_client()
    monkeypatch.setattr(ApkClient, "_parsed", lambda self, path: parsed)
    payload = client.classes(tmp_path / "app.apk")
    assert payload["scan_capped"] is True
    assert payload["total"] == 1


def test_methods_reports_when_the_scan_was_capped(
    tmp_path: Path, monkeypatch: Any
) -> None:
    monkeypatch.setattr("headless_re_mcp.backends.apk.client._MAX_METHODS_COLLECT", 1)
    parsed = _Parsed(classes=[_Klass("Lcom/app/Foo;", methods=3)])
    client = _available_client()
    monkeypatch.setattr(ApkClient, "_parsed", lambda self, path: parsed)
    payload = client.methods(tmp_path / "app.apk", "com.app.Foo")
    assert payload["scan_capped"] is True
    assert payload["total"] == 1


def test_strings_reports_when_the_scan_was_capped(
    tmp_path: Path, monkeypatch: Any
) -> None:
    monkeypatch.setattr("headless_re_mcp.backends.apk.client._MAX_STRINGS_COLLECT", 1)
    parsed = _Parsed(strings=["alpha", "bravo", "charlie"])
    client = _available_client()
    monkeypatch.setattr(ApkClient, "_parsed", lambda self, path: parsed)
    payload = client.strings(tmp_path / "app.apk")
    assert payload["scan_capped"] is True
    assert payload["total"] == 1


def test_native_libs_lists_an_abi_less_lib_without_recording_an_abi(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A lib/ entry without an abi segment is still listed, contributing no abi."""

    class _Apk:
        def get_files(self) -> list[str]:
            return ["lib/note.txt", "lib/arm64-v8a/libfoo.so", "res/x.png"]

    client = _available_client()
    monkeypatch.setattr(ApkClient, "_apk", lambda self, path: _Apk())
    payload = client.native_libs(tmp_path / "app.apk")
    assert payload["native_libs"] == ["lib/arm64-v8a/libfoo.so", "lib/note.txt"]
    assert payload["abis"] == ["arm64-v8a"]


# ---------------------------------------------------------------------------
# _dotted_to_smali.
# ---------------------------------------------------------------------------
def test_dotted_to_smali_leaves_an_already_smali_name_alone() -> None:
    assert _dotted_to_smali("Lcom/example/Foo;") == "Lcom/example/Foo;"
    assert _dotted_to_smali("com.example.Foo") == "Lcom/example/Foo;"
