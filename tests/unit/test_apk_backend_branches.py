"""APK static (androguard) backend guard, shaping, and honesty branches.

The live paths (parse a real app's DEX) need a sizeable sample and live in the
Android gate. Everything here drives the shaping and caching logic through fakes
so the decisions that hold on every machine run on every machine: the cap/`has_more`
accounting, the "this zip is not an APK" refusal, the page clamping that keeps the
agent/OpenAI transports from tail-slicing the DEX, and the per-version fallbacks
that must degrade rather than raise.
"""

from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from headless_re_mcp.backends.apk import client as apk_client
from headless_re_mcp.backends.apk.client import (
    _MAX_MANIFEST_CHARS,
    ApkClient,
    ApkError,
    _cap_names,
    _clamp_page,
    _dotted_to_smali,
)

MP = pytest.MonkeyPatch


# ----------------------------------------------------------------------------
# Fakes for the parsed-APK objects
# ----------------------------------------------------------------------------
class _Axml:
    def __init__(self, xml: bytes) -> None:
        self._xml = xml

    def get_xml(self) -> bytes:
        return self._xml


class _RaisingStr:
    def __str__(self) -> str:
        raise RuntimeError("subject encoding failed")


class _FakeApk:
    def __init__(self, **over: Any) -> None:
        self._d: dict[str, Any] = {
            "package": "com.example.app",
            "version_name": "1.0",
            "version_code": "10",
            "min_sdk": "24",
            "target_sdk": "34",
            "main_activity": "com.example.app.Main",
            "permissions": ["android.permission.INTERNET"],
            "requested_permissions": ["android.permission.INTERNET"],
            "files": ["classes.dex", "lib/arm64-v8a/libx.so", "lib/x86/liby.so"],
            "manifest_xml": b"<manifest/>",
            "signature_names": ["META-INF/CERT.RSA"],
            "certificates": [],
            "activities": ["com.example.app.Main"],
            "services": [],
            "receivers": [],
            "providers": [],
        }
        self._d.update(over)

    def get_package(self) -> Any:
        return self._d["package"]

    def get_androidversion_name(self) -> Any:
        return self._d["version_name"]

    def get_androidversion_code(self) -> Any:
        return self._d["version_code"]

    def get_min_sdk_version(self) -> Any:
        return self._d["min_sdk"]

    def get_target_sdk_version(self) -> Any:
        return self._d["target_sdk"]

    def get_main_activity(self) -> Any:
        return self._d["main_activity"]

    def get_permissions(self) -> Any:
        return self._d["permissions"]

    def get_requested_permissions(self) -> Any:
        req = self._d["requested_permissions"]
        if isinstance(req, BaseException):
            raise req
        return req

    def get_files(self) -> Any:
        return self._d["files"]

    def get_android_manifest_axml(self) -> Any:
        xml = self._d["manifest_xml"]
        if isinstance(xml, BaseException):
            raise xml
        return _Axml(xml)

    def get_signature_names(self) -> Any:
        names = self._d["signature_names"]
        if isinstance(names, BaseException):
            raise names
        return names

    def get_certificates(self) -> Any:
        return self._d["certificates"]

    def get_activities(self) -> Any:
        return self._d["activities"]

    def get_services(self) -> Any:
        return self._d["services"]

    def get_receivers(self) -> Any:
        return self._d["receivers"]

    def get_providers(self) -> Any:
        return self._d["providers"]


class _FakeMethod:
    def __init__(self, name: str, *, external: bool = False, callers: int = 0) -> None:
        self.name = name
        self.descriptor = "()V"
        self.access = "public"
        self._external = external
        self._callers = callers

    def is_external(self) -> bool:
        return self._external

    def get_xref_from(self) -> list[tuple[object, Any, int]]:
        call = SimpleNamespace(class_name="Lcom/example/Caller;", name="invoke")
        return [(None, call, i) for i in range(self._callers)]


class _FakeClass:
    def __init__(
        self, name: str, *, external: bool = False, methods: list[_FakeMethod] | None = None
    ) -> None:
        self.name = name
        self._external = external
        self._methods = methods or []

    def is_external(self) -> bool:
        return self._external

    def get_methods(self) -> list[_FakeMethod]:
        return self._methods


class _FakeString:
    def __init__(self, value: str) -> None:
        self._value = value

    def get_value(self) -> str:
        return self._value


class _FakeAnalysis:
    def __init__(
        self,
        *,
        classes: list[_FakeClass] | None = None,
        strings: list[_FakeString] | None = None,
        methods: list[_FakeMethod] | None = None,
    ) -> None:
        self._classes = classes or []
        self._strings = strings or []
        self._methods = methods or []

    def get_classes(self) -> list[_FakeClass]:
        return self._classes

    def get_strings(self) -> list[_FakeString]:
        return self._strings

    def get_methods(self) -> list[_FakeMethod]:
        return self._methods


def _with_apk(monkeypatch: MP, apk: _FakeApk) -> ApkClient:
    client = ApkClient()
    client._available = True
    monkeypatch.setattr(ApkClient, "_apk", lambda self, path: apk)
    return client


def _with_parsed(monkeypatch: MP, analysis: _FakeAnalysis) -> ApkClient:
    client = ApkClient()
    client._available = True
    parsed = SimpleNamespace(apk=_FakeApk(), analysis=analysis, _dex=None)
    monkeypatch.setattr(ApkClient, "_parsed", lambda self, path: parsed)
    return client


APK = Path("/tmp/does-not-matter.apk")


# ----------------------------------------------------------------------------
# Pure helpers
# ----------------------------------------------------------------------------
class TestHelpers:
    def test_cap_names_sorts_and_flags_more(self) -> None:
        # The cap is applied before the sort, so it is the first ``limit`` items
        # that survive and are then ordered -- here "c","a" -> "a","c".
        names, more = _cap_names(["c", "a", "b"], 2)
        assert names == ["a", "c"]
        assert more is True
        names, more = _cap_names(["a"], 5)
        assert names == ["a"] and more is False
        assert _cap_names(None, 5) == ([], False)

    def test_clamp_page_rejects_negatives_and_caps(self) -> None:
        assert _clamp_page(-5, 10, max_limit=100) == (0, 10)
        assert _clamp_page(3, -1, max_limit=100) == (3, 1)
        assert _clamp_page(0, 10_000, max_limit=1000) == (0, 1000)

    def test_dotted_to_smali_both_forms(self) -> None:
        assert _dotted_to_smali("com.example.Foo") == "Lcom/example/Foo;"
        assert _dotted_to_smali("Lcom/example/Foo;") == "Lcom/example/Foo;"


# ----------------------------------------------------------------------------
# Availability / require / release / cache
# ----------------------------------------------------------------------------
class TestAvailabilityAndCache:
    def test_import_failure_degrades(self, monkeypatch: MP) -> None:
        monkeypatch.setitem(sys.modules, "androguard", None)
        client = ApkClient()
        assert client.available is False
        with pytest.raises(ApkError) as info:
            client._require(APK)
        assert info.value.code == "capability_unavailable"

    def test_require_missing_file_is_not_found(self, tmp_path: Path) -> None:
        client = ApkClient()
        client._available = True
        with pytest.raises(ApkError) as info:
            client._require(tmp_path / "missing.apk")
        assert info.value.code == "not_found"

    def test_release_handles_unresolvable_path(self) -> None:
        class _BadPath:
            def expanduser(self) -> Any:
                return self

            def resolve(self) -> Any:
                raise OSError("cannot resolve")

        assert ApkClient.release(_BadPath()) is False  # type: ignore[arg-type]

    def test_light_cache_parse_hit_and_evict(self, monkeypatch: MP, tmp_path: Path) -> None:
        parsed_paths: list[str] = []

        class _FakeAPKClass:
            def __init__(self, path: str) -> None:
                parsed_paths.append(path)
                self.path = path

            def get_package(self) -> str:
                return "com.example.app"

        monkeypatch.setattr("androguard.core.apk.APK", _FakeAPKClass, raising=False)
        ApkClient._light_cache.clear()
        client = ApkClient()
        client._available = True

        apks = []
        for i in range(5):
            p = tmp_path / f"app{i}.apk"
            p.write_bytes(b"PK\x03\x04data")
            apks.append(p)

        first = client._apk(apks[0])
        again = client._apk(apks[0])  # cache hit: no second parse
        assert first is again
        assert parsed_paths.count(str(apks[0].resolve())) == 1

        for p in apks[1:]:
            client._apk(p)
        # Cache is capped at 4, so the oldest key was evicted.
        assert len(ApkClient._light_cache) <= 4
        # Releasing an unknown path returns False; a cached one returns True.
        assert client.release(tmp_path / "nope.apk") is False
        assert client.release(apks[-1]) is True

    def test_light_parse_failure_is_backend_error(self, monkeypatch: MP, tmp_path: Path) -> None:
        class _Boom:
            def __init__(self, path: str) -> None:
                raise RuntimeError("corrupt zip")

        monkeypatch.setattr("androguard.core.apk.APK", _Boom, raising=False)
        ApkClient._light_cache.clear()
        client = ApkClient()
        client._available = True
        p = tmp_path / "bad.apk"
        p.write_bytes(b"PK")
        with pytest.raises(ApkError) as info:
            client._apk(p)
        assert info.value.code == "backend_error"

    def test_full_parse_hit_and_failure(self, monkeypatch: MP, tmp_path: Path) -> None:
        analyze_calls: list[str] = []

        def fake_analyze(path: str) -> tuple[Any, Any, Any]:
            analyze_calls.append(path)
            return _FakeApk(), None, _FakeAnalysis()

        monkeypatch.setattr("androguard.misc.AnalyzeAPK", fake_analyze, raising=False)
        ApkClient._full_cache.clear()
        client = ApkClient()
        client._available = True
        p = tmp_path / "app.apk"
        p.write_bytes(b"PK\x03\x04")
        one = client._parsed(p)
        two = client._parsed(p)
        assert one is two
        assert len(analyze_calls) == 1

        def boom(path: str) -> tuple[Any, Any, Any]:
            raise RuntimeError("dex parse failed")

        monkeypatch.setattr("androguard.misc.AnalyzeAPK", boom, raising=False)
        ApkClient._full_cache.clear()
        with pytest.raises(ApkError) as info:
            client._parsed(p)
        assert info.value.code == "backend_error"

    def test_full_cache_evicts_oldest(self, monkeypatch: MP, tmp_path: Path) -> None:
        monkeypatch.setattr(
            "androguard.misc.AnalyzeAPK",
            lambda path: (_FakeApk(), None, _FakeAnalysis()),
            raising=False,
        )
        ApkClient._full_cache.clear()
        client = ApkClient()
        client._available = True
        for i in range(5):
            p = tmp_path / f"a{i}.apk"
            p.write_bytes(b"PK\x03\x04")
            client._parsed(p)
        assert len(ApkClient._full_cache) <= 4


# ----------------------------------------------------------------------------
# Manifest-level readers
# ----------------------------------------------------------------------------
class TestManifestReaders:
    def test_open_reports_package_and_abis(self, monkeypatch: MP) -> None:
        client = _with_apk(monkeypatch, _FakeApk())
        result = client.open(APK)
        assert result["package"] == "com.example.app"
        assert result["native_abis"] == ["arm64-v8a", "x86"]

    def test_open_without_package_is_backend_error(self, monkeypatch: MP) -> None:
        client = _with_apk(monkeypatch, _FakeApk(package=None))
        with pytest.raises(ApkError) as info:
            client.open(APK)
        assert info.value.code == "backend_error"

    def test_manifest_truncates(self, monkeypatch: MP) -> None:
        big = ("<x/>" * (_MAX_MANIFEST_CHARS)).encode()
        client = _with_apk(monkeypatch, _FakeApk(manifest_xml=big))
        result = client.manifest(APK)
        assert result["truncated"] is True
        assert len(result["manifest_xml"]) == _MAX_MANIFEST_CHARS

    def test_manifest_decode_failure_is_backend_error(self, monkeypatch: MP) -> None:
        client = _with_apk(monkeypatch, _FakeApk(manifest_xml=RuntimeError("no axml")))
        with pytest.raises(ApkError) as info:
            client.manifest(APK)
        assert info.value.code == "backend_error"

    def test_permissions_requested_fallback(self, monkeypatch: MP) -> None:
        # Older androguard lacks get_requested_permissions; the reader must fall
        # back to the declared set rather than raising.
        apk = _FakeApk(requested_permissions=AttributeError("no such method"))
        client = _with_apk(monkeypatch, apk)
        result = client.permissions(APK)
        assert result["requested_permissions"] == result["permissions"]

    def test_certificates_shapes_and_flags(self, monkeypatch: MP) -> None:
        good = SimpleNamespace(
            subject="CN=Test", issuer="CN=Test", serial_number=1, sha256_fingerprint="ab"
        )
        client = _with_apk(monkeypatch, _FakeApk(certificates=[good]))
        result = client.certificates(APK)
        assert result["v1_signed"] is True
        assert result["certificates"][0]["sha256"] == "ab"

    def test_certificates_signature_name_failure_degrades(self, monkeypatch: MP) -> None:
        apk = _FakeApk(signature_names=RuntimeError("v2 only"), certificates=[])
        client = _with_apk(monkeypatch, apk)
        result = client.certificates(APK)
        assert result["signature_files"] == []
        assert result["v1_signed"] is False

    def test_certificates_cap_and_bad_cert_are_handled(self, monkeypatch: MP) -> None:
        names = [f"META-INF/C{i}.RSA" for i in range(40)]
        certs: list[Any] = [SimpleNamespace(subject=_RaisingStr())]  # skipped via continue
        certs += [
            SimpleNamespace(subject="s", issuer="i", serial_number=i, sha256_fingerprint="x")
            for i in range(40)
        ]
        client = _with_apk(monkeypatch, _FakeApk(signature_names=names, certificates=certs))
        result = client.certificates(APK)
        assert result["has_more"] is True
        assert len(result["signature_files"]) == 32

    def test_components_listed(self, monkeypatch: MP) -> None:
        apk = _FakeApk(services=["s.Svc"], receivers=["r.Rec"], providers=["p.Prov"])
        client = _with_apk(monkeypatch, apk)
        result = client.components(APK)
        assert result["services"] == ["s.Svc"]
        assert result["main_activity"] == "com.example.app.Main"

    def test_native_libs_caps_but_still_collects_abis(self, monkeypatch: MP) -> None:
        files = [f"lib/arm64-v8a/lib{i}.so" for i in range(apk_client._MAX_NATIVE_LIBS + 5)]
        files.append("lib/x86/liby.so")
        # A lib/ path with too few segments has no ABI and must be skipped for
        # the abi set without crashing on the missing index.
        files.append("lib/stray-no-abi")
        client = _with_apk(monkeypatch, _FakeApk(files=files))
        result = client.native_libs(APK)
        assert result["has_more"] is True
        assert set(result["abis"]) == {"arm64-v8a", "x86"}
        assert result["count"] == apk_client._MAX_NATIVE_LIBS


# ----------------------------------------------------------------------------
# DEX readers
# ----------------------------------------------------------------------------
class TestDexReaders:
    def test_classes_skip_external_and_paginate(self, monkeypatch: MP) -> None:
        classes = [_FakeClass(f"Lcom/x/C{i};") for i in range(3)]
        classes.append(_FakeClass("Lext/Ext;", external=True))
        client = _with_parsed(monkeypatch, _FakeAnalysis(classes=classes))
        result = client.classes(APK, offset=0, limit=2)
        assert result["total"] == 3  # external excluded
        assert result["count"] == 2
        assert result["has_more"] is True

    def test_methods_requires_class_name(self, monkeypatch: MP) -> None:
        client = _with_parsed(monkeypatch, _FakeAnalysis())
        with pytest.raises(ApkError) as info:
            client.methods(APK, "   ")
        assert info.value.code == "invalid_params"

    def test_methods_unknown_class_is_not_found(self, monkeypatch: MP) -> None:
        client = _with_parsed(monkeypatch, _FakeAnalysis(classes=[_FakeClass("Lcom/x/A;")]))
        with pytest.raises(ApkError) as info:
            client.methods(APK, "com.x.Missing")
        assert info.value.code == "not_found"

    def test_methods_resolve_via_dotted_or_smali(self, monkeypatch: MP) -> None:
        klass = _FakeClass(
            "Lcom/x/A;",
            methods=[_FakeMethod("decrypt"), _FakeMethod("encrypt")],
        )
        client = _with_parsed(monkeypatch, _FakeAnalysis(classes=[klass]))
        dotted = client.methods(APK, "com.x.A")
        assert dotted["count"] == 2
        smali = client.methods(APK, "Lcom/x/A;")
        assert smali["class_name"] == "Lcom/x/A;"

    def test_strings_dedup_and_paginate(self, monkeypatch: MP) -> None:
        strings = [_FakeString("b"), _FakeString("a"), _FakeString("a")]
        client = _with_parsed(monkeypatch, _FakeAnalysis(strings=strings))
        result = client.strings(APK, offset=0, limit=1)
        assert result["total"] == 2  # deduped
        assert result["strings"] == ["a"]
        assert result["has_more"] is True

    def test_xrefs_requires_method_name(self, monkeypatch: MP) -> None:
        client = _with_parsed(monkeypatch, _FakeAnalysis())
        with pytest.raises(ApkError) as info:
            client.xrefs(APK, "")
        assert info.value.code == "invalid_params"

    def test_xrefs_skip_external_and_report_more(self, monkeypatch: MP) -> None:
        methods = [
            _FakeMethod("decrypt", external=True, callers=3),  # skipped
            _FakeMethod("decrypt", callers=25),
        ]
        client = _with_parsed(monkeypatch, _FakeAnalysis(methods=methods))
        result = client.xrefs(APK, "decrypt", limit=10)
        assert result["count"] == 10
        assert result["has_more"] is True

    def test_xrefs_complete_is_not_partial(self, monkeypatch: MP) -> None:
        client = _with_parsed(
            monkeypatch, _FakeAnalysis(methods=[_FakeMethod("decrypt", callers=3)])
        )
        result = client.xrefs(APK, "decrypt", limit=10)
        assert result["count"] == 3
        assert result["has_more"] is False
