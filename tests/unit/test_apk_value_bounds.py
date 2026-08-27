"""apk.* enumerations must clip pathological APK-derived strings per value.

The lists are count-capped, but every row -- a class name, method descriptor,
zip entry path, component id, permission, or certificate field -- comes from
the APK under analysis, which is untrusted and often malware. A crafted DEX
type name, or a zip entry name (the format allows up to 64 KiB), can bloat a
single tool result far past what the row count suggests. ``strings()`` already
clips its values; these tests lock the sibling enumerations to the same rule
and to the ``truncated`` flag that reports it.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

from headless_re_mcp.backends.apk.client import _MAX_ABIS, _MAX_NAME_LEN, ApkClient
from headless_re_mcp.tools.apk import build_apk_tools


def _tool_docstring(name: str) -> str:
    source = Path(build_apk_tools.__code__.co_filename).read_text(encoding="utf-8")
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        for decorator in node.decorator_list:
            if not isinstance(decorator, ast.Call):
                continue
            for keyword in decorator.keywords:
                if (
                    keyword.arg == "name"
                    and isinstance(keyword.value, ast.Constant)
                    and keyword.value.value == name
                ):
                    return ast.get_docstring(node) or ""
    return ""


class _HugeFilesApk:
    def get_files(self) -> list[str]:
        # One pathological 64 KiB zip entry name plus a real one.
        return ["lib/arm64-v8a/" + "a" * (64 * 1024) + ".so", "lib/x86/libc.so"]


def test_native_libs_clips_a_hostile_entry_and_flags_it() -> None:
    """A zip entry name can be up to 64 KiB; 256 of them would be megabytes.

    Measured: the crafted entry is clipped to the per-value length cap, the
    reply sets truncated, and a real lib beside it is returned intact.
    """
    client = ApkClient()
    client._apk = lambda _path: _HugeFilesApk()  # type: ignore[method-assign]
    payload = client.native_libs(Path("dummy.apk"))
    assert payload["truncated"] is True
    assert any(len(name) == _MAX_NAME_LEN for name in payload["native_libs"])
    assert "lib/x86/libc.so" in payload["native_libs"]
    assert payload["abis"] == ["arm64-v8a", "x86"]
    assert "truncated" in _tool_docstring("apk.native_libs")


class _NormalFilesApk:
    def get_files(self) -> list[str]:
        return ["lib/arm64-v8a/libfoo.so", "classes.dex"]


def test_native_libs_leaves_a_normal_apk_untruncated() -> None:
    """An ordinary APK is unchanged: truncated is false, paths intact."""
    client = ApkClient()
    client._apk = lambda _path: _NormalFilesApk()  # type: ignore[method-assign]
    payload = client.native_libs(Path("dummy.apk"))
    assert payload["truncated"] is False
    assert payload["native_libs"] == ["lib/arm64-v8a/libfoo.so"]


class _ManyAbisApk:
    """A crafted package with more distinct lib/<abi>/ prefixes than any device.

    open() reads identity beside the ABI set; native_libs() reads only files, so
    the fake answers both surfaces.
    """

    def __init__(self, count: int) -> None:
        self._count = count

    def get_package(self) -> str:
        return "com.x"

    def get_androidversion_name(self) -> str:
        return "1.0"

    def get_androidversion_code(self) -> str:
        return "1"

    def get_min_sdk_version(self) -> str:
        return "21"

    def get_target_sdk_version(self) -> str:
        return "33"

    def get_main_activity(self) -> str:
        return "com.x.Main"

    def get_permissions(self) -> list[str]:
        return ["A"]

    def get_files(self) -> list[str]:
        return [f"lib/abi{i:05d}/libx.so" for i in range(self._count)]


def test_native_libs_caps_a_flood_of_distinct_abis_and_flags_it() -> None:
    """The ABI set is built from every lib/ path, not the paged lib list.

    Measured: a package with 200 distinct lib/<abi>/ prefixes returns exactly
    _MAX_ABIS ABIs and sets truncated, so the set cannot grow with the archive.
    """
    client = ApkClient()
    client._apk = lambda _path: _ManyAbisApk(200)  # type: ignore[method-assign]
    payload = client.native_libs(Path("dummy.apk"))
    assert len(payload["abis"]) == _MAX_ABIS
    assert payload["truncated"] is True


def test_open_caps_a_flood_of_distinct_abis_and_flags_it() -> None:
    """open() computes the same ABI set for identity; it is bounded the same way.

    Measured: 200 distinct prefixes yield _MAX_ABIS ABIs and set
    native_abis_truncated.
    """
    client = ApkClient()
    client._available = True
    client._apk = lambda _path: _ManyAbisApk(200)  # type: ignore[method-assign]
    payload = client.open(Path("dummy.apk"))
    assert len(payload["native_abis"]) == _MAX_ABIS
    assert payload["native_abis_truncated"] is True


def test_open_leaves_a_normal_apk_abi_set_unflagged() -> None:
    """A real handful of ABIs is returned whole with the flag clear."""
    client = ApkClient()
    client._available = True
    client._apk = lambda _path: _ManyAbisApk(3)  # type: ignore[method-assign]
    payload = client.open(Path("dummy.apk"))
    assert len(payload["native_abis"]) == 3
    assert payload["native_abis_truncated"] is False


class _PermApk:
    def __init__(self, permissions: list[str]) -> None:
        self._permissions = permissions

    def get_permissions(self) -> list[str]:
        return self._permissions

    def get_requested_permissions(self) -> list[str]:
        return self._permissions


def test_permissions_clips_a_hostile_name_and_flags_it() -> None:
    """A manifest permission id is attacker-authored text.

    Measured: a 9 KiB permission name is clipped to the per-value length cap,
    the reply sets truncated, and a real permission beside it is intact.
    """
    client = ApkClient()
    client._apk = lambda _path: _PermApk(  # type: ignore[method-assign]
        ["p" * 9000, "android.permission.INTERNET"]
    )
    payload = client.permissions(Path("dummy.apk"))
    assert payload["truncated"] is True
    assert any(len(name) == _MAX_NAME_LEN for name in payload["permissions"])
    assert "android.permission.INTERNET" in payload["permissions"]
    assert "truncated" in _tool_docstring("apk.permissions")


class _ComponentApk:
    def get_activities(self) -> list[str]:
        return ["a" * 9000, "com.example.MainActivity"]

    def get_services(self) -> list[str]:
        return ["com.example.Svc"]

    def get_receivers(self) -> list[str]:
        return []

    def get_providers(self) -> list[str]:
        return []

    def get_main_activity(self) -> str:
        return "com.example.MainActivity"


def test_components_clips_a_hostile_activity_and_flags_it() -> None:
    """Component ids come straight from the manifest.

    Measured: a 9 KiB activity name is clipped to the per-value length cap,
    the reply sets truncated, and the real component beside it is intact.
    """
    client = ApkClient()
    client._apk = lambda _path: _ComponentApk()  # type: ignore[method-assign]
    payload = client.components(Path("dummy.apk"))
    assert payload["truncated"] is True
    assert any(len(name) == _MAX_NAME_LEN for name in payload["activities"])
    assert "com.example.MainActivity" in payload["activities"]
    assert payload["services"] == ["com.example.Svc"]
    assert "truncated" in _tool_docstring("apk.components")


class _Cert:
    def __init__(self, subject: str, issuer: str, serial: str) -> None:
        self.subject = subject
        self.issuer = issuer
        self.serial_number = serial
        self.sha256_fingerprint = "ab" * 32


class _CertApk:
    def get_signature_names(self) -> list[str]:
        return ["META-INF/" + "s" * 9000 + ".RSA"]

    def get_certificates(self) -> list[_Cert]:
        return [_Cert("CN=" + "x" * 9000, "CN=Real Issuer", "12345")]


def test_certificates_clips_hostile_fields_and_flags_them() -> None:
    """A certificate subject/issuer DN and a v1 signature name are crafted text.

    Measured: a 9 KiB subject and a 9 KiB signature-file name are each clipped
    to the per-value length cap, the reply sets truncated, and the real issuer
    beside them is intact.
    """
    client = ApkClient()
    client._apk = lambda _path: _CertApk()  # type: ignore[method-assign]
    payload = client.certificates(Path("dummy.apk"))
    assert payload["truncated"] is True
    assert len(payload["certificates"][0]["subject"]) == _MAX_NAME_LEN
    assert payload["certificates"][0]["issuer"] == "CN=Real Issuer"
    assert any(len(name) == _MAX_NAME_LEN for name in payload["signature_files"])
    assert "truncated" in _tool_docstring("apk.certificates")


class _Klass:
    def __init__(self, name: str) -> None:
        self.name = name

    def is_external(self) -> bool:
        return False


class _Method:
    def __init__(self, name: str, descriptor: str, access: str) -> None:
        self.name = name
        self.descriptor = descriptor
        self.access = access


class _MethodKlass(_Klass):
    def __init__(self, name: str, methods: list[_Method]) -> None:
        super().__init__(name)
        self._methods = methods

    def get_methods(self) -> list[_Method]:
        return self._methods


class _Parsed:
    def __init__(self, classes: list[Any]) -> None:
        self.analysis = self
        self._classes = classes

    def get_classes(self) -> list[Any]:
        return self._classes


def test_classes_clips_a_hostile_class_name_and_flags_it() -> None:
    """A DEX type name is attacker-authored and can be pathologically long.

    Measured: a 9 KiB class name is clipped to the per-value length cap, the
    reply sets truncated, and a real class beside it is intact.
    """
    client = ApkClient()
    client._parsed = lambda _path: _Parsed(  # type: ignore[method-assign]
        [_Klass("L" + "z" * 9000 + ";"), _Klass("Lcom/example/Foo;")]
    )
    payload = client.classes(Path("dummy.apk"), offset=0, limit=100)
    assert payload["truncated"] is True
    assert any(len(name) == _MAX_NAME_LEN for name in payload["classes"])
    assert "Lcom/example/Foo;" in payload["classes"]
    assert "truncated" in _tool_docstring("apk.classes")


def test_methods_clips_a_hostile_descriptor_and_flags_it() -> None:
    """A method name/descriptor/access string comes from the DEX.

    Measured: a 9 KiB descriptor is clipped to the per-value length cap, the
    reply sets truncated, and the real method name beside it is intact.
    """
    client = ApkClient()
    klass = _MethodKlass(
        "Lcom/example/Foo;",
        [
            _Method("bar", "(" + "I" * 9000 + ")V", "public"),
            _Method("baz", "()V", "private"),
        ],
    )
    client._parsed = lambda _path: _Parsed([klass])  # type: ignore[method-assign]
    payload = client.methods(Path("dummy.apk"), "Lcom/example/Foo;", offset=0, limit=100)
    assert payload["truncated"] is True
    assert any(len(m["descriptor"]) == _MAX_NAME_LEN for m in payload["methods"])
    assert any(m["name"] == "baz" for m in payload["methods"])
    assert "truncated" in _tool_docstring("apk.methods")


class _Call:
    def __init__(self, class_name: str, name: str) -> None:
        self.class_name = class_name
        self.name = name


class _XrefMethod:
    def __init__(self, name: str, callers: list[_Call]) -> None:
        self.name = name
        self._callers = callers

    def is_external(self) -> bool:
        return False

    def get_xref_from(self) -> list[tuple[Any, _Call, Any]]:
        return [(None, call, None) for call in self._callers]


class _XrefParsed:
    def __init__(self, methods: list[_XrefMethod]) -> None:
        self.analysis = self
        self._methods = methods

    def get_methods(self) -> list[_XrefMethod]:
        return self._methods


def test_xrefs_clips_a_hostile_caller_and_flags_it() -> None:
    """A caller's class/method name is DEX text like any other.

    Measured: a 9 KiB caller class name is clipped to the per-value length
    cap, the reply sets truncated, and a real caller beside it is intact.
    """
    client = ApkClient()
    method = _XrefMethod(
        "target",
        [_Call("L" + "q" * 9000 + ";", "callerA"), _Call("Lcom/example/Bar;", "callerB")],
    )
    client._parsed = lambda _path: _XrefParsed([method])  # type: ignore[method-assign]
    payload = client.xrefs(Path("dummy.apk"), "target", limit=100)
    assert payload["truncated"] is True
    assert any(len(caller["class"]) == _MAX_NAME_LEN for caller in payload["callers"])
    assert any(caller["class"] == "Lcom/example/Bar;" for caller in payload["callers"])
    assert "truncated" in _tool_docstring("apk.xrefs")
