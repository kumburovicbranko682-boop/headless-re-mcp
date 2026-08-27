"""apk.class_info returns one class's hierarchy and shape from androguard."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from headless_re_mcp.backends.apk.client import ApkClient, ApkError
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


class _FakeVmClass:
    def __init__(self, access: str) -> None:
        self._access = access

    def get_access_flags_string(self) -> str:
        return self._access


class _FakeExternalVmClass:
    """External classes expose no flag string, like androguard's ExternalClass."""


class _FakeClass:
    def __init__(
        self,
        name: str,
        *,
        extends: str = "Ljava/lang/Object;",
        implements: list[str] | None = None,
        external: bool = False,
        android_api: bool = False,
        num_methods: int = 0,
        num_fields: int = 0,
        access: str = "public",
    ) -> None:
        self.name = name
        self.extends = extends
        self.implements = implements or []
        self._external = external
        self._android_api = android_api
        self._num_methods = num_methods
        self._num_fields = num_fields
        self._access = access

    def is_external(self) -> bool:
        return self._external

    def is_android_api(self) -> bool:
        return self._android_api

    def get_nb_methods(self) -> int:
        return self._num_methods

    def get_fields(self) -> list[object]:
        return [object() for _ in range(self._num_fields)]

    def get_vm_class(self) -> object:
        if self._external:
            return _FakeExternalVmClass()
        return _FakeVmClass(self._access)


class _FakeParsed:
    def __init__(self, classes: list[_FakeClass]) -> None:
        self.analysis = self
        self._classes = classes

    def get_classes(self) -> list[_FakeClass]:
        return list(self._classes)


def _client(classes: list[_FakeClass]) -> ApkClient:
    client = ApkClient()
    client._parsed = lambda _path: _FakeParsed(classes)  # type: ignore[method-assign, assignment, return-value]
    return client


def test_class_info_reports_hierarchy_and_shape() -> None:
    """extends/implements/flags/counts come straight from androguard.

    A custom Activity that implements two interfaces should report its
    superclass, both interfaces sorted, the flag string, both booleans false,
    and the method and field counts.
    """
    target = _FakeClass(
        "Lcom/example/MainActivity;",
        extends="Landroid/app/Activity;",
        implements=["Landroid/view/View$OnClickListener;", "Ljava/lang/Runnable;"],
        num_methods=7,
        num_fields=3,
        access="public final",
    )
    other = _FakeClass("Lcom/example/Other;")
    payload = _client([target, other]).class_info(Path("dummy.apk"), "Lcom/example/MainActivity;")
    assert payload["class_name"] == "Lcom/example/MainActivity;"
    assert payload["superclass"] == "Landroid/app/Activity;"
    assert payload["interfaces"] == [
        "Landroid/view/View$OnClickListener;",
        "Ljava/lang/Runnable;",
    ]
    assert payload["interfaces_count"] == 2
    assert payload["interfaces_truncated"] is False
    assert payload["access"] == "public final"
    assert payload["is_external"] is False
    assert payload["is_android_api"] is False
    assert payload["num_methods"] == 7
    assert payload["num_fields"] == 3


def test_class_info_accepts_dotted_name() -> None:
    """A dotted class name resolves to the smali form androguard stores."""
    target = _FakeClass("Lcom/example/MainActivity;", num_methods=1)
    payload = _client([target]).class_info(Path("dummy.apk"), "com.example.MainActivity")
    assert payload["class_name"] == "Lcom/example/MainActivity;"
    assert payload["num_methods"] == 1


def test_class_info_external_class_has_no_access_string() -> None:
    """External classes report Object as parent, no interfaces, empty access."""
    target = _FakeClass(
        "Lcom/thirdparty/Sdk;",
        extends="Ljava/lang/Object;",
        implements=[],
        external=True,
        android_api=True,
    )
    payload = _client([target]).class_info(Path("dummy.apk"), "Lcom/thirdparty/Sdk;")
    assert payload["superclass"] == "Ljava/lang/Object;"
    assert payload["interfaces"] == []
    assert payload["interfaces_count"] == 0
    assert payload["access"] == ""
    assert payload["is_external"] is True
    assert payload["is_android_api"] is True


def test_class_info_caps_interfaces_and_reports_true_total() -> None:
    """Many interfaces are sorted and capped while the true count is kept."""
    implements = [f"Lp/I{index:04d};" for index in range(300)]
    target = _FakeClass("Lcom/example/Wide;", implements=implements)
    payload = _client([target]).class_info(Path("dummy.apk"), "Lcom/example/Wide;")
    assert len(payload["interfaces"]) == 256
    assert payload["interfaces"] == sorted(implements)[:256]
    assert payload["interfaces_count"] == 300
    assert payload["interfaces_truncated"] is True


def test_class_info_unknown_class_is_not_found() -> None:
    client = _client([_FakeClass("Lcom/example/Only;")])
    with pytest.raises(ApkError) as excinfo:
        client.class_info(Path("dummy.apk"), "Lcom/example/Missing;")
    assert excinfo.value.code == "not_found"


def test_class_info_requires_class_name() -> None:
    client = _client([_FakeClass("Lcom/example/Only;")])
    with pytest.raises(ApkError) as excinfo:
        client.class_info(Path("dummy.apk"), "   ")
    assert excinfo.value.code == "invalid_params"


def test_class_info_docstring_names_shape() -> None:
    doc = _tool_docstring("apk.class_info")
    assert "superclass" in doc
    assert "interfaces" in doc
    assert "num_methods" in doc
    assert "is_external" in doc
