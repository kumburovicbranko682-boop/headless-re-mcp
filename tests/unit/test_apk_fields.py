"""apk tool descriptions must name the fields the backends return."""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.apk.client import _MAX_MANIFEST_CHARS, ApkClient, ApkError
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


class _FakeCall:
    def __init__(self, index: int) -> None:
        self.class_name = f"Lcom/example/Caller{index};"
        self.name = "invoke"


class _FakeMethod:
    def __init__(self, name: str, callers: int) -> None:
        self.name = name
        self._callers = callers

    def is_external(self) -> bool:
        return False

    def get_xref_from(self) -> list[tuple[object, _FakeCall, int]]:
        return [(None, _FakeCall(index), index) for index in range(self._callers)]


class _FakeParsed:
    def __init__(self, methods: list[_FakeMethod]) -> None:
        self.analysis = self
        self._methods = methods

    def get_methods(self) -> list[_FakeMethod]:
        return self._methods


def test_apk_xrefs_puts_the_list_in_callers_and_says_when_it_stopped(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """The catalog said xrefs-from and never named the payload.

    Measured: 25 callers, limit 10 -> count 10, has_more True, field is
    callers not xrefs. Looking for xrefs after a successful call reads as
    no callers, and a full page with no has_more reads as the whole list.
    """
    client = ApkClient()
    monkeypatch.setattr(
        ApkClient,
        "_parsed",
        lambda self, path: _FakeParsed([_FakeMethod("decrypt", 25)]),
    )
    payload = client.xrefs(tmp_path / "app.apk", "decrypt", limit=10)
    assert "xrefs" not in payload
    assert payload["count"] == 10
    assert len(payload["callers"]) == 10
    assert payload["has_more"] is True
    doc = _tool_docstring("apk.xrefs")
    assert "Answers with callers" in doc
    assert "has_more" in doc


def test_apk_xrefs_names_method_name_on_the_payload(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """The catalog named callers and never named the method the page is for.

    Measured: xrefs(..., 'decrypt', limit=10) -> method_name decrypt, 10
    callers. Looking for method after a successful page reads as a list
    with no target, so a later page cannot be aimed at the same name.
    """
    client = ApkClient()
    monkeypatch.setattr(
        ApkClient,
        "_parsed",
        lambda self, path: _FakeParsed([_FakeMethod("decrypt", 25)]),
    )
    payload = client.xrefs(tmp_path / "app.apk", "decrypt", limit=10)
    assert payload["method_name"] == "decrypt"
    assert "method" not in payload
    doc = " ".join(_tool_docstring("apk.xrefs").split())
    assert "callers (class and method), method_name" in doc


class _FakeDirectionalMethod(_FakeMethod):
    """A _FakeMethod that also exposes xref-to (callees), for the direction switch."""

    def __init__(self, name: str, callers: int, callees: int) -> None:
        super().__init__(name, callers)
        self._callees = callees

    def get_xref_to(self) -> list[tuple[object, _FakeCall, int]]:
        return [(None, _FakeCall(index), index) for index in range(self._callees)]


def test_apk_xrefs_callees_direction_reads_xref_to_and_answers_under_callees(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """direction=callees must read xref-to and answer under callees, not callers.

    Measured: a method with 2 callers and 3 callees -> direction callees gives
    count 3 in a callees field with no callers key and direction echoed; the
    default still gives the 2 callers in a callers field with no callees key.
    The 2-vs-3 split is what proves callees read get_xref_to, not get_xref_from.
    """
    client = ApkClient()
    monkeypatch.setattr(
        ApkClient,
        "_parsed",
        lambda self, path: _FakeParsed([_FakeDirectionalMethod("decrypt", 2, 3)]),
    )
    apk = tmp_path / "app.apk"
    callees = client.xrefs(apk, "decrypt", direction="callees")
    assert callees["direction"] == "callees"
    assert callees["count"] == 3
    assert len(callees["callees"]) == 3
    assert "callers" not in callees
    default = client.xrefs(apk, "decrypt")
    assert default["direction"] == "callers"
    assert default["count"] == 2
    assert len(default["callers"]) == 2
    assert "callees" not in default
    doc = " ".join(_tool_docstring("apk.xrefs").split())
    assert "direction" in doc
    assert "callees" in doc


def test_apk_xrefs_rejects_an_unknown_direction(tmp_path: Path, monkeypatch: Any) -> None:
    """A direction other than callers/callees is invalid_params, not a silent default."""
    client = ApkClient()
    monkeypatch.setattr(
        ApkClient,
        "_parsed",
        lambda self, path: _FakeParsed([_FakeDirectionalMethod("decrypt", 1, 1)]),
    )
    with pytest.raises(ApkError) as info:
        client.xrefs(tmp_path / "app.apk", "decrypt", direction="sideways")
    assert info.value.code == "invalid_params"


class _FakeStringRef:
    """The MethodAnalysis half of a StringAnalysis xref-from edge."""

    def __init__(self, class_name: str, name: str) -> None:
        self.class_name = class_name
        self.name = name


class _FakeStringAnalysis:
    """androguard StringAnalysis: a value plus (ClassAnalysis, MethodAnalysis) edges."""

    def __init__(self, value: str, refs: list[_FakeStringRef]) -> None:
        self._value = value
        self._refs = refs

    def get_value(self) -> str:
        return self._value

    def get_xref_from(self) -> list[tuple[object, _FakeStringRef]]:
        return [(None, ref) for ref in self._refs]


class _FakeStringParsed:
    def __init__(self, strings: list[_FakeStringAnalysis]) -> None:
        self.analysis = self
        self._strings = strings

    def get_strings(self) -> list[_FakeStringAnalysis]:
        return self._strings


def test_apk_string_xrefs_exact_lists_the_methods_that_reference_the_string(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """apk.strings says a string exists; string_xrefs says who uses it.

    Measured: the marker string is referenced by two methods and an unrelated
    string by a third; an exact query returns exactly the two under xrefs (not
    callers/results), each row carrying the class, the method, and the string
    it matched, with strings_matched 1 and the third method never appearing.
    """
    client = ApkClient()
    strings = [
        _FakeStringAnalysis(
            "https://api.example.com/login",
            [
                _FakeStringRef("Lcom/example/Net;", "connect"),
                _FakeStringRef("Lcom/example/Auth;", "login"),
            ],
        ),
        _FakeStringAnalysis("unrelated", [_FakeStringRef("Lcom/example/Other;", "noise")]),
    ]
    monkeypatch.setattr(
        ApkClient, "_parsed", lambda self, path: _FakeStringParsed(strings)
    )
    payload = client.string_xrefs(tmp_path / "app.apk", "https://api.example.com/login")
    assert "callers" not in payload
    assert "results" not in payload
    assert payload["match"] == "exact"
    assert payload["strings_matched"] == 1
    assert payload["count"] == 2
    pairs = {(row["class"], row["method"]) for row in payload["xrefs"]}
    assert pairs == {("Lcom/example/Net;", "connect"), ("Lcom/example/Auth;", "login")}
    assert all(row["string"] == "https://api.example.com/login" for row in payload["xrefs"])
    assert payload["has_more"] is False
    assert payload["scan_capped"] is False
    doc = _tool_docstring("apk.string_xrefs")
    assert "xrefs" in doc
    assert "strings_matched" in doc
    assert "scan_capped" in doc


def test_apk_string_xrefs_contains_matches_several_strings_and_labels_each_row(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """contains widens the query to any string holding the needle, labelled per row.

    Measured: two http URLs and one ftp URL; contains "http://" matches the two
    http strings (strings_matched 2), and each returned row names the specific
    string its edge belongs to so the hits stay attributable. The same needle
    matched exactly finds nothing -- no constant is literally "http://".
    """
    client = ApkClient()
    strings = [
        _FakeStringAnalysis("http://a.example/one", [_FakeStringRef("LcomA;", "a")]),
        _FakeStringAnalysis("http://b.example/two", [_FakeStringRef("LcomB;", "b")]),
        _FakeStringAnalysis("ftp://c.example/three", [_FakeStringRef("LcomC;", "c")]),
    ]
    monkeypatch.setattr(
        ApkClient, "_parsed", lambda self, path: _FakeStringParsed(strings)
    )
    apk = tmp_path / "app.apk"
    hits = client.string_xrefs(apk, "http://", contains=True)
    assert hits["match"] == "contains"
    assert hits["strings_matched"] == 2
    assert hits["count"] == 2
    by_method = {row["method"]: row["string"] for row in hits["xrefs"]}
    assert by_method == {"a": "http://a.example/one", "b": "http://b.example/two"}
    exact = client.string_xrefs(apk, "http://")
    assert exact["match"] == "exact"
    assert exact["strings_matched"] == 0
    assert exact["count"] == 0
    assert exact["xrefs"] == []
    doc = " ".join(_tool_docstring("apk.string_xrefs").split())
    assert "contains" in doc
    assert "match" in doc


def test_apk_string_xrefs_limit_caps_rows_and_flags_has_more(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A busy string caps at the limit and says the list did not end.

    Measured: 25 referencing methods, limit 10 -> count 10, has_more True,
    strings_matched still 1. A full page with no has_more would read as the
    whole reference set.
    """
    client = ApkClient()
    refs = [_FakeStringRef(f"Lcom/example/C{i};", f"m{i}") for i in range(25)]
    strings = [_FakeStringAnalysis("SECRET_KEY", refs)]
    monkeypatch.setattr(
        ApkClient, "_parsed", lambda self, path: _FakeStringParsed(strings)
    )
    payload = client.string_xrefs(tmp_path / "app.apk", "SECRET_KEY", limit=10)
    assert payload["count"] == 10
    assert len(payload["xrefs"]) == 10
    assert payload["has_more"] is True
    assert payload["strings_matched"] == 1


def test_apk_string_xrefs_rejects_an_empty_value(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """An empty needle would match every string in contains mode, so reject it."""
    client = ApkClient()
    monkeypatch.setattr(
        ApkClient, "_parsed", lambda self, path: _FakeStringParsed([])
    )
    with pytest.raises(ApkError) as info:
        client.string_xrefs(tmp_path / "app.apk", "")
    assert info.value.code == "invalid_params"


class _FakeIns:
    """One Dalvik instruction: mnemonic, operands, and byte length."""

    def __init__(self, name: str, output: str, length: int = 2) -> None:
        self._name = name
        self._output = output
        self._length = length

    def get_name(self) -> str:
        return self._name

    def get_output(self) -> str:
        return self._output

    def get_length(self) -> int:
        return self._length


class _FakeEncoded:
    def __init__(self, instructions: list[_FakeIns]) -> None:
        self._instructions = instructions

    def get_instructions(self) -> list[_FakeIns]:
        return list(self._instructions)


class _FakeDisasmMethod:
    """A MethodAnalysis whose get_method() yields a code body to disassemble."""

    def __init__(
        self,
        class_name: str,
        name: str,
        descriptor: str,
        access: str,
        instructions: list[_FakeIns],
        *,
        external: bool = False,
    ) -> None:
        self.class_name = class_name
        self.name = name
        self.descriptor = descriptor
        self.access = access
        self._instructions = instructions
        self._external = external

    def is_external(self) -> bool:
        return self._external

    def get_method(self) -> _FakeEncoded:
        return _FakeEncoded(self._instructions)


class _FakeDisasmParsed:
    def __init__(self, methods: list[_FakeDisasmMethod]) -> None:
        self.analysis = self
        self._methods = methods

    def get_methods(self) -> list[_FakeDisasmMethod]:
        return self._methods


_CALLEE = _FakeDisasmMethod(
    "Lcom/example/gate/Sample;",
    "callee",
    "()Ljava/lang/String;",
    "public",
    [
        _FakeIns("const-string", 'v0, "APK_GATE_MARKER_STRING"', 4),
        _FakeIns("return-object", "v0", 2),
    ],
)


def test_apk_disassemble_lists_instructions_with_code_unit_offsets(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """The tool reads DEX bytecode straight from androguard, no jadx/apktool.

    Measured: callee's two instructions come back as {idx, addr, mnemonic,
    operands} with addr as the code-unit offset (0 then 2, since const-string is
    4 bytes), the const-string operand carrying the marker; descriptor/access are
    echoed, total 2, has_more False, and overloads lists the one descriptor.
    """
    client = ApkClient()
    monkeypatch.setattr(
        ApkClient, "_parsed", lambda self, path: _FakeDisasmParsed([_CALLEE])
    )
    payload = client.disassemble(
        tmp_path / "app.apk", "Lcom/example/gate/Sample;", "callee"
    )
    assert "smali" not in payload
    assert "source" not in payload
    assert payload["descriptor"] == "()Ljava/lang/String;"
    assert payload["access"] == "public"
    assert payload["total"] == 2
    assert payload["count"] == 2
    assert payload["has_more"] is False
    assert payload["scan_capped"] is False
    assert payload["overloads"] == ["()Ljava/lang/String;"]
    rows = payload["instructions"]
    assert rows[0] == {
        "idx": 0,
        "addr": 0,
        "mnemonic": "const-string",
        "operands": 'v0, "APK_GATE_MARKER_STRING"',
    }
    assert rows[1]["idx"] == 1
    assert rows[1]["addr"] == 2
    assert rows[1]["mnemonic"] == "return-object"
    doc = _tool_docstring("apk.disassemble")
    assert "instructions" in doc
    assert "mnemonic" in doc
    assert "operands" in doc
    assert "overloads" in doc


def test_apk_disassemble_accepts_a_dotted_class_name(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A dotted class resolves to the same smali class the DEX stores.

    Measured: querying com.example.gate.Sample finds the Lcom/...; method, so a
    caller need not know androguard's internal smali form.
    """
    client = ApkClient()
    monkeypatch.setattr(
        ApkClient, "_parsed", lambda self, path: _FakeDisasmParsed([_CALLEE])
    )
    payload = client.disassemble(tmp_path / "app.apk", "com.example.gate.Sample", "callee")
    assert payload["class_name"] == "Lcom/example/gate/Sample;"
    assert payload["count"] == 2


def test_apk_disassemble_lists_overloads_and_descriptor_picks_one(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """With overloads, all descriptors are listed and descriptor picks the body.

    Measured: two run() overloads (()V and (I)V); no descriptor -> the ()V body
    (first by sorted descriptor) with overloads naming both; descriptor "(I)V"
    -> the (I)V body instead.
    """
    run_void = _FakeDisasmMethod(
        "Lcom/example/gate/Sample;",
        "run",
        "()V",
        "public",
        [_FakeIns("return-void", "", 2)],
    )
    run_int = _FakeDisasmMethod(
        "Lcom/example/gate/Sample;",
        "run",
        "(I)V",
        "public",
        [_FakeIns("nop", "", 2), _FakeIns("return-void", "", 2)],
    )
    client = ApkClient()
    monkeypatch.setattr(
        ApkClient,
        "_parsed",
        lambda self, path: _FakeDisasmParsed([run_int, run_void]),
    )
    apk = tmp_path / "app.apk"
    default = client.disassemble(apk, "Lcom/example/gate/Sample;", "run")
    assert default["descriptor"] == "()V"
    assert default["count"] == 1
    assert default["overloads"] == ["()V", "(I)V"]
    pinned = client.disassemble(apk, "Lcom/example/gate/Sample;", "run", descriptor="(I)V")
    assert pinned["descriptor"] == "(I)V"
    assert pinned["count"] == 2


def test_apk_disassemble_unknown_method_is_not_found(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A name that is not in the class is not_found, not an empty listing."""
    client = ApkClient()
    monkeypatch.setattr(
        ApkClient, "_parsed", lambda self, path: _FakeDisasmParsed([_CALLEE])
    )
    with pytest.raises(ApkError) as info:
        client.disassemble(tmp_path / "app.apk", "Lcom/example/gate/Sample;", "ghost")
    assert info.value.code == "not_found"


def test_apk_disassemble_blank_arguments_are_invalid_params(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A blank class_name or method_name is rejected before any lookup."""
    client = ApkClient()
    monkeypatch.setattr(
        ApkClient, "_parsed", lambda self, path: _FakeDisasmParsed([_CALLEE])
    )
    apk = tmp_path / "app.apk"
    with pytest.raises(ApkError) as no_class:
        client.disassemble(apk, "  ", "callee")
    assert no_class.value.code == "invalid_params"
    with pytest.raises(ApkError) as no_method:
        client.disassemble(apk, "Lcom/example/gate/Sample;", "  ")
    assert no_method.value.code == "invalid_params"


def test_apk_disassemble_paginates_a_long_method(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A long method pages by offset/limit and says the listing did not end.

    Measured: 50 nops, limit 10 -> count 10, total 50, has_more True; offset 45
    -> the last 5, has_more False. addr tracks the code-unit offset per row.
    """
    long_method = _FakeDisasmMethod(
        "Lcom/example/gate/Sample;",
        "loop",
        "()V",
        "public",
        [_FakeIns("nop", "", 2) for _ in range(50)],
    )
    client = ApkClient()
    monkeypatch.setattr(
        ApkClient, "_parsed", lambda self, path: _FakeDisasmParsed([long_method])
    )
    apk = tmp_path / "app.apk"
    first = client.disassemble(apk, "Lcom/example/gate/Sample;", "loop", limit=10)
    assert first["count"] == 10
    assert first["total"] == 50
    assert first["has_more"] is True
    assert first["instructions"][0]["addr"] == 0
    assert first["instructions"][1]["addr"] == 1
    tail = client.disassemble(apk, "Lcom/example/gate/Sample;", "loop", offset=45, limit=10)
    assert tail["count"] == 5
    assert tail["has_more"] is False
    assert tail["instructions"][0]["idx"] == 45


class _ManifestBody:
    def get_xml(self) -> bytes:
        return b"<manifest/>" * ((_MAX_MANIFEST_CHARS // 10) + 20)


class _FakeApk:
    def get_android_manifest_axml(self) -> _ManifestBody:
        return _ManifestBody()

    def get_package(self) -> str:
        return "com.example.app"


def test_apk_manifest_names_manifest_xml_and_says_when_it_was_cut(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """The catalog said AndroidManifest.xml and never named the payload.

    Measured: truncated True, manifest_xml 200000 chars (the cap), no
    manifest or xml field. Looking for those after a successful call reads
    as a missing manifest, and a 200000-char string with no truncated flag
    reads as the whole file.
    """
    client = ApkClient()
    monkeypatch.setattr(ApkClient, "_apk", lambda self, path: _FakeApk())
    payload = client.manifest(tmp_path / "app.apk")
    assert "manifest" not in payload
    assert "xml" not in payload
    assert payload["truncated"] is True
    assert payload["package"] == "com.example.app"
    assert len(payload["manifest_xml"]) == _MAX_MANIFEST_CHARS
    doc = _tool_docstring("apk.manifest")
    assert "manifest_xml" in doc
    assert "truncated" in doc


class _FlagApk:
    """Fake APK whose manifest declares the given <application> attributes."""

    def __init__(self, values: dict[str, str]) -> None:
        self._values = values

    def get_android_manifest_axml(self) -> _ManifestBody:
        return _ManifestBody()

    def get_package(self) -> str:
        return "com.example.app"

    def get_attribute_value(self, tag: str, attribute: str) -> str | None:
        assert tag == "application"
        return self._values.get(attribute)


def test_apk_manifest_maps_application_security_flags(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """debuggable/allowBackup come back as real bools, not AXML strings.

    A caller triaging an APK should not have to know that androguard returns the
    manifest attribute as the string "true"/"false"; the field maps it to a bool
    so debuggable True (a release-build red flag) reads directly.
    """
    client = ApkClient()
    monkeypatch.setattr(
        ApkClient,
        "_apk",
        lambda self, path: _FlagApk(
            {
                "debuggable": "true",
                "allowBackup": "false",
                "usesCleartextTraffic": "true",
                "networkSecurityConfig": "@xml/network_security_config",
            }
        ),
    )
    payload = client.manifest(tmp_path / "app.apk")
    assert payload["debuggable"] is True
    assert payload["allow_backup"] is False
    # Cleartext HTTP explicitly permitted, and a Network Security Config governs
    # the app: both are first-class fields, the config reported as its reference.
    assert payload["uses_cleartext_traffic"] is True
    assert payload["network_security_config"] == "@xml/network_security_config"


def test_apk_manifest_undeclared_flags_are_null_not_false(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """An undeclared flag reports null, never a fabricated False.

    allowBackup unset still defaults to backups enabled on pre-Android-12
    targets, so collapsing "not declared" to False would read as an explicit
    deny the manifest never made. null keeps "never pinned" distinct.
    """
    client = ApkClient()
    monkeypatch.setattr(ApkClient, "_apk", lambda self, path: _FlagApk({}))
    payload = client.manifest(tmp_path / "app.apk")
    assert payload["debuggable"] is None
    assert payload["allow_backup"] is None
    # An undeclared cleartext flag is null too (not False): unset still defaults
    # to allowing plaintext HTTP below target API 28, so null keeps "never
    # pinned" distinct. A manifest with no <application> networkSecurityConfig
    # reports null rather than an empty string.
    assert payload["uses_cleartext_traffic"] is None
    assert payload["network_security_config"] is None


class _FakeClass:
    def __init__(self, name: str, *, external: bool = False) -> None:
        self.name = name
        self._external = external

    def is_external(self) -> bool:
        return self._external


class _FakeClassParsed:
    def __init__(self, classes: list[_FakeClass]) -> None:
        self.analysis = self
        self._classes = classes

    def get_classes(self) -> list[_FakeClass]:
        return self._classes


def test_apk_classes_puts_the_list_in_classes_and_says_when_it_stopped(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """The catalog said pagination and never named the payload.

    Measured: 25 classes, limit 10 -> count 10, total 25, has_more True,
    field is classes not class_list or items. Looking for those after a
    successful call reads as no classes, and a full page with no has_more
    reads as the whole DEX.
    """
    client = ApkClient()
    monkeypatch.setattr(
        ApkClient,
        "_parsed",
        lambda self, path: _FakeClassParsed(
            [_FakeClass(f"L{index};") for index in range(25)]
        ),
    )
    payload = client.classes(tmp_path / "app.apk", offset=0, limit=10)
    assert "class_list" not in payload
    assert "items" not in payload
    assert payload["count"] == 10
    assert payload["total"] == 25
    assert len(payload["classes"]) == 10
    assert payload["has_more"] is True
    doc = _tool_docstring("apk.classes")
    assert "Answers with classes" in doc
    assert "has_more" in doc


_MIXED_CLASSES = [
    _FakeClass("Lcom/example/CryptoUtil;"),
    _FakeClass("Lcom/example/crypto/AesHelper;"),
    _FakeClass("Lcom/example/net/HttpClient;"),
    _FakeClass("Lcom/other/Foo;"),
    _FakeClass("Lext/Skip;", external=True),
]


def test_apk_classes_contains_filters_case_insensitively_and_flags_filtered(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """contains keeps only classes whose name holds the needle, any case.

    Measured: five classes (one external, skipped) -> contains 'crypto' keeps
    the two crypto classes, total 2, filtered True; 'CRYPTO' keeps the same two,
    proving the match ignores case; an unmatched needle yields an empty, honest
    list with filtered True (not the whole DEX).
    """
    client = ApkClient()
    monkeypatch.setattr(
        ApkClient, "_parsed", lambda self, path: _FakeClassParsed(list(_MIXED_CLASSES))
    )
    payload = client.classes(tmp_path / "app.apk", contains="crypto")
    assert payload["classes"] == [
        "Lcom/example/CryptoUtil;",
        "Lcom/example/crypto/AesHelper;",
    ]
    assert payload["total"] == 2
    assert payload["filtered"] is True
    upper = client.classes(tmp_path / "app.apk", contains="CRYPTO")
    assert upper["total"] == 2
    miss = client.classes(tmp_path / "app.apk", contains="nosuchclass")
    assert miss["classes"] == []
    assert miss["total"] == 0
    assert miss["filtered"] is True


def test_apk_classes_blank_contains_is_ignored_not_matched(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A whitespace-only contains behaves as no filter, not match-all/none.

    Measured: contains '   ' -> all four internal classes, and no filtered flag,
    so an accidentally-blank argument does not silently widen or empty the list.
    """
    client = ApkClient()
    monkeypatch.setattr(
        ApkClient, "_parsed", lambda self, path: _FakeClassParsed(list(_MIXED_CLASSES))
    )
    payload = client.classes(tmp_path / "app.apk", contains="   ")
    assert payload["total"] == 4  # the external class is still excluded
    assert "filtered" not in payload
    doc = _tool_docstring("apk.classes")
    assert "contains" in doc
    assert "filtered" in doc


_MIXED_STRINGS = [
    _FakeStringAnalysis("https://api.example.com/login", []),
    _FakeStringAnalysis("http://plain.example/health", []),
    _FakeStringAnalysis("GET /users", []),
    _FakeStringAnalysis("device_SECRET_token", []),
]


def test_apk_strings_contains_filters_case_insensitively_and_flags_filtered(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """contains keeps only constants that hold the needle, tested on the full value.

    Measured: four strings -> contains 'http' keeps the two URLs, total 2,
    filtered True; 'HTTP' keeps the same two (case-insensitive); 'secret' matches
    a substring in the middle of a value, proving the test is a substring of the
    whole constant, not a prefix.
    """
    client = ApkClient()
    monkeypatch.setattr(
        ApkClient, "_parsed", lambda self, path: _FakeStringParsed(list(_MIXED_STRINGS))
    )
    payload = client.strings(tmp_path / "app.apk", contains="http")
    assert payload["strings"] == [
        "http://plain.example/health",
        "https://api.example.com/login",
    ]
    assert payload["total"] == 2
    assert payload["filtered"] is True
    assert client.strings(tmp_path / "app.apk", contains="HTTP")["total"] == 2
    middle = client.strings(tmp_path / "app.apk", contains="secret")
    assert middle["strings"] == ["device_SECRET_token"]


def test_apk_strings_blank_contains_is_ignored_not_matched(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A whitespace-only contains behaves as no filter, not match-all/none."""
    client = ApkClient()
    monkeypatch.setattr(
        ApkClient, "_parsed", lambda self, path: _FakeStringParsed(list(_MIXED_STRINGS))
    )
    payload = client.strings(tmp_path / "app.apk", contains="  ")
    assert payload["total"] == 4
    assert "filtered" not in payload
    doc = _tool_docstring("apk.strings")
    assert "contains" in doc
    assert "filtered" in doc

class _FakeApkMethod:
    def __init__(self, index: int) -> None:
        self.name = f"m{index}"
        self.descriptor = "()V"
        self.access = "public"


class _FakeMethodClass:
    def __init__(self, count: int) -> None:
        self.name = "Lcom/example/Foo;"
        self._methods = [_FakeApkMethod(index) for index in range(count)]

    def get_methods(self) -> list[_FakeApkMethod]:
        return self._methods


class _FakeMethodParsed:
    def __init__(self, count: int) -> None:
        self.analysis = self
        self._classes = [_FakeMethodClass(count)]

    def get_classes(self) -> list[_FakeMethodClass]:
        return self._classes


def test_apk_methods_puts_the_list_in_methods_and_says_when_it_stopped(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """The catalog said paginated and never named the payload.

    Measured: 25 methods, limit 10 -> count 10, total 25, has_more True,
    field is methods not method_list or items. Looking for those after a
    successful call reads as no methods, and a full page with no has_more
    reads as the whole class.
    """
    client = ApkClient()
    monkeypatch.setattr(ApkClient, "_parsed", lambda self, path: _FakeMethodParsed(25))
    payload = client.methods(tmp_path / "app.apk", "com.example.Foo", offset=0, limit=10)
    assert "method_list" not in payload
    assert "items" not in payload
    assert payload["count"] == 10
    assert payload["total"] == 25
    assert len(payload["methods"]) == 10
    assert payload["has_more"] is True
    doc = _tool_docstring("apk.methods")
    assert "Answers with methods" in doc
    assert "has_more" in doc


class _NamedMethod:
    def __init__(self, name: str) -> None:
        self.name = name
        self.descriptor = "()V"
        self.access = "public"


class _NamedMethodClass:
    def __init__(self, names: list[str]) -> None:
        self.name = "Lcom/example/Foo;"
        self._methods = [_NamedMethod(name) for name in names]

    def get_methods(self) -> list[_NamedMethod]:
        return self._methods


class _NamedMethodParsed:
    def __init__(self, names: list[str]) -> None:
        self.analysis = self
        self._classes = [_NamedMethodClass(names)]

    def get_classes(self) -> list[_NamedMethodClass]:
        return self._classes


_METHOD_NAMES = ["<init>", "encryptPayload", "Encrypt", "decrypt", "doNetworkCall", "toString"]


def test_apk_methods_contains_filters_case_insensitively_and_flags_filtered(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """contains keeps only methods whose name holds the (case-insensitive) needle.

    Measured on a 6-method class: contains="encrypt" keeps encryptPayload and
    Encrypt (decrypt does not hold "encrypt"), total counts only matches, and
    filtered is flagged; the unfiltered call still returns all 6 with no
    filtered flag. The needle tests the method name, not the descriptor, so
    "()V" matches nothing even though every descriptor is "()V".
    """
    client = ApkClient()
    monkeypatch.setattr(
        ApkClient, "_parsed", lambda self, path: _NamedMethodParsed(list(_METHOD_NAMES))
    )
    apk = tmp_path / "app.apk"

    filtered = client.methods(apk, "com.example.Foo", contains="encrypt")
    assert {m["name"] for m in filtered["methods"]} == {"encryptPayload", "Encrypt"}
    assert filtered["total"] == 2
    assert filtered["filtered"] is True

    full = client.methods(apk, "com.example.Foo")
    assert full["total"] == 6
    assert "filtered" not in full

    # The filter matches the name only; the shared "()V" descriptor never leaks in.
    by_descriptor = client.methods(apk, "com.example.Foo", contains="()V")
    assert by_descriptor["total"] == 0
    assert by_descriptor["filtered"] is True

    doc = _tool_docstring("apk.methods")
    assert "contains" in doc
    assert "filtered" in doc


def test_apk_methods_blank_contains_is_ignored_not_matched(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A whitespace-only filter is treated as no filter, not a match-all."""
    client = ApkClient()
    monkeypatch.setattr(
        ApkClient, "_parsed", lambda self, path: _NamedMethodParsed(list(_METHOD_NAMES))
    )
    payload = client.methods(tmp_path / "app.apk", "com.example.Foo", contains="   ")
    assert payload["total"] == 6
    assert "filtered" not in payload


def test_apk_decompile_names_source_and_says_when_it_was_cut(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """The catalog said Java and never named the payload.

    Measured: truncated True, a ``source`` bounded to the JSON-encoded transport
    budget (not a raw byte count), and no java, code or text field. Looking for
    those after a successful call reads as a missing class; an over-budget string
    with no truncated flag reads as the whole file -- and would be discarded whole
    for a ~16 KiB summary in transit rather than returned cleanly cut.
    """
    import json as _json

    from headless_re_mcp.backends.common.json_budget import RESULT_BUDGET_BYTES
    from headless_re_mcp.backends.jadx.client import JadxClient

    apk = tmp_path / "app.apk"
    apk.write_bytes(b"PK")
    out = tmp_path / "out"
    src_dir = out / "sources" / "com" / "example"
    src_dir.mkdir(parents=True)
    (src_dir / "Foo.java").write_text("x" * (RESULT_BUDGET_BYTES + 80), encoding="utf-8")
    client = JadxClient(tmp_path / "jadx.bat")
    monkeypatch.setattr(client, "export_sources", lambda *args, **kwargs: {"ok": True})
    payload = client.decompile(apk, out, "com.example.Foo")
    assert "java" not in payload
    assert "code" not in payload
    assert "text" not in payload
    assert payload["truncated"] is True
    assert payload["class_name"] == "com.example.Foo"
    assert len(payload["source"]) < RESULT_BUDGET_BYTES + 80
    encoded = len(_json.dumps(payload["source"], ensure_ascii=False).encode("utf-8"))
    assert encoded <= RESULT_BUDGET_BYTES
    doc = _tool_docstring("apk.decompile")
    assert "source" in doc
    assert "truncated" in doc

def test_apk_export_sources_says_when_the_java_list_was_cut(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """The catalog said a Java source tree and never named the payload.

    Measured: 5 java files, list capped at 3, has_more True, field is
    java_files not files or sources. Looking for those after a successful
    call reads as a missing tree, and a full page with no has_more reads
    as every class.
    """
    from headless_re_mcp.backends.jadx import client as mod

    out = tmp_path / "out"
    sources = out / "sources"
    sources.mkdir(parents=True)
    for index in range(5):
        (sources / f"C{index}.java").write_text("class C {}", encoding="utf-8")
    monkeypatch.setattr(mod, "_MAX_LISTED_FILES", 3)
    client = mod.JadxClient(tmp_path / "jadx.bat")
    monkeypatch.setattr(client, "_run", lambda *args, **kwargs: ("", "", 0))
    payload = client.export_sources(tmp_path / "app.apk", out)
    assert "files" not in payload
    assert "sources" not in payload
    assert payload["java_file_count"] == 5
    assert len(payload["java_files"]) == 3
    assert payload["has_more"] is True
    doc = _tool_docstring("apk.export_sources")
    assert "java_files" in doc
    assert "has_more" in doc


class _FakeVmClass:
    def __init__(self, access: str) -> None:
        self._access = access

    def get_access_flags_string(self) -> str:
        return self._access


class _FakeHierClass:
    """A ClassAnalysis carrying inheritance (extends/implements) and a shape."""

    def __init__(
        self,
        name: str,
        *,
        external: bool = False,
        extends: str | None = None,
        implements: list[str] | None = None,
        methods: int = 0,
        fields: int = 0,
        access: str = "public",
    ) -> None:
        self.name = name
        self._external = external
        self.extends = extends
        self.implements = implements or []
        self._methods = list(range(methods))
        self._fields = list(range(fields))
        self._access = access

    def is_external(self) -> bool:
        return self._external

    def get_vm_class(self) -> _FakeVmClass:
        return _FakeVmClass(self._access)

    def get_methods(self) -> list[int]:
        return list(self._methods)

    def get_fields(self) -> list[int]:
        return list(self._fields)


class _FakeHierParsed:
    def __init__(self, classes: list[_FakeHierClass]) -> None:
        self.analysis = self
        self._classes = classes

    def get_classes(self) -> list[_FakeHierClass]:
        return self._classes


def test_apk_class_info_reports_superclass_interfaces_access_and_counts(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """The gap between apk.classes (names) and apk.methods (bodies): what a class is.

    Measured: an internal class extending an Activity and implementing two
    interfaces -> superclass and the two interface names come back in Lsmali/
    form, is_external False, access echoed, method_count/field_count as counted.
    interfaces is the SSL/worker map a reverse engineer navigates by.
    """
    client = ApkClient()
    widget = _FakeHierClass(
        "Lcom/example/Widget;",
        extends="Landroid/app/Activity;",
        implements=["Ljava/lang/Runnable;", "Landroid/view/View$OnClickListener;"],
        methods=4,
        fields=2,
        access="public final",
    )
    monkeypatch.setattr(
        ApkClient, "_parsed", lambda self, path: _FakeHierParsed([widget])
    )
    payload = client.class_info(tmp_path / "app.apk", "Lcom/example/Widget;")
    assert payload["class_name"] == "Lcom/example/Widget;"
    assert payload["is_external"] is False
    assert payload["superclass"] == "Landroid/app/Activity;"
    assert payload["interfaces"] == [
        "Ljava/lang/Runnable;",
        "Landroid/view/View$OnClickListener;",
    ]
    assert payload["access"] == "public final"
    assert payload["method_count"] == 4
    assert payload["field_count"] == 2
    doc = _tool_docstring("apk.class_info")
    for token in (
        "superclass",
        "interfaces",
        "method_count",
        "field_count",
        "is_external",
        "access",
    ):
        assert token in doc


def test_apk_class_info_accepts_a_dotted_class_name(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A dotted class resolves to the same Lsmali/class the DEX stores."""
    client = ApkClient()
    monkeypatch.setattr(
        ApkClient,
        "_parsed",
        lambda self, path: _FakeHierParsed(
            [_FakeHierClass("Lcom/example/Widget;", extends="Ljava/lang/Object;")]
        ),
    )
    payload = client.class_info(tmp_path / "app.apk", "com.example.Widget")
    assert payload["class_name"] == "Lcom/example/Widget;"
    assert payload["superclass"] == "Ljava/lang/Object;"


def test_apk_class_info_no_interfaces_is_an_empty_list_not_omitted(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A class implementing nothing reports interfaces [] (a stated absence).

    An omitted interfaces field would be ambiguous with "not analysed"; the
    empty list says plainly the class implements no interface.
    """
    client = ApkClient()
    monkeypatch.setattr(
        ApkClient,
        "_parsed",
        lambda self, path: _FakeHierParsed(
            [_FakeHierClass("Lcom/example/Plain;", extends="Ljava/lang/Object;")]
        ),
    )
    payload = client.class_info(tmp_path / "app.apk", "Lcom/example/Plain;")
    assert payload["interfaces"] == []


def test_apk_class_info_external_reference_omits_the_fabricated_hierarchy(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """For an external class only class_name/is_external come back, not a stub.

    androguard fabricates a bare stub for a framework/library reference (a
    default Object superclass, no body); the tool must not present that as real,
    so superclass/interfaces/access/counts are omitted and is_external says why.
    """
    client = ApkClient()
    external = _FakeHierClass(
        "Landroidx/appcompat/app/AppCompatActivity;",
        external=True,
        extends="Ljava/lang/Object;",  # androguard's fabricated default
        methods=99,
    )
    monkeypatch.setattr(
        ApkClient, "_parsed", lambda self, path: _FakeHierParsed([external])
    )
    payload = client.class_info(
        tmp_path / "app.apk", "Landroidx/appcompat/app/AppCompatActivity;"
    )
    assert payload["is_external"] is True
    assert payload["class_name"] == "Landroidx/appcompat/app/AppCompatActivity;"
    for field in ("superclass", "interfaces", "access", "method_count", "field_count"):
        assert field not in payload


def test_apk_class_info_unknown_class_is_not_found(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A class the DEX does not define is not_found, not an empty summary."""
    client = ApkClient()
    monkeypatch.setattr(
        ApkClient,
        "_parsed",
        lambda self, path: _FakeHierParsed([_FakeHierClass("Lcom/example/Widget;")]),
    )
    with pytest.raises(ApkError) as info:
        client.class_info(tmp_path / "app.apk", "Lcom/example/Ghost;")
    assert info.value.code == "not_found"


def test_apk_class_info_blank_class_name_is_invalid_params(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A blank class_name is rejected before any lookup."""
    client = ApkClient()
    monkeypatch.setattr(
        ApkClient,
        "_parsed",
        lambda self, path: _FakeHierParsed([_FakeHierClass("Lcom/example/Widget;")]),
    )
    with pytest.raises(ApkError) as info:
        client.class_info(tmp_path / "app.apk", "   ")
    assert info.value.code == "invalid_params"


_HIER_CLASSES = [
    _FakeHierClass("Lcom/example/Screen;", extends="Landroid/app/Activity;"),
    _FakeHierClass("Lcom/example/Worker;", implements=["Ljava/lang/Runnable;"]),
    _FakeHierClass(
        "Lcom/example/TrustAll;",
        implements=["Ljavax/net/ssl/X509TrustManager;"],
    ),
    _FakeHierClass("Lcom/example/Plain;", extends="Ljava/lang/Object;"),
    _FakeHierClass("Lext/Framework;", external=True, extends="Landroid/app/Activity;"),
]


def test_apk_subclasses_finds_extends_and_implements_with_relation(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """The reverse of class_info: who extends or implements a given type.

    Measured on five classes (one external, skipped): querying the Activity base
    finds the one that extends it labelled "extends"; querying Runnable finds the
    one that implements it labelled "implements"; querying the dotted trust-
    manager interface finds TrustAll (proving dotted resolution) -- the SSL-bypass
    hunt in one call.
    """
    client = ApkClient()
    monkeypatch.setattr(
        ApkClient, "_parsed", lambda self, path: _FakeHierParsed(list(_HIER_CLASSES))
    )
    apk = tmp_path / "app.apk"

    activities = client.subclasses(apk, "Landroid/app/Activity;")
    assert activities["type_name"] == "Landroid/app/Activity;"
    assert activities["subclasses"] == [
        {"class": "Lcom/example/Screen;", "relation": "extends"}
    ]
    assert activities["total"] == 1

    runnables = client.subclasses(apk, "Ljava/lang/Runnable;")
    assert runnables["subclasses"] == [
        {"class": "Lcom/example/Worker;", "relation": "implements"}
    ]

    # A dotted interface name resolves to the same Lsmali/type the DEX stores.
    trust = client.subclasses(apk, "javax.net.ssl.X509TrustManager")
    assert trust["type_name"] == "Ljavax/net/ssl/X509TrustManager;"
    assert trust["subclasses"] == [
        {"class": "Lcom/example/TrustAll;", "relation": "implements"}
    ]

    doc = _tool_docstring("apk.subclasses")
    for token in ("subclasses", "relation", "extends", "implements", "type_name", "scan_capped"):
        assert token in doc


def test_apk_subclasses_skips_external_classes(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """An external class that matches the type is never a result (only app classes).

    Lext/Framework; also extends the Activity base, but it is a framework stub,
    not the app's own code, so it must not appear -- otherwise the audit is
    polluted with classes the app did not write.
    """
    client = ApkClient()
    monkeypatch.setattr(
        ApkClient, "_parsed", lambda self, path: _FakeHierParsed(list(_HIER_CLASSES))
    )
    result = client.subclasses(tmp_path / "app.apk", "Landroid/app/Activity;")
    names = {row["class"] for row in result["subclasses"]}
    assert "Lext/Framework;" not in names
    assert result["total"] == 1


def test_apk_subclasses_no_match_is_an_empty_list_not_an_error(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A type nothing extends or implements yields an empty list, not not_found."""
    client = ApkClient()
    monkeypatch.setattr(
        ApkClient, "_parsed", lambda self, path: _FakeHierParsed(list(_HIER_CLASSES))
    )
    result = client.subclasses(tmp_path / "app.apk", "Lcom/example/Nonexistent;")
    assert result["subclasses"] == []
    assert result["total"] == 0
    assert result["scan_capped"] is False


def test_apk_subclasses_blank_type_name_is_invalid_params(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A blank type_name is rejected before any scan."""
    client = ApkClient()
    monkeypatch.setattr(
        ApkClient, "_parsed", lambda self, path: _FakeHierParsed(list(_HIER_CLASSES))
    )
    with pytest.raises(ApkError) as info:
        client.subclasses(tmp_path / "app.apk", "   ")
    assert info.value.code == "invalid_params"


def test_apk_subclasses_paginates_and_flags_has_more(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A common base pages by offset/limit and says the list did not end.

    Measured: 25 classes extending Object, limit 10 -> count 10, total 25,
    has_more True; offset 20 -> the last 5, has_more False.
    """
    classes = [
        _FakeHierClass(f"Lcom/example/C{index:02d};", extends="Ljava/lang/Object;")
        for index in range(25)
    ]
    client = ApkClient()
    monkeypatch.setattr(
        ApkClient, "_parsed", lambda self, path: _FakeHierParsed(classes)
    )
    apk = tmp_path / "app.apk"
    first = client.subclasses(apk, "Ljava/lang/Object;", limit=10)
    assert first["count"] == 10
    assert first["total"] == 25
    assert first["has_more"] is True
    assert all(row["relation"] == "extends" for row in first["subclasses"])
    tail = client.subclasses(apk, "Ljava/lang/Object;", offset=20, limit=10)
    assert tail["count"] == 5
    assert tail["has_more"] is False
