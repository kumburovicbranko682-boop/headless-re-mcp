"""apk.disassemble decodes one method's Dalvik (smali) instruction stream.

Driven through the _parsed seam with fakes mimicking androguard's
get_classes() / ClassAnalysis.get_methods() / MethodAnalysis.get_method() and
the EncodedMethod.get_code()/get_instructions() surface a disassembly walks.
"""

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


class _Ins:
    def __init__(
        self,
        name: str,
        output: str,
        length: int,
        op: int,
        hexs: str = "",
    ) -> None:
        self._name = name
        self._output = output
        self._length = length
        self._op = op
        self._hex = hexs

    def get_name(self) -> str:
        return self._name

    def get_output(self, idx: int = -1) -> str:
        # Prove the code offset reaches operand rendering (branch targets).
        if self._name == "goto":
            return f"{self._output}:{idx}"
        return self._output

    def get_length(self) -> int:
        return self._length

    def get_op_value(self) -> int:
        return self._op

    def get_hex(self) -> str:
        return self._hex


class _Encoded:
    def __init__(self, instructions: list[_Ins] | None) -> None:
        self._instructions = instructions

    def get_code(self) -> object | None:
        return object() if self._instructions is not None else None

    def get_instructions(self) -> list[_Ins]:
        return self._instructions or []


class _MethodAnalysis:
    def __init__(
        self,
        name: str,
        descriptor: str,
        access: str,
        encoded: _Encoded,
        *,
        external: bool = False,
    ) -> None:
        self.name = name
        self.descriptor = descriptor
        self.access = access
        self._encoded = encoded
        self._external = external

    def get_method(self) -> _Encoded:
        return self._encoded

    def is_external(self) -> bool:
        return self._external


class _ClassAnalysis:
    def __init__(self, name: str, methods: list[_MethodAnalysis]) -> None:
        self.name = name
        self._methods = methods

    def get_methods(self) -> list[_MethodAnalysis]:
        return self._methods

    def is_external(self) -> bool:
        return False


class _Analysis:
    def __init__(self, classes: list[_ClassAnalysis]) -> None:
        self._classes = classes

    def get_classes(self) -> list[_ClassAnalysis]:
        return self._classes


class _Parsed:
    def __init__(self, analysis: _Analysis) -> None:
        self.analysis = analysis


def _client(classes: list[_ClassAnalysis]) -> ApkClient:
    client = ApkClient()
    client._parsed = lambda _path: _Parsed(_Analysis(classes))  # type: ignore[method-assign]
    return client


def _body() -> _Encoded:
    return _Encoded(
        [
            _Ins("const/4", "v0, 0x1", 2, 0x12, "12 10"),
            _Ins("invoke-virtual", "v0, Lcom/x/Foo;->bar()V", 6, 0x6E, "6e 20"),
            _Ins("return-void", "", 2, 0x0E, "0e 00"),
        ]
    )


def _simple_class(smali: str = "Lcom/x/Foo;") -> list[_ClassAnalysis]:
    return [
        _ClassAnalysis(
            smali,
            [_MethodAnalysis("bar", "()V", "public", _body())],
        )
    ]


def test_disassemble_walks_the_instruction_stream() -> None:
    payload = _client(_simple_class()).disassemble(
        Path("d.apk"), "com.x.Foo", "bar"
    )
    assert payload["has_code"] is True
    assert payload["total"] == 3
    assert payload["class_name"] == "Lcom/x/Foo;"
    assert payload["descriptor"] == "()V"
    assert payload["return_type"] == "void"
    assert payload["ambiguous"] is False
    assert payload["overloads"] == 1

    ins = payload["instructions"]
    assert [i["mnemonic"] for i in ins] == [
        "const/4",
        "invoke-virtual",
        "return-void",
    ]
    # Byte offsets accumulate from each instruction's size.
    assert [i["offset"] for i in ins] == [0, 2, 8]
    assert ins[0]["opcode"] == 0x12
    assert ins[0]["hex"] == "12 10"
    assert ins[1]["operands"] == "v0, Lcom/x/Foo;->bar()V"


def test_resolves_class_by_smali_form_too() -> None:
    payload = _client(_simple_class()).disassemble(
        Path("d.apk"), "Lcom/x/Foo;", "bar"
    )
    assert payload["total"] == 3


def test_branch_operand_receives_code_offset() -> None:
    classes = [
        _ClassAnalysis(
            "Lc/A;",
            [
                _MethodAnalysis(
                    "loop",
                    "()V",
                    "public",
                    _Encoded(
                        [
                            _Ins("nop", "", 2, 0x00),
                            _Ins("goto", "-> target", 2, 0x28),
                        ]
                    ),
                )
            ],
        )
    ]
    payload = _client(classes).disassemble(Path("d.apk"), "c.A", "loop")
    goto = payload["instructions"][1]
    # get_output was called with the running offset (2) of the goto.
    assert goto["operands"] == "-> target:2"


def test_overload_disambiguated_by_descriptor() -> None:
    classes = [
        _ClassAnalysis(
            "Lc/A;",
            [
                _MethodAnalysis(
                    "run",
                    "()V",
                    "public",
                    _Encoded([_Ins("return-void", "", 2, 0x0E)]),
                ),
                _MethodAnalysis(
                    "run",
                    "(I)V",
                    "public",
                    _Encoded(
                        [
                            _Ins("const/4", "v0, 0x0", 2, 0x12),
                            _Ins("return-void", "", 2, 0x0E),
                        ]
                    ),
                ),
            ],
        )
    ]
    picked = _client(classes).disassemble(
        Path("d.apk"), "c.A", "run", descriptor="(I)V"
    )
    assert picked["descriptor"] == "(I)V"
    assert picked["total"] == 2
    assert picked["ambiguous"] is False
    assert picked["overloads"] == 2


def test_overload_without_descriptor_is_ambiguous() -> None:
    classes = [
        _ClassAnalysis(
            "Lc/A;",
            [
                _MethodAnalysis(
                    "run", "()V", "public", _Encoded([_Ins("return-void", "", 2, 0x0E)])
                ),
                _MethodAnalysis(
                    "run", "(I)V", "public", _Encoded([_Ins("return-void", "", 2, 0x0E)])
                ),
            ],
        )
    ]
    payload = _client(classes).disassemble(Path("d.apk"), "c.A", "run")
    assert payload["ambiguous"] is True
    assert payload["overloads"] == 2


def test_prefers_overload_that_has_a_body() -> None:
    classes = [
        _ClassAnalysis(
            "Lc/A;",
            [
                # Same name, no code (e.g. a synthetic bridge) listed first.
                _MethodAnalysis("run", "()V", "public", _Encoded(None)),
                _MethodAnalysis(
                    "run", "(I)V", "public", _Encoded([_Ins("return-void", "", 2, 0x0E)])
                ),
            ],
        )
    ]
    payload = _client(classes).disassemble(Path("d.apk"), "c.A", "run")
    assert payload["has_code"] is True
    assert payload["descriptor"] == "(I)V"


def test_native_method_reports_no_code() -> None:
    classes = [
        _ClassAnalysis(
            "Lc/A;",
            [_MethodAnalysis("decrypt", "([B)[B", "public native", _Encoded(None))],
        )
    ]
    payload = _client(classes).disassemble(Path("d.apk"), "c.A", "decrypt")
    assert payload["has_code"] is False
    assert payload["instructions"] == []
    assert payload["total"] == 0


def test_external_method_reports_no_code() -> None:
    classes = [
        _ClassAnalysis(
            "Lc/A;",
            [
                _MethodAnalysis(
                    "run",
                    "()V",
                    "public",
                    _Encoded([_Ins("return-void", "", 2, 0x0E)]),
                    external=True,
                )
            ],
        )
    ]
    payload = _client(classes).disassemble(Path("d.apk"), "c.A", "run")
    assert payload["has_code"] is False


def test_paging() -> None:
    body = _Encoded([_Ins(f"nop{i}", "", 2, 0x00) for i in range(5)])
    classes = [_ClassAnalysis("Lc/A;", [_MethodAnalysis("m", "()V", "public", body)])]
    page = _client(classes).disassemble(Path("d.apk"), "c.A", "m", offset=0, limit=2)
    assert page["count"] == 2
    assert page["total"] == 5
    assert page["has_more"] is True
    tail = _client(classes).disassemble(Path("d.apk"), "c.A", "m", offset=4, limit=2)
    assert tail["count"] == 1
    assert tail["has_more"] is False
    assert tail["offset"] == 4


def test_missing_class_is_not_found() -> None:
    with pytest.raises(ApkError) as caught:
        _client(_simple_class()).disassemble(Path("d.apk"), "c.Nope", "bar")
    assert caught.value.code == "not_found"


def test_missing_method_is_not_found() -> None:
    with pytest.raises(ApkError) as caught:
        _client(_simple_class()).disassemble(Path("d.apk"), "com.x.Foo", "ghost")
    assert caught.value.code == "not_found"


def test_blank_class_name_is_invalid_params() -> None:
    with pytest.raises(ApkError) as caught:
        _client(_simple_class()).disassemble(Path("d.apk"), "   ", "bar")
    assert caught.value.code == "invalid_params"


def test_apk_disassemble_tool_is_registered() -> None:
    from headless_re_mcp.config import Settings
    from headless_re_mcp.core.service import AnalysisService

    service = AnalysisService(Settings.load())
    names = {tool.name for tool in build_apk_tools(service)}
    assert "apk.disassemble" in names


def test_apk_disassemble_docstring_names_the_shape() -> None:
    doc = " ".join(_tool_docstring("apk.disassemble").split())
    assert "instructions" in doc
    assert "mnemonic" in doc
    assert "operands" in doc
    assert "has_code" in doc
    assert "ambiguous" in doc
    assert "descriptor" in doc
    assert "target_mismatch" in doc
