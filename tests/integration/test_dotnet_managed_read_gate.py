"""Live Gate for the pure-Python .NET managed metadata / IL read surface.

The only .NET gate on ``main`` (``test_dotnet_m6_gate.py``) drives de4dot and
skips unless a de4dot build and an obfuscated sample are configured. But the
read surface underneath it -- ``dotnet.inspect`` / ``dotnet.enumerate`` /
``dotnet.il`` / ``dotnet.xrefs`` -- is a pure-Python ECMA-335 parser that needs
no .NET runtime at read time, and it had no end-to-end coverage of its own. A
regression in the metadata-table walk, the #Strings resolution, the IL body
reader, or the MemberRef listing would only surface on a real assembly.

This gate pins that reader against a committed, purpose-built managed assembly
(``managed_gate.dll``, built once from ``managed_gate_fixture.cs`` with the .NET
SDK; the C# source is committed beside it). Because the reader is pure Python,
the gate needs no toolchain at test time and never skips -- there is nothing to
skip. It checks the CLR header/streams, the TypeDef/MethodDef/Field/#Strings
tables, a MethodDef IL body, and the MemberRef xrefs (which include the
``System.Console::WriteLine`` the fixture calls), plus the argument guards and
the "native PE is not .NET" path.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService

_REPO = Path(__file__).resolve().parents[2]
_MANAGED = _REPO / "fixtures" / "dotnet" / "managed_gate.dll"
_NATIVE = _REPO / "fixtures" / "upx" / "console_fixture-x64.pre-upx.exe"

_METHODDEF = 0x06000000
_TYPEDEF = 0x02000000
_MEMBERREF = 0x0A000000


def _service(tmp_path: Path) -> AnalysisService:
    return AnalysisService(
        Settings(
            ida_home=None,
            x64dbg_source=None,
            x64dbg_headless_x64=None,
            x64dbg_headless_x86=None,
            artifact_root=tmp_path / "artifacts",
            diec=None,
        )
    )


def _require(path: Path) -> None:
    if not path.is_file():
        pytest.skip(f"fixture missing: {path}")


def _open(service: AnalysisService, path: Path) -> str:
    created = service.create_session(str(path))
    assert created.ok and created.data is not None, created.error
    return str(created.data["session"]["id"])


def _methods(service: AnalysisService, session_id: str) -> dict[str, dict]:
    page = service.dotnet_enumerate(session_id, "methods", limit=128)
    assert page.ok and page.data is not None, page.error
    return {item["name"]: item for item in page.data["items"]}


@pytest.mark.integration
def test_inspect_reports_verified_managed_metadata(tmp_path: Path) -> None:
    _require(_MANAGED)
    service = _service(tmp_path)
    session_id = _open(service, _MANAGED)

    inspected = service.dotnet_inspect(session_id)
    assert inspected.ok and inspected.data is not None, inspected.error
    data = inspected.data
    assert data["is_dotnet"] is True
    assert data["verified_clr"] is True
    assert data["kind"] == "pure_managed"
    assert str(data["metadata_version"]).startswith("v")
    # The module name is the one baked into metadata at build time, not the
    # on-disk fixture filename.
    assert data["module_name"] == "ManagedGate.dll"
    # The standard metadata streams are all present in a real assembly.
    for stream in ("#~", "#Strings", "#US", "#Blob"):
        assert stream in data["streams"], data["streams"]

    # The recorded entry point is Main's MethodDef token.
    main = _methods(service, session_id)["Main"]
    assert data["entry_point_token"] == main["token"]
    assert (main["token"] & 0xFF000000) == _METHODDEF


@pytest.mark.integration
def test_enumerate_types_methods_and_fields(tmp_path: Path) -> None:
    _require(_MANAGED)
    service = _service(tmp_path)
    session_id = _open(service, _MANAGED)

    types = service.dotnet_enumerate(session_id, "types", limit=128)
    assert types.ok and types.data is not None, types.error
    by_name = {item["name"]: item for item in types.data["items"]}
    assert "<Module>" in by_name
    assert by_name["Calculator"]["namespace"] == "GateFixture"
    assert by_name["Program"]["namespace"] == "GateFixture"
    assert (by_name["Calculator"]["token"] & 0xFF000000) == _TYPEDEF

    methods = _methods(service, session_id)
    for name in ("Add", "LastResult", "Main", ".cctor"):
        assert name in methods, methods.keys()
        assert (methods[name]["token"] & 0xFF000000) == _METHODDEF

    fields = service.dotnet_enumerate(session_id, "fields", limit=128)
    assert fields.ok and fields.data is not None, fields.error
    field_names = {item["name"] for item in fields.data["items"]}
    assert {"Version", "_lastResult"} <= field_names

    strings = service.dotnet_enumerate(session_id, "strings", limit=512)
    assert strings.ok and strings.data is not None, strings.error
    heap = {item["value"] for item in strings.data["items"]}
    # #Strings holds identifiers (type/method/field names), not #US literals.
    assert {"Add", "Calculator", "GateFixture", "WriteLine"} <= heap


@pytest.mark.integration
def test_il_disassembles_methoddef_bodies(tmp_path: Path) -> None:
    _require(_MANAGED)
    service = _service(tmp_path)
    session_id = _open(service, _MANAGED)
    methods = _methods(service, session_id)

    add_il = service.dotnet_il(session_id, methods["Add"]["token"])
    assert add_il.ok and add_il.data is not None, add_il.error
    assert add_il.data["method_token"] == methods["Add"]["token"]
    assert add_il.data["backend"] == "dotnet_metadata"
    assert add_il.data["not_ida_idalib"] is True
    assert add_il.data["claims_universal_unpack"] is False
    assert add_il.data["il_bytes"] > 0
    mnemonics = [insn.get("mnemonic") for insn in add_il.data["instructions"]]
    assert mnemonics, "no instructions decoded"
    assert "ret" in mnemonics
    assert any(str(m).startswith("ldarg") for m in mnemonics)

    # Main calls into the BCL; the decoder surfaces call sites and their tokens.
    main_il = service.dotnet_il(session_id, methods["Main"]["token"])
    assert main_il.ok and main_il.data is not None, main_il.error
    main_mnemonics = [insn.get("mnemonic") for insn in main_il.data["instructions"]]
    assert "call" in main_mnemonics
    call_tokens = main_il.data["call_tokens"]
    assert call_tokens, "Main decoded no call tokens"
    assert any((token & 0xFF000000) == _MEMBERREF for token in call_tokens)


@pytest.mark.integration
def test_xrefs_list_memberrefs_including_console_writeline(tmp_path: Path) -> None:
    _require(_MANAGED)
    service = _service(tmp_path)
    session_id = _open(service, _MANAGED)

    xrefs = service.dotnet_xrefs(session_id, limit=128)
    assert xrefs.ok and xrefs.data is not None, xrefs.error
    assert xrefs.data["total"] >= 1
    names = {item["name"] for item in xrefs.data["items"]}
    # The fixture's Main does `Console.WriteLine("..." + total)`, which emits
    # MemberRefs to Console::WriteLine and String::Concat.
    assert "WriteLine" in names
    assert "Concat" in names
    assert all((item["token"] & 0xFF000000) == _MEMBERREF for item in xrefs.data["items"])


@pytest.mark.integration
def test_read_surface_argument_guards(tmp_path: Path) -> None:
    _require(_MANAGED)
    service = _service(tmp_path)
    session_id = _open(service, _MANAGED)

    bad_kind = service.dotnet_enumerate(session_id, "functions")
    assert bad_kind.ok is False and bad_kind.error is not None
    assert bad_kind.error.code == "invalid_argument"

    # A TypeDef token is not a MethodDef token.
    not_methoddef = service.dotnet_il(session_id, _TYPEDEF | 1)
    assert not_methoddef.ok is False and not_methoddef.error is not None
    assert not_methoddef.error.code == "invalid_argument"

    out_of_range = service.dotnet_il(session_id, _METHODDEF | 0x9999)
    assert out_of_range.ok is False and out_of_range.error is not None
    assert out_of_range.error.code == "not_found"

    bad_flag = service.dotnet_inspect(session_id, require_verified="yes")  # type: ignore[arg-type]
    assert bad_flag.ok is False and bad_flag.error is not None
    assert bad_flag.error.code == "invalid_params"


@pytest.mark.integration
def test_native_pe_is_reported_as_not_dotnet(tmp_path: Path) -> None:
    _require(_NATIVE)
    service = _service(tmp_path)
    session_id = _open(service, _NATIVE)

    inspected = service.dotnet_inspect(session_id)
    assert inspected.ok and inspected.data is not None, inspected.error
    assert inspected.data["is_dotnet"] is False

    enumerated = service.dotnet_enumerate(session_id, "types")
    assert enumerated.ok is False and enumerated.error is not None
    assert enumerated.error.code == "not_dotnet"
