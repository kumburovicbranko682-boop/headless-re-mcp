""".NET metadata/IL read gate: the pure-Python CLR reader on a real assembly.

The existing .NET gate (``test_dotnet_m6_gate.py``) couples its metadata/IL read
tests to de4dot: ``dotnet.enumerate`` / ``dotnet.il`` / ``dotnet.xrefs`` are only
exercised through ``_gate_sample``, which skips unless ``HEADLESS_RE_DE4DOT`` and
an external sample are both configured. But those reads never call de4dot -- they
are a pure-Python ECMA-335 parser -- so on a clean machine this substantial,
delicate reader had no integration coverage at all, even though it needs nothing
but a committed assembly to run.

This gate closes that. It ships a genuine, minimal, verifiable .NET assembly
(``fixtures/dotnet/managed_gate.exe``, built from the adjacent
``managed_gate_fixture.cs`` with the Mono C# compiler) and reads it back through
``AnalysisService``. The assembly is shaped so every assertion checks recovered
content tied to the source, not a non-empty envelope: a namespaced type
``HeadlessRe.DotnetGate.GateFixture``, methods ``GetMarker`` /
``ComputeChecksum`` / ``Announce`` / ``Main``, a field ``Marker``, a
``GetMarker`` body that is exactly ``ldstr <marker>; ret``, a ``ComputeChecksum``
loop whose IL carries branch + call opcodes, and a ``System.Console.WriteLine``
MemberRef. The reader has no optional dependency, so this gate always runs; the
negative paths (bad token, bad kind, out-of-range rid, a native PE that is not
managed) are exercised inline.

Verified against the Mono 6.8 C# compiler's output, read by the built-in Python
CLR parser on Linux with no .NET runtime.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.core.service import AnalysisService

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_DOTNET_FIXTURE = _PROJECT_ROOT / "fixtures" / "dotnet" / "managed_gate.exe"
_NATIVE_PE = _PROJECT_ROOT / "fixtures" / "upx" / "console_fixture-x64.pre-upx.exe"


def _names(items: list[dict]) -> set[str]:
    return {item.get("name") for item in items}


def _token_by_name(items: list[dict], name: str) -> int:
    for item in items:
        if item.get("name") == name:
            return int(item["token"])
    raise AssertionError(f"method {name!r} not found in {_names(items)}")


@pytest.mark.integration
def test_dotnet_read_recovers_managed_metadata() -> None:
    assert _DOTNET_FIXTURE.is_file(), f"fixture missing: {_DOTNET_FIXTURE}"
    service = AnalysisService()
    try:
        created = service.create_session(str(_DOTNET_FIXTURE))
        assert created.ok, created.error
        assert created.data["session"]["target"] == "pe"
        session_id = created.data["session"]["id"]

        inspected = service.dotnet_inspect(session_id, require_verified=True)
        assert inspected.ok, inspected.error
        assert inspected.data["is_dotnet"] is True
        assert inspected.data["verified_clr"] is True
        assert inspected.data["module_name"] == _DOTNET_FIXTURE.name
        assert str(inspected.data["metadata_version"]).startswith("v")
        entry_point_token = inspected.data["entry_point_token"]
        assert entry_point_token

        types = service.dotnet_enumerate(session_id, "types", limit=32)
        assert types.ok, types.error
        assert types.data["capability"] == "dotnet_metadata"
        gate_type = next((t for t in types.data["items"] if t.get("name") == "GateFixture"), None)
        assert gate_type is not None, _names(types.data["items"])
        assert gate_type["namespace"] == "HeadlessRe.DotnetGate"

        methods = service.dotnet_enumerate(session_id, "methods", limit=64)
        assert methods.ok, methods.error
        method_items = methods.data["items"]
        assert {"GetMarker", "ComputeChecksum", "Announce", "Main"} <= _names(method_items)
        # The module's recorded entry point must resolve to the Main we recovered.
        assert entry_point_token == _token_by_name(method_items, "Main")

        fields = service.dotnet_enumerate(session_id, "fields", limit=32)
        assert fields.ok, fields.error
        assert "Marker" in _names(fields.data["items"])

        strings = service.dotnet_enumerate(session_id, "strings", limit=64)
        assert strings.ok, strings.error
        heap = {item.get("value") for item in strings.data["items"]}
        # The #Strings heap holds identifiers; recovering them proves the heap
        # was decoded, not merely that a list came back.
        assert {"GateFixture", "GetMarker"} <= heap, sorted(s for s in heap if s)[:20]

        # GetMarker's whole body is `ldstr <marker>; ret` -- an exact, tiny IL
        # sequence, so the opcode decoder either reproduces it or it does not.
        get_marker_token = _token_by_name(method_items, "GetMarker")
        il = service.dotnet_il(session_id, get_marker_token)
        assert il.ok, il.error
        mnemonics = [insn.get("mnemonic") for insn in il.data["instructions"]]
        assert mnemonics == ["ldstr", "ret"], mnemonics
        # ldstr carries a #US string token operand.
        assert isinstance(il.data["instructions"][0].get("operand"), int)

        # ComputeChecksum has a loop and an indexer call, so its IL must carry a
        # branch, a call, and a terminating ret across many instructions.
        checksum_token = _token_by_name(method_items, "ComputeChecksum")
        il2 = service.dotnet_il(session_id, checksum_token)
        assert il2.ok, il2.error
        mnem2 = [insn.get("mnemonic") for insn in il2.data["instructions"]]
        assert len(mnem2) >= 10
        assert "ret" in mnem2
        assert "callvirt" in mnem2
        assert any(m in {"br", "br.s"} for m in mnem2), mnem2

        xrefs = service.dotnet_xrefs(session_id, limit=64)
        assert xrefs.ok, xrefs.error
        # Announce calls System.Console.WriteLine, which lands in the MemberRef
        # table; recovering that name is the whole point of the xref listing.
        assert "WriteLine" in _names(xrefs.data["items"]), xrefs.data["items"]

        # Negative paths the reader enforces.
        bad_token = service.dotnet_il(session_id, 0x02000001)  # a TypeDef, not MethodDef
        assert not bad_token.ok
        assert bad_token.error is not None
        assert bad_token.error.code == "invalid_argument"

        bad_kind = service.dotnet_enumerate(session_id, "bogus")
        assert not bad_kind.ok
        assert bad_kind.error is not None
        assert bad_kind.error.code == "invalid_argument"

        out_of_range = service.dotnet_il(session_id, 0x06009999)
        assert not out_of_range.ok
        assert out_of_range.error is not None
        assert out_of_range.error.code == "not_found"
    finally:
        service.close_all()


@pytest.mark.integration
def test_dotnet_enumerate_refuses_a_native_pe() -> None:
    """A non-managed PE is rejected as not_dotnet, not parsed as if it were CLR."""
    assert _NATIVE_PE.is_file(), f"fixture missing: {_NATIVE_PE}"
    service = AnalysisService()
    try:
        created = service.create_session(str(_NATIVE_PE))
        assert created.ok, created.error
        session_id = created.data["session"]["id"]

        result = service.dotnet_enumerate(session_id, "methods")
        assert not result.ok
        assert result.error is not None
        assert result.error.code == "not_dotnet"
    finally:
        service.close_all()
