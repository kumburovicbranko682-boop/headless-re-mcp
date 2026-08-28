"""M6.4 Gate: the pure-Python .NET metadata line, end to end, no de4dot.

The other .NET gate (``test_dotnet_m6_gate``) drives deobfuscation, which shells
out to de4dot and therefore skips unless a GPL de4dot is configured. But
``dotnet.inspect`` / ``dotnet.enumerate`` / ``dotnet.il`` / ``dotnet.xrefs`` --
and the checker plus ownership guard behind ``dotnet.verify`` -- are
self-contained ECMA-335 code that needs no external tool. That surface used to
skip too, reached only through the de4dot-gated tests, so it never actually ran
in CI. This gate closes that: it drives the capability through
``AnalysisService`` against a real, committed managed assembly
(``fixtures/dotnet/minimal_assembly.exe``, produced by
``fixtures/dotnet/build_minimal_dotnet.py``) and asserts real content. It needs
nothing but Python, so it runs on every platform. Skip is not a pass; this one
does not skip.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService

_FIXTURE_DIR = Path(__file__).resolve().parents[2] / "fixtures" / "dotnet"
_FIXTURE = _FIXTURE_DIR / "minimal_assembly.exe"
_HINT_FIXTURE = _FIXTURE_DIR / "minimal_clr_hint.exe"


def _service(tmp_path: Path) -> AnalysisService:
    return AnalysisService(
        Settings(
            ida_home=None,
            x64dbg_source=None,
            x64dbg_headless_x64=None,
            x64dbg_headless_x86=None,
            artifact_root=tmp_path / "artifacts",
        )
    )


def _data(result: object) -> dict:
    assert getattr(result, "ok", False), result
    payload = getattr(result, "data", None)
    assert isinstance(payload, dict)
    return payload


@pytest.mark.integration
def test_dotnet_metadata_inspect_enumerate_il_xrefs(tmp_path: Path) -> None:
    if not _FIXTURE.is_file():
        pytest.skip(
            "minimal .NET fixture missing; run fixtures/dotnet/build_minimal_dotnet.py"
            " (skip != pass)"
        )
    service = _service(tmp_path)
    try:
        created = _data(service.create_session(str(_FIXTURE)))["session"]
        session_id = created["id"]

        # Session creation already reads the managed-vs-native fork stdlib-only:
        # the metadata carries a dotnet block before any dotnet.* tool runs.
        session_facts = created["metadata"]["dotnet"]
        assert session_facts["is_dotnet"] is True
        assert session_facts["il_only"] is True
        assert session_facts["entry_point_token"] == 0x06000003

        # inspect: a verified, pure-managed CLR image with real metadata.
        report = _data(service.dotnet_inspect(session_id, require_verified=True))
        assert report["is_dotnet"] is True
        assert report["verified_clr"] is True
        assert report["kind"] == "pure_managed"
        assert report["claims_universal_unpack"] is False
        assert report["entry_point_token"] == 0x06000003
        assert "ILONLY" in report["flags_decoded"]
        assert "#~" in report["streams"] and "#Strings" in report["streams"]
        assert str(report["metadata_version"]).startswith("v")
        # The two readers parse the BSJB root independently; they must agree.
        assert report["metadata_version"] == session_facts["metadata_version"]
        assert report["module_name"] == "MyModule.dll"
        # assembly_name only reads correctly once the walker steps over the
        # TypeDef/Field/MethodDef tables that sit before Assembly in any real
        # image; a shallow walk returns None here.
        assert report["assembly_name"] == "MyAssembly"
        # The assembly's four-part version and the module's MVID are the managed
        # analogue of a native binary's soname/build-id: the declared identity
        # plus a per-build fingerprint. Both must come off the real tables.
        assert report["assembly_version"] == "1.0.0.0"
        assert report["mvid"] == "8b8a2c3d-4e5f-6071-8293-a4b5c6d7e8f9"
        # The platform the build targets, decoded from the CustomAttribute the
        # fixture stamps on the assembly -- the monodis gate cross-checks this
        # same string against Mono's own decode of the attribute.
        assert report["target_framework"] == ".NETFramework,Version=v4.8"
        # The strong-name identity: the token of the assembly's public key --
        # the managed "who signed it". The monodis gate cross-checks it against
        # Mono's own decode of the same key; the value is the published token
        # of the ECMA key the fixture is signed with.
        assert report["public_key_token"] == "b77a5c561934e089"
        # The entry point resolved to a name, not just a token -- the method
        # monodis marks .entrypoint, which its gate cross-checks.
        assert report["entry_point_name"] == "Sample::Run"
        # The module initializer: <Module>'s static .cctor (MethodDef row 1),
        # run at module load before the entry point -- the managed
        # code-before-main. The monodis gate cross-checks the same row via
        # Mono's "global method .cctor" rendering.
        assert report["module_initializer_token"] == 0x06000001
        # The CodeView PDB reference from the debug directory: the per-build
        # GUID/age (the symbol-server key, the managed build-id analogue) and
        # the PDB path the linker baked in. The debug gate cross-checks these
        # same values against objdump's independent PE decode.
        assert report["pdb"] == {
            "guid": "a1b2c3d4-e5f6-4788-99aa-bbccddeeff00",
            "age": 1,
            "path": r"C:\build\headless\MyAssembly.pdb",
            "signature": "A1B2C3D4E5F6478899AABBCCDDEEFF001",
        }
        stats = report["metadata_stats"]
        assert stats["type_count"] == 2
        assert stats["method_count"] == 3
        assert stats["field_count"] == 1
        assert stats["resource_count"] == 1

        # enumerate: types / methods / fields / strings all carry real names.
        types = _data(service.dotnet_enumerate(session_id, "types", limit=16))
        assert types["capability"] == "dotnet_metadata"
        assert types["not_ida_idalib"] is True
        assert types["total"] == 2
        assert {t["name"] for t in types["items"]} == {"<Module>", "Sample"}

        methods = _data(service.dotnet_enumerate(session_id, "methods", limit=16))
        assert methods["total"] == 3
        by_name = {m["name"]: m for m in methods["items"]}
        assert set(by_name) == {".cctor", "Add", "Run"}
        # Laid out in row order: the module initializer's body first, then
        # Sample's two methods.
        assert by_name[".cctor"]["rva"] > 0
        assert by_name["Add"]["rva"] > by_name[".cctor"]["rva"]
        assert by_name["Run"]["rva"] > by_name["Add"]["rva"]

        fields = _data(service.dotnet_enumerate(session_id, "fields", limit=16))
        assert [f["name"] for f in fields["items"]] == ["Secret"]

        resources = _data(service.dotnet_enumerate(session_id, "resources", limit=16))
        assert resources["total"] == 1
        resource = resources["items"][0]
        assert resource["name"] == "config.json"
        assert resource["token"] == 0x28000001
        assert resource["flags"] == 0x0001

        strings = _data(service.dotnet_enumerate(session_id, "strings", limit=64))
        string_values = {s["value"] for s in strings["items"]}
        assert {"Sample", "Add", "Run", "MyAssembly"} <= string_values

        # il: the two method bodies disassemble to the CIL we wrote.
        add_token = by_name["Add"]["token"]
        run_token = by_name["Run"]["token"]
        il_add = _data(service.dotnet_il(session_id, add_token))
        assert il_add["backend"] == "dotnet_metadata"
        add_ops = [i["mnemonic"] for i in il_add["instructions"]]
        assert add_ops == ["ldc.i4.5", "ret"]

        il_run = _data(service.dotnet_il(session_id, run_token))
        run_ops = [i["mnemonic"] for i in il_run["instructions"]]
        assert run_ops == ["call", "ret"]
        assert 0x0A000001 in il_run["call_tokens"]

        # xrefs: the weak MemberRef listing surfaces the call target plus the
        # TargetFrameworkAttribute ctor the fixture's CustomAttribute row uses.
        xrefs = _data(service.dotnet_xrefs(session_id, limit=16))
        assert xrefs["kind"] == "xrefs"
        assert xrefs["not_ida_idalib"] is True
        assert xrefs["total"] == 2
        by_token = {item["token"]: item["name"] for item in xrefs["items"]}
        assert by_token == {0x0A000001: "WriteLine", 0x0A000002: ".ctor"}
    finally:
        service.close_all()


@pytest.mark.integration
def test_dotnet_il_rejects_non_methoddef_token(tmp_path: Path) -> None:
    """The IL reader must refuse a token that is not a MethodDef (0x06)."""
    if not _FIXTURE.is_file():
        pytest.skip("minimal .NET fixture missing (skip != pass)")
    service = _service(tmp_path)
    try:
        session_id = _data(service.create_session(str(_FIXTURE)))["session"]["id"]
        bad = service.dotnet_il(session_id, 0x0A000001)  # a MemberRef token
        assert not bad.ok
        assert bad.error is not None
        assert bad.error.code == "invalid_argument"
    finally:
        service.close_all()


@pytest.mark.integration
def test_dotnet_verify_guards_ownership_and_confirms_clr(tmp_path: Path) -> None:
    """dotnet.verify re-inspects an artifact, but only inside the session tree.

    In real use it verifies a de4dot output under ``dotnet/<session>/``; that
    path is de4dot-gated, but the checker and its fail-closed ownership guard
    are not, so we exercise both without de4dot: reject a path outside the
    session tree, accept a verified assembly planted inside it, and still refuse
    an unverified CLR hint even when it is owned.
    """
    if not _FIXTURE.is_file():
        pytest.skip("minimal .NET fixture missing (skip != pass)")
    artifact_root = (tmp_path / "artifacts").resolve()
    service = _service(tmp_path)
    try:
        session_id = _data(service.create_session(str(_FIXTURE)))["session"]["id"]

        # The fixture lives outside the artifact tree: verify must refuse it and
        # report the roots it would have accepted.
        outside = service.dotnet_verify(session_id, str(_FIXTURE))
        assert not outside.ok
        assert outside.error is not None
        assert outside.error.code == "invalid_params"
        roots = outside.error.details["allowed_roots"]
        assert any(str(artifact_root) in r and r.endswith(session_id) for r in roots)

        # Plant a copy inside the owned dotnet/<session> root and verify it.
        owned_dir = artifact_root / "dotnet" / session_id
        owned_dir.mkdir(parents=True, exist_ok=True)
        owned_copy = owned_dir / "candidate.exe"
        shutil.copyfile(_FIXTURE, owned_copy)
        verified = _data(service.dotnet_verify(session_id, str(owned_copy)))
        assert verified["ok"] is True
        assert verified["verify"]["verified_clr"] is True
        assert verified["verify"]["assembly_name"] == "MyAssembly"
        assert verified["claims_universal_unpack"] is False

        # An owned but unverifiable CLR hint is still refused under require_verified.
        if _HINT_FIXTURE.is_file():
            owned_hint = owned_dir / "hint.exe"
            shutil.copyfile(_HINT_FIXTURE, owned_hint)
            refused = service.dotnet_verify(session_id, str(owned_hint))
            assert not refused.ok
            assert refused.error is not None
            assert refused.error.code == "clr_unverified"
    finally:
        service.close_all()
