"""Input guards and structured error arms of the .NET service mixin.

Every arm here must answer with a structured envelope: a missing CLI is
``capability_unavailable`` with a hint, a swapped input file is
``input_changed`` with both hashes, and a tool refusal keeps its own code
instead of collapsing into ``internal_error``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

import headless_re_mcp.core.service_dotnet as service_dotnet_module
from headless_re_mcp.config import Settings
from headless_re_mcp.core.models import Architecture, Session, TargetKind
from headless_re_mcp.core.repository import InMemoryAnalysisRepository
from headless_re_mcp.core.service_dotnet import DotnetAnalysisMixin
from headless_re_mcp.core.session import SessionRegistry, file_sha256
from headless_re_mcp.dotnet.clr_inspect import DotnetInspectError
from headless_re_mcp.dotnet.de4dot import De4dotError
from headless_re_mcp.dotnet.net_reactor_slayer import NetReactorSlayerError

JsonObject = dict[str, Any]


class _Report:
    """The least inspect_dotnet report the flows under test read."""

    metadata_stats = None
    verified_clr = True

    class kind:  # noqa: N801 - stands in for an enum member
        value = "dotnet"

    def to_dict(self) -> JsonObject:
        return {"kind": "dotnet"}


class _Service(DotnetAnalysisMixin):
    def __init__(
        self,
        artifact_root: Path,
        *,
        de4dot: Path | None = None,
        net_reactor_slayer: Path | None = None,
    ) -> None:
        self.settings = Settings(
            ida_home=None,
            x64dbg_source=None,
            x64dbg_headless_x64=None,
            x64dbg_headless_x86=None,
            artifact_root=artifact_root,
            de4dot=de4dot,
            net_reactor_slayer=net_reactor_slayer,
        )
        self.registry = SessionRegistry()
        self.repository = InMemoryAnalysisRepository(artifact_root)
        self._de4dot_runner = _refuse_runner
        self._net_reactor_slayer_runner = _refuse_runner

    def pe_session(self, session_id: str = "sid", *, sha256: str | None = None) -> str:
        binary = self.settings.artifact_root / "sample.exe"
        binary.write_bytes(b"MZ not really a CLR image")
        self.registry.adopt(
            Session(
                id=session_id,
                target=TargetKind.PE,
                binary=binary,
                sha256=sha256 if sha256 is not None else file_sha256(binary),
                architecture=Architecture.X64,
            )
        )
        return session_id


def _refuse_runner(*args: Any, **kwargs: Any) -> Any:
    raise AssertionError("the runner must not be reached in this test")


def _stub_inspect(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(service_dotnet_module, "inspect_dotnet", lambda *a, **k: _Report())


def test_inspect_rejects_a_non_boolean_require_verified(tmp_path: Path) -> None:
    service = _Service(tmp_path)
    sid = service.pe_session()

    result = service.dotnet_inspect(sid, require_verified="yes")  # type: ignore[arg-type]

    assert not result.ok and result.error is not None
    assert result.error.code == "invalid_params"


def test_inspect_keeps_the_structured_code_of_a_clr_refusal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _Service(tmp_path)
    sid = service.pe_session()

    def refuse(*args: Any, **kwargs: Any) -> Any:
        raise DotnetInspectError("not_dotnet", "no CLR header", details={"clue": "mz-only"})

    monkeypatch.setattr(service_dotnet_module, "inspect_dotnet", refuse)
    result = service.dotnet_inspect(sid)

    assert not result.ok and result.error is not None
    assert result.error.code == "not_dotnet"
    assert result.error.details["clue"] == "mz-only"


def test_deobfuscate_without_a_configured_cli_is_unavailable_not_broken(
    tmp_path: Path,
) -> None:
    service = _Service(tmp_path, de4dot=None)
    sid = service.pe_session()

    result = service.dotnet_deobfuscate(sid)

    assert not result.ok and result.error is not None
    assert result.error.code == "capability_unavailable"
    assert "HEADLESS_RE_DE4DOT" in str(result.error.details.get("hint"))


def test_deobfuscate_refuses_an_input_that_changed_after_creation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A swapped sample must not be deobfuscated under the old session identity."""
    service = _Service(tmp_path, de4dot=tmp_path / "de4dot.exe")
    sid = service.pe_session(sha256="0" * 64)
    _stub_inspect(monkeypatch)

    result = service.dotnet_deobfuscate(sid)

    assert not result.ok and result.error is not None
    assert result.error.code == "input_changed"
    assert result.error.details["expected_sha256"] == "0" * 64
    assert result.error.details["actual_sha256"] != "0" * 64


def test_deobfuscate_keeps_the_structured_code_of_a_runner_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _Service(tmp_path, de4dot=tmp_path / "de4dot.exe")
    sid = service.pe_session()
    _stub_inspect(monkeypatch)

    def broken_runner(*args: Any, **kwargs: Any) -> Any:
        raise De4dotError("process_failed", "de4dot exited 1", details={"exit_code": 1})

    service._de4dot_runner = broken_runner
    result = service.dotnet_deobfuscate(sid)

    assert not result.ok and result.error is not None
    assert result.error.code == "process_failed"
    assert result.error.details["exit_code"] == 1


def test_reactor_unpack_without_a_configured_cli_is_unavailable_not_broken(
    tmp_path: Path,
) -> None:
    service = _Service(tmp_path, net_reactor_slayer=None)
    sid = service.pe_session()

    result = service.dotnet_reactor_unpack(sid)

    assert not result.ok and result.error is not None
    assert result.error.code == "capability_unavailable"
    assert "NETReactorSlayer" in str(result.error.details.get("hint"))


def test_reactor_unpack_refuses_an_input_that_changed_after_creation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _Service(tmp_path, net_reactor_slayer=tmp_path / "nrs.exe")
    sid = service.pe_session(sha256="1" * 64)
    _stub_inspect(monkeypatch)

    result = service.dotnet_reactor_unpack(sid)

    assert not result.ok and result.error is not None
    assert result.error.code == "input_changed"
    assert result.error.details["expected_sha256"] == "1" * 64


def test_reactor_unpack_keeps_the_structured_code_of_a_runner_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _Service(tmp_path, net_reactor_slayer=tmp_path / "nrs.exe")
    sid = service.pe_session()
    _stub_inspect(monkeypatch)

    def broken_runner(*args: Any, **kwargs: Any) -> Any:
        raise NetReactorSlayerError("timeout", "unpack outran its deadline")

    service._net_reactor_slayer_runner = broken_runner
    result = service.dotnet_reactor_unpack(sid)

    assert not result.ok and result.error is not None
    assert result.error.code == "timeout"


def test_enumerate_keeps_the_structured_code_of_a_metadata_refusal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _Service(tmp_path)
    sid = service.pe_session()

    def refuse(*args: Any, **kwargs: Any) -> Any:
        raise DotnetInspectError("invalid_argument", "unknown kind")

    monkeypatch.setattr(service_dotnet_module, "enumerate_metadata", refuse)
    result = service.dotnet_enumerate(sid, "typedefs")

    assert not result.ok and result.error is not None
    assert result.error.code == "invalid_argument"


def test_il_disassembles_a_method_and_forwards_the_arguments(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _Service(tmp_path)
    sid = service.pe_session()
    seen: list[tuple[Any, ...]] = []

    def fake_disassemble(path: Path, token: int, *, require_verified: bool) -> JsonObject:
        seen.append((path, token, require_verified))
        return {"token": token, "instructions": []}

    monkeypatch.setattr(service_dotnet_module, "disassemble_method_il", fake_disassemble)
    result = service.dotnet_il(sid, 0x06000001, require_verified=False)

    assert result.ok and result.data is not None
    assert result.data["token"] == 0x06000001
    assert seen == [(service.registry.get(sid).binary, 0x06000001, False)]


def test_il_keeps_the_structured_code_of_a_token_refusal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _Service(tmp_path)
    sid = service.pe_session()

    def refuse(*args: Any, **kwargs: Any) -> Any:
        raise DotnetInspectError("token_not_found", "no MethodDef row for token")

    monkeypatch.setattr(service_dotnet_module, "disassemble_method_il", refuse)
    result = service.dotnet_il(sid, 0x06000099)

    assert not result.ok and result.error is not None
    assert result.error.code == "token_not_found"


def test_xrefs_keeps_the_structured_code_of_a_metadata_refusal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _Service(tmp_path)
    sid = service.pe_session()

    def refuse(*args: Any, **kwargs: Any) -> Any:
        raise DotnetInspectError("not_dotnet", "no CLR metadata")

    monkeypatch.setattr(service_dotnet_module, "list_memberref_xrefs", refuse)
    result = service.dotnet_xrefs(sid)

    assert not result.ok and result.error is not None
    assert result.error.code == "not_dotnet"


def test_inspect_reports_an_unknown_session_as_not_found(tmp_path: Path) -> None:
    result = _Service(tmp_path).dotnet_inspect("never-created")

    assert not result.ok and result.error is not None
    assert result.error.code == "session_not_found"


def test_verify_refuses_a_path_outside_the_session_artifacts(tmp_path: Path) -> None:
    """Verify must not become a read primitive over arbitrary local files."""
    service = _Service(tmp_path)
    sid = service.pe_session()
    foreign = tmp_path / "elsewhere.exe"
    foreign.write_bytes(b"MZ")

    result = service.dotnet_verify(sid, str(foreign))

    assert not result.ok and result.error is not None
    assert result.error.code == "invalid_params"
    assert result.error.details["allowed_roots"]


def test_verify_keeps_the_structured_code_of_an_inspection_refusal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _Service(tmp_path)
    sid = service.pe_session()
    owned = tmp_path / "dotnet" / sid / "candidate.exe"
    owned.parent.mkdir(parents=True, exist_ok=True)
    owned.write_bytes(b"MZ still not a CLR image")

    def refuse(*args: Any, **kwargs: Any) -> Any:
        raise DotnetInspectError("not_dotnet", "no CLR header")

    monkeypatch.setattr(service_dotnet_module, "inspect_dotnet", refuse)
    result = service.dotnet_verify(sid, str(owned))

    assert not result.ok and result.error is not None
    assert result.error.code == "not_dotnet"
