"""unpack.plan Gate: a side-effect-free route plan that honours a forced override.

``unpack.plan`` turns detection into an ordered, non-authoritative plan: it runs
``packer.classify`` plus the built-in PE scan, picks a route and a backend, and lays
out the exact tool steps an operator would run -- *without* executing any of them. It
is the read-only sibling of ``unpack.start`` and the tool an agent calls to decide what
to do next.

It has no integration coverage at all. The only end-to-end unpack gates
(``test_unpack_live_gate.py``, ``test_m5_unpack_live_gate.py``) require x64dbg + IDA +
DIE and are Windows-only, and the detection triage gate stops at ``unpack.recommend``,
which never emits the ordered ``steps`` / ``backend`` that ``unpack.plan`` adds. This
gate drives it on the committed UPX fixture pair with every backend unset and proves:

  * a real UPX-packed image plans the ordered UPX route (``m3_upx``: detect -> upx.test
    -> upx.unpack -> verify -> reanalyze) while its unpacked twin plans the inert
    ``none`` route (detect -> static.open);
  * planning is genuinely inert -- it opens no unpack orchestration and writes no
    unpack artifacts;
  * ``force_route`` overrides the detection verdict and rebuilds the step list for the
    forced backend;
  * an unknown ``force_route`` is refused with an envelope.

No external tool is involved, so nothing should skip on any platform; a missing fixture
skips loudly (skip != pass).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService, JsonObject

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_FIXTURES = _PROJECT_ROOT / "fixtures" / "upx"

_ARCHES = [pytest.param("x86", id="x86"), pytest.param("x64", id="x64")]

# The route builder is deterministic; these are the exact ordered steps it emits.
_UPX_PLAN_STEPS = [
    ("detect", "detect.scan", True),
    ("upx_test", "unpack.upx.test", True),
    ("upx_unpack", "unpack.upx.unpack", True),
    ("verify", "unpack.verify", False),
    ("reanalyze", "static.open", False),
]
_NONE_PLAN_STEPS = [
    ("detect", "detect.scan", True),
    ("static", "static.open", False),
]


def _fixture_pair(arch: str) -> tuple[Path, Path]:
    packed = _FIXTURES / f"console_fixture-{arch}.upx.exe"
    unpacked = _FIXTURES / f"console_fixture-{arch}.pre-upx.exe"
    for path in (packed, unpacked):
        if not path.is_file():
            pytest.skip(f"missing committed UPX fixture: {path} (skip != pass)")
    return packed, unpacked


def _service(tmp_path: Path) -> AnalysisService:
    settings = Settings(
        ida_home=None,
        x64dbg_source=None,
        x64dbg_headless_x64=None,
        x64dbg_headless_x86=None,
        artifact_root=tmp_path / "artifacts",
        upx=None,
        diec=None,
    )
    return AnalysisService(settings)


def _data(result: object) -> JsonObject:
    assert getattr(result, "ok", False), getattr(result, "error", None)
    data = getattr(result, "data", None)
    assert isinstance(data, dict)
    return data


def _session_id(service: AnalysisService, binary: Path) -> str:
    created = _data(service.create_session(str(binary)))
    session = created["session"]
    assert isinstance(session, dict)
    return str(session["id"])


def _steps(plan: JsonObject) -> list[tuple[str, str, bool]]:
    return [(str(s["id"]), str(s["tool"]), bool(s["required"])) for s in plan["steps"]]


@pytest.mark.integration
@pytest.mark.parametrize("arch", _ARCHES)
def test_unpack_plan_routes_a_upx_binary_and_its_clean_twin(tmp_path: Path, arch: str) -> None:
    packed, unpacked = _fixture_pair(arch)
    service = _service(tmp_path)
    try:
        packed_id = _session_id(service, packed)
        plan = _data(service.unpack_plan(packed_id, use_die=False))["plan"]
        assert plan["route"] == "upx", plan
        assert plan["backend"] == "m3_upx", plan
        assert _steps(plan) == _UPX_PLAN_STEPS, _steps(plan)
        # A plan is a suggestion, never a verdict.
        assert plan["authoritative"] is False, plan
        assert plan["claims_universal_unpack"] is False, plan

        # Planning is inert: it must not open an unpack orchestration.
        status = service.unpack_status(packed_id)
        assert status.ok is False
        assert status.error is not None
        assert status.error.code == "unpack_not_started", status.error

        # ... and it must not write any unpack output under the artifact root.
        artifact_root = (tmp_path / "artifacts").resolve()
        unpack_dir = artifact_root / "unpack"
        assert not unpack_dir.exists() or not any(unpack_dir.rglob("*")), list(
            unpack_dir.rglob("*")
        )

        clean_id = _session_id(service, unpacked)
        clean_plan = _data(service.unpack_plan(clean_id, use_die=False))["plan"]
        assert clean_plan["route"] == "none", clean_plan
        assert clean_plan["backend"] == "none", clean_plan
        assert _steps(clean_plan) == _NONE_PLAN_STEPS, _steps(clean_plan)
    finally:
        service.close_all()


@pytest.mark.integration
def test_unpack_plan_force_route_overrides_detection(tmp_path: Path) -> None:
    packed, unpacked = _fixture_pair("x64")
    service = _service(tmp_path)
    try:
        # The clean twin detects as "none"; forcing a dynamic route must rebuild the
        # plan around that backend rather than defer to detection.
        clean_id = _session_id(service, unpacked)
        forced = _data(service.unpack_plan(clean_id, use_die=False, force_route="generic_dynamic"))
        plan = forced["plan"]
        assert plan["route"] == "generic_dynamic", plan
        assert plan["backend"] == "m4_generic", plan
        assert forced["force_route"] == "generic_dynamic", forced
        tools = [step["tool"] for step in plan["steps"]]
        assert "dynamic.open" in tools and "unpack.dump_module" in tools, tools
        # The UPX-only steps must be gone: this is a different route entirely.
        assert "unpack.upx.unpack" not in tools, tools

        # bounded_dynamic is the only route that carries the iat.validate gate step,
        # so forcing it on the packed image is a distinct, checkable shape.
        packed_id = _session_id(service, packed)
        bounded = _data(
            service.unpack_plan(packed_id, use_die=False, force_route="bounded_dynamic")
        )["plan"]
        assert bounded["route"] == "bounded_dynamic", bounded
        assert bounded["backend"] == "m4_bounded", bounded
        assert any(step["id"] == "iat_validate" for step in bounded["steps"]), bounded
    finally:
        service.close_all()


@pytest.mark.integration
def test_unpack_plan_rejects_an_unknown_force_route(tmp_path: Path) -> None:
    packed, _ = _fixture_pair("x64")
    service = _service(tmp_path)
    try:
        session_id = _session_id(service, packed)
        bad = service.unpack_plan(session_id, use_die=False, force_route="not_a_route")
        assert bad.ok is False
        assert bad.error is not None
        assert bad.error.code == "invalid_request", bad.error
    finally:
        service.close_all()
