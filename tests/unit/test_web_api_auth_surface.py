"""Pin that every HTTP ``/api`` route is wired to an auth guard.

Each route's authorization is enforced by a call inside the handler
(``authorize`` for the agent router, ``_require_token`` for the legacy/provider
router), not by a shared dependency the framework applies for us. That makes an
omission invisible: a new ``/api`` route that simply forgets the call ships as a
world-readable (loopback) endpoint, and every existing per-route test still
passes because it only exercises the routes it names. The token itself is
sound and constant-time compared; the risk is a route that never reaches the
check.

Assert structurally -- the shipped app's real routes, not a mock -- that every
``/api`` handler references one of the known guards. A guard is a closure over
the router factory, so the reference lands in the endpoint's free variables; a
handler that never names it is one that never calls it. Public, unauthenticated
endpoints (``/healthz``, ``/readyz``, ``/metrics``) live outside ``/api`` by
design and are out of scope here.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest
from fastapi.routing import APIRoute

from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.web.app import create_app

# The auth guards a handler may call. Renaming or adding one is a reviewed act:
# a new name that is not here makes every route using it read as unguarded, so
# the mismatch surfaces for a human rather than passing silently.
_AUTH_GUARDS = frozenset({"authorize", "_require_token", "require_token"})


def _referenced_names(endpoint: object) -> set[str]:
    code = endpoint.__code__  # type: ignore[attr-defined]
    return set(code.co_freevars) | set(code.co_names)


def test_every_web_api_route_references_an_auth_guard(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HEADLESS_RE_PROVIDER_CONFIG", str(tmp_path / "providers.json"))
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    try:
        app = create_app(service, token="web-secret", settings=settings)
        api_routes = [
            route
            for route in app.routes
            if isinstance(route, APIRoute) and route.path.startswith("/api/")
        ]
        assert api_routes, "expected the web app to expose /api routes"

        unguarded = {
            route.path: sorted(route.methods or ())
            for route in api_routes
            if not (_AUTH_GUARDS & _referenced_names(route.endpoint))
        }
        assert unguarded == {}, f"/api routes with no auth-guard reference: {unguarded}"

        # Non-vacuous: the two guards that actually protect the /api surface are
        # both in play, so the assertion above cannot pass because nothing named
        # a guard at all.
        used: set[str] = set()
        for route in api_routes:
            used |= _AUTH_GUARDS & _referenced_names(route.endpoint)
        assert {"authorize", "_require_token"} <= used
    finally:
        service.close_all()
