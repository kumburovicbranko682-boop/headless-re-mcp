"""Production SPA fallback registered after all API routers."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from headless_re_mcp.web.auth import tokens_match

if TYPE_CHECKING:
    from fastapi import FastAPI


def register_spa_fallback(app: FastAPI, *, token: str) -> None:
    from fastapi import Header, HTTPException, Query
    from fastapi.responses import HTMLResponse

    spa_dir = Path(__file__).resolve().parents[1] / "spa"

    def require_token(authorization: str | None, token_query: str | None) -> None:
        provided = None
        if authorization and authorization.lower().startswith("bearer "):
            provided = authorization[7:].strip()
        elif token_query:
            provided = token_query.strip()
        if not tokens_match(provided, token):
            raise HTTPException(status_code=401, detail="unauthorized")

    @app.get("/{spa_path:path}", response_class=HTMLResponse)
    def spa_fallback(
        spa_path: str,
        authorization: str | None = Header(default=None),
        token_q: str | None = Query(default=None, alias="token"),
    ) -> HTMLResponse:
        require_token(authorization, token_q)
        if spa_path.startswith("api/") or spa_path == "healthz" or spa_path.startswith("assets/"):
            raise HTTPException(status_code=404, detail="not_found")
        index_path = spa_dir / "index.html"
        if not index_path.is_file():
            raise HTTPException(
                status_code=503,
                detail="WebUI build missing; run: cd webui; npm ci; npm run build",
            )
        return HTMLResponse(index_path.read_text(encoding="utf-8"))

