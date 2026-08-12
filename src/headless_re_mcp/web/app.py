"""FastAPI composition root and loopback server launcher."""

from __future__ import annotations

import ipaddress
from typing import Any

from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.error_boundary import (
    install_global_exception_hooks,
    register_fastapi_exception_boundary,
)
from headless_re_mcp.web.auth import ensure_web_token
from headless_re_mcp.web.routes.agent import register_agent_routes
from headless_re_mcp.web.routes.legacy import register_legacy_routes
from headless_re_mcp.web.routes.spa import register_spa_fallback


def create_app(
    service: AnalysisService,
    *,
    token: str,
    settings: Settings | None = None,
) -> Any:
    try:
        from fastapi import FastAPI
    except ImportError as exc:  # pragma: no cover - optional web extra
        raise RuntimeError(
            "web extra required: pip install 'headless-re-mcp[web]'"
        ) from exc

    cfg = settings or service.settings
    install_global_exception_hooks("web")
    app = FastAPI(title="Headless RE-MCP Monitor", docs_url=None, redoc_url=None)
    register_fastapi_exception_boundary(app)
    app.state.service = service
    app.state.token = token
    app.state.settings = cfg
    app.state.bootstrap_sessions = set()
    register_legacy_routes(app, service, token=token, settings=cfg)
    register_agent_routes(app, service, token=token, settings=cfg)
    register_spa_fallback(app, token=token)
    return app


def run_web(
    settings: Settings,
    *,
    host: str | None = None,
    port: int | None = None,
    auto_port: bool = True,
    port_span: int = 40,
    quiet_banner: bool = False,
) -> int:
    """Run the loopback web console.

    When ``auto_port`` is true and the preferred port is busy, bind the next free
    port in ``[preferred, preferred+port_span]``.
    """
    from headless_re_mcp.web.launch_util import choose_bind_port

    bind_host = host or settings.http_host
    preferred = port if port is not None else settings.http_port
    try:
        addr = ipaddress.ip_address(bind_host)
    except ValueError:
        print(f"拒绝绑定：主机不是合法 IP：{bind_host}")
        return 2
    if not addr.is_loopback:
        print(f"拒绝绑定：仅允许回环地址，当前为 {bind_host}")
        return 2

    bind_port, reason = choose_bind_port(
        bind_host,
        int(preferred),
        span=port_span,
        auto=auto_port,
    )
    if reason == "busy":
        print(f"端口已被占用且未启用自动换端口：{bind_host}:{preferred}")
        return 3
    if reason == "exhausted":
        print(
            f"端口区间均不可用：{bind_host}:{preferred}-"
            f"{int(preferred) + max(1, port_span)}，请关闭占用进程或指定 --port"
        )
        return 3

    token, token_path = ensure_web_token(settings)
    service = AnalysisService(settings)
    app = create_app(service, token=token, settings=settings)
    # Expose the effective bind for callers / tests.
    app.state.bind_host = bind_host
    app.state.bind_port = bind_port

    try:
        import uvicorn
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError(
            "需要 web 额外依赖：pip install 'headless-re-mcp[web]'"
        ) from exc

    if not quiet_banner:
        if reason == "fallback":
            print(f"端口 {preferred} 已被占用，自动改用 {bind_port}")
        print(f"监控台已启动：http://{bind_host}:{bind_port}/?token=…")
        print(f"Token 文件：{token_path}")
        print("仅本机回环可访问；非本机连接将返回 403。")

    uvicorn.run(app, host=bind_host, port=bind_port, log_level="warning")
    return 0
