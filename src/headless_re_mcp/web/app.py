"""FastAPI composition root and loopback server launcher."""

from __future__ import annotations

import ipaddress
import os
from pathlib import Path
from typing import Any

from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.error_boundary import (
    install_global_exception_hooks,
    register_fastapi_exception_boundary,
)
from headless_re_mcp.telemetry import configure_telemetry_logging
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


def _claim_artifact_root(root: Path) -> int | None:
    """Hold this artifact root for one console. None when another already has it.

    A second console on the same root is not additive. Creating the app declares
    every run the first one has in flight dead and requeues its missions, and
    then both schedulers claim from the same database. Measured: a run that was
    streaming became interrupted with service_restarted while the first instance
    was still executing it, and the default auto-port made a second start
    succeed rather than collide.

    An operating-system lock rather than a lease, because the supervisor
    restarts this within a second of killing it and a lease would leave the
    replacement waiting for its own predecessor to expire. The kernel releases
    this the moment the holder dies, however it dies.
    """
    try:
        (root / "meta").mkdir(parents=True, exist_ok=True)
        handle = os.open(root / "meta" / "console.lock", os.O_CREAT | os.O_RDWR)
    except OSError:
        # Cannot make the lock. That is not a reason to refuse to serve.
        return -1
    try:
        if os.name == "nt":
            import msvcrt

            msvcrt.locking(handle, msvcrt.LK_NBLCK, 1)
        else:
            import fcntl  # type: ignore[import-not-found,unused-ignore]

            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)  # type: ignore[attr-defined,unused-ignore]
    except OSError:
        os.close(handle)
        return None
    return handle


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

    claim = _claim_artifact_root(settings.artifact_root)
    if claim is None:
        print(
            "另一个控制台已在使用同一制品目录："
            f"{settings.artifact_root}\n"
            "第二个实例会把前一个正在执行的 run 标记为中断并重新排队它的任务，"
            "两个调度器随后会抢同一个数据库。请先停止它，或改用其它 artifact_root。"
        )
        # 78 is the sysexits code for a correct invocation against a
        # configuration that cannot work. A supervisor reads it as a refusal and
        # stops, rather than restarting a child that will refuse again.
        return 78

    configure_telemetry_logging()
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

    try:
        uvicorn.run(app, host=bind_host, port=bind_port, log_level="warning")
    finally:
        # The stdio transport has always done this on the way out; this one
        # never did. A session owns a real IDA or x64dbg process and the
        # debuggee under it, none of which exit because the server did, so
        # every shutdown left them running -- and the supervised deployment
        # restarts this process on purpose. An IDA instance is measured in
        # gigabytes, so a few restarts is a machine that has to be rebooted.
        service.close_all()
    return 0
