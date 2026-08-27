"""项目根目录启动脚本：依赖预检 → 自动端口 → 打开监控台。

用法：
  python start_web.py
  python start_web.py --wizard
  python start_web.py --port 8765 --no-browser
  python start_web.py --no-auto-port
"""

from __future__ import annotations

import argparse
import os
import sys
import threading
import time
import webbrowser
from pathlib import Path


def _ensure_src_on_path() -> Path:
    root = Path(__file__).resolve().parent
    src = root / "src"
    if src.is_dir():
        src_s = str(src)
        if src_s not in sys.path:
            sys.path.insert(0, src_s)
    os.chdir(root)
    return root


def _log(msg: str) -> None:
    print(msg, flush=True)


def _bracketed_authority(host: str, port: int) -> str:
    """Return ``host:port`` for a URL, bracketing an IPv6 literal host.

    ``run_web`` accepts any loopback address, ``::1`` among them. Without
    brackets ``http://::1:8765/`` is not a URL a browser can parse -- the
    authority needs ``[::1]`` to separate the host from the port -- so the
    printed link and the one handed to ``webbrowser.open`` both pointed nowhere
    on an IPv6-loopback console. IPv4 and hostnames are returned unchanged.
    """
    host_part = f"[{host}]" if ":" in host else host
    return f"{host_part}:{int(port)}"


def _preflight(settings: object) -> int:
    """在 WebUI 起来之前跑安装向导同款依赖步骤。返回非 0 表示严重失败。"""
    from headless_re_mcp.web.setup import run_setup_step

    _log("")
    _log("======== 启动前依赖检测 ========")
    steps = (
        ("environment", "运行环境"),
        ("sync_x64dbg", "同步 x64dbg → external/"),
        ("probe_runtimes", "运行时路径探针"),
        ("persist_defaults", "固化默认配置"),
    )
    hard_fail = False
    for step, title in steps:
        _log(f"[检测] {title} …")
        try:
            result = run_setup_step(settings, step)  # type: ignore[arg-type]
        except Exception as exc:  # pragma: no cover
            _log(f"[失败] {title}：{exc}")
            hard_fail = True
            continue
        ok = bool(result.get("ok"))
        mark = "通过" if ok else "警告"
        _log(f"[{mark}] {title}")
        if step == "environment":
            py = result.get("python") or {}
            web = result.get("web_extra") or {}
            _log(f"  Python：{py.get('version')}（{py.get('executable')}）")
            web_status = "已安装" if web.get("ok") else '缺失 — pip install -e ".[web]"'
            _log(f"  Web 依赖：{web_status}")
            if not ok:
                hard_fail = True
        elif step == "sync_x64dbg":
            for item in result.get("items") or []:
                arch = item.get("arch")
                if item.get("copied"):
                    _log(f"  {arch}：已同步到 {item.get('destination')}")
                elif item.get("already_present"):
                    _log(f"  {arch}：external 已存在")
                elif item.get("ok"):
                    _log(f"  {arch}：发现现有 headless → {item.get('headless')}")
                else:
                    _log(f"  {arch}：未找到（可稍后构建或手动同步）")
        elif step == "probe_runtimes":
            for check in result.get("checks") or []:
                cid = check.get("id")
                if check.get("ok"):
                    _log(f"  {cid}：就绪 → {check.get('path')}")
                else:
                    note = "（IDA 需本机授权，禁止打包）" if cid == "ida_home" else ""
                    _log(f"  {cid}：未就绪{note}")
        elif step == "persist_defaults":
            _log(f"  配置文件：{result.get('config_path')}")
            _log(f"  写入键：{', '.join(result.get('written_keys') or [])}")

    _log("提示：IDA 不会被打包；可在监控台安装向导中配置路径。")
    _log("提示：claims_universal_unpack=false")
    _log("======== 依赖检测结束 ========")
    _log("")
    return 1 if hard_fail else 0


def _mandate_hidden_desktop(settings: object, config_path: Path | None) -> object:
    """Web console always streams x64dbg from a hidden Win32 desktop."""
    from headless_re_mcp.config import update_config_values

    if not bool(getattr(settings, "hidden_desktop", False)):
        _log("已强制开启隐藏虚拟桌面（分析会话的窗口在隔离桌面上监视）。")
    object.__setattr__(settings, "hidden_desktop", True)
    update_config_values({"hidden_desktop": True}, config_path=config_path)
    return settings


def main(argv: list[str] | None = None) -> int:
    root = _ensure_src_on_path()

    parser = argparse.ArgumentParser(
        description="启动 Headless RE-MCP 本机监控台（含依赖预检与自动换端口）",
    )
    parser.add_argument("--host", default=None, help="回环地址（默认读取配置）")
    parser.add_argument("--port", type=int, default=None, help="首选端口（默认 8765）")
    parser.add_argument("--wizard", action="store_true", help="打开浏览器并强制进入安装向导")
    parser.add_argument("--no-browser", action="store_true", help="不自动打开浏览器")
    parser.add_argument("--no-auto-port", action="store_true", help="端口占用时不自动换端口")
    parser.add_argument("--skip-preflight", action="store_true", help="跳过启动前依赖检测")
    parser.add_argument("--config", type=Path, default=None, help="可选 config.json 路径")
    parser.add_argument("--port-span", type=int, default=40, help="自动换端口时向后尝试的数量")
    args = parser.parse_args(argv)

    try:
        from headless_re_mcp.config import Settings
        from headless_re_mcp.web.app import run_web
        from headless_re_mcp.web.auth import ensure_web_token
        from headless_re_mcp.web.launch_util import choose_bind_port, probe_our_healthz
    except ImportError as exc:
        _log("无法导入 headless_re_mcp。请先安装：")
        _log('  python -m pip install -e ".[web]"')
        _log(f"详情：{exc}")
        return 1

    _log("Headless RE-MCP 监控台启动器")
    _log(f"项目根目录：{root}")

    settings = Settings.load(config_path=args.config) if args.config else Settings.load()
    settings = _mandate_hidden_desktop(settings, args.config)
    if not args.skip_preflight:
        code = _preflight(settings)
        if code != 0:
            _log("环境检测未通过（例如缺少 Web 依赖）。已中止启动。")
            return code
        # 预检可能写入了 config / external，重新加载 Settings。
        settings = Settings.load(config_path=args.config) if args.config else Settings.load()
        settings = _mandate_hidden_desktop(settings, args.config)

    host = args.host or settings.http_host or "127.0.0.1"
    preferred = args.port if args.port is not None else int(settings.http_port or 8765)
    auto_port = not args.no_auto_port
    token, token_path = ensure_web_token(settings)

    # 若首选端口上已有本服务，直接复用，避免 10048。
    existing = probe_our_healthz(host, preferred)
    if existing is not None:
        query = f"token={token}"
        if args.wizard:
            query += "&wizard=1"
        authority = _bracketed_authority(host, preferred)
        url = f"http://{authority}/?{query}"
        _log(f"检测到监控台已在运行：http://{authority}/")
        _log(f"Token 文件：{token_path}")
        _log("将打开已有实例，不再重复绑定端口。")
        if not args.no_browser:
            try:
                webbrowser.open(url)
            except Exception as exc:  # pragma: no cover
                _log(f"打开浏览器失败：{exc}")
                _log(f"请手动访问：{url}")
        else:
            _log(f"请手动访问：{url}")
        return 0

    bind_port, reason = choose_bind_port(
        host,
        preferred,
        span=max(1, int(args.port_span)),
        auto=auto_port,
    )
    if reason == "busy":
        _log(
            f"端口 {host}:{preferred} 已被占用，且未启用自动换端口"
            "（可用默认行为或去掉 --no-auto-port）。"
        )
        return 3
    if reason == "exhausted":
        _log(f"端口 {preferred} 起连续 {args.port_span} 个均不可用，请释放端口或指定 --port。")
        return 3
    if reason == "fallback":
        _log(f"端口 {preferred} 已被占用，自动改用 {bind_port}")

    query = f"token={token}"
    if args.wizard:
        query += "&wizard=1"
    authority = _bracketed_authority(host, bind_port)
    url = f"http://{authority}/?{query}"

    _log(f"监听地址：http://{authority}/")
    _log(f"完整 URL：{url}")
    _log(f"Token 文件：{token_path}")
    _log("说明：IDA 永不打包；需要时在安装向导中配置本机路径。")
    _log("提示：python start_web.py --wizard")

    if not args.no_browser:
        def _open() -> None:
            # 等 uvicorn 完成绑定后再打开，避免连上旧端口。
            for _ in range(40):
                if probe_our_healthz(host, bind_port) is not None:
                    break
                time.sleep(0.15)
            try:
                webbrowser.open(url)
            except Exception as exc:  # pragma: no cover
                _log(f"打开浏览器失败：{exc}")

        threading.Thread(target=_open, daemon=True).start()

    # run_web 再做一次自动换端口保护（竞态下仍可能被抢占）。
    return run_web(
        settings,
        host=host,
        port=bind_port,
        auto_port=auto_port,
        port_span=max(1, int(args.port_span)),
        quiet_banner=True,
    )


if __name__ == "__main__":
    _ensure_src_on_path()
    try:
        from headless_re_mcp.error_boundary import run_cli_safely
    except ImportError as exc:
        _log(f"启动器依赖尚未安装：{exc}")
        _log("请先运行一键安装：python setup.py")
        raise SystemExit(1) from None
    raise SystemExit(run_cli_safely(lambda: main(), context="start-web"))
