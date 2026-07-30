"""Shared first-run configuration logic for CLI and native GUI."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

JsonObject = dict[str, Any]


def ensure_repo_on_path() -> Path:
    """Put repo ``src`` on ``sys.path`` and chdir to repo root."""
    # native_app -> headless_re_mcp -> src -> repo
    root = Path(__file__).resolve().parents[3]
    # When installed as a package, parents[3] may not be the repo; fall back.
    if not (root / "src" / "headless_re_mcp").is_dir():
        from headless_re_mcp.config import repo_root

        root = repo_root()
    src = root / "src"
    if src.is_dir():
        src_s = str(src)
        if src_s not in sys.path:
            sys.path.insert(0, src_s)
    os.chdir(root)
    return root


def discover_defaults() -> JsonObject:
    from headless_re_mcp.config import (
        Settings,
        discover_ida_home,
        discover_x64dbg_headless,
        list_ida_install_candidates,
    )

    settings = Settings.load()
    return {
        "ida_home": discover_ida_home() or settings.ida_home,
        "ida_candidates": list_ida_install_candidates(),
        "x64dbg_headless_x64": discover_x64dbg_headless("x64") or settings.x64dbg_headless_x64,
        "x64dbg_headless_x86": discover_x64dbg_headless("x86") or settings.x64dbg_headless_x86,
        "upx": settings.upx,
        "diec": settings.diec,
        "r2": settings.r2,
        "cdb": settings.cdb,
        "ghidra_home": settings.ghidra_home,
        "de4dot": settings.de4dot,
    }


def apply_paths(
    updates: dict[str, Any],
    *,
    activate_ida: bool = False,
) -> JsonObject:
    """Write user config.json and optionally activate idalib."""
    from headless_re_mcp.config import Settings, default_config_path, update_config_values
    from headless_re_mcp.web.setup import configure_ida

    cleaned: dict[str, Any] = {
        "local_full_access": True,
        "http_host": "127.0.0.1",
        "http_port": 8765,
    }
    for key, value in updates.items():
        if value in (None, ""):
            continue
        cleaned[key] = Path(str(value)).expanduser().resolve()

    config_path = update_config_values(cleaned)
    activation: JsonObject | None = None
    ida = cleaned.get("ida_home")
    if activate_ida and ida is not None:
        activation = configure_ida(ida_home=ida, activate=True, config_path=config_path)

    settings = Settings.load(config_path=config_path)
    return {
        "ok": True,
        "config_path": str(config_path),
        "default_config_path": str(default_config_path()),
        "written": {k: str(v) if isinstance(v, Path) else v for k, v in cleaned.items()},
        "activation": activation,
        "settings": settings,
    }


def sync_and_probe() -> list[JsonObject]:
    from headless_re_mcp.config import Settings
    from headless_re_mcp.web.setup import run_setup_step

    settings = Settings.load()
    results: list[JsonObject] = []
    for step in ("sync_x64dbg", "probe_runtimes", "persist_defaults"):
        try:
            results.append(run_setup_step(settings, step))
        except Exception as exc:  # pragma: no cover
            results.append({"ok": False, "step": step, "error": str(exc)})
    return results


def export_mcp_files(repo_root: Path) -> JsonObject:
    from headless_re_mcp.config import Settings, default_config_path
    from headless_re_mcp.config_generate import export_mcp_environment

    settings = Settings.load()
    export = export_mcp_environment(
        settings,
        persist=True,
        config_path=default_config_path(),
    )
    examples = export.get("examples") or {}
    cursor = examples.get("cursor") if isinstance(examples, dict) else None
    written_cursor = None
    if isinstance(cursor, dict):
        cursor_dir = repo_root / ".cursor"
        cursor_dir.mkdir(parents=True, exist_ok=True)
        path = cursor_dir / "mcp.json"
        path.write_text(json.dumps(cursor, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        written_cursor = str(path)
    return {
        "ok": bool(export.get("ok")),
        "written": export.get("written") or {},
        "cursor_mcp": written_cursor,
        "cursor_payload": cursor if isinstance(cursor, dict) else None,
        "doctor_ready": export.get("doctor_ready"),
    }


def run_doctor_summary() -> JsonObject:
    from headless_re_mcp.config import Settings
    from headless_re_mcp.doctor import run_doctor

    report = run_doctor(Settings.load())
    return {
        "ready": report.ready,
        "probes": [
            {
                "name": p.name,
                "status": p.status.value,
                "summary": p.summary,
            }
            for p in report.probes
        ],
    }


def pip_install_editable(repo_root: Path, extras: str = ".[dev,ida,pe,web]") -> int:
    cmd = [sys.executable, "-m", "pip", "install", "-e", extras]
    completed = subprocess.run(cmd, cwd=str(repo_root), check=False)
    return int(completed.returncode)


def start_mcp_serve() -> subprocess.Popen[Any]:
    """Start MCP stdio server as a detached-ish child (caller manages lifetime)."""
    return subprocess.Popen(
        [sys.executable, "-m", "headless_re_mcp", "serve"],
        cwd=str(ensure_repo_on_path()),
    )


def start_web_console() -> subprocess.Popen[Any]:
    """Start local web console process (UI chrome stays native; browser is optional client)."""
    return subprocess.Popen(
        [sys.executable, "-m", "headless_re_mcp", "serve-web"],
        cwd=str(ensure_repo_on_path()),
    )


def _ask(prompt: str, default: str | None = None) -> str:
    suffix = f" [{default}]" if default else ""
    raw = input(f"{prompt}{suffix}: ").strip()
    if raw == "" and default is not None:
        return default
    return raw


def _ask_yes(prompt: str, *, default: bool = False) -> bool:
    hint = "Y/n" if default else "y/N"
    raw = input(f"{prompt} ({hint}): ").strip().lower()
    if raw == "":
        return default
    return raw in {"y", "yes", "是", "1", "true"}


def _resolve_path(text: str, *, expect: str) -> Path | None:
    raw = text.strip().strip('"').strip("'")
    if not raw or raw in {"-", "skip", "无", "n"}:
        return None
    path = Path(raw).expanduser()
    try:
        path = path.resolve()
    except OSError:
        print(f"  ! 无法解析：{raw}", flush=True)
        return None
    if expect == "dir" and not path.is_dir():
        print(f"  ! 不是目录：{path}", flush=True)
        return None
    if expect == "file" and not path.is_file():
        print(f"  ! 文件不存在：{path}", flush=True)
        return None
    return path


def _ask_path_cli(
    title: str,
    *,
    expect: str,
    detected: Path | None,
    required: bool,
    non_interactive: bool,
) -> Path | None:
    print(f"\n—— {title} ——", flush=True)
    if detected is not None:
        print(f"  已检测到：{detected}", flush=True)
    else:
        print("  未自动检测到", flush=True)
    if non_interactive:
        if detected is None and required:
            raise SystemExit(f"非交互模式缺少必需路径：{title}")
        return detected
    while True:
        default = str(detected) if detected is not None else None
        raw = _ask("  回车采用检测值 / 输入路径 / - 跳过", default=default)
        if raw in {"-", "skip", "无"}:
            if required and detected is None:
                print("  此项为必需", flush=True)
                continue
            return None if detected is None else detected if raw == "" else None
        path = _resolve_path(raw, expect=expect)
        if path is None:
            if required:
                continue
            return None
        if expect == "dir" and title.startswith("IDA"):
            from headless_re_mcp.config import validate_ida_home

            checked = validate_ida_home(path)
            if not checked.get("ok"):
                print(f"  ! {checked.get('message')}", flush=True)
                if not _ask_yes("  仍使用该路径？", default=False):
                    continue
        return path


def run_cli_setup(
    *,
    skip_pip: bool = False,
    non_interactive: bool = False,
    activate_ida: bool = True,
) -> int:
    root = ensure_repo_on_path()
    print("Headless RE-MCP 首次配置（CLI）", flush=True)
    print(f"仓库：{root}", flush=True)

    if not skip_pip and (non_interactive or _ask_yes('执行 pip install -e ".[dev,ida,pe,web]"？', default=True)):
        code = pip_install_editable(root)
        print(f"pip 退出码：{code}", flush=True)

    defaults = discover_defaults()
    ida = _ask_path_cli(
        "IDA Professional 9.x 安装目录",
        expect="dir",
        detected=defaults.get("ida_home"),  # type: ignore[arg-type]
        required=True,
        non_interactive=non_interactive,
    )
    x64 = _ask_path_cli(
        "x64dbg headless.exe (x64)",
        expect="file",
        detected=defaults.get("x64dbg_headless_x64"),  # type: ignore[arg-type]
        required=True,
        non_interactive=non_interactive,
    )
    x86 = _ask_path_cli(
        "x64dbg headless.exe (x86)",
        expect="file",
        detected=defaults.get("x64dbg_headless_x86"),  # type: ignore[arg-type]
        required=True,
        non_interactive=non_interactive,
    )

    updates: dict[str, Any] = {
        "ida_home": ida,
        "x64dbg_headless_x64": x64,
        "x64dbg_headless_x86": x86,
    }
    if non_interactive or _ask_yes("配置可选工具（UPX/DIE/Rizin/cdb）？", default=False):
        for key, title, expect in (
            ("upx", "UPX upx.exe", "file"),
            ("diec", "DIE diec.exe", "file"),
            ("r2", "Rizin/r2", "file"),
            ("cdb", "cdb.exe", "file"),
        ):
            updates[key] = _ask_path_cli(
                title,
                expect=expect,
                detected=defaults.get(key),  # type: ignore[arg-type]
                required=False,
                non_interactive=non_interactive,
            )

    result = apply_paths(updates, activate_ida=activate_ida and ida is not None)
    print(f"已写入：{result['config_path']}", flush=True)
    for item in sync_and_probe():
        print(f"  [{('OK' if item.get('ok') else 'WARN')}] {item.get('step')}", flush=True)
    mcp = export_mcp_files(root)
    if mcp.get("cursor_mcp"):
        print(f"Cursor MCP 文件：{mcp['cursor_mcp']}", flush=True)
    payload = mcp.get("cursor_payload")
    if isinstance(payload, dict):
        print("======== MCP 配置（可复制到 Cursor mcp.json） ========", flush=True)
        print(json.dumps(payload, indent=2, ensure_ascii=False), flush=True)
        print("======== MCP 配置结束 ========", flush=True)
    doctor = run_doctor_summary()
    print(f"doctor.ready = {doctor['ready']}", flush=True)
    for probe in doctor["probes"]:
        print(f"  [{probe['status']}] {probe['name']}: {probe['summary']}", flush=True)
    return 0 if doctor["ready"] else 2
