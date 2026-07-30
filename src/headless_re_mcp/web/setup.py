"""Install / first-run setup steps for the local web wizard (loopback only)."""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
import sys
from dataclasses import replace
from pathlib import Path
from typing import Any

from headless_re_mcp.config import (
    Settings,
    default_config_path,
    default_data_path,
    discover_x64dbg_headless,
    list_ida_install_candidates,
    repo_root,
    update_config_values,
    validate_ida_home,
)
from headless_re_mcp.doctor import ProbeStatus, probe_ida, run_doctor
from headless_re_mcp.web.deps import build_deps_snapshot

JsonObject = dict[str, Any]

SETUP_STEPS = (
    "environment",
    "sync_x64dbg",
    "probe_runtimes",
    "configure_ida",
    "doctor",
    "persist_defaults",
    "generate_mcp",
    "finalize",
)


def _no_window_flags() -> int:
    if os.name == "nt":
        return getattr(subprocess, "CREATE_NO_WINDOW", 0)
    return 0


def setup_status(settings: Settings) -> JsonObject:
    probe = probe_ida(settings)
    deps = build_deps_snapshot(settings)
    return {
        "ok": True,
        "config_path": str(default_config_path()),
        "data_path": str(default_data_path()),
        "repo_root": str(repo_root()),
        "ida_home": str(settings.ida_home) if settings.ida_home else None,
        "env_override": bool(os.environ.get("HEADLESS_RE_IDA_HOME")),
        "candidates": [str(path) for path in list_ida_install_candidates()],
        "x64dbg_headless_x64": str(settings.x64dbg_headless_x64)
        if settings.x64dbg_headless_x64
        else None,
        "x64dbg_headless_x86": str(settings.x64dbg_headless_x86)
        if settings.x64dbg_headless_x86
        else None,
        "steps": list(SETUP_STEPS),
        "probe": {
            "name": probe.name,
            "status": probe.status.value,
            "summary": probe.summary,
            "message": probe.summary,
            "remediation": probe.remediation,
            "details": probe.details,
        },
        "deps_counts": deps.get("counts"),
        "never_bundle_ida": True,
        "claims_universal_unpack": False,
    }


def activate_idalib(ida_home: Path) -> JsonObject:
    script = ida_home / "idalib" / "python" / "py-activate-idalib.py"
    if not script.is_file():
        return {
            "ok": False,
            "code": "activation_script_missing",
            "message": "py-activate-idalib.py not found under this IDA install",
            "script": str(script),
        }
    command = [sys.executable, str(script), "--ida-install-dir", str(ida_home)]
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=120,
            creationflags=_no_window_flags(),
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {
            "ok": False,
            "code": "activation_failed",
            "message": str(exc),
            "script": str(script),
        }
    return {
        "ok": completed.returncode == 0,
        "code": "activated" if completed.returncode == 0 else "activation_exit_nonzero",
        "exit_code": completed.returncode,
        "stdout": (completed.stdout or "")[-4000:],
        "stderr": (completed.stderr or "")[-4000:],
        "script": str(script),
        "python": sys.executable,
    }


def configure_ida(
    *,
    ida_home: str | Path,
    activate: bool = True,
    config_path: Path | None = None,
) -> JsonObject:
    checked = validate_ida_home(ida_home)
    if not checked.get("ok"):
        return {"ok": False, "saved": False, "validation": checked, "activation": None}

    home = Path(str(checked["path"]))
    saved_path = update_config_values({"ida_home": home}, config_path=config_path)
    activation = activate_idalib(home) if activate else None
    probe_settings = replace(Settings.load(config_path=saved_path), ida_home=home)
    probe = probe_ida(probe_settings)
    return {
        "ok": True,
        "saved": True,
        "config_path": str(saved_path),
        "ida_home": str(home),
        "validation": checked,
        "activation": activation,
        "probe": {
            "name": probe.name,
            "status": probe.status.value,
            "summary": probe.summary,
            "message": probe.summary,
            "remediation": probe.remediation,
            "details": probe.details,
        },
        "env_override": bool(os.environ.get("HEADLESS_RE_IDA_HOME")),
        "note_zh": "已写入本机 config.json，不会修改 IDA 安装目录。",
        "note_en": "Wrote local config.json only; IDA install tree untouched.",
        "never_bundle_ida": True,
    }


def _step_environment(settings: Settings) -> JsonObject:
    py_ok = sys.version_info >= (3, 11)
    web_ok = True
    web_error = None
    try:
        import fastapi  # noqa: F401
        import uvicorn  # noqa: F401
    except ImportError as exc:
        web_ok = False
        web_error = str(exc)
    return {
        "ok": py_ok and web_ok,
        "step": "environment",
        "python": {
            "executable": sys.executable,
            "version": platform.python_version(),
            "ok": py_ok,
            "required": "3.11+",
        },
        "platform": {
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
        },
        "web_extra": {"ok": web_ok, "error": web_error},
        "paths": {
            "repo_root": str(repo_root()),
            "config_path": str(default_config_path()),
            "data_path": str(default_data_path()),
            "artifact_root": str(settings.artifact_root),
        },
        "claims_universal_unpack": False,
    }


def _sync_one_arch(arch: str) -> JsonObject:
    root = repo_root()
    src = root / "artifacts" / f"x64dbg-{arch}" / "Release"
    dst = root / "external" / f"x64dbg-{arch}"
    result: JsonObject = {
        "arch": arch,
        "source": str(src),
        "destination": str(dst),
        "copied": False,
        "already_present": False,
        "ok": False,
    }
    dst_exe = dst / "headless.exe"
    if dst_exe.is_file():
        result["already_present"] = True
        result["ok"] = True
        result["headless"] = str(dst_exe.resolve())
        return result
    src_exe = src / "headless.exe"
    if not src_exe.is_file():
        # Fall back to discover elsewhere (runtime/artifacts) without copying.
        found = discover_x64dbg_headless(arch)
        if found is not None:
            result["ok"] = True
            result["headless"] = str(found)
            result["note"] = "discovered_existing"
            return result
        result["message"] = "source Release/headless.exe missing"
        return result
    dst.mkdir(parents=True, exist_ok=True)
    for item in dst.iterdir():
        if item.name in {"README.md", ".gitkeep"}:
            continue
        if item.is_dir():
            shutil.rmtree(item)
        else:
            item.unlink()
    for item in src.iterdir():
        target = dst / item.name
        if item.is_dir():
            shutil.copytree(item, target, dirs_exist_ok=True)
        else:
            shutil.copy2(item, target)
    result["copied"] = True
    result["ok"] = (dst / "headless.exe").is_file()
    result["headless"] = str((dst / "headless.exe").resolve()) if result["ok"] else None
    return result


def _step_sync_x64dbg(_settings: Settings) -> JsonObject:
    items = [_sync_one_arch("x64"), _sync_one_arch("x86")]
    return {
        "ok": any(item.get("ok") for item in items),
        "step": "sync_x64dbg",
        "items": items,
        "hint": "pwsh -File scripts/sync_external_x64dbg.ps1",
        "packable": True,
        "never_bundle_ida": True,
    }


def _step_probe_runtimes(settings: Settings) -> JsonObject:
    refreshed = Settings.load()
    # Prefer freshly discovered paths after sync.
    x64 = refreshed.x64dbg_headless_x64 or settings.x64dbg_headless_x64
    x86 = refreshed.x64dbg_headless_x86 or settings.x64dbg_headless_x86
    ida = refreshed.ida_home or settings.ida_home
    checks = [
        {
            "id": "x64dbg_x64",
            "ok": bool(x64 and Path(x64).is_file()),
            "path": str(x64) if x64 else None,
            "packable": True,
        },
        {
            "id": "x64dbg_x86",
            "ok": bool(x86 and Path(x86).is_file()),
            "path": str(x86) if x86 else None,
            "packable": True,
        },
        {
            "id": "ida_home",
            "ok": bool(ida and Path(ida).is_dir() and (Path(ida) / "idalib.dll").is_file()),
            "path": str(ida) if ida else None,
            "packable": False,
            "never_bundle": True,
        },
    ]
    return {
        "ok": all(c["ok"] for c in checks if str(c["id"]).startswith("x64dbg")),
        "step": "probe_runtimes",
        "checks": checks,
        "settings_reloaded": True,
    }


def _step_doctor(settings: Settings) -> JsonObject:
    report = run_doctor(settings)
    probes = [probe.to_dict() for probe in report.probes]
    ready_core = [
        p
        for p in probes
        if str(p.get("name") or "")
        in {
            "python",
            "ida_idalib",
            "x64dbg_headless_binaries",
        }
    ]
    return {
        "ok": report.ready,
        "step": "doctor",
        "ready": report.ready,
        "probes": probes,
        "core_ready_count": sum(1 for p in ready_core if p["status"] == ProbeStatus.READY),
        "core_total": len(ready_core),
        "summary": {
            "ready": sum(1 for p in probes if p["status"] == "ready"),
            "missing": sum(1 for p in probes if p["status"] == "missing"),
            "blocked": sum(1 for p in probes if p["status"] == "blocked"),
            "detected": sum(1 for p in probes if p["status"] == "detected"),
        },
    }


def _step_persist_defaults(settings: Settings) -> JsonObject:
    updates = {
        "http_host": settings.http_host or "127.0.0.1",
        "http_port": int(settings.http_port or 8765),
        "artifact_root": str(settings.artifact_root),
        "local_full_access": True,
    }
    if settings.ida_home is not None:
        updates["ida_home"] = str(settings.ida_home)
    if settings.x64dbg_headless_x64 is not None:
        updates["x64dbg_headless_x64"] = str(settings.x64dbg_headless_x64)
    if settings.x64dbg_headless_x86 is not None:
        updates["x64dbg_headless_x86"] = str(settings.x64dbg_headless_x86)
    path = update_config_values(updates)
    return {
        "ok": True,
        "step": "persist_defaults",
        "config_path": str(path),
        "written_keys": sorted(updates.keys()),
        "values": updates,
    }


def _step_generate_mcp(settings: Settings) -> JsonObject:
    from headless_re_mcp.config_generate import export_mcp_environment

    export = export_mcp_environment(settings, persist=True)
    examples = export.get("examples") or {}
    cursor = examples.get("cursor") if isinstance(examples, dict) else None
    return {
        "ok": bool(export.get("ok", True)),
        "step": "generate_mcp",
        "output": (export.get("written") or {}).get("bundle"),
        "written": export.get("written") or {},
        "bundle_ok": export.get("ok"),
        "has_examples": bool(examples),
        "embedded_env_keys": export.get("embedded_env_keys") or [],
        "env_inventory": export.get("env_inventory") or [],
        "doctor_ready": export.get("doctor_ready"),
        "stdio": export.get("stdio"),
        "examples": examples,
        "cursor_snippet": cursor,
        "server_keys": list((cursor or {}).get("mcpServers") or {})
        if isinstance(cursor, dict)
        else [],
        "note_zh": "已按本机探测路径生成 MCP 配置（含 HEADLESS_RE_* / PYTHONPATH）。",
        "note_en": "MCP config generated from discovered local paths (HEADLESS_RE_* / PYTHONPATH).",
    }


def _step_finalize(settings: Settings) -> JsonObject:
    status = setup_status(settings)
    deps = build_deps_snapshot(settings)
    missing_core = deps.get("missing_core") or []
    return {
        "ok": len(missing_core) == 0 or all(
            item.get("id") == "ida_home" for item in missing_core
        ),
        "step": "finalize",
        "ida_home": status.get("ida_home"),
        "x64dbg_headless_x64": status.get("x64dbg_headless_x64"),
        "x64dbg_headless_x86": status.get("x64dbg_headless_x86"),
        "config_path": status.get("config_path"),
        "missing_core": missing_core,
        "next_commands": [
            "python start_web.py",
            "python -m headless_re_mcp doctor",
            "python -m headless_re_mcp serve",
            "python -m headless_re_mcp serve-web",
        ],
        "claims_universal_unpack": False,
        "never_bundle_ida": True,
    }


def run_setup_step(
    settings: Settings,
    step: str,
    *,
    ida_home: str | None = None,
    activate: bool = True,
) -> JsonObject:
    """Execute one install-wizard step. Returns structured result for the UI."""
    name = (step or "").strip()
    if name not in SETUP_STEPS and name != "configure_ida":
        return {"ok": False, "step": name, "code": "unknown_step", "message": "unknown setup step"}

    if name == "environment":
        return _step_environment(settings)
    if name == "sync_x64dbg":
        return _step_sync_x64dbg(settings)
    if name == "probe_runtimes":
        return _step_probe_runtimes(settings)
    if name == "configure_ida":
        if not ida_home:
            # Soft probe-only when path omitted.
            return {
                "ok": settings.ida_home is not None,
                "step": "configure_ida",
                "skipped": True,
                "ida_home": str(settings.ida_home) if settings.ida_home else None,
                "candidates": [str(p) for p in list_ida_install_candidates()],
                "message": "ida_home not provided",
            }
        return {"step": "configure_ida", **configure_ida(ida_home=ida_home, activate=activate)}
    if name == "doctor":
        return _step_doctor(settings)
    if name == "persist_defaults":
        return _step_persist_defaults(settings)
    if name == "generate_mcp":
        return _step_generate_mcp(settings)
    if name == "finalize":
        return _step_finalize(settings)
    return {"ok": False, "step": name, "code": "unknown_step"}
