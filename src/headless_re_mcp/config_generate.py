"""MCP client config generator (M14) — embeds discovered local paths."""

from __future__ import annotations

import importlib.util
import json
import sys
from dataclasses import replace
from pathlib import Path
from typing import Any

from headless_re_mcp.config import Settings, default_config_path, repo_root
from headless_re_mcp.doctor import run_doctor

JsonObject = dict[str, Any]

_SECRET_KEYS = frozenset(
    {
        "token",
        "rpc_token",
        "ida_license",
        "license",
        "password",
        "secret",
        "api_key",
        "apikey",
    }
)

# Settings field → MCP env var (only present, real paths are embedded).
_SETTINGS_ENV_MAP: tuple[tuple[str, str], ...] = (
    ("ida_home", "HEADLESS_RE_IDA_HOME"),
    ("x64dbg_source", "HEADLESS_RE_X64DBG_SOURCE"),
    ("x64dbg_headless_x64", "HEADLESS_RE_X64DBG_HEADLESS_X64"),
    ("x64dbg_headless_x86", "HEADLESS_RE_X64DBG_HEADLESS_X86"),
    ("artifact_root", "HEADLESS_RE_ARTIFACT_ROOT"),
    ("diec", "HEADLESS_RE_DIEC"),
    ("exeinfope", "HEADLESS_RE_EXEINFOPE"),
    ("upx", "HEADLESS_RE_UPX"),
    ("de4dot", "HEADLESS_RE_DE4DOT"),
    ("net_reactor_slayer", "HEADLESS_RE_NET_REACTOR_SLAYER"),
    ("xvlkc", "HEADLESS_RE_XVLKC"),
    ("vmp_dumper", "HEADLESS_RE_VMP_DUMPER"),
    ("scylla", "HEADLESS_RE_SCYLLA"),
    ("r2", "HEADLESS_RE_R2"),
    ("ghidra_home", "HEADLESS_RE_GHIDRA_HOME"),
    ("cdb", "HEADLESS_RE_CDB"),
)


def _python_executable(explicit: Path | None) -> str:
    if explicit is not None:
        return str(explicit.resolve())
    return sys.executable


def _strip_secrets(data: JsonObject) -> JsonObject:
    cleaned: JsonObject = {}
    for key, value in data.items():
        if key.casefold() in _SECRET_KEYS:
            continue
        if isinstance(value, dict):
            cleaned[key] = _strip_secrets(value)
        else:
            cleaned[key] = value
    return cleaned


def _path_exists(path: Path | None) -> bool:
    if path is None:
        return False
    try:
        return path.exists()
    except OSError:
        return False


def _package_importable() -> bool:
    try:
        return importlib.util.find_spec("headless_re_mcp") is not None
    except (ImportError, ModuleNotFoundError, ValueError):
        return False


def resolve_pythonpath_for_mcp() -> str | None:
    """Return repo ``src`` for PYTHONPATH when the package is only available in-tree."""
    src = (repo_root() / "src").resolve()
    if not (src / "headless_re_mcp").is_dir():
        return None
    # Prefer PYTHONPATH when not installed into the active interpreter.
    if not _package_importable():
        return str(src)
    # Still useful for editable/source trees so hosts that change cwd keep working.
    return str(src)


def build_discovered_env(
    settings: Settings,
    *,
    config_path: Path | None = None,
    include_pythonpath: bool = True,
) -> tuple[JsonObject, list[JsonObject]]:
    """Build MCP ``env`` from Settings + discovery; return (env, inventory)."""
    env: JsonObject = {}
    inventory: list[JsonObject] = []

    cfg = config_path or default_config_path()
    if cfg is not None:
        env["HEADLESS_RE_CONFIG"] = str(Path(cfg).resolve())
        inventory.append(
            {
                "key": "HEADLESS_RE_CONFIG",
                "path": str(Path(cfg).resolve()),
                "present": Path(cfg).is_file(),
                "source": "config_path",
            }
        )

    for field_name, env_key in _SETTINGS_ENV_MAP:
        value = getattr(settings, field_name, None)
        if not isinstance(value, Path):
            continue
        resolved = value.expanduser().resolve()
        present = _path_exists(resolved)
        inventory.append(
            {
                "key": env_key,
                "path": str(resolved),
                "present": present,
                "source": field_name,
            }
        )
        if present:
            env[env_key] = str(resolved)

    if include_pythonpath:
        pythonpath = resolve_pythonpath_for_mcp()
        if pythonpath is not None:
            env["PYTHONPATH"] = pythonpath
            inventory.append(
                {
                    "key": "PYTHONPATH",
                    "path": pythonpath,
                    "present": True,
                    "source": "repo_src",
                }
            )

    return env, inventory


def build_stdio_server_config(
    *,
    python_path: Path | None = None,
    config_path: Path | None = None,
    module: str = "headless_re_mcp",
    settings: Settings | None = None,
    embed_discovered_env: bool = False,
) -> JsonObject:
    """Generic stdio MCP server block (no secrets).

    When ``embed_discovered_env`` is true and ``settings`` is provided, inject
    resolved ``HEADLESS_RE_*`` paths so the MCP host matches this machine.
    """
    args = ["-m", module, "serve"]
    env: JsonObject = {}
    if embed_discovered_env and settings is not None:
        env, _ = build_discovered_env(settings, config_path=config_path)
        # Prefer --config argv when a config file path is known.
        cfg = config_path or default_config_path()
        if cfg is not None:
            args = ["-m", module, "--config", str(Path(cfg).resolve()), "serve"]
    elif config_path is not None:
        env["HEADLESS_RE_CONFIG"] = str(config_path.resolve())
        args = ["-m", module, "--config", str(config_path.resolve()), "serve"]
    return {
        "command": _python_executable(python_path),
        "args": args,
        "env": env,
    }


def build_cursor_example(server: JsonObject) -> JsonObject:
    return {"mcpServers": {"headless-re-mcp": server}}


def build_vscode_example(server: JsonObject) -> JsonObject:
    return {
        "servers": {
            "headless-re-mcp": {
                "type": "stdio",
                "command": server["command"],
                "args": server["args"],
                "env": server.get("env") or {},
            }
        }
    }


def build_claude_desktop_example(server: JsonObject) -> JsonObject:
    return {"mcpServers": {"headless-re-mcp": server}}


def generate_config_bundle(
    settings: Settings,
    *,
    python_path: Path | None = None,
    config_path: Path | None = None,
    run_doctor_check: bool = True,
    include_examples: bool = True,
    embed_discovered_env: bool = False,
) -> JsonObject:
    """Build config payloads; optionally require Doctor readiness for required backends."""
    doctor_report: JsonObject | None = None
    if run_doctor_check:
        report = run_doctor(settings)
        doctor_report = json.loads(report.to_json())
        if not report.ready:
            return {
                "ok": False,
                "error": {
                    "code": "doctor_not_ready",
                    "message": "doctor --strict would fail; fix required backends first",
                },
                "doctor": doctor_report,
            }

    cfg_path = config_path or default_config_path()
    server = build_stdio_server_config(
        python_path=python_path,
        config_path=cfg_path,
        settings=settings,
        embed_discovered_env=embed_discovered_env,
    )
    env_inventory: list[JsonObject] = []
    if embed_discovered_env:
        _, env_inventory = build_discovered_env(settings, config_path=cfg_path)

    bundle: JsonObject = {
        "ok": True,
        "stdio": server,
        "notes": [
            "Do not embed IDA licenses, RPC tokens, or other secrets in MCP configs.",
            "Examples are optional copy-paste templates, not installers.",
            f"Suggested config path: {cfg_path}",
        ],
    }
    if embed_discovered_env:
        bundle["notes"].append(
            "env embeds paths discovered on this machine (HEADLESS_RE_* / PYTHONPATH)."
        )
        bundle["env_inventory"] = env_inventory
        bundle["embedded_env_keys"] = sorted(str(k) for k in (server.get("env") or {}))
    if include_examples:
        bundle["examples"] = {
            "cursor": build_cursor_example(server),
            "vscode": build_vscode_example(server),
            "claude_desktop": build_claude_desktop_example(server),
        }
    if doctor_report is not None:
        bundle["doctor"] = _strip_secrets(doctor_report)
    elif embed_discovered_env:
        # Soft doctor snapshot for UI (does not block export).
        soft = run_doctor(settings)
        bundle["doctor"] = _strip_secrets(json.loads(soft.to_json()))
        bundle["doctor_ready"] = soft.ready
    return _strip_secrets(bundle)


def merge_live_settings(
    live: Settings | None,
    *,
    config_path: Path | None = None,
) -> Settings:
    """Fresh disk/PATH discovery, overlaid with non-None live session paths."""
    fresh = Settings.load(config_path=config_path)
    if live is None:
        return fresh
    overlays: dict[str, Any] = {}
    for field_name, _env_key in _SETTINGS_ENV_MAP:
        live_value = getattr(live, field_name, None)
        if live_value is not None:
            overlays[field_name] = live_value
    return replace(fresh, **overlays) if overlays else fresh


def export_mcp_environment(
    settings: Settings | None = None,
    *,
    python_path: Path | None = None,
    config_path: Path | None = None,
    persist: bool = False,
    output_dir: Path | None = None,
    refresh_discovery: bool = True,
) -> JsonObject:
    """Discover current Settings, embed real paths, optionally write JSON files."""
    if refresh_discovery:
        current = merge_live_settings(settings, config_path=config_path)
    else:
        current = settings or Settings.load(config_path=config_path)

    cfg_path = config_path or default_config_path()
    bundle = generate_config_bundle(
        current,
        python_path=python_path,
        config_path=cfg_path,
        run_doctor_check=False,
        include_examples=True,
        embed_discovered_env=True,
    )

    written: JsonObject = {}
    if persist and bundle.get("ok"):
        out_dir = output_dir or Path(cfg_path).parent
        out_dir.mkdir(parents=True, exist_ok=True)
        full_path = out_dir / "mcp.stdio.generated.json"
        full_path.write_text(
            json.dumps(bundle, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        written["bundle"] = str(full_path)
        examples = bundle.get("examples") or {}
        mapping = {
            "cursor": "mcp.cursor.json",
            "vscode": "mcp.vscode.json",
            "claude_desktop": "mcp.claude_desktop.json",
        }
        for key, filename in mapping.items():
            payload = examples.get(key)
            if not isinstance(payload, dict):
                continue
            path = out_dir / filename
            path.write_text(
                json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )
            written[key] = str(path)

    return {
        "ok": bool(bundle.get("ok")),
        "python": _python_executable(python_path),
        "config_path": str(Path(cfg_path).resolve()),
        "repo_root": str(repo_root()),
        "package_importable": _package_importable(),
        "stdio": bundle.get("stdio"),
        "examples": bundle.get("examples"),
        "env_inventory": bundle.get("env_inventory") or [],
        "embedded_env_keys": bundle.get("embedded_env_keys") or [],
        "doctor": bundle.get("doctor"),
        "doctor_ready": bundle.get("doctor_ready"),
        "notes": bundle.get("notes") or [],
        "written": written,
        "claims_universal_unpack": False,
        "never_bundle_ida": True,
    }
