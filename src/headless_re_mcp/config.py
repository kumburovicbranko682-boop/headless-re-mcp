from __future__ import annotations

import json
import os
import shutil
import tempfile
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from platformdirs import user_config_path, user_data_path

from headless_re_mcp.core.retention import DEFAULT_MAX_TOTAL_BYTES


@dataclass(frozen=True, slots=True)
class Settings:
    ida_home: Path | None
    x64dbg_source: Path | None
    x64dbg_headless_x64: Path | None
    x64dbg_headless_x86: Path | None
    artifact_root: Path
    # ScyllaHide is loaded from the live headless plugins directory. enabled=false
    # still writes CurrentProfile=Disabled so the plugin does not keep injecting.
    x64dbg_stealth_enabled: bool = True
    x64dbg_stealth_profile: str = "vmp"
    hidden_desktop: bool = False
    # Seconds between background backend health sweeps; 0 disables the monitor.
    health_check_interval_s: float = 5.0
    local_full_access: bool = True
    # Unattended Agent policy. Explicit empty tuples stay fail-closed.
    # Settings.load() fills packed-analysis defaults when the keys are absent.
    # A denial here outranks every grant, including the read-only baseline.
    agent_auto_approve_effects: tuple[str, ...] = ()
    agent_auto_approve_tools: tuple[str, ...] = ()
    agent_never_auto_approve: tuple[str, ...] = ()
    # Watchdog. Reporting is always on; correcting is not, because a recovered
    # dynamic backend comes back attached to nothing.
    watchdog_interval_s: float = 30.0
    watchdog_auto_recover_backends: bool = False
    # Isolation between samples. The debugger executes the sample, so continuous
    # intake needs the VM rolled back; the command is the deployment's, since the
    # hypervisor and snapshot names are not this service's to guess.
    isolation_command: tuple[str, ...] = ()
    isolation_timeout_s: float = 600.0
    isolation_required: bool = True
    http_host: str = "127.0.0.1"
    http_port: int = 8765
    # Startup work direction. "full" exposes every tool; pe/android/web trim the
    # MCP surface to one workflow so a client is not flooded with unrelated tools.
    workspace_profile: str = "full"
    diec: Path | None = None
    exeinfope: Path | None = None
    upx: Path | None = None
    de4dot: Path | None = None
    net_reactor_slayer: Path | None = None
    xvlkc: Path | None = None
    vmp_dumper: Path | None = None
    scylla: Path | None = None
    r2: Path | None = None
    ghidra_home: Path | None = None
    ghidra_wasm_plugin: Path | None = None
    cdb: Path | None = None
    # Android and Web reverse-engineering tool paths (all optional; missing
    # degrades the corresponding tool rather than blocking readiness).
    adb: Path | None = None
    frida_server: Path | None = None
    jadx: Path | None = None
    apktool: Path | None = None
    apksigner: Path | None = None
    wabt: Path | None = None
    webcrack: Path | None = None
    windbg_allow_kernel: bool = False
    persist_debug_events: bool = False
    # Background drain keeps copying native ring events into the durable log
    # while the MCP consumer is idle (needed for true lag replay).
    debug_event_background_drain: bool = True
    # Byte budget for registered artifacts, collected oldest-first. 0 disables
    # collection entirely and accepts unbounded growth.
    artifact_max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES

    @classmethod
    def load(cls, config_path: Path | None = None) -> Settings:
        data: dict[str, Any] = {}
        path = config_path or default_config_path()
        if path.is_file():
            data = json.loads(path.read_text(encoding="utf-8"))

        ida_home = _optional_path(
            os.environ.get("HEADLESS_RE_IDA_HOME")
            or data.get("ida_home")
            or discover_ida_home()
        )
        x64dbg_source = _optional_path(
            os.environ.get("HEADLESS_RE_X64DBG_SOURCE")
            or data.get("x64dbg_source")
            or discover_x64dbg_source()
        )
        artifact_root = Path(
            os.environ.get("HEADLESS_RE_ARTIFACT_ROOT")
            or data.get("artifact_root")
            or default_data_path() / "artifacts"
        ).expanduser()

        return cls(
            ida_home=ida_home,
            x64dbg_source=x64dbg_source,
            x64dbg_headless_x64=_optional_path(
                os.environ.get("HEADLESS_RE_X64DBG_HEADLESS_X64")
                or data.get("x64dbg_headless_x64")
                or discover_x64dbg_headless("x64")
            ),
            x64dbg_headless_x86=_optional_path(
                os.environ.get("HEADLESS_RE_X64DBG_HEADLESS_X86")
                or data.get("x64dbg_headless_x86")
                or discover_x64dbg_headless("x86")
            ),
            artifact_root=artifact_root,
            diec=_optional_path(
                os.environ.get("HEADLESS_RE_DIEC")
                or data.get("diec")
                or shutil.which("diec")
            ),
            exeinfope=_optional_path(
                os.environ.get("HEADLESS_RE_EXEINFOPE")
                or data.get("exeinfope")
            ),
            upx=_optional_path(
                os.environ.get("HEADLESS_RE_UPX")
                or data.get("upx")
                or shutil.which("upx")
            ),
            de4dot=_optional_path(
                os.environ.get("HEADLESS_RE_DE4DOT")
                or data.get("de4dot")
                or shutil.which("de4dot")
            ),
            net_reactor_slayer=_optional_path(
                os.environ.get("HEADLESS_RE_NET_REACTOR_SLAYER")
                or data.get("net_reactor_slayer")
                or shutil.which("NETReactorSlayer.CLI")
                or shutil.which("NETReactorSlayer-x64.CLI")
            ),
            xvlkc=_optional_path(
                os.environ.get("HEADLESS_RE_XVLKC")
                or data.get("xvlkc")
            ),
            vmp_dumper=_optional_path(
                os.environ.get("HEADLESS_RE_VMP_DUMPER")
                or data.get("vmp_dumper")
            ),
            scylla=_optional_path(
                os.environ.get("HEADLESS_RE_SCYLLA")
                or data.get("scylla")
            ),
            r2=_optional_path(
                os.environ.get("HEADLESS_RE_R2")
                or data.get("r2")
                or shutil.which("r2")
                or shutil.which("rizin")
            ),
            ghidra_home=_optional_path(
                os.environ.get("HEADLESS_RE_GHIDRA_HOME")
                or data.get("ghidra_home")
            ),
            ghidra_wasm_plugin=_optional_path(
                os.environ.get("HEADLESS_RE_GHIDRA_WASM_PLUGIN")
                or data.get("ghidra_wasm_plugin")
            ),
            cdb=_optional_path(
                os.environ.get("HEADLESS_RE_CDB")
                or data.get("cdb")
                or shutil.which("cdb")
            ),
            adb=_optional_path(
                os.environ.get("HEADLESS_RE_ADB")
                or data.get("adb")
                or shutil.which("adb")
            ),
            frida_server=_optional_path(
                os.environ.get("HEADLESS_RE_FRIDA_SERVER")
                or data.get("frida_server")
            ),
            jadx=_optional_path(
                os.environ.get("HEADLESS_RE_JADX")
                or data.get("jadx")
                or shutil.which("jadx")
                or shutil.which("jadx.bat")
            ),
            apktool=_optional_path(
                os.environ.get("HEADLESS_RE_APKTOOL")
                or data.get("apktool")
                or shutil.which("apktool")
                or shutil.which("apktool.bat")
            ),
            apksigner=_optional_path(
                os.environ.get("HEADLESS_RE_APKSIGNER")
                or data.get("apksigner")
                or shutil.which("apksigner")
                or shutil.which("apksigner.bat")
            ),
            wabt=_optional_path(
                os.environ.get("HEADLESS_RE_WABT")
                or data.get("wabt")
                or shutil.which("wasm2wat")
            ),
            webcrack=_optional_path(
                os.environ.get("HEADLESS_RE_WEBCRACK")
                or data.get("webcrack")
                or shutil.which("webcrack")
            ),
            windbg_allow_kernel=_as_bool(
                os.environ.get("HEADLESS_RE_WINDBG_ALLOW_KERNEL"),
                data.get("windbg_allow_kernel", False),
            ),
            persist_debug_events=_as_bool(
                os.environ.get("HEADLESS_RE_PERSIST_DEBUG_EVENTS"),
                data.get("persist_debug_events", False),
            ),
            debug_event_background_drain=_as_bool(
                os.environ.get("HEADLESS_RE_DEBUG_EVENT_BACKGROUND_DRAIN"),
                data.get("debug_event_background_drain", True),
            ),
            hidden_desktop=_as_bool(
                os.environ.get("HEADLESS_RE_HIDDEN_DESKTOP"),
                data.get("hidden_desktop", True),
            ),
            health_check_interval_s=_as_float(
                os.environ.get("HEADLESS_RE_HEALTH_CHECK_INTERVAL_S"),
                data.get("health_check_interval_s", 5.0),
                fallback=5.0,
            ),
            local_full_access=_as_bool(
                os.environ.get("HEADLESS_RE_LOCAL_FULL_ACCESS"),
                data.get("local_full_access", True),
            ),
            agent_auto_approve_effects=_loaded_string_tuple(
                os.environ.get("HEADLESS_RE_AGENT_AUTO_APPROVE_EFFECTS"),
                data,
                "agent_auto_approve_effects",
                preset=_packed_analysis_auto_approve_effects,
            ),
            agent_auto_approve_tools=_loaded_string_tuple(
                os.environ.get("HEADLESS_RE_AGENT_AUTO_APPROVE_TOOLS"),
                data,
                "agent_auto_approve_tools",
                preset=_packed_analysis_auto_approve_tools,
            ),
            agent_never_auto_approve=_as_tuple(
                os.environ.get("HEADLESS_RE_AGENT_NEVER_AUTO_APPROVE"),
                data.get("agent_never_auto_approve", ()),
            ),
            watchdog_interval_s=_as_float(
                os.environ.get("HEADLESS_RE_WATCHDOG_INTERVAL_S"),
                data.get("watchdog_interval_s", 30.0),
                fallback=30.0,
            ),
            watchdog_auto_recover_backends=_as_bool(
                os.environ.get("HEADLESS_RE_WATCHDOG_AUTO_RECOVER_BACKENDS"),
                data.get("watchdog_auto_recover_backends", False),
            ),
            isolation_command=_as_command(
                os.environ.get("HEADLESS_RE_ISOLATION_COMMAND"),
                data.get("isolation_command", ()),
            ),
            isolation_timeout_s=_as_float(
                os.environ.get("HEADLESS_RE_ISOLATION_TIMEOUT_S"),
                data.get("isolation_timeout_s", 600.0),
                fallback=600.0,
            ),
            isolation_required=_as_bool(
                os.environ.get("HEADLESS_RE_ISOLATION_REQUIRED"),
                data.get("isolation_required", True),
            ),
            # Environment overrides exist here for the same reason as every
            # other field: a deployment that can only set variables could not
            # move the console off a busy port.
            http_host=str(
                os.environ.get("HEADLESS_RE_HTTP_HOST") or data.get("http_host", "127.0.0.1")
            ),
            http_port=_as_int(
                os.environ.get("HEADLESS_RE_HTTP_PORT"),
                data.get("http_port", 8765),
                fallback=8765,
            ),
            workspace_profile=_as_profile(
                os.environ.get("HEADLESS_RE_WORKSPACE_PROFILE")
                or data.get("workspace_profile")
            ),
            artifact_max_total_bytes=_as_int(
                os.environ.get("HEADLESS_RE_ARTIFACT_MAX_TOTAL_BYTES"),
                data.get("artifact_max_total_bytes", DEFAULT_MAX_TOTAL_BYTES),
                fallback=DEFAULT_MAX_TOTAL_BYTES,
            ),
            x64dbg_stealth_enabled=_as_bool(
                os.environ.get("HEADLESS_RE_X64DBG_STEALTH_ENABLED"),
                data.get("x64dbg_stealth_enabled", True),
            ),
            x64dbg_stealth_profile=str(
                os.environ.get("HEADLESS_RE_X64DBG_STEALTH_PROFILE")
                or data.get("x64dbg_stealth_profile")
                or "vmp"
            ).strip()
            or "vmp",
        )


def default_config_path() -> Path:
    return user_config_path("headless-re-mcp", appauthor=False) / "config.json"


def default_data_path() -> Path:
    return user_data_path("headless-re-mcp", appauthor=False)


def list_ida_install_candidates() -> list[Path]:
    """Return local IDA 9.x installs that contain ``idalib.dll`` (never from external/)."""
    found: list[Path] = []
    seen: set[str] = set()

    def _add(path: Path | None) -> None:
        if path is None or not path.is_dir():
            return
        if not (path / "idalib.dll").is_file():
            return
        key = str(path.resolve()).lower()
        if key in seen:
            return
        seen.add(key)
        found.append(path.resolve())

    _add(_ida_config_home())
    roots = [
        Path(os.environ.get("PROGRAMFILES", r"C:\Program Files")),
        Path(os.environ.get("PROGRAMFILES(X86)", r"C:\Program Files (x86)")),
    ]
    for root in roots:
        for match in root.glob("IDA Professional 9.*"):
            _add(match)
        for match in (root / "Hex-Rays").glob("IDA Pro 9.*"):
            _add(match)
    return sorted(found, key=lambda path: path.name, reverse=True)


def discover_ida_home() -> Path | None:
    candidates = list_ida_install_candidates()
    return candidates[0] if candidates else None


def validate_ida_home(path: Path | str) -> dict[str, Any]:
    """Validate a user-supplied IDA install directory (read-only checks)."""
    home = _optional_path(path)
    if home is None:
        return {"ok": False, "code": "empty_path", "message": "IDA path is empty"}
    if not home.is_dir():
        return {
            "ok": False,
            "code": "not_a_directory",
            "message": f"not a directory: {home}",
            "path": str(home),
        }
    idalib = home / "idalib.dll"
    activation = home / "idalib" / "python" / "py-activate-idalib.py"
    details = {
        "path": str(home),
        "idalib": str(idalib) if idalib.is_file() else None,
        "ida_exe": str(home / "ida.exe") if (home / "ida.exe").is_file() else None,
        "activation_script": str(activation) if activation.is_file() else None,
    }
    if not idalib.is_file():
        return {
            "ok": False,
            "code": "idalib_missing",
            "message": "idalib.dll not found under this path",
            **details,
        }
    return {"ok": True, "code": "ok", "message": "IDA install looks usable", **details}


def update_config_values(
    updates: dict[str, Any],
    *,
    config_path: Path | None = None,
) -> Path:
    """Merge keys into the user config.json (does not touch the IDA install tree)."""
    path = config_path or default_config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    data: dict[str, Any] = {}
    if path.is_file():
        try:
            loaded = json.loads(path.read_text(encoding="utf-8"))
        except OSError as exc:
            raise OSError(f"could not read existing config: {path}") from exc
        except (ValueError, TypeError) as exc:
            raise ValueError(f"existing config is not valid JSON: {path}") from exc
        if not isinstance(loaded, dict):
            raise ValueError(f"existing config root must be an object: {path}")
        data = loaded
    for key, value in updates.items():
        if value is None:
            data.pop(key, None)
        elif isinstance(value, Path):
            data[key] = str(value)
        else:
            data[key] = value
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}-",
            suffix=".tmp",
            delete=False,
        ) as stream:
            temporary = Path(stream.name)
            stream.write(json.dumps(data, indent=2, ensure_ascii=False) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        temporary = None
    finally:
        if temporary is not None:
            with suppress(OSError):
                temporary.unlink()
    with suppress(OSError):
        path.chmod(0o600)
    return path


def repo_root() -> Path:
    """Repository / package root (parent of ``src/``)."""
    return Path(__file__).resolve().parents[2]


def discover_x64dbg_source() -> Path | None:
    candidates = [
        Path.cwd() / "upstream" / "x64dbg",
        repo_root() / "upstream" / "x64dbg",
    ]
    for path in candidates:
        if (path / "src" / "headless" / "headless.cpp").is_file():
            return path.resolve()
    return None


def discover_x64dbg_headless(architecture: str) -> Path | None:
    """Locate packable headless.exe under external/runtime/artifacts.

    Preferred layout (may be shipped in portable packages)::

        external/x64dbg-{x86,x64}/headless.exe

    IDA must never be discovered from ``external/``.
    """
    arch = architecture.lower().strip()
    if arch not in {"x86", "x64"}:
        return None
    root = repo_root()
    candidates = [
        root / "external" / f"x64dbg-{arch}" / "headless.exe",
        root / "external" / f"x64dbg-{arch}" / "Release" / "headless.exe",
        root / "runtime" / f"x64dbg-{arch}" / "headless.exe",
        root / "runtime" / f"x64dbg-{arch}" / "Release" / "headless.exe",
        # Build cache fallback (dev machines); portable packages use external/runtime.
        root / "artifacts" / f"x64dbg-{arch}" / "Release" / "headless.exe",
    ]
    for path in candidates:
        if path.is_file():
            return path.resolve()
    return None


def _ida_config_home() -> Path | None:
    appdata = os.environ.get("APPDATA")
    if not appdata:
        return None
    path = Path(appdata) / "Hex-Rays" / "IDA Pro" / "ida-config.json"
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        value = raw.get("Paths", {}).get("ida-install-dir")
        result = _optional_path(value)
        if result is not None and (result / "idalib.dll").is_file():
            return result
    except (OSError, ValueError, TypeError):
        pass
    return None


VALID_WORKSPACE_PROFILES = ("full", "pe", "android", "web")


def _as_profile(value: object) -> str:
    text = str(value).strip().lower() if value not in (None, "") else "full"
    return text if text in VALID_WORKSPACE_PROFILES else "full"


def _optional_path(value: object) -> Path | None:
    if value in (None, ""):
        return None
    return Path(str(value)).expanduser().resolve()


def _as_bool(raw: str | None, default: object) -> bool:
    if raw is None:
        return bool(default)
    return raw.strip().lower() not in {"0", "false", "no", "off"}


def _as_command(raw: str | None, default: object) -> tuple[str, ...]:
    """Read an isolation command as argv.

    A string (env var or JSON string) is split the way an operator would write
    it, including Windows paths. A JSON array is already argv. ``_as_tuple``
    is the wrong tool: it splits on commas and de-duplicates, so
    ``pwsh -File C:\\vm\\revert.ps1`` becomes one un-runnable program name.
    """
    from headless_re_mcp.core.isolation import _split_command

    if raw is not None:
        return _split_command(raw)
    if isinstance(default, str):
        return _split_command(default)
    if isinstance(default, (list, tuple)):
        return tuple(str(part) for part in default if str(part).strip())
    return ()


def _packed_analysis_auto_approve_effects() -> tuple[str, ...]:
    from headless_re_mcp.agent.autonomy import PACKED_ANALYSIS_AUTO_APPROVE_EFFECTS

    return PACKED_ANALYSIS_AUTO_APPROVE_EFFECTS


def _packed_analysis_auto_approve_tools() -> tuple[str, ...]:
    from headless_re_mcp.agent.autonomy import PACKED_ANALYSIS_AUTO_APPROVE_TOOLS

    return PACKED_ANALYSIS_AUTO_APPROVE_TOOLS


def _loaded_string_tuple(
    raw: str | None,
    data: dict[str, Any],
    key: str,
    *,
    preset: Callable[[], tuple[str, ...]],
) -> tuple[str, ...]:
    """Env wins; an explicit JSON key (including []) is fail-closed; else preset."""
    if raw is not None:
        return _as_tuple(raw, ())
    if key in data:
        return _as_tuple(None, data.get(key, ()))
    return preset()


def _as_tuple(raw: str | None, default: object) -> tuple[str, ...]:
    """Read a list setting from a comma-separated env var or a JSON array.

    Order is not preserved as meaning anywhere these are used, but duplicates are
    dropped so a repeated entry cannot look like two rules.
    """
    if raw is not None:
        items: list[str] = [part.strip() for part in raw.split(",")]
    elif isinstance(default, str):
        items = [part.strip() for part in default.split(",")]
    elif isinstance(default, (list, tuple)):
        items = [str(part).strip() for part in default]
    else:
        return ()
    seen: dict[str, None] = {}
    for item in items:
        if item:
            seen[item] = None
    return tuple(seen)


def _as_int(raw: str | None, default: object, *, fallback: int = 0) -> int:
    """Read a non-negative integer setting, tolerating an unreadable value."""
    for candidate in (raw, default):
        if candidate is None:
            continue
        try:
            return max(0, int(str(candidate)))
        except (TypeError, ValueError):
            continue
    return fallback


def _as_float(raw: str | None, default: object, *, fallback: float = 0.0) -> float:
    # An unreadable value must not stop the server from starting, so fall back
    # rather than raising out of configuration loading. The fallback is explicit
    # because silently returning 0 turned a typo into a disabled feature.
    for candidate in (raw, default):
        try:
            if candidate is not None:
                return max(0.0, float(candidate))  # type: ignore[arg-type]
        except (TypeError, ValueError):
            continue
    return fallback
