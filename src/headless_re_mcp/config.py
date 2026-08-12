from __future__ import annotations

import json
import os
import shutil
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from platformdirs import user_config_path, user_data_path


@dataclass(frozen=True, slots=True)
class Settings:
    ida_home: Path | None
    x64dbg_source: Path | None
    x64dbg_headless_x64: Path | None
    x64dbg_headless_x86: Path | None
    artifact_root: Path
    hidden_desktop: bool = False
    local_full_access: bool = True
    http_host: str = "127.0.0.1"
    http_port: int = 8765
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
    cdb: Path | None = None
    windbg_allow_kernel: bool = False
    persist_debug_events: bool = False

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
            cdb=_optional_path(
                os.environ.get("HEADLESS_RE_CDB")
                or data.get("cdb")
                or shutil.which("cdb")
            ),
            windbg_allow_kernel=_as_bool(
                os.environ.get("HEADLESS_RE_WINDBG_ALLOW_KERNEL"),
                data.get("windbg_allow_kernel", False),
            ),
            persist_debug_events=_as_bool(
                os.environ.get("HEADLESS_RE_PERSIST_DEBUG_EVENTS"),
                data.get("persist_debug_events", False),
            ),
            hidden_desktop=_as_bool(
                os.environ.get("HEADLESS_RE_HIDDEN_DESKTOP"),
                data.get("hidden_desktop", False),
            ),
            local_full_access=_as_bool(
                os.environ.get("HEADLESS_RE_LOCAL_FULL_ACCESS"),
                data.get("local_full_access", True),
            ),
            http_host=str(data.get("http_host", "127.0.0.1")),
            http_port=int(data.get("http_port", 8765)),
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
            if isinstance(loaded, dict):
                data = loaded
        except (OSError, ValueError, TypeError):
            data = {}
    for key, value in updates.items():
        if value is None:
            data.pop(key, None)
        elif isinstance(value, Path):
            data[key] = str(value)
        else:
            data[key] = value
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
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


def _optional_path(value: object) -> Path | None:
    if value in (None, ""):
        return None
    return Path(str(value)).expanduser().resolve()


def _as_bool(raw: str | None, default: object) -> bool:
    if raw is None:
        return bool(default)
    return raw.strip().lower() not in {"0", "false", "no", "off"}
