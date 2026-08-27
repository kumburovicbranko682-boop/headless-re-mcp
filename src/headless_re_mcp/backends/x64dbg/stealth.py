"""ScyllaHide profile control for the live headless x64dbg plugins directory.

Hide is applied by writing ``CurrentProfile`` in ``scylla_hide.ini`` next to
the plugin that ``headless.exe`` actually loads (``<headless-dir>/plugins``),
before the debugger process starts. This module does not send plugin commands.
"""

from __future__ import annotations

import configparser
import re
import shutil
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from threading import Lock
from typing import Any, Final

from headless_re_mcp.core.models import Architecture

JsonObject = dict[str, Any]

INI_NAME: Final[str] = "scylla_hide.ini"
_PLUGIN_FILES: Final[dict[Architecture, tuple[str, str]]] = {
    Architecture.X86: ("ScyllaHideX64DBGPlugin.dp32", "HookLibraryx86.dll"),
    Architecture.X64: ("ScyllaHideX64DBGPlugin.dp64", "HookLibraryx64.dll"),
}

PROFILE_SECTIONS: Final[dict[str, str]] = {
    "vmp": "VMProtect x86/x64",
    "themida": "Themida x86/x64",
    "obsidium": "Obsidium x86/x64",
    "armadillo": "Armadillo x86",
    "basic": "Basic",
    "off": "Disabled",
}
PROFILE_ALIASES: Final[dict[str, str]] = {
    "vmprotect": "vmp",
    "disabled": "off",
    "none": "off",
    "tmd": "themida",
    "winlicense": "themida",
    "winlic": "themida",
    "oreans": "themida",
}
X64_FORBIDDEN_PROFILES: Final[frozenset[str]] = frozenset({"armadillo"})
DEFAULT_PROFILE_ID: Final[str] = "vmp"
_SECTION_TO_ID: Final[dict[str, str]] = {section: pid for pid, section in PROFILE_SECTIONS.items()}
_SECTION_FOLD_TO_ID: Final[dict[str, str]] = {
    section.casefold(): pid for pid, section in PROFILE_SECTIONS.items()
}
STEALTH_HINT_KEY: Final[str] = "stealth_hint"
_PACKER_CATEGORIES: Final[frozenset[str]] = frozenset({"packer", "protector", "obfuscator"})
# Longer tokens first so "vmprotect" wins over the short "vmp" abbreviation.
_DETECTION_HINTS: Final[tuple[tuple[str, tuple[str, ...]], ...]] = (
    ("themida", ("winlicense", "winlic", "themida", "oreans", "tmd")),
    ("vmp", ("vmprotect", "vmp")),
    ("obsidium", ("obsidium",)),
    ("armadillo", ("armadillo",)),
)

_INI_LOCK = Lock()


class StealthError(RuntimeError):
    """Structured failure for hide status/set/launch preparation."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        details: JsonObject | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.details = dict(details or {})
        self.retryable = False


@dataclass(frozen=True, slots=True)
class StealthLayout:
    architecture: Architecture
    headless: Path
    plugins_dir: Path
    plugin: Path
    hook_library: Path
    ini: Path

    @property
    def plugin_present(self) -> bool:
        return self.plugin.is_file() and self.hook_library.is_file()


def plugins_dir_for_headless(headless: Path) -> Path:
    return Path(headless).expanduser().resolve().parent / "plugins"


def layout_for_headless(
    headless: Path | None,
    architecture: Architecture,
) -> StealthLayout | None:
    if headless is None:
        return None
    path = Path(headless).expanduser()
    plugin_name, hook_name = _PLUGIN_FILES[architecture]
    plugins = plugins_dir_for_headless(path)
    return StealthLayout(
        architecture=architecture,
        headless=path.resolve() if path.exists() else path,
        plugins_dir=plugins,
        plugin=plugins / plugin_name,
        hook_library=plugins / hook_name,
        ini=plugins / INI_NAME,
    )


def canonical_profile_id(raw: str) -> str:
    if not isinstance(raw, str) or not raw.strip():
        raise StealthError(
            "invalid_params",
            "stealth profile must be a non-empty string",
            details={"allowed": sorted(PROFILE_SECTIONS)},
        )
    token = raw.strip().casefold()
    if token in PROFILE_SECTIONS:
        return token
    if token in PROFILE_ALIASES:
        return PROFILE_ALIASES[token]
    if token in _SECTION_FOLD_TO_ID:
        return _SECTION_FOLD_TO_ID[token]
    raise StealthError(
        "invalid_params",
        f"unknown stealth profile: {raw.strip()}",
        details={"allowed": sorted(PROFILE_SECTIONS), "aliases": sorted(PROFILE_ALIASES)},
    )


def _hint_in_blob(blob: str, token: str) -> bool:
    if len(token) <= 3:
        return re.search(rf"\b{re.escape(token)}\b", blob) is not None
    return token in blob


def profile_from_candidates(
    candidates: list[JsonObject] | tuple[JsonObject, ...],
    *,
    architecture: Architecture | None = None,
) -> str | None:
    """Map DIE/packer.classify names onto a whitelist id, or None if unknown."""
    best: tuple[int, float] | None = None
    matched: str | None = None
    for item in candidates:
        if not isinstance(item, dict):
            continue
        if str(item.get("category", "")).casefold() not in _PACKER_CATEGORIES:
            continue
        blob = f"{item.get('name', '')} {item.get('summary', '')}".casefold()
        try:
            confidence = float(item.get("confidence") or 0.0)
        except (TypeError, ValueError):
            confidence = 0.0
        for profile, tokens in _DETECTION_HINTS:
            for token in tokens:
                if not _hint_in_blob(blob, token):
                    continue
                score = (len(token), confidence)
                if best is None or score > best:
                    best = score
                    matched = profile
    if matched is None:
        return None
    if architecture is Architecture.X64 and matched in X64_FORBIDDEN_PROFILES:
        return "basic"
    return matched


def remember_stealth_hint(
    candidates: list[JsonObject] | tuple[JsonObject, ...],
    *,
    architecture: Architecture | None = None,
) -> tuple[str | None, JsonObject]:
    """Return (profile, metadata fragment) to persist via SessionRegistry.update_metadata."""
    profile = profile_from_candidates(candidates, architecture=architecture)
    return profile, {STEALTH_HINT_KEY: {"profile": profile}}


def stealth_hint_profile(metadata: Mapping[str, Any]) -> str | None:
    hint = metadata.get(STEALTH_HINT_KEY)
    if not isinstance(hint, dict):
        return None
    raw = hint.get("profile")
    if not isinstance(raw, str) or not raw.strip():
        return None
    try:
        return canonical_profile_id(raw)
    except StealthError:
        return None


def section_for_profile(profile_id: str, *, architecture: Architecture) -> str:
    canonical = canonical_profile_id(profile_id)
    if architecture is Architecture.X64 and canonical in X64_FORBIDDEN_PROFILES:
        raise StealthError(
            "invalid_params",
            "armadillo is an x86-only ScyllaHide profile",
            details={
                "profile": canonical,
                "architecture": architecture.value,
                "section": PROFILE_SECTIONS[canonical],
            },
        )
    return PROFILE_SECTIONS[canonical]


def profile_id_for_section(section: str) -> str | None:
    return _SECTION_TO_ID.get(section.strip())


def inspect_layout(layout: StealthLayout | None) -> JsonObject:
    if layout is None:
        return {
            "configured": False,
            "plugin_present": False,
            "ini_present": False,
            "current_profile": None,
            "current_section": None,
        }
    current_section = read_current_section(layout.ini) if layout.ini.is_file() else None
    return {
        "configured": True,
        "architecture": layout.architecture.value,
        "headless": str(layout.headless),
        "plugins_dir": str(layout.plugins_dir),
        "plugin": str(layout.plugin),
        "hook_library": str(layout.hook_library),
        "ini": str(layout.ini),
        "plugin_present": layout.plugin_present,
        "ini_present": layout.ini.is_file(),
        "current_profile": (profile_id_for_section(current_section) if current_section else None),
        "current_section": current_section,
    }


def read_current_section(ini_path: Path) -> str | None:
    parser = _read_ini_file(ini_path)
    if parser is None or not parser.has_section("SETTINGS"):
        return None
    value = parser.get("SETTINGS", "CurrentProfile", fallback="").strip()
    return value or None


def apply_profile(
    layout: StealthLayout,
    profile_id: str,
    *,
    require_plugin: bool,
) -> JsonObject:
    """Write CurrentProfile for this architecture's live plugins directory."""
    section = section_for_profile(profile_id, architecture=layout.architecture)
    canonical = canonical_profile_id(profile_id)
    if require_plugin and not layout.plugin_present:
        raise StealthError(
            "plugin_missing",
            f"ScyllaHide plugin files are missing for {layout.architecture.value}",
            details=_missing_plugin_details(layout),
        )
    layout.plugins_dir.mkdir(parents=True, exist_ok=True)
    with _INI_LOCK:
        parser = _load_or_seed(layout.ini)
        if not parser.has_section(section):
            raise StealthError(
                "invalid_params",
                f"stealth ini has no section {section!r}",
                details={"section": section, "ini": str(layout.ini)},
            )
        if not parser.has_section("SETTINGS"):
            parser.add_section("SETTINGS")
        parser.set("SETTINGS", "CurrentProfile", section)
        _quiet_network_hooks(parser)
        _atomic_write_ini(layout.ini, parser)
    return {
        "architecture": layout.architecture.value,
        "profile": canonical,
        "section": section,
        "ini": str(layout.ini),
        "plugin_present": layout.plugin_present,
        "plugins_dir": str(layout.plugins_dir),
    }


def install_from_extracted_tree(
    source: Path,
    layout: StealthLayout,
    *,
    seed_ini: bool = True,
) -> JsonObject:
    """Copy plugin + hook library from an extracted ScyllaHide tree into layout."""
    plugin_name = layout.plugin.name
    hook_name = layout.hook_library.name
    plugin_src = _find_named(source, plugin_name)
    hook_src = _find_named(source, hook_name)
    if plugin_src is None or hook_src is None:
        raise StealthError(
            "plugin_missing",
            "extracted ScyllaHide tree is missing plugin files",
            details={
                "source": str(source),
                "plugin": plugin_name,
                "hook_library": hook_name,
                "found_plugin": plugin_src is not None,
                "found_hook_library": hook_src is not None,
            },
        )
    layout.plugins_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(plugin_src, layout.plugin)
    shutil.copy2(hook_src, layout.hook_library)
    ini_src = _find_named(source, INI_NAME)
    if seed_ini and not layout.ini.is_file():
        if ini_src is not None:
            shutil.copy2(ini_src, layout.ini)
        else:
            _atomic_write_ini(layout.ini, _seed_parser())
        with _INI_LOCK:
            parser = _load_or_seed(layout.ini)
            _quiet_network_hooks(parser)
            _atomic_write_ini(layout.ini, parser)
    return inspect_layout(layout)


def _missing_plugin_details(layout: StealthLayout) -> JsonObject:
    return {
        "architecture": layout.architecture.value,
        "plugins_dir": str(layout.plugins_dir),
        "plugin": str(layout.plugin),
        "plugin_exists": layout.plugin.is_file(),
        "hook_library": str(layout.hook_library),
        "hook_library_exists": layout.hook_library.is_file(),
    }


def _find_named(root: Path, name: str) -> Path | None:
    direct = root / name
    if direct.is_file():
        return direct
    matches = sorted(path for path in root.rglob(name) if path.is_file())
    return matches[0] if matches else None


def _parser() -> configparser.ConfigParser:
    parser = configparser.ConfigParser(interpolation=None)
    parser.optionxform = str  # type: ignore[assignment]
    return parser


def _seed_parser() -> configparser.ConfigParser:
    parser = _parser()
    parser.read_string(_DEFAULT_INI)
    _quiet_network_hooks(parser)
    return parser


def _read_ini_file(ini_path: Path) -> configparser.ConfigParser | None:
    """Read an ini as UTF-8, then UTF-16 -- ScyllaHide writes its ini as UTF-16.

    ``configparser.read`` only swallows ``OSError``; the ``UnicodeDecodeError``
    a UTF-16 file raises when first decoded as UTF-8 propagates straight out, so
    the UTF-16 retry has to catch ``UnicodeError`` explicitly or it is never
    reached. Each attempt uses a fresh parser so a partially decoded UTF-8 read
    cannot bleed into the UTF-16 result. Returns None when nothing could be read
    (missing/unreadable file or neither encoding decoding it).
    """
    for encoding in ("utf-8", "utf-16"):
        parser = _parser()
        try:
            read = parser.read(ini_path, encoding=encoding)
        except OSError:
            return None
        except UnicodeError:
            continue
        if read:
            return parser
    return None


def _load_or_seed(ini_path: Path) -> configparser.ConfigParser:
    parser = _read_ini_file(ini_path) or _parser()
    if not parser.has_section("SETTINGS"):
        seeded = _seed_parser()
        for section in seeded.sections():
            if not parser.has_section(section):
                parser.add_section(section)
            for key, value in seeded.items(section):
                if not parser.has_option(section, key):
                    parser.set(section, key, value)
    return parser


def _quiet_network_hooks(parser: configparser.ConfigParser) -> None:
    """Disable the IDA-oriented inject server so we do not open a listen port."""
    for section in parser.sections():
        if parser.has_option(section, "AutostartServer"):
            parser.set(section, "AutostartServer", "0")
        if parser.has_option(section, "ServerPort"):
            parser.set(section, "ServerPort", "0")


def _atomic_write_ini(path: Path, parser: configparser.ConfigParser) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines: list[str] = []
    for section in parser.sections():
        lines.append(f"[{section}]\n")
        for key, value in parser.items(section):
            lines.append(f"{key}={value}\n")
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text("".join(lines), encoding="utf-8", newline="\n")
    tmp.replace(path)


def allowed_profiles(*, architecture: Architecture) -> list[str]:
    if architecture is Architecture.X64:
        return [pid for pid in PROFILE_SECTIONS if pid not in X64_FORBIDDEN_PROFILES]
    return list(PROFILE_SECTIONS)


_DEFAULT_INI = """[SETTINGS]
CurrentProfile=VMProtect x86/x64
[VMProtect x86/x64]
DLLNormal=1
DLLStealth=0
DLLUnload=0
GetTickCount64Hook=1
GetTickCountHook=1
NtCloseHook=1
NtQueryInformationProcessHook=1
NtQueryObjectHook=1
NtQuerySystemInformationHook=1
NtSetDebugFilterStateHook=1
NtSetInformationThreadHook=1
NtUserBuildHwndListHook=1
NtUserFindWindowExHook=1
NtUserQueryWindowHook=1
NtUserGetForegroundWindowHook=1
OutputDebugStringHook=1
PebBeingDebugged=1
PebHeapFlags=1
PebNtGlobalFlag=1
PebStartupInfo=1
PebOsBuildNumber=1
AutostartServer=0
ServerPort=0
BreakOnTLS=1
KillAntiAttach=1
[Obsidium x86/x64]
DLLNormal=1
NtCloseHook=1
NtQueryInformationProcessHook=1
NtQuerySystemInformationHook=1
NtUserBuildHwndListHook=1
NtUserFindWindowExHook=1
NtUserQueryWindowHook=1
PebBeingDebugged=1
PebHeapFlags=1
PebNtGlobalFlag=1
PebStartupInfo=1
PebOsBuildNumber=1
AutostartServer=0
ServerPort=0
BreakOnTLS=1
[Themida x86/x64]
DLLNormal=1
NtCloseHook=1
NtCreateThreadExHook=1
NtQueryInformationProcessHook=1
NtQuerySystemInformationHook=1
NtSetInformationThreadHook=1
NtUserBuildHwndListHook=1
NtUserFindWindowExHook=1
NtUserQueryWindowHook=1
NtUserGetForegroundWindowHook=1
PebBeingDebugged=1
PebHeapFlags=1
PebNtGlobalFlag=1
PebStartupInfo=1
PebOsBuildNumber=1
AutostartServer=0
ServerPort=0
BreakOnTLS=1
[Armadillo x86]
DLLNormal=1
NtCloseHook=1
OutputDebugStringHook=1
PebBeingDebugged=1
PebHeapFlags=1
PebNtGlobalFlag=1
PebStartupInfo=1
PebOsBuildNumber=1
AutostartServer=0
ServerPort=0
[Basic]
DLLNormal=1
PebBeingDebugged=1
PebHeapFlags=1
PebNtGlobalFlag=1
PebStartupInfo=1
PebOsBuildNumber=1
AutostartServer=0
ServerPort=0
[Disabled]
DLLNormal=1
PebBeingDebugged=0
PebHeapFlags=0
PebNtGlobalFlag=0
PebStartupInfo=0
PebOsBuildNumber=0
AutostartServer=0
ServerPort=0
"""


def summarize_settings(
    *,
    enabled: bool,
    default_profile: str,
    layouts: Mapping[Architecture, StealthLayout | None],
) -> JsonObject:
    try:
        default_id = canonical_profile_id(default_profile)
    except StealthError:
        default_id = DEFAULT_PROFILE_ID
    architectures = {
        architecture.value: inspect_layout(layout) for architecture, layout in layouts.items()
    }
    return {
        "enabled": bool(enabled),
        "default_profile": default_id,
        "allowed_profiles": sorted(PROFILE_SECTIONS),
        "architectures": architectures,
    }
