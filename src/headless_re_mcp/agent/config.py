"""Server-only provider profiles and safe Zerofall import."""

from __future__ import annotations

import getpass
import ipaddress
import json
import os
import tempfile
from contextlib import suppress
from dataclasses import asdict, dataclass, field
from pathlib import Path
from threading import RLock
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from headless_re_mcp.agent.redaction import masked_secret, redact
from headless_re_mcp.backends.common.bounded_run import TimedOut, run_bounded

ZEROFALL_IMPORT_FIELDS = frozenset(
    {
        "ai.apiBaseUrl",
        "apiKey",
        "model",
        "knownModels",
        "modelCatalogs",
        "providerApiKeys",
        "enableThinking",
        "reasoningEffort",
        "contextCompressionThresholdPercent",
    }
)
_MAX_PROVIDER_CONFIG_BYTES = 4 * 1024 * 1024


def _windows_acl_principal() -> str:
    try:
        principal = os.getlogin().strip()
    except OSError:
        principal = ""
    if not principal:
        principal = os.environ.get("USERNAME", "").strip()
    if not principal:
        principal = getpass.getuser().strip()
    if not principal:
        raise OSError("current Windows account is unavailable")
    return principal


def normalize_base_url(value: str) -> str:
    raw = value.strip()
    if not raw:
        raise ValueError("provider base URL is required")
    parsed = urlsplit(raw)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("provider base URL must be absolute http(s)")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("provider base URL must not include credentials")
    path = parsed.path.rstrip("/")
    if not path.endswith("/v1"):
        path = f"{path}/v1" if path else "/v1"
    return urlunsplit((parsed.scheme.lower(), parsed.netloc, path, "", ""))


@dataclass(slots=True)
class ProviderProfile:
    id: str
    base_url: str
    model: str
    api_key: str | None = None
    known_models: list[str] = field(default_factory=list)
    model_catalogs: list[dict[str, Any]] = field(default_factory=list)
    enable_thinking: bool = False
    reasoning_effort: str | None = None
    context_compression_threshold_percent: int = 75

    def __post_init__(self) -> None:
        self.base_url = normalize_base_url(self.base_url)
        parsed = urlsplit(self.base_url)
        if self.api_key and parsed.scheme == "http":
            hostname = parsed.hostname or ""
            try:
                loopback = ipaddress.ip_address(hostname).is_loopback
            except ValueError:
                loopback = hostname.casefold() == "localhost"
            if not loopback:
                raise ValueError(
                    "provider API keys require HTTPS unless the host is loopback"
                )
        if not self.id.strip() or not self.model.strip():
            raise ValueError("profile id and model are required")
        if not 10 <= self.context_compression_threshold_percent <= 95:
            raise ValueError("context compression threshold must be 10..95")

    def public(self, *, source: str = "file") -> dict[str, Any]:
        return {
            "id": self.id,
            "base_url": self.base_url,
            "model": self.model,
            "known_models": list(self.known_models),
            "model_catalogs": redact(self.model_catalogs),
            "enable_thinking": self.enable_thinking,
            "reasoning_effort": self.reasoning_effort,
            "context_compression_threshold_percent": self.context_compression_threshold_percent,
            "configured": bool(self.api_key),
            "api_key_masked": masked_secret(self.api_key),
            "source": source,
        }


class ProviderConfigStore:
    def __init__(self, path: Path) -> None:
        self.path = path.expanduser().resolve()
        self._lock = RLock()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._best_effort_protect(self.path.parent, directory=True)

    @staticmethod
    def _best_effort_protect(path: Path, *, directory: bool = False, timeout: float = 10.0) -> None:
        try:
            if os.name == "nt":
                import subprocess

                target = str(path)
                principal = _windows_acl_principal()
                grant = (
                    f"{principal}:(OI)(CI)F" if directory else f"{principal}:F"
                )
                # icacls is looked up on PATH. A hanging stand-in plus
                # subprocess.run's untimed drain after kill left this ACL
                # tweak blocking a provider save; TimeoutExpired is not a
                # TimeoutError, so the old except also missed it.
                run_bounded(
                    ["icacls", target, "/inheritance:r", "/grant:r", grant],
                    timeout=timeout,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
            else:
                path.chmod(0o700 if directory else 0o600)
        except (OSError, TimeoutError, TimedOut):
            pass

    def _read(self) -> dict[str, Any]:
        if not self.path.is_file():
            return {"profiles": {}, "current": None}
        with self.path.open("rb") as stream:
            payload = stream.read(_MAX_PROVIDER_CONFIG_BYTES + 1)
        if len(payload) > _MAX_PROVIDER_CONFIG_BYTES:
            raise ValueError(
                f"provider config exceeds {_MAX_PROVIDER_CONFIG_BYTES} bytes"
            )
        raw = json.loads(payload.decode("utf-8"))
        if not isinstance(raw, dict):
            raise ValueError("provider config root must be an object")
        return raw

    def _write(self, data: dict[str, Any]) -> None:
        payload = json.dumps(data, ensure_ascii=False, indent=2)
        if len(payload.encode("utf-8")) > _MAX_PROVIDER_CONFIG_BYTES:
            raise ValueError(
                f"provider config exceeds {_MAX_PROVIDER_CONFIG_BYTES} bytes"
            )
        temporary: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=self.path.parent,
                prefix=f".{self.path.name}-",
                suffix=".tmp",
                delete=False,
            ) as stream:
                temporary = Path(stream.name)
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            self._best_effort_protect(temporary)
            os.replace(temporary, self.path)
            temporary = None
        finally:
            if temporary is not None:
                with suppress(OSError):
                    temporary.unlink()
        self._best_effort_protect(self.path)

    def list_public(self) -> dict[str, Any]:
        with self._lock:
            data = self._read()
        profiles_value = data.get("profiles")
        profiles: dict[str, Any] = profiles_value if isinstance(profiles_value, dict) else {}
        return {
            "current": data.get("current"),
            "profiles": [self._profile_from_raw(key, value).public(source="file") for key, value in profiles.items() if isinstance(value, dict)],
        }

    def _profile_from_raw(self, profile_id: str, raw: dict[str, Any]) -> ProviderProfile:
        env_prefix = f"HEADLESS_RE_PROVIDER_{profile_id.upper().replace('-', '_')}_"
        api_key = os.getenv(env_prefix + "API_KEY") or os.getenv("HEADLESS_RE_PROVIDER_API_KEY") or raw.get("api_key")
        base_url = os.getenv(env_prefix + "BASE_URL") or os.getenv("HEADLESS_RE_PROVIDER_BASE_URL") or raw.get("base_url") or "https://api.openai.com/v1"
        model = os.getenv(env_prefix + "MODEL") or os.getenv("HEADLESS_RE_PROVIDER_MODEL") or raw.get("model") or "gpt-4.1-mini"
        return ProviderProfile(
            id=profile_id,
            base_url=str(base_url),
            model=str(model),
            api_key=str(api_key) if api_key else None,
            known_models=[str(x) for x in raw.get("known_models", []) if isinstance(x, str)],
            model_catalogs=[dict(x) for x in raw.get("model_catalogs", []) if isinstance(x, dict)],
            enable_thinking=bool(raw.get("enable_thinking", False)),
            reasoning_effort=str(raw["reasoning_effort"]) if raw.get("reasoning_effort") else None,
            context_compression_threshold_percent=int(raw.get("context_compression_threshold_percent", 75)),
        )

    def get(self, profile_id: str | None = None) -> ProviderProfile:
        with self._lock:
            data = self._read()
        recorded_current = data.get("current")
        selected = profile_id or recorded_current or "default"
        profiles_value = data.get("profiles")
        profiles: dict[str, Any] = profiles_value if isinstance(profiles_value, dict) else {}
        raw = profiles.get(selected)
        if raw is None:
            # profiles.get used to default to {}, a dict, so the guard below
            # never fired for a missing profile: get() silently fabricated a
            # keyless api.openai.com default named after the absent id. Three
            # callers wrap this in `except KeyError` expecting a 404 for an id
            # that is not there -- save_provider, probe_models, and the run-start
            # route -- so instead a model probe reached OpenAI and a run began
            # keyless. Raise unless this is the untouched first run (no id asked
            # for, nothing recorded current, no profiles at all), where a
            # synthetic default still lets the empty console build a provider.
            bootstrap = profile_id is None and not recorded_current and not profiles
            if not bootstrap:
                raise KeyError(selected)
            raw = {}
        if not isinstance(raw, dict):
            raise KeyError(selected)
        return self._profile_from_raw(str(selected), raw)

    def save(self, profile: ProviderProfile, *, make_current: bool = True) -> dict[str, Any]:
        with self._lock:
            data = self._read()
            profiles = data.setdefault("profiles", {})
            if not isinstance(profiles, dict):
                profiles = data["profiles"] = {}
            profiles[profile.id] = asdict(profile)
            if make_current:
                data["current"] = profile.id
            self._write(data)
        return profile.public(source="file")

    @staticmethod
    def _flatten_zerofall(raw: dict[str, Any]) -> dict[str, Any]:
        ai_value = raw.get("ai")
        ai: dict[str, Any] = ai_value if isinstance(ai_value, dict) else {}
        flat = {key: raw[key] for key in raw if key in ZEROFALL_IMPORT_FIELDS}
        if "apiBaseUrl" in ai:
            flat["ai.apiBaseUrl"] = ai["apiBaseUrl"]
        return flat

    def preview_zerofall(self, raw: dict[str, Any]) -> dict[str, Any]:
        fields = self._flatten_zerofall(raw)
        ignored = sorted(set(raw) - {key for key in ZEROFALL_IMPORT_FIELDS if "." not in key} - {"ai"})
        preview = redact(fields)
        if "apiKey" in fields:
            preview["apiKey"] = masked_secret(str(fields["apiKey"]))
        if "providerApiKeys" in fields and isinstance(fields["providerApiKeys"], dict):
            preview["providerApiKeys"] = {str(k): masked_secret(str(v)) for k, v in fields["providerApiKeys"].items()}
        return {"fields": preview, "ignored": ignored, "requires_confirmation": True}

    def import_zerofall(self, raw: dict[str, Any], *, confirm: bool, profile_id: str = "zerofall") -> dict[str, Any]:
        if not confirm:
            raise ValueError("confirm_required")
        fields = self._flatten_zerofall(raw)
        keys_value = fields.get("providerApiKeys")
        keys: dict[str, Any] = keys_value if isinstance(keys_value, dict) else {}
        api_key = fields.get("apiKey") or keys.get(profile_id) or keys.get("openai")
        profile = ProviderProfile(
            id=profile_id,
            base_url=str(fields.get("ai.apiBaseUrl") or "https://api.openai.com/v1"),
            model=str(fields.get("model") or "gpt-4.1-mini"),
            api_key=str(api_key) if api_key else None,
            known_models=[str(x) for x in fields.get("knownModels", []) if isinstance(x, str)],
            model_catalogs=[dict(x) for x in fields.get("modelCatalogs", []) if isinstance(x, dict)],
            enable_thinking=bool(fields.get("enableThinking", False)),
            reasoning_effort=str(fields["reasoningEffort"]) if fields.get("reasoningEffort") else None,
            context_compression_threshold_percent=int(fields.get("contextCompressionThresholdPercent", 75)),
        )
        return self.save(profile)
