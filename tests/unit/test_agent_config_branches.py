"""Validation, degradation, and Zerofall-import branches of the provider store.

Atomicity, POSIX permissions, and URL normalisation are pinned elsewhere. This
file covers the provider config store's remaining reachable edges on any host:
the Windows ACL-principal fallback chain (called directly, not through the
platform gate), the profile invariants, the on-disk guards a corrupt config
trips, and both halves of the Zerofall import surface. These back every agent
run, PE or not, so a bad config file must fail loud rather than silently serve
the wrong provider.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from headless_re_mcp.agent import config as config_module
from headless_re_mcp.agent.config import ProviderConfigStore, ProviderProfile

# --------------------------------------------------------------------------
# _windows_acl_principal fallback chain
# --------------------------------------------------------------------------


def test_acl_principal_prefers_the_login_name(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(config_module.os, "getlogin", lambda: "  analyst  ")
    assert config_module._windows_acl_principal() == "analyst"


def test_acl_principal_falls_back_to_username_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """A service with no login session uses %USERNAME% instead."""
    def no_login() -> str:
        raise OSError("no controlling terminal")

    monkeypatch.setattr(config_module.os, "getlogin", no_login)
    monkeypatch.setenv("USERNAME", "service-account")
    assert config_module._windows_acl_principal() == "service-account"


def test_acl_principal_falls_back_to_getpass(monkeypatch: pytest.MonkeyPatch) -> None:
    def no_login() -> str:
        raise OSError("no session")

    monkeypatch.setattr(config_module.os, "getlogin", no_login)
    monkeypatch.delenv("USERNAME", raising=False)
    monkeypatch.setattr(config_module.getpass, "getuser", lambda: "pwuser")
    assert config_module._windows_acl_principal() == "pwuser"


def test_acl_principal_raises_when_no_account_is_discoverable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def no_login() -> str:
        raise OSError("no session")

    monkeypatch.setattr(config_module.os, "getlogin", no_login)
    monkeypatch.delenv("USERNAME", raising=False)
    monkeypatch.setattr(config_module.getpass, "getuser", lambda: "")
    with pytest.raises(OSError, match="account is unavailable"):
        config_module._windows_acl_principal()


# --------------------------------------------------------------------------
# ProviderProfile invariants
# --------------------------------------------------------------------------


def test_profile_requires_a_non_empty_id_and_model() -> None:
    with pytest.raises(ValueError, match="id and model are required"):
        ProviderProfile(id="   ", base_url="https://api.example", model="m")
    with pytest.raises(ValueError, match="id and model are required"):
        ProviderProfile(id="default", base_url="https://api.example", model="  ")


def test_profile_bounds_the_compression_threshold() -> None:
    with pytest.raises(ValueError, match="10..95"):
        ProviderProfile(
            id="default",
            base_url="https://api.example",
            model="m",
            context_compression_threshold_percent=5,
        )


# --------------------------------------------------------------------------
# _best_effort_protect swallows a chmod it cannot do
# --------------------------------------------------------------------------


def test_best_effort_protect_swallows_a_chmod_that_fails(tmp_path: Path) -> None:
    """Protecting a path that is not there is best-effort, never fatal."""
    missing = tmp_path / "does-not-exist" / "providers.json"
    ProviderConfigStore._best_effort_protect(missing)  # must not raise


# --------------------------------------------------------------------------
# _read / get / save guards on corrupt state
# --------------------------------------------------------------------------


def test_read_rejects_a_config_whose_root_is_not_an_object(tmp_path: Path) -> None:
    path = tmp_path / "providers.json"
    store = ProviderConfigStore(path)
    path.write_text("[1, 2, 3]", encoding="utf-8")
    with pytest.raises(ValueError, match="root must be an object"):
        store.list_public()


def test_get_refuses_a_profile_entry_that_is_not_an_object(tmp_path: Path) -> None:
    path = tmp_path / "providers.json"
    store = ProviderConfigStore(path)
    path.write_text(
        json.dumps({"current": "default", "profiles": {"default": "corrupt"}}),
        encoding="utf-8",
    )
    with pytest.raises(KeyError, match="default"):
        store.get("default")


def test_save_repairs_a_profiles_map_that_is_not_a_map(tmp_path: Path) -> None:
    """A hand-mangled config whose profiles went non-dict is reset, not indexed into."""
    path = tmp_path / "providers.json"
    store = ProviderConfigStore(path)
    path.write_text(json.dumps({"current": None, "profiles": "corrupt"}), encoding="utf-8")

    store.save(ProviderProfile(id="default", base_url="https://api.example", model="m"))

    saved = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(saved["profiles"], dict)
    assert "default" in saved["profiles"]


def test_save_can_leave_the_current_pointer_alone(tmp_path: Path) -> None:
    """Saving a secondary profile without make_current must not steal selection."""
    path = tmp_path / "providers.json"
    store = ProviderConfigStore(path)
    store.save(ProviderProfile(id="default", base_url="https://api.example", model="m"))

    store.save(
        ProviderProfile(id="backup", base_url="https://api.example", model="m2"),
        make_current=False,
    )

    saved = json.loads(path.read_text(encoding="utf-8"))
    assert saved["current"] == "default"
    assert set(saved["profiles"]) == {"default", "backup"}


# --------------------------------------------------------------------------
# Zerofall preview / import
# --------------------------------------------------------------------------


def test_preview_masks_provider_api_keys_without_a_top_level_key(tmp_path: Path) -> None:
    """A Zerofall export carrying only a keyed map still has its secrets masked.

    preview must never echo a secret, whether it arrives as a single apiKey or
    as a providerApiKeys map, so an operator confirming an import cannot leak
    one by reading the preview.
    """
    store = ProviderConfigStore(tmp_path / "providers.json")

    preview = store.preview_zerofall(
        {
            "ai": {"apiBaseUrl": "https://api.z.example"},
            "model": "z-model",
            "providerApiKeys": {"openai": "sk-secret", "z": "zz-secret"},
        }
    )

    assert "apiKey" not in preview["fields"]
    masked = preview["fields"]["providerApiKeys"]
    assert masked["openai"] != "sk-secret"
    assert masked["z"] != "zz-secret"
    assert preview["requires_confirmation"] is True


def test_preview_masks_a_lone_top_level_api_key(tmp_path: Path) -> None:
    """An export with a single apiKey and no keyed map still masks the secret."""
    store = ProviderConfigStore(tmp_path / "providers.json")

    preview = store.preview_zerofall({"model": "z", "apiKey": "sk-secret"})

    assert preview["fields"]["apiKey"] != "sk-secret"
    assert "providerApiKeys" not in preview["fields"]


def test_import_defaults_the_base_url_when_no_ai_block_is_present(tmp_path: Path) -> None:
    """A Zerofall export lacking the ai block falls back to the OpenAI base URL."""
    store = ProviderConfigStore(tmp_path / "providers.json")

    public = store.import_zerofall(
        {"model": "z-model", "apiKey": "sk-secret"}, confirm=True
    )

    assert public["base_url"] == "https://api.openai.com/v1"
    assert public["configured"] is True


def test_import_requires_confirmation(tmp_path: Path) -> None:
    store = ProviderConfigStore(tmp_path / "providers.json")
    with pytest.raises(ValueError, match="confirm_required"):
        store.import_zerofall({"apiKey": "sk"}, confirm=False)


def test_import_builds_and_saves_a_profile_from_a_zerofall_export(tmp_path: Path) -> None:
    """Confirmed import maps the Zerofall fields onto a saved, current profile."""
    path = tmp_path / "providers.json"
    store = ProviderConfigStore(path)

    public = store.import_zerofall(
        {
            "ai": {"apiBaseUrl": "https://api.z.example"},
            "apiKey": "sk-secret",
            "model": "z-model",
            "knownModels": ["z-model", 7],
            "modelCatalogs": [{"id": "z-model"}, "junk"],
            "enableThinking": True,
            "reasoningEffort": "high",
            "contextCompressionThresholdPercent": 80,
        },
        confirm=True,
    )

    assert public["configured"] is True
    assert public["model"] == "z-model"
    assert public["base_url"] == "https://api.z.example/v1"
    assert public["enable_thinking"] is True
    assert public["reasoning_effort"] == "high"

    saved = json.loads(path.read_text(encoding="utf-8"))
    assert saved["current"] == "zerofall"
    profile = saved["profiles"]["zerofall"]
    assert profile["api_key"] == "sk-secret"
    assert profile["known_models"] == ["z-model"]  # the non-string was dropped
    assert profile["model_catalogs"] == [{"id": "z-model"}]  # the non-object was dropped


def test_import_reads_the_api_key_from_the_keyed_map_when_absent(tmp_path: Path) -> None:
    """With no top-level apiKey, the profile-named or openai key is used."""
    store = ProviderConfigStore(tmp_path / "providers.json")

    public = store.import_zerofall(
        {
            "ai": {"apiBaseUrl": "https://api.z.example"},
            "model": "z-model",
            "providerApiKeys": {"openai": "sk-from-map"},
        },
        confirm=True,
    )

    assert public["configured"] is True
