"""Validation and import guards for the server-only provider config store.

``test_agent_config_persistence.py`` covers atomic save and POSIX privacy.
This file pins the pure guards: the Windows ACL principal fallback chain,
``ProviderProfile`` validation, best-effort chmod error swallowing, the
non-object config root and non-dict profile rejections, the ``save`` reset of
a corrupt ``profiles`` map, the Zerofall preview masking, and the full
``import_zerofall`` flow (confirmation required, then a saved profile).
"""

from __future__ import annotations

import getpass
import json
import os
from pathlib import Path

import pytest

from headless_re_mcp.agent import config as config_module
from headless_re_mcp.agent.config import ProviderConfigStore, ProviderProfile

_LOOPBACK = "http://localhost:8080"


def test_windows_acl_principal_prefers_getlogin(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(os, "getlogin", lambda: "realuser")
    assert config_module._windows_acl_principal() == "realuser"


def test_windows_acl_principal_falls_back_then_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def boom() -> str:
        raise OSError("no controlling terminal")

    monkeypatch.setattr(os, "getlogin", boom)
    monkeypatch.setenv("USERNAME", "")
    monkeypatch.setattr(getpass, "getuser", lambda: "svc-account")
    assert config_module._windows_acl_principal() == "svc-account"

    monkeypatch.setattr(getpass, "getuser", lambda: "")
    with pytest.raises(OSError, match="Windows account is unavailable"):
        config_module._windows_acl_principal()


def test_provider_profile_requires_id_and_model() -> None:
    with pytest.raises(ValueError, match="id and model"):
        ProviderProfile(id="  ", base_url=_LOOPBACK, model="gpt")


def test_provider_profile_rejects_out_of_range_threshold() -> None:
    with pytest.raises(ValueError, match="10..95"):
        ProviderProfile(
            id="p",
            base_url=_LOOPBACK,
            model="gpt",
            context_compression_threshold_percent=5,
        )


def test_best_effort_protect_swallows_filesystem_errors(tmp_path: Path) -> None:
    # chmod on a path whose parent does not exist raises OSError, which the
    # helper is required to swallow so a provider save is never blocked by it.
    ProviderConfigStore._best_effort_protect(tmp_path / "missing" / "file")


def test_read_rejects_a_non_object_root(tmp_path: Path) -> None:
    path = tmp_path / "cfg.json"
    path.write_text("[1, 2, 3]", encoding="utf-8")
    store = ProviderConfigStore(path)
    with pytest.raises(ValueError, match="must be an object"):
        store.list_public()


def test_get_rejects_a_non_dict_profile(tmp_path: Path) -> None:
    path = tmp_path / "cfg.json"
    path.write_text('{"profiles": {"bad": [1, 2]}, "current": "bad"}', encoding="utf-8")
    store = ProviderConfigStore(path)
    with pytest.raises(KeyError):
        store.get("bad")


def test_save_resets_a_corrupt_profiles_map_and_can_skip_current(tmp_path: Path) -> None:
    path = tmp_path / "cfg.json"
    path.write_text('{"profiles": "corrupt", "current": "x"}', encoding="utf-8")
    store = ProviderConfigStore(path)
    profile = ProviderProfile(id="p1", base_url=_LOOPBACK, model="gpt")

    store.save(profile, make_current=False)

    data = json.loads(path.read_text(encoding="utf-8"))
    assert "p1" in data["profiles"]
    assert data["current"] == "x", "make_current=False must not move the pointer"


def test_preview_zerofall_masks_provider_keys_without_a_top_level_key(
    tmp_path: Path,
) -> None:
    store = ProviderConfigStore(tmp_path / "cfg.json")
    preview = store.preview_zerofall(
        {"model": "gpt-4o", "providerApiKeys": {"openai": "sk-secret-value"}}
    )
    assert preview["requires_confirmation"] is True
    assert "sk-secret-value" not in json.dumps(preview["fields"])
    assert preview["fields"]["providerApiKeys"]["openai"] != "sk-secret-value"


def test_import_zerofall_requires_confirmation(tmp_path: Path) -> None:
    store = ProviderConfigStore(tmp_path / "cfg.json")
    with pytest.raises(ValueError, match="confirm_required"):
        store.import_zerofall({"model": "gpt-4o"}, confirm=False)


def test_import_zerofall_saves_a_profile_from_flattened_fields(tmp_path: Path) -> None:
    store = ProviderConfigStore(tmp_path / "cfg.json")
    raw = {
        "ai": {"apiBaseUrl": "https://api.example.com"},
        "model": "gpt-4o",
        "providerApiKeys": {"zerofall": "sk-zf"},
        "knownModels": ["gpt-4o", 5],
        "modelCatalogs": [{"name": "c"}, "bad"],
        "enableThinking": True,
        "reasoningEffort": "high",
        "contextCompressionThresholdPercent": 60,
    }

    result = store.import_zerofall(raw, confirm=True)

    assert result["id"] == "zerofall"
    assert result["base_url"] == "https://api.example.com/v1"
    assert result["model"] == "gpt-4o"
    assert result["configured"] is True
    assert result["known_models"] == ["gpt-4o"]
    assert result["enable_thinking"] is True
    assert result["reasoning_effort"] == "high"
    assert result["context_compression_threshold_percent"] == 60
    stored = json.loads((tmp_path / "cfg.json").read_text(encoding="utf-8"))
    assert stored["current"] == "zerofall"
