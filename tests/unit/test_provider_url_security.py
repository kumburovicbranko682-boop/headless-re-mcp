from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.agent import config as provider_config
from headless_re_mcp.agent.config import (
    ProviderConfigStore,
    ProviderProfile,
    normalize_base_url,
)


@pytest.mark.parametrize(
    "url",
    [
        "https://user:password@provider.example/v1",
        "https://access-token@provider.example",
        "http://:password@127.0.0.1:8000/v1",
    ],
)
def test_provider_base_url_rejects_embedded_credentials(url: str) -> None:
    with pytest.raises(ValueError, match="must not include credentials"):
        normalize_base_url(url)

    with pytest.raises(ValueError, match="must not include credentials"):
        ProviderProfile("unsafe", url, "model")


def test_provider_base_url_still_normalizes_safe_urls() -> None:
    assert normalize_base_url("HTTPS://provider.example:8443/api/") == (
        "https://provider.example:8443/api/v1"
    )


@pytest.mark.parametrize(
    "url",
    [
        "http://provider.example/v1",
        "http://192.0.2.10:8000",
    ],
)
def test_provider_api_keys_are_not_sent_over_remote_plaintext(url: str) -> None:
    with pytest.raises(ValueError, match="API keys require HTTPS"):
        ProviderProfile("unsafe", url, "model", api_key="secret")


@pytest.mark.parametrize(
    "url",
    [
        "http://localhost:8000",
        "http://127.0.0.1:8000/v1",
        "http://[::1]:8000",
    ],
)
def test_provider_api_keys_may_use_local_plaintext(url: str) -> None:
    profile = ProviderProfile("local", url, "model", api_key="secret")
    assert profile.base_url.startswith("http://")


def test_remote_plaintext_without_a_secret_remains_supported() -> None:
    profile = ProviderProfile("public", "http://provider.example", "model")
    assert profile.base_url == "http://provider.example/v1"


def test_provider_config_is_rejected_before_an_unbounded_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(provider_config, "_MAX_PROVIDER_CONFIG_BYTES", 64)
    path = tmp_path / "providers.json"
    path.write_bytes(b"{" + b" " * 64 + b"}")

    with pytest.raises(ValueError, match="provider config exceeds 64 bytes"):
        ProviderConfigStore(path).list_public()


def test_provider_config_refuses_writes_that_it_could_not_read_back(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(provider_config, "_MAX_PROVIDER_CONFIG_BYTES", 1024)
    path = tmp_path / "providers.json"
    store = ProviderConfigStore(path)
    store.save(ProviderProfile("default", "https://provider.example", "small"))
    original = path.read_bytes()

    with pytest.raises(ValueError, match="provider config exceeds 1024 bytes"):
        store.save(
            ProviderProfile(
                "oversized",
                "https://provider.example",
                "x" * 2048,
            )
        )

    assert path.read_bytes() == original
